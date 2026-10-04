/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package local_cache

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// openTierStream opens a stream over a tiered object for the cache to proxy.
//
// The object is pinned for the life of the stream.  A proxied object gets no
// redirect-hold stamp -- no URL was handed out -- so the pin is its only protection:
// without it, eviction could delete the remote object between two of this
// stream's ranged GETs, which is exactly the configuration operators are
// pointed at for private namespaces.
//
// The stream reads only the copy the cache uploaded.  If the target no longer
// holds it -- the object was overwritten in the bucket -- the read fails, and
// dropping the entry lets the next request fetch the object from the origin
// again rather than fail the same way until the integrity scan notices.  The
// bucket object goes with it, since it is not ours.
func (pc *PersistentCache) openTierStream(ctx context.Context, target *tierTarget, res *objectResolution) *tierObjectStream {
	stream := newTierObjectStream(ctx, target, res.instanceHash, res.meta.ContentLength)
	stream.onClose = pc.storage.PinObject(res.instanceHash)
	stream.expect = res.meta.Remote
	hash := res.instanceHash
	tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByProxy).Inc()
	stream.onChanged = func() {
		tierChangedObjectsTotal.WithLabelValues(target.metricLabel(), tierChangeSeenOnRead).Inc()
		pc.egrp.Go(func() error {
			if err := pc.storage.Delete(hash); err != nil {
				log.Warnf("Failed to drop tiered object %s after it changed on its target: %v", hash, err)
			}
			return nil
		})
	}
	return stream
}

// newTierSeekableReader builds a SeekableReader that proxies a tiered
// object through the cache (used when redirect is disabled, or by internal
// callers such as the data-integrity scan).
func (pc *PersistentCache) newTierSeekableReader(ctx context.Context, target *tierTarget, res *objectResolution) *SeekableReader {
	stream := pc.openTierStream(ctx, target, res)
	return &SeekableReader{RangeReader: &RangeReader{
		storage:      pc.storage,
		instanceHash: res.instanceHash,
		meta:         res.meta,
		start:        0,
		end:          res.meta.ContentLength - 1,
		remoteStream: stream,
	}}
}

// redirectHoldHeadroom is how much longer than a pre-signed URL's lifetime the
// eviction hold must last, covering the gap between minting a URL and the
// client actually finishing with it.
const redirectHoldHeadroom = 5 * time.Minute

// tierRedirectExpiry returns the configured presigned-URL lifetime.
func tierRedirectExpiry() time.Duration {
	if d := param.Cache_TieringRedirectExpiry.GetDuration(); d > 0 {
		return d
	}
	return 5 * time.Minute
}

// redirectRetainsAuthorization reports whether a spec-compliant HTTP client
// following a redirect from this cache to the given host would carry the
// client's Authorization header along with it.
//
// This mirrors net/http's own rule (shouldCopyHeaderOnRedirect ->
// isDomainOrSubdomain): the header survives when the destination is the same
// host as the origin *or any subdomain of it* -- "foo.com" to "sub.foo.com" is
// deliberately permitted.  Matching by equality alone would miss the subdomain
// case, which is not exotic for object storage: a cache on cache.example.org
// beside a MinIO or Ceph RGW on s3.cache.example.org hits it, and virtual-host
// bucket addressing adds another label on top.
//
// Ports are irrelevant (net/http compares hostnames only), and an IP literal
// can never be a subdomain, matching net/http's ':'/'%' bail-out.
func redirectRetainsAuthorization(destHost, cacheHost string) bool {
	dest, cache := hostOnly(destHost), hostOnly(cacheHost)
	if dest == "" || cache == "" {
		// Nothing to compare; assume the worst so the caller proxies.
		return true
	}
	if dest == cache {
		return true
	}
	if strings.ContainsAny(dest, ":%") {
		return false // IP literal or zone-scoped address
	}
	if !strings.HasSuffix(dest, cache) {
		return false
	}
	return dest[len(dest)-len(cache)-1] == '.'
}

// hostOnly folds a host[:port] (or a bare URL) down to the ASCII hostname
// net/http would compare, reusing the cache's own IDNA folding.
func hostOnly(host string) string {
	if host == "" {
		return ""
	}
	if u, err := url.Parse(host); err == nil && u.Host != "" {
		host = u.Host
	}
	normalized := normalizeHost(host)
	if h, _, err := net.SplitHostPort(normalized); err == nil {
		normalized = h
	}
	return strings.Trim(normalized, "[]")
}

// cacheExternalHost returns the host clients use to reach this cache, which is
// the origin host of the redirect for Authorization-forwarding purposes.
func cacheExternalHost() string {
	if u := param.Server_ExternalWebUrl.GetString(); u != "" {
		return hostOnly(u)
	}
	return hostOnly(param.Server_Hostname.GetString())
}

// clientAcceptsRedirectScheme reports whether the request advertised that the
// client can follow a redirect in the given scheme.  The header and its
// parsing live in server_structs so the client writing it and the cache
// reading it cannot drift apart.
func clientAcceptsRedirectScheme(r *http.Request, scheme string) bool {
	return server_structs.AcceptsRedirectScheme(
		r.Header.Get(server_structs.AcceptRedirectHeader), scheme)
}

// tryTierRedirect serves a GET by redirecting the client straight to the
// tiering target that holds the object, so the bytes never pass through the
// cache.  Returns true when the response has been written; false means the
// caller should proceed with the normal serving path (object not tiered, the
// target cannot issue URLs, redirect disabled, object stale, and so on).
//
// The redirect is only issued for objects that are fully resident on a
// tiering target and still fresh — stale objects fall through so the normal path
// revalidates against the origin.  Issuing the URL stamps the redirect-hold key,
// which protects the object from eviction for Cache.TieringRedirectEvictionHold.
//
// Token safety: the URL points at a storage provider outside the federation
// trust boundary, so the client's bearer token must not reach it.  Two of the
// three ways it could are closed by construction:
//   - The URL (the redirect Location) is self-authenticating -- a pre-signed
//     URL carries only the provider's own signature material -- and the
//     Pelican token is never embedded in it.
//   - A token delivered as ?authz= (how the director hands one to a client)
//     is not carried onto the Location: http.Redirect only rewrites the query
//     for relative targets, and these URLs are absolute.
//
// The third is the Authorization header, which a compliant client drops only
// when the destination is neither the host it connected to nor a subdomain of
// it (see redirectRetainsAuthorization).  When a request carries such a header
// and the target's redirect host falls inside that domain, this function
// declines and the object is proxied instead, so a storage endpoint
// co-located with the cache cannot be handed federation tokens.
//
// Residual risk: a client that re-sends Authorization across unrelated hosts,
// contrary to the spec (e.g. curl --location-trusted), still discloses it.
// Operators serving private namespaces to such clients should set
// Cache.TieringDisableRedirect.  See TestTierRedirectDropsAuthorizationCrossHost.
func (pc *PersistentCache) tryTierRedirect(w http.ResponseWriter, r *http.Request, objectPath, token string, reqLog *log.Entry, startTime time.Time) bool {
	if len(pc.storage.tierTargets) == 0 || param.Cache_TieringDisableRedirect.GetBool() {
		return false
	}

	if ok, _ := pc.ac.authorize(token_scopes.Wlcg_Storage_Read, objectPath, token); !ok {
		// Let the normal path produce the proper 403 response.
		return false
	}

	pelicanURL := pc.normalizePath(objectPath)
	objectHash := pc.db.ObjectHash(pelicanURL)
	etag, found, err := pc.db.GetLatestETag(objectHash)
	if err != nil || !found {
		return false
	}
	instanceHash := pc.db.InstanceHash(etag, objectHash)
	meta, err := pc.storage.GetMetadata(instanceHash)
	if err != nil || meta == nil || meta.Completed.IsZero() {
		return false
	}
	target := pc.storage.getTierTarget(meta.StorageID)
	if target == nil || !target.canRedirect {
		// Either the object is not tiered, or its target cannot hand out a
		// URL the client could fetch on its own; proxy instead.
		return false
	}
	// A URL the client fetches over something other than HTTP -- a file://
	// path on shared storage, say -- only works if the client is in a
	// position to use it, and nothing observable about a request says
	// whether it is: the same subnet does not imply the same mount, and a
	// containerized client can share a host without sharing a mount
	// namespace.  So the client has to say so, and we believe only what it
	// claims.  http and https need no advertisement; every client follows
	// those.
	if scheme := target.redirectScheme; scheme != "http" && scheme != "https" && !clientAcceptsRedirectScheme(r, scheme) {
		reqLog.WithField("scheme", scheme).Debug("Client did not advertise support for this redirect scheme; proxying instead")
		return false
	}
	// Would redirecting hand this client's Authorization header to the target?
	// Only a request that carries one has anything to leak -- a public read,
	// or the director's ?authz= flow, does not -- and the host to compare
	// against is the one the client actually connected to, since that is what
	// its redirect policy compares.  The destination is the target's probed
	// redirect host rather than its configured endpoint: that is where the
	// client would really be sent, and it exists for every kind of target.
	// Checking before a URL is minted keeps a request that is going to be
	// proxied anyway from paying for one.  See the doc comment.
	if r.Header.Get("Authorization") != "" && target.redirectSendsCredentials(r.Host) {
		reqLog.Debug("Proxying instead of redirecting: the tier target shares this cache's DNS domain, " +
			"so the client would forward its credentials to it")
		return false
	}

	// Freshness: no-store/no-cache objects and anything past its expiry
	// must go through the normal path so revalidation happens.
	if meta.CCFlags&(ccNoStore|ccNoCache) != 0 {
		return false
	}
	if expires := meta.ComputeExpires(); expires.IsZero() || !expires.After(time.Now()) {
		return false
	}

	// A client revalidating with the ETag it already holds is answered here
	// rather than redirected.  Sending it to the target instead would make it
	// re-download the whole object for nothing: the far end cannot complete the
	// revalidation, because the storage provider answers with its own ETag
	// (for S3, an MD5 of the stored bytes), which never matches the origin's.
	if meta.ETag != "" {
		for _, match := range strings.Split(r.Header.Get("If-None-Match"), ",") {
			if match = strings.TrimSpace(match); match == "*" || (match != "" && match == meta.ETag) {
				w.Header().Set("ETag", meta.ETag)
				w.Header().Set("Cache-Control", meta.ResponseCacheControl())
				w.WriteHeader(http.StatusNotModified)
				tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedNotModified).Inc()
				reqLog.WithFields(log.Fields{
					"status":   http.StatusNotModified,
					"cache":    "hit-redirect",
					"duration": time.Since(startTime).Round(time.Millisecond).String(),
				}).Info("Request complete")
				return true
			}
		}
	}

	targetURL, err := target.redirectURL(r.Context(), instanceHash, tierRedirectExpiry(), meta.Remote)
	if err != nil {
		reqLog.WithError(err).Warn("Failed to build a redirect URL for the tier target; falling back to proxying")
		return false
	}
	// The credential check above was made against the host the startup probe
	// reported.  Every backend we have points all of its URLs at one host,
	// but nothing guarantees that, so a URL that disagrees is refused rather
	// than handed out on the strength of a check made about somewhere else.
	if dst, perr := url.Parse(targetURL); perr != nil ||
		!strings.EqualFold(dst.Scheme, target.redirectScheme) || !strings.EqualFold(dst.Host, target.redirectHost) {
		reqLog.Warn("Tier target produced a redirect URL for a different destination than it reported at startup; proxying instead")
		return false
	}

	// Stamp the redirect-hold key *before* handing out the URL so the eviction
	// hold is in place by the time the client can use it.
	if err := pc.db.RecordRedirectIssued(instanceHash); err != nil {
		reqLog.WithError(err).Warn("Failed to record redirect-hold stamp; falling back to proxying")
		return false
	}
	if err := pc.eviction.RecordAccess(instanceHash); err != nil {
		log.Debugf("Failed to record access for %s during tiering redirect: %v", instanceHash, err)
	}

	// Carry the same validators and freshness metadata the proxied path sets,
	// so a redirected client is not told less about the object than a proxied
	// one.  The client verifies the checksums against what it receives from the
	// bucket; the cache never sees those bytes.
	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
	}
	if digest := formatDigestHeader(meta.Checksums); digest != "" {
		w.Header().Set("Digest", digest)
	}
	if !meta.Completed.IsZero() {
		if age := int(time.Since(meta.Completed).Seconds()); age >= 0 {
			w.Header().Set("Age", strconv.Itoa(age))
		}
	}
	w.Header().Set("Cache-Control", meta.ResponseCacheControl())
	http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
	tierRequestsTotal.WithLabelValues(target.metricLabel(), tierServedByRedirect).Inc()
	tierRedirectedBytesTotal.WithLabelValues(target.metricLabel()).Add(float64(redirectedBytes(r, meta.ContentLength)))
	reqLog.WithFields(log.Fields{
		"status":   http.StatusTemporaryRedirect,
		"cache":    "hit-redirect",
		"duration": time.Since(startTime).Round(time.Millisecond).String(),
	}).Info("Request complete")
	return true
}

// redirectedBytes is how much of an object a redirected request asked for:
// the requested ranges, or the whole object when there are none (or the
// header cannot be parsed, in which case the target decides what to send).
func redirectedBytes(r *http.Request, size int64) int64 {
	header := r.Header.Get("Range")
	if header == "" {
		return size
	}
	ranges, err := ParseRangeHeader(header, size)
	if err != nil || len(ranges) == 0 {
		return size
	}
	var n int64
	for _, rg := range ranges {
		n += rg.End - rg.Start + 1
	}
	return n
}

// limitedReadCloser bounds a stream to n bytes while preserving Close.
type limitedReadCloser struct {
	stream *tierObjectStream
	remain int64
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	if l.remain <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > l.remain {
		p = p[:l.remain]
	}
	n, err := l.stream.Read(p)
	l.remain -= int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.stream.Close()
}
