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
	"github.com/pelicanplatform/pelican/token_scopes"
)

// newS3SeekableReader builds a SeekableReader that proxies an S3-resident
// object through the cache (used when redirect is disabled, or by internal
// callers such as the data-integrity scan).
//
// The object is pinned for the life of the stream.  A proxied object gets no
// presign stamp -- no URL was handed out -- so the pin is its only protection:
// without it, eviction could delete the bucket object between two of this
// reader's ranged GETs, which is exactly the configuration operators are
// pointed at for private namespaces.
func (pc *PersistentCache) newS3SeekableReader(ctx context.Context, target *s3Target, res *objectResolution) *SeekableReader {
	stream := newS3ObjectStream(ctx, target, res.instanceHash, res.meta.ContentLength)
	stream.onClose = pc.storage.PinObject(res.instanceHash)
	return &SeekableReader{RangeReader: &RangeReader{
		storage:      pc.storage,
		instanceHash: res.instanceHash,
		meta:         res.meta,
		start:        0,
		end:          res.meta.ContentLength - 1,
		remoteStream: stream,
	}}
}

// presignHoldHeadroom is how much longer than a pre-signed URL's lifetime the
// eviction hold must last, covering the gap between minting a URL and the
// client actually finishing with it.
const presignHoldHeadroom = 5 * time.Minute

// s3PresignExpiry returns the configured presigned-URL lifetime.
func s3PresignExpiry() time.Duration {
	if d := param.Cache_S3PresignExpiry.GetDuration(); d > 0 {
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

// tryS3Redirect serves a GET by redirecting the client to a pre-signed S3
// URL when possible.  Returns true when the response has been written
// (redirect issued); false means the caller should proceed with the normal
// serving path (object not on S3, redirect disabled, object stale, etc.).
//
// The redirect is only issued for objects that are fully resident on an S3
// target and still fresh — stale objects fall through so the normal path
// revalidates against the origin.  Issuing the URL stamps the presign key,
// which protects the object from eviction for Cache.S3PresignEvictionHold.
//
// Token safety: the presigned URL points at the S3 provider, which is outside
// the federation trust boundary, so the client's bearer token must not reach
// it.  Two of the three ways it could are closed by construction:
//   - The presigned URL (the redirect Location) is self-authenticating and
//     carries only AWS SigV4 material; the Pelican token is never embedded.
//   - A token delivered as ?authz= (how the director hands one to a client)
//     is not carried onto the Location: http.Redirect only rewrites the query
//     for relative targets, and a presigned URL is absolute.
//
// The third is the Authorization header, which a compliant client drops only
// when the destination is neither the host it connected to nor a subdomain of
// it (see redirectRetainsAuthorization).  When a request carries such a header
// and the bucket endpoint falls inside that domain, this function declines and
// the object is proxied instead, so an S3 endpoint co-located with the cache
// cannot be handed federation tokens.
//
// Residual risk: a client that re-sends Authorization across unrelated hosts,
// contrary to the spec (e.g. curl --location-trusted), still discloses it.
// Operators serving private namespaces to such clients should set
// Cache.S3DisableRedirect.  See TestS3RedirectDropsAuthorizationCrossHost.
func (pc *PersistentCache) tryS3Redirect(w http.ResponseWriter, r *http.Request, objectPath, token string, reqLog *log.Entry, startTime time.Time) bool {
	if len(pc.storage.s3Targets) == 0 || param.Cache_S3DisableRedirect.GetBool() {
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
	target := pc.storage.getS3Target(meta.StorageID)
	if target == nil {
		return false
	}
	// Would redirecting hand this client's Authorization header to the bucket?
	// Only a request that carries one has anything to leak -- a public read,
	// or the director's ?authz= flow, does not -- and the host to compare
	// against is the one the client actually connected to, since that is what
	// its redirect policy compares.  See the doc comment.
	if r.Header.Get("Authorization") != "" && redirectRetainsAuthorization(target.cfg.ServiceUrl, r.Host) {
		reqLog.Debug("Proxying instead of redirecting: the bucket endpoint shares this cache's DNS domain, " +
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
	// rather than redirected.  Sending it to the bucket instead would make it
	// re-download the whole object for nothing: the far end cannot complete the
	// revalidation, because S3 answers with its own ETag (an MD5 of the stored
	// bytes) which never matches the origin's.
	if meta.ETag != "" {
		for _, match := range strings.Split(r.Header.Get("If-None-Match"), ",") {
			if match = strings.TrimSpace(match); match == "*" || (match != "" && match == meta.ETag) {
				w.Header().Set("ETag", meta.ETag)
				w.Header().Set("Cache-Control", meta.ResponseCacheControl())
				w.WriteHeader(http.StatusNotModified)
				reqLog.WithFields(log.Fields{
					"status":   http.StatusNotModified,
					"cache":    "hit-redirect",
					"duration": time.Since(startTime).Round(time.Millisecond).String(),
				}).Info("Request complete")
				return true
			}
		}
	}

	presignedURL, err := target.presignGet(r.Context(), instanceHash, s3PresignExpiry())
	if err != nil {
		reqLog.WithError(err).Warn("Failed to presign S3 URL; falling back to proxying")
		return false
	}

	// Stamp the presign key *before* handing out the URL so the eviction
	// hold is in place by the time the client can use it.
	if err := pc.db.RecordPresignIssued(instanceHash); err != nil {
		reqLog.WithError(err).Warn("Failed to record presign stamp; falling back to proxying")
		return false
	}
	if err := pc.eviction.RecordAccess(instanceHash); err != nil {
		log.Debugf("Failed to record access for %s during S3 redirect: %v", instanceHash, err)
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
	http.Redirect(w, r, presignedURL, http.StatusTemporaryRedirect)
	reqLog.WithFields(log.Fields{
		"status":   http.StatusTemporaryRedirect,
		"cache":    "hit-redirect",
		"duration": time.Since(startTime).Round(time.Millisecond).String(),
	}).Info("Request complete")
	return true
}

// limitedReadCloser bounds a stream to n bytes while preserving Close.
type limitedReadCloser struct {
	stream *s3ObjectStream
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
