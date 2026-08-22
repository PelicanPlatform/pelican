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
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// newS3SeekableReader builds a SeekableReader that proxies an S3-resident
// object through the cache (used when redirect is disabled, or by internal
// callers such as the data-integrity scan).
func (pc *PersistentCache) newS3SeekableReader(ctx context.Context, target *s3Target, res *objectResolution) *SeekableReader {
	stream := newS3ObjectStream(ctx, target, res.instanceHash, res.meta.ContentLength)
	return &SeekableReader{RangeReader: &RangeReader{
		storage:      pc.storage,
		instanceHash: res.instanceHash,
		meta:         res.meta,
		start:        0,
		end:          res.meta.ContentLength - 1,
		remoteStream: stream,
	}}
}

// s3PresignExpiry returns the configured presigned-URL lifetime.
func s3PresignExpiry() time.Duration {
	if d := param.Cache_S3PresignExpiry.GetDuration(); d > 0 {
		return d
	}
	return 5 * time.Minute
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
// Token safety: the presigned URL points at the S3 provider, which is
// outside the federation trust boundary, so the client's bearer token must
// not reach it.  It does not, because the token never travels in a header
// or query the client would forward to S3:
//   - The presigned URL (the redirect Location) is self-authenticating and
//     carries only AWS SigV4 material; the Pelican token is never embedded.
//   - The token reaches the cache either in the Authorization header (the
//     native Pelican client) or the ?authz= query parameter (a director
//     redirect).  A ?authz= query is not carried onto the Location.  An
//     Authorization header is stripped by any spec-compliant client on a
//     cross-host redirect — including Pelican's own client (config.GetClient
//     sets no CheckRedirect, so Go's default cross-host stripping applies);
//     see TestS3RedirectDropsAuthorizationCrossHost.
//
// Residual risk: a non-compliant client that re-sends Authorization across
// hosts (e.g. curl --location-trusted), or an S3 endpoint deployed on the
// same hostname as the cache (Go strips by hostname, not port), would
// disclose the token.  Operators serving private namespaces to such clients
// should set Cache.S3DisableRedirect to proxy instead.
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

	// Freshness: no-store/no-cache objects and anything past its expiry
	// must go through the normal path so revalidation happens.
	if meta.CCFlags&(ccNoStore|ccNoCache) != 0 {
		return false
	}
	if expires := meta.ComputeExpires(); expires.IsZero() || !expires.After(time.Now()) {
		return false
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

	if meta.ETag != "" {
		w.Header().Set("ETag", meta.ETag)
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
