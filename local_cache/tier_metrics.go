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
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Tiering metrics.  The per-target ones are labelled with the target's
// display URL, which is credential-free and bounded by configuration.
//
// Tiering runs only in the cache server (never in the local cache module or
// an origin's data store), so unlike the scan metrics these need no
// suppression switch.

// Values of the "result" label on the upload metrics.
const (
	tierUploadSucceeded = "success"
	tierUploadFailed    = "failure"
)

// Values of the "mode" label on tierRequestsTotal.
const (
	tierServedByRedirect  = "redirect"
	tierServedByProxy     = "proxy"
	tierServedNotModified = "not_modified"
)

// Values of the "detected_by" label on tierChangedObjectsTotal.
const (
	tierChangeSeenOnRead = "read"
	tierChangeSeenByScan = "scan"
)

// Values of the "kind" label on tierSweepRemovedTotal.
const (
	tierSweepRemovedRemoteObject = "remote_object"
	tierSweepRemovedEntry        = "entry"
)

// Values of the "reason" label on tierRedirectSkippedTotal: why a read of a
// tiered object was proxied rather than redirected.
const (
	// The target cannot hand out URLs a client could fetch on its own.
	tierSkipCannotRedirect = "cannot_redirect"
	// It can, but its latest redirect self-test failed.
	tierSkipSelfTestFailing = "self_test_failing"
	// The target's URLs use a scheme the client did not say it accepts.
	tierSkipSchemeNotAccepted = "scheme_not_accepted"
	// Redirecting would hand the client's Authorization header to the target.
	tierSkipCredentialForwarding = "credential_forwarding"
	// The object must be revalidated first (no-cache, no-store or expired).
	tierSkipNeedsRevalidation = "needs_revalidation"
	// The target holds no credential to mint a URL with right now -- for
	// dCache, no macaroon that outlasts the URL.
	tierSkipNoCredential = "no_credential"
	// Minting the URL failed for another reason.
	tierSkipMintFailed = "mint_failed"
	// The minted URL pointed somewhere other than the target's probed host.
	tierSkipDestinationMismatch = "destination_mismatch"
	// The eviction hold for the redirected object could not be recorded.
	tierSkipHoldFailed = "hold_failed"
)

// Values of the "result" label on tierMacaroonRequestsTotal.
const (
	tierMacaroonIssued           = "success"
	tierMacaroonRefused          = "refused"
	tierMacaroonRefusedForScopes = "refused_for_scopes"
	tierMacaroonError            = "error"
)

// tierHTTPCodeError is the "code" of a request to a target that got no
// response at all: the connection failed or timed out.
const tierHTTPCodeError = "error"

var (
	tierUploadsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_uploads_total",
		Help: "Uploads of completed objects to a tiering target, by target and result (success or failure)",
	}, []string{"target", "result"})
	tierUploadBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_upload_bytes_total",
		Help: "Size of the objects uploaded to a tiering target, by target and result (success or failure)",
	}, []string{"target", "result"})
	tierUploadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_cache_tiering_upload_duration_seconds",
		Help:    "Time taken by successful uploads to a tiering target",
		Buckets: prometheus.ExponentialBuckets(0.05, 2, 16), // 50ms to ~27 minutes
	}, []string{"target"})

	tierQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_queue_depth",
		Help: "Objects waiting for a tiering upload worker",
	})
	tierQueueDropsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_queue_drops_total",
		Help: "Objects not queued for tiering because the queue was full; the periodic rescan retries them",
	})
	tierDeferredNoRoomTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_deferred_no_room_total",
		Help: "Tiering attempts deferred because no tiering target had room for the object",
	})
	tierPendingLocalReleases = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_pending_local_releases",
		Help: "Tiered objects whose local copy is kept until a reader still using it finishes",
	})

	tierRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_requests_total",
		Help: "Reads of objects resident on a tiering target, by target and how they were answered: " +
			"redirect (the client was sent to the target), proxy (the cache streamed the bytes), " +
			"or not_modified (a revalidation the cache answered itself)",
	}, []string{"target", "mode"})
	tierRedirectedBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_redirected_bytes_total",
		Help: "Bytes clients were redirected to a tiering target to read (the object, or the requested range). " +
			"The target serves them, so they are absent from the cache's transfer monitoring; " +
			"this counts what was handed off, not what was confirmed transferred",
	}, []string{"target"})
	tierTargetUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_target_up",
		Help: "1 when a tiering target passed its latest liveness probe (a small write read back); 0 when it failed",
	}, []string{"target"})
	tierUploadsAbandonedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_uploads_abandoned_total",
		Help: "Objects the uploader stopped trying to tier after repeated failures while their target was healthy; " +
			"they stay on local storage",
	})
	tierRedirectCapable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_redirect_capable",
		Help: "1 when a tiering target's objects are served by redirect: it can issue redirect URLs and the latest " +
			"self-test (a minted URL fetched with no other credential, at startup and with each liveness probe) " +
			"worked; 0 when they are proxied through the cache",
	}, []string{"target"})

	tierChangedObjectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_changed_objects_total",
		Help: "Tiered objects found to differ from the copy the cache uploaded -- overwritten or truncated on the " +
			"target -- by target and how the change was detected (read or scan).  Each is dropped and fetched again",
	}, []string{"target", "detected_by"})
	tierSweepRemovedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_sweep_removed_total",
		Help: "Removals by the tiering consistency sweep, by target and kind: remote_object (an object on the " +
			"target the cache has no record of) or entry (a record whose object is missing from, or changed on, the target)",
	}, []string{"target", "kind"})
	tierSweepLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_sweep_last_success_timestamp_seconds",
		Help: "Unix timestamp when the tiering consistency sweep last completed for a target",
	}, []string{"target"})

	tierRedirectSkippedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_redirect_skipped_total",
		Help: "Reads of objects resident on a tiering target that were not redirected, by target and reason: " +
			"cannot_redirect, self_test_failing, scheme_not_accepted, credential_forwarding, needs_revalidation, " +
			"no_credential, mint_failed, destination_mismatch or hold_failed",
	}, []string{"target", "reason"})
	tierProxiedBytesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_proxied_bytes_total",
		Help: "Bytes the cache read from a tiering target to serve clients itself, rather than redirecting them",
	}, []string{"target"})
	tierProxyReadErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_proxy_read_errors_total",
		Help: "Failed reads from a tiering target while proxying an object to a client: a read that could not be " +
			"started, or one that broke partway (the cache reopens it once from where it stopped)",
	}, []string{"target"})

	tierMacaroonRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_macaroon_requests_total",
		Help: "Requests for a root macaroon from a dCache tiering target, by target and result: success, refused " +
			"(the door does not issue macaroons for this login), refused_for_scopes (the token carries storage.* " +
			"scopes) or error (an outage or a credential problem, retried)",
	}, []string{"target", "result"})
	tierMacaroonExpiry = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_macaroon_expiry_timestamp_seconds",
		Help: "Unix timestamp when the root macaroon held for a dCache tiering target expires; 0 while none is held. " +
			"Redirect URLs are minted from it only while it outlasts them",
	}, []string{"target"})

	tierTargetHTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_tiering_target_http_requests_total",
		Help: "HTTP requests the cache made to a WebDAV tiering target, by target, method and status code; " +
			"code is \"error\" when no response arrived.  A redirect followed counts each hop",
	}, []string{"target", "method", "code"})
	tierTargetHTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "pelican_cache_tiering_target_http_request_duration_seconds",
		Help: "Time a WebDAV tiering target took to answer the cache's HTTP requests, to the response headers " +
			"(for an upload, that includes sending the body), by target and method",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 18), // 5ms to ~11 minutes
	}, []string{"target", "method"})
)

// metricLabel is the target's value for the "target" label.
func (t *tierTarget) metricLabel() string { return t.DisplayURL() }

// recordTierUpload records the outcome of one upload attempt.
func recordTierUpload(target *tierTarget, result string, size int64, elapsed time.Duration) {
	label := target.metricLabel()
	tierUploadsTotal.WithLabelValues(label, result).Inc()
	tierUploadBytesTotal.WithLabelValues(label, result).Add(float64(size))
	if result == tierUploadSucceeded {
		tierUploadDuration.WithLabelValues(label).Observe(elapsed.Seconds())
	}
}

// tierMetricsTransport counts and times the HTTP requests a tiering target's
// client makes, by method and status, so the target's own answers -- a 401
// when the token has lapsed, a 507 when it is full -- are visible without
// reading the logs.
//
// A request the cache cancelled (its reader went away, or the cache is
// closing) is not counted: that says nothing about the target.  One that ran
// out of time is, as an error.
type tierMetricsTransport struct {
	base   http.RoundTripper
	target string
}

func newTierMetricsTransport(base http.RoundTripper, target string) http.RoundTripper {
	return &tierMetricsTransport{base: base, target: target}
}

func (t *tierMetricsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	code := tierHTTPCodeError
	switch {
	case err == nil:
		code = strconv.Itoa(resp.StatusCode)
	case errors.Is(req.Context().Err(), context.Canceled):
		return resp, err
	}
	tierTargetHTTPRequestsTotal.WithLabelValues(t.target, req.Method, code).Inc()
	tierTargetHTTPDuration.WithLabelValues(t.target, req.Method).Observe(time.Since(start).Seconds())
	return resp, err
}
