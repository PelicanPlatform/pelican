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
	"time"

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
	tierRedirectCapable = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_tiering_redirect_capable",
		Help: "1 when a tiering target can issue redirect URLs (probed at startup), so its objects can be served " +
			"by redirect; 0 when they are always proxied through the cache",
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
