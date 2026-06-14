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

// File metadata_metrics.go declares the Prometheus instruments for the
// metadata publish path. These are package-private helpers; the
// controller calls them, no other package should.

package origin_serve

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metadataEventsEnqueuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "events_enqueued_total",
			Help:      "Object-commit events successfully written to the metadata publish queue.",
		},
		[]string{"namespace", "mode"},
	)

	metadataPublishAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "publish_attempts_total",
			Help:      "Per-attempt outcome of object-commit publishes.",
		},
		[]string{"namespace", "mode", "outcome"},
	)

	metadataPublishLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "publish_latency_seconds",
			Help:      "End-to-end latency of one publish attempt (success or failure).",
			Buckets:   prometheus.ExponentialBucketsRange(0.005, 60, 12),
		},
		[]string{"namespace", "mode"},
	)

	metadataQueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "queue_depth",
			Help:      "Pending rows in the metadata publish queue.",
		},
		[]string{"namespace"},
	)

	metadataOldestPendingSeconds = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "oldest_pending_seconds",
			Help:      "Age in seconds of the oldest pending row, per namespace.",
		},
		[]string{"namespace"},
	)

	metadataHealth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "health",
			Help:      "Origin-wide metadata-service health (1 for the active state, 0 otherwise).",
		},
		[]string{"state"},
	)

	metadataSkippedObjectDeleted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "skipped_object_deleted_total",
			Help:      "Queue rows dropped because the object had already been deleted.",
		},
		[]string{"namespace"},
	)

	metadataRollbackFailed = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "rollback_failed_total",
			Help:      "Transactional rollback (final-object delete) failures.",
		},
		[]string{"namespace"},
	)

	metadataAdminDeletes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_metadata",
			Name:      "admin_deletes_total",
			Help:      "Queue rows removed by an operator via the admin endpoint.",
		},
		[]string{"namespace"},
	)

	poscActiveUploads = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "pelican_origin_posc",
			Name:      "active_uploads",
			Help:      "POSC in-progress files currently open.",
		},
	)

	poscExpiredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_posc",
			Name:      "expired_total",
			Help:      "Stale POSC temp files removed by the expiry goroutine.",
		},
	)

	// ---- object-metadata batcher ----

	objMetaBatchFlushes = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "batch_flushes_total",
			Help:      "Number of COMMITs the SQLite write-behind batcher has issued.",
		},
	)

	objMetaBatchErrors = promauto.NewCounter(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "batch_errors_total",
			Help:      "Number of failed COMMITs by the SQLite write-behind batcher.",
		},
	)

	objMetaBatchSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "batch_size",
			Help:      "Number of ops per coalesced batcher flush.",
			Buckets:   prometheus.ExponentialBucketsRange(1, 1024, 11),
		},
	)

	objMetaBatchAgeSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "batch_age_seconds",
			Help:      "Wall-clock from oldest op enqueue to batch COMMIT.",
			Buckets:   prometheus.ExponentialBucketsRange(0.0005, 5, 12),
		},
	)

	// Back-pressure: time a caller spent blocked on the batcher's
	// in-memory channel because the buffer was full. Only observed
	// when the non-blocking send fails (so this histogram's
	// _count tells you how often back-pressure fired). A growing
	// _sum indicates the batcher buffer is undersized for current
	// traffic — operators should bump Origin.Metadata.BatchBufferSize.
	objMetaBatchEnqueueWaitSeconds = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "batch_enqueue_wait_seconds",
			Help:      "Time a caller spent blocked because the batcher channel was full.",
			Buckets:   prometheus.ExponentialBucketsRange(0.0001, 10, 14),
		},
		[]string{"durability"},
	)

	// ---- object-metadata observation cache ----

	objMetaCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "cache_hits_total",
			Help:      "Stat-path cache hits where the etag matched (no DB work).",
		},
		[]string{"namespace"},
	)

	objMetaCacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "cache_misses_total",
			Help:      "Stat-path cache misses (forced a LookupLive against the DB).",
		},
		[]string{"namespace"},
	)

	objMetaExternalChanges = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "external_events_total",
			Help:      "Out-of-band events observed during Stat: external_observe / external_modify / external_delete.",
		},
		[]string{"namespace", "event_type"},
	)

	// ---- pruner ----

	objMetaPrunerDeleted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "pruner_deleted_total",
			Help:      "Object-metadata-history rows removed by the background pruner.",
		},
		[]string{"namespace"},
	)

	objMetaPrunerPassSeconds = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "pruner_pass_duration_seconds",
			Help:      "Wall-clock per pruner pass across all namespaces.",
			Buckets:   prometheus.ExponentialBucketsRange(0.001, 60, 12),
		},
	)

	// Access-time debouncer depth, sampled on every Prometheus
	// scrape. A growing value indicates Origin.Metadata.AccessFlushInterval
	// is too generous for the read traffic, or the batcher is back-
	// pressured (so forced flushes aren't draining the map quickly
	// enough). When tracking is off, objectMetaAccess is nil and the
	// gauge reports 0.
	objMetaAccessDepth = promauto.NewGaugeFunc(
		prometheus.GaugeOpts{
			Namespace: "pelican_origin_object_metadata",
			Name:      "access_debouncer_depth",
			Help:      "Number of (namespace, path) entries currently buffered in the atime debouncer awaiting flush.",
		},
		func() float64 {
			if objectMetaAccess == nil {
				return 0
			}
			return float64(objectMetaAccess.Depth())
		},
	)
)

// batcherMetricsHooks wires the SQLite batcher's optional hooks to
// the Prometheus instruments above. Called by InitializeHandlers.
func batcherMetricsHooks() BatcherHooks {
	return BatcherHooks{
		IncFlush:        func(size int) { objMetaBatchFlushes.Inc(); objMetaBatchSize.Observe(float64(size)) },
		IncError:        func() { objMetaBatchErrors.Inc() },
		ObserveBatchAge: func(d time.Duration) { objMetaBatchAgeSeconds.Observe(d.Seconds()) },
		ObserveEnqueueWait: func(durability string, d time.Duration) {
			objMetaBatchEnqueueWaitSeconds.WithLabelValues(durability).Observe(d.Seconds())
		},
	}
}

// prunerMetricsHooks wires the pruner's optional hooks.
func prunerMetricsHooks() PrunerHooks {
	return PrunerHooks{
		IncDeleted:          func(namespace string, n int64) { objMetaPrunerDeleted.WithLabelValues(namespace).Add(float64(n)) },
		ObservePassDuration: func(d time.Duration) { objMetaPrunerPassSeconds.Observe(d.Seconds()) },
	}
}

// poscMetricsHooks returns the hook bundle wired up to the Prometheus
// counters above. Used by InitializeHandlers when constructing the
// POSC layer. `namespace` is the federation prefix the POSC instance
// is serving, used as a label on rollback-failure events.
func poscMetricsHooks(namespace string) *PoscMetricsHooks {
	return &PoscMetricsHooks{
		IncActive: func() { poscActiveUploads.Inc() },
		DecActive: func() { poscActiveUploads.Dec() },
		IncExpire: func() { poscExpiredTotal.Inc() },
		IncRollbackFailed: func() {
			metadataRollbackFailed.WithLabelValues(namespace).Inc()
		},
	}
}
