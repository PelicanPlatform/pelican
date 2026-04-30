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
)

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
