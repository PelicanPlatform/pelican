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

package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics exposed by the cache's per-origin fair scheduler
// (client.TagScheduler). See docs/object-transfer-semantics.md and
// docs/tag-scheduler-design.md for what each cap and EMA mean.
var (
	CacheSchedulerActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_active",
		Help: "Per-origin count of upstream fetches currently held by the cache's fair scheduler (starving + actively transferring).",
	}, []string{"origin"})

	CacheSchedulerStarving = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_starving",
		Help: "Per-origin count of upstream fetches currently held by the cache's fair scheduler that have not yet received a first byte of body from the origin.",
	}, []string{"origin"})

	CacheSchedulerPending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pending",
		Help: "Per-origin count of upstream fetches queued for dispatch to a worker.",
	}, []string{"origin"})

	CacheSchedulerEMA = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_ema",
		Help: "Per-origin exponentially-weighted moving average of the active-worker count. Used to weight the fair scheduler's round-robin: lower value → more likely to be picked next.",
	}, []string{"origin"})

	CacheSchedulerAdmitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_scheduler_admits_total",
		Help: "Per-origin count of upstream fetches admitted into the cache's fair scheduler.",
	}, []string{"origin"})

	CacheSchedulerRejectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_scheduler_rejects_total",
		Help: "Per-origin count of upstream fetches rejected by the cache's fair scheduler with a 429-equivalent error. reason=\"global\": the global pending buffer was full; reason=\"per_tag\": this origin's own pending queue was full.",
	}, []string{"origin", "reason"})

	// Pool-wide aggregates. Handy for a single-panel overview even if
	// no per-origin labels are being scraped.
	CacheSchedulerPoolSize = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pool_size",
		Help: "The cache's worker-pool size that the scheduler is sharing (usually Cache.WorkerCount).",
	})
	CacheSchedulerPoolPending = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pool_pending_total",
		Help: "Total number of upstream fetches queued for dispatch across all origins.",
	})
	CacheSchedulerPoolTags = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pool_tags_total",
		Help: "Number of distinct origins the scheduler is currently tracking (either in-flight, queued, or with a still-decaying EMA).",
	})
	CacheSchedulerPoolStarvingCap = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pool_starving_cap",
		Help: "Absolute count of worker slots any single origin may hold while starving (derived from Cache.Throttle.PerOriginStarvingPercent).",
	})
	CacheSchedulerPoolActiveCap = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_cache_scheduler_pool_active_cap",
		Help: "Absolute count of worker slots any single origin may hold in total (derived from Cache.Throttle.PerOriginActivePercent).",
	})
)

// schedulerCounterTracker remembers the last observed monotonic total
// per (origin, reason) tuple so we can Add the delta to the underlying
// Prometheus counter without double-counting on republish.
type schedulerCounterTracker struct {
	mu           sync.Mutex
	lastAdmits   map[string]uint64
	lastRejects  map[schedulerRejectKey]uint64
	knownAdmits  map[string]struct{} // set of tags that currently have an Admits > 0 series
	knownRejects map[schedulerRejectKey]struct{}
	knownGauges  map[string]struct{} // set of tags that currently have any gauge value published
}

type schedulerRejectKey struct {
	origin string
	reason string // "global" or "per_tag"
}

var schedulerTracker = &schedulerCounterTracker{
	lastAdmits:   make(map[string]uint64),
	lastRejects:  make(map[schedulerRejectKey]uint64),
	knownAdmits:  make(map[string]struct{}),
	knownRejects: make(map[schedulerRejectKey]struct{}),
	knownGauges:  make(map[string]struct{}),
}

// SchedulerGlobalStats mirrors client.GlobalStats but lives in the
// metrics package so callers can convert once and hand it in.
type SchedulerGlobalStats struct {
	WorkerCount        int
	StarvingCap        int
	ActiveCap          int
	TotalPending       int
	TotalTags          int
	TotalAdmits        uint64
	TotalRejects       uint64
	TotalRejectsGlobal uint64
	TotalRejectsPerTag uint64
}

// SchedulerPerTagStats mirrors client.PerTagStats.
type SchedulerPerTagStats struct {
	Pending  int
	Active   int
	Starving int
	EMA      float64
	Admits   uint64
	Rejects  uint64
}

// PublishCacheSchedulerSnapshot updates the Prometheus scheduler
// metrics from a snapshot taken by (client.TagScheduler).Snapshot().
// It is expected to be called on a fixed cadence (say 5 s) from the
// cache's monitor goroutine.
//
// Tags that disappear from the snapshot (because their EMA decayed
// out and they have no queued or in-flight work) have their labeled
// gauges deleted. Their monotonic admit/reject counters are also
// deleted from the CounterVec so the (origin=…) series no longer
// counts against Prometheus cardinality once the origin has been
// idle long enough to drop out. Since Prometheus preserves the last
// scraped value until the series ages out, occasional flicker at
// the tail is acceptable.
func PublishCacheSchedulerSnapshot(global SchedulerGlobalStats, tags map[string]SchedulerPerTagStats) {
	CacheSchedulerPoolSize.Set(float64(global.WorkerCount))
	CacheSchedulerPoolPending.Set(float64(global.TotalPending))
	CacheSchedulerPoolTags.Set(float64(global.TotalTags))
	CacheSchedulerPoolStarvingCap.Set(float64(global.StarvingCap))
	CacheSchedulerPoolActiveCap.Set(float64(global.ActiveCap))

	schedulerTracker.mu.Lock()
	defer schedulerTracker.mu.Unlock()

	nowKnownGauges := make(map[string]struct{}, len(tags))
	nowKnownAdmits := make(map[string]struct{}, len(tags))
	nowKnownRejects := make(map[schedulerRejectKey]struct{}, len(tags))

	for origin, s := range tags {
		nowKnownGauges[origin] = struct{}{}
		CacheSchedulerActive.WithLabelValues(origin).Set(float64(s.Active))
		CacheSchedulerStarving.WithLabelValues(origin).Set(float64(s.Starving))
		CacheSchedulerPending.WithLabelValues(origin).Set(float64(s.Pending))
		CacheSchedulerEMA.WithLabelValues(origin).Set(s.EMA)

		if s.Admits > 0 {
			nowKnownAdmits[origin] = struct{}{}
			last := schedulerTracker.lastAdmits[origin]
			if s.Admits > last {
				CacheSchedulerAdmitsTotal.WithLabelValues(origin).Add(float64(s.Admits - last))
			}
			schedulerTracker.lastAdmits[origin] = s.Admits
		}
		if s.Rejects > 0 {
			// The snapshot only reports the sum across reasons per
			// tag; we can only tell them apart via the global
			// totals. For per-origin labels, publish the full delta
			// under a synthetic reason="any" so the per-origin view
			// still works. The reason=global/per_tag detail is
			// available via the pool-wide counters.
			key := schedulerRejectKey{origin: origin, reason: "any"}
			nowKnownRejects[key] = struct{}{}
			last := schedulerTracker.lastRejects[key]
			if s.Rejects > last {
				CacheSchedulerRejectsTotal.WithLabelValues(origin, "any").Add(float64(s.Rejects - last))
			}
			schedulerTracker.lastRejects[key] = s.Rejects
		}
	}

	// Publish pool-wide reject totals under a special "*" origin so
	// operators get the reason breakdown without paying a per-origin
	// cardinality cost.
	poolAllOriginKeyGlobal := schedulerRejectKey{origin: "*", reason: "global"}
	poolAllOriginKeyPerTag := schedulerRejectKey{origin: "*", reason: "per_tag"}
	nowKnownRejects[poolAllOriginKeyGlobal] = struct{}{}
	nowKnownRejects[poolAllOriginKeyPerTag] = struct{}{}
	if delta := global.TotalRejectsGlobal - schedulerTracker.lastRejects[poolAllOriginKeyGlobal]; delta > 0 {
		CacheSchedulerRejectsTotal.WithLabelValues("*", "global").Add(float64(delta))
	}
	schedulerTracker.lastRejects[poolAllOriginKeyGlobal] = global.TotalRejectsGlobal
	if delta := global.TotalRejectsPerTag - schedulerTracker.lastRejects[poolAllOriginKeyPerTag]; delta > 0 {
		CacheSchedulerRejectsTotal.WithLabelValues("*", "per_tag").Add(float64(delta))
	}
	schedulerTracker.lastRejects[poolAllOriginKeyPerTag] = global.TotalRejectsPerTag

	// Prune labels for tags that disappeared from the snapshot.
	for origin := range schedulerTracker.knownGauges {
		if _, still := nowKnownGauges[origin]; !still {
			CacheSchedulerActive.DeleteLabelValues(origin)
			CacheSchedulerStarving.DeleteLabelValues(origin)
			CacheSchedulerPending.DeleteLabelValues(origin)
			CacheSchedulerEMA.DeleteLabelValues(origin)
		}
	}
	for origin := range schedulerTracker.knownAdmits {
		if _, still := nowKnownAdmits[origin]; !still {
			CacheSchedulerAdmitsTotal.DeleteLabelValues(origin)
			delete(schedulerTracker.lastAdmits, origin)
		}
	}
	for key := range schedulerTracker.knownRejects {
		if _, still := nowKnownRejects[key]; !still {
			CacheSchedulerRejectsTotal.DeleteLabelValues(key.origin, key.reason)
			delete(schedulerTracker.lastRejects, key)
		}
	}
	schedulerTracker.knownGauges = nowKnownGauges
	schedulerTracker.knownAdmits = nowKnownAdmits
	schedulerTracker.knownRejects = nowKnownRejects
}
