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
// (client.TagScheduler in client/tag_scheduler.go). The starving/active
// caps and the EMA weighting are documented on client.SchedulerConfig and
// in the Cache.Throttle.* parameter descriptions in docs/parameters.yaml.
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
		Help: "Per-origin count of upstream fetches rejected by the cache's fair scheduler with a 429-equivalent error.",
	}, []string{"origin"})

	// The cause breakdown is a separate metric rather than an extra label
	// on the per-origin counter: the scheduler's per-origin snapshot does
	// not attribute rejections to a cause, so publishing both views under
	// one name would make the obvious sum() over that name count every
	// rejection twice.
	CacheSchedulerRejectsByCauseTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_cache_scheduler_rejects_by_cause_total",
		Help: "Pool-wide count of upstream fetches rejected by the cache's fair scheduler, broken down by cause: \"global\" (the global pending buffer was full) or \"per_tag\" (the origin's own pending queue was full).",
	}, []string{"cause"})

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
		Help: "Number of distinct origins the scheduler is currently tracking (in-flight, queued, with a still-decaying EMA, or awaiting idle eviction). Idle origins are evicted after a grace period, so this can shrink.",
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
// per origin so we can Add the delta to the underlying Prometheus
// counter without double-counting on republish.
type schedulerCounterTracker struct {
	mu                 sync.Mutex
	lastAdmits         map[string]uint64
	lastRejects        map[string]uint64
	lastRejectsByCause map[string]uint64
	knownAdmits        map[string]struct{} // set of tags that currently have an Admits > 0 series
	knownRejects       map[string]struct{}
	knownGauges        map[string]struct{} // set of tags that currently have any gauge value published
}

func newSchedulerCounterTracker() *schedulerCounterTracker {
	return &schedulerCounterTracker{
		lastAdmits:         make(map[string]uint64),
		lastRejects:        make(map[string]uint64),
		lastRejectsByCause: make(map[string]uint64),
		knownAdmits:        make(map[string]struct{}),
		knownRejects:       make(map[string]struct{}),
		knownGauges:        make(map[string]struct{}),
	}
}

var schedulerTracker = newSchedulerCounterTracker()

// counterDelta computes how much to Add to a Prometheus counter given the
// previously published total and the current one.
//
// Both are unsigned, so the subtraction must not be done blind: a current
// total below the previous one means the source counters restarted, and
// `current - last` would wrap to something near 2^64. Treat that case as a
// reset and count the current value as entirely new. Per-origin totals restart
// whenever the scheduler evicts an idle tag and the origin later returns;
// pool-wide totals restart when a whole scheduler is replaced in-process.
//
// This detects a reset only by the total going down, so it relies on the reset
// being observed while the new total is still below the old one. For per-origin
// counters that holds because the eviction grace period is comfortably longer
// than the publish interval, so the tag's absence is always sampled in between
// and its tracked total forgotten (see the prune below).
func counterDelta(current, last uint64) float64 {
	if current < last {
		return float64(current)
	}
	return float64(current - last)
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
	nowKnownRejects := make(map[string]struct{}, len(tags))

	for origin, s := range tags {
		nowKnownGauges[origin] = struct{}{}
		CacheSchedulerActive.WithLabelValues(origin).Set(float64(s.Active))
		CacheSchedulerStarving.WithLabelValues(origin).Set(float64(s.Starving))
		CacheSchedulerPending.WithLabelValues(origin).Set(float64(s.Pending))
		CacheSchedulerEMA.WithLabelValues(origin).Set(s.EMA)

		if s.Admits > 0 {
			nowKnownAdmits[origin] = struct{}{}
			if delta := counterDelta(s.Admits, schedulerTracker.lastAdmits[origin]); delta > 0 {
				CacheSchedulerAdmitsTotal.WithLabelValues(origin).Add(delta)
			}
			schedulerTracker.lastAdmits[origin] = s.Admits
		}
		if s.Rejects > 0 {
			nowKnownRejects[origin] = struct{}{}
			if delta := counterDelta(s.Rejects, schedulerTracker.lastRejects[origin]); delta > 0 {
				CacheSchedulerRejectsTotal.WithLabelValues(origin).Add(delta)
			}
			schedulerTracker.lastRejects[origin] = s.Rejects
		}
	}

	// The per-origin snapshot does not attribute a rejection to a cause, so
	// the breakdown is only available pool-wide.
	for cause, total := range map[string]uint64{
		"global":  global.TotalRejectsGlobal,
		"per_tag": global.TotalRejectsPerTag,
	} {
		if delta := counterDelta(total, schedulerTracker.lastRejectsByCause[cause]); delta > 0 {
			CacheSchedulerRejectsByCauseTotal.WithLabelValues(cause).Add(delta)
		}
		schedulerTracker.lastRejectsByCause[cause] = total
	}

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
	for origin := range schedulerTracker.knownRejects {
		if _, still := nowKnownRejects[origin]; !still {
			CacheSchedulerRejectsTotal.DeleteLabelValues(origin)
			delete(schedulerTracker.lastRejects, origin)
		}
	}
	schedulerTracker.knownGauges = nowKnownGauges
	schedulerTracker.knownAdmits = nowKnownAdmits
	schedulerTracker.knownRejects = nowKnownRejects
}

// ResetCacheSchedulerMetrics drops every scheduler series and zeroes the
// pool-wide gauges. Call it when a cache's scheduler goes away: the gauges
// describe instantaneous state, so leaving the final pre-shutdown values in
// the exposition would misreport a scheduler that no longer exists.
//
// The delta bookkeeping is reset too, so a scheduler created afterwards in
// the same process starts its counters from zero rather than being diffed
// against a dead instance's totals.
func ResetCacheSchedulerMetrics() {
	schedulerTracker.mu.Lock()
	defer schedulerTracker.mu.Unlock()

	CacheSchedulerActive.Reset()
	CacheSchedulerStarving.Reset()
	CacheSchedulerPending.Reset()
	CacheSchedulerEMA.Reset()
	CacheSchedulerAdmitsTotal.Reset()
	CacheSchedulerRejectsTotal.Reset()
	CacheSchedulerRejectsByCauseTotal.Reset()

	CacheSchedulerPoolSize.Set(0)
	CacheSchedulerPoolPending.Set(0)
	CacheSchedulerPoolTags.Set(0)
	CacheSchedulerPoolStarvingCap.Set(0)
	CacheSchedulerPoolActiveCap.Set(0)

	fresh := newSchedulerCounterTracker()
	schedulerTracker.lastAdmits = fresh.lastAdmits
	schedulerTracker.lastRejects = fresh.lastRejects
	schedulerTracker.lastRejectsByCause = fresh.lastRejectsByCause
	schedulerTracker.knownAdmits = fresh.knownAdmits
	schedulerTracker.knownRejects = fresh.knownRejects
	schedulerTracker.knownGauges = fresh.knownGauges
}
