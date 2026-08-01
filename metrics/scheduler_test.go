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
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// The scheduler metrics are package-level collectors on the default
// Prometheus registry and the delta bookkeeping lives in the package-level
// schedulerTracker, so state would otherwise survive from one test to the
// next. Each test starts from a clean slate instead, which is also what a
// cache shutting down does.
func resetSchedulerMetrics(t *testing.T) {
	t.Helper()
	ResetCacheSchedulerMetrics()
	t.Cleanup(ResetCacheSchedulerMetrics)
}

// TestPublishCacheSchedulerSnapshotGauges pins that the gauges are a
// straight mirror of the snapshot: whatever the scheduler reported for a
// tag is what the per-origin gauges read, and the GlobalStats fields land
// on the pool-wide gauges.
func TestPublishCacheSchedulerSnapshotGauges(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "gauges.example.com"

	global := SchedulerGlobalStats{
		WorkerCount:  16,
		StarvingCap:  4,
		ActiveCap:    8,
		TotalPending: 7,
		TotalTags:    1,
	}
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		origin: {
			Pending:  7,
			Active:   3,
			Starving: 2,
			EMA:      1.5,
		},
	})

	assert.Equal(t, float64(3), testutil.ToFloat64(CacheSchedulerActive.WithLabelValues(origin)))
	assert.Equal(t, float64(2), testutil.ToFloat64(CacheSchedulerStarving.WithLabelValues(origin)))
	assert.Equal(t, float64(7), testutil.ToFloat64(CacheSchedulerPending.WithLabelValues(origin)))
	assert.Equal(t, 1.5, testutil.ToFloat64(CacheSchedulerEMA.WithLabelValues(origin)))

	assert.Equal(t, float64(16), testutil.ToFloat64(CacheSchedulerPoolSize))
	assert.Equal(t, float64(7), testutil.ToFloat64(CacheSchedulerPoolPending))
	assert.Equal(t, float64(1), testutil.ToFloat64(CacheSchedulerPoolTags))
	assert.Equal(t, float64(4), testutil.ToFloat64(CacheSchedulerPoolStarvingCap))
	assert.Equal(t, float64(8), testutil.ToFloat64(CacheSchedulerPoolActiveCap))

	// A later snapshot with new values overwrites rather than accumulates:
	// gauges are absolute readings, unlike the admit/reject counters.
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		origin: {Pending: 0, Active: 1, Starving: 0, EMA: 0.25},
	})
	assert.Equal(t, float64(1), testutil.ToFloat64(CacheSchedulerActive.WithLabelValues(origin)))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerStarving.WithLabelValues(origin)))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPending.WithLabelValues(origin)))
	assert.Equal(t, 0.25, testutil.ToFloat64(CacheSchedulerEMA.WithLabelValues(origin)))
}

// TestPublishCacheSchedulerSnapshotCounterDeltas pins that the snapshot's
// Admits/Rejects are treated as monotonic totals, not as increments. The
// publisher must add only the difference since the last snapshot, so
// republishing an unchanged snapshot (which happens whenever the cache is
// idle between two scrapes of the same counter values) must not
// double-count.
func TestPublishCacheSchedulerSnapshotCounterDeltas(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "deltas.example.com"
	global := SchedulerGlobalStats{WorkerCount: 4, StarvingCap: 1, ActiveCap: 2, TotalTags: 1}

	first := map[string]SchedulerPerTagStats{origin: {Active: 1, Admits: 5, Rejects: 5}}
	PublishCacheSchedulerSnapshot(global, first)
	assert.Equal(t, float64(5), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(5), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))

	// Republishing the identical totals is a no-op.
	PublishCacheSchedulerSnapshot(global, first)
	PublishCacheSchedulerSnapshot(global, first)
	assert.Equal(t, float64(5), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(5), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))

	// Growing the totals adds exactly the delta.
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		origin: {Active: 1, Admits: 8, Rejects: 8},
	})
	assert.Equal(t, float64(8), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(8), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))
}

// TestPublishCacheSchedulerSnapshotCounterRestart pins the behavior when the
// totals a snapshot reports are *lower* than the ones already published,
// which happens whenever a scheduler is replaced by a fresh one in the same
// process: the new instance starts counting from zero while the package-level
// tracker still holds the dead instance's high-water marks.
//
// The totals are unsigned, so subtracting them blind wraps to something near
// 2^64 and feeds Prometheus a garbage increment. The pool-wide series are
// especially unforgiving because nothing ever prunes them, so a single bad
// Add corrupts them for the life of the process.
func TestPublishCacheSchedulerSnapshotCounterRestart(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "restart.example.com"
	high := SchedulerGlobalStats{
		WorkerCount:        4,
		TotalTags:          1,
		TotalRejects:       30,
		TotalRejectsGlobal: 20,
		TotalRejectsPerTag: 10,
	}
	PublishCacheSchedulerSnapshot(high, map[string]SchedulerPerTagStats{
		origin: {Active: 1, Admits: 40, Rejects: 30},
	})
	assert.Equal(t, float64(40), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(20), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(10), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))

	// A brand-new scheduler reports much smaller totals for the same origin,
	// with no intervening publish that would have pruned the tracker.
	low := SchedulerGlobalStats{
		WorkerCount:        4,
		TotalTags:          1,
		TotalRejects:       3,
		TotalRejectsGlobal: 2,
		TotalRejectsPerTag: 1,
	}
	PublishCacheSchedulerSnapshot(low, map[string]SchedulerPerTagStats{
		origin: {Active: 1, Admits: 4, Rejects: 3},
	})

	// The restart is counted as new activity on top of what came before.
	// What must not happen is a decrease, or a jump of ~1.8e19 from an
	// unsigned wrap.
	assert.Equal(t, float64(44), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(33), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(22), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(11), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))
}

// TestPublishCacheSchedulerSnapshotPrunesVanishedOrigins pins that an
// origin the scheduler has evicted (its EMA decayed away and it has no
// queued or in-flight work, so it is simply absent from the snapshot's
// tag map) loses all of its label series. Otherwise every origin the
// cache ever contacted would stay in the exposition forever and the
// cardinality would only grow.
//
// Existence is checked by counting the series in each collector rather
// than by reading a value: ToFloat64(vec.WithLabelValues(...)) would
// create the very series whose absence is under test.
func TestPublishCacheSchedulerSnapshotPrunesVanishedOrigins(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "prunes.example.com"
	const other = "prunes.other.example.com"
	global := SchedulerGlobalStats{WorkerCount: 4, StarvingCap: 1, ActiveCap: 2, TotalTags: 1}

	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		origin: {Pending: 1, Active: 2, Starving: 1, EMA: 2.5, Admits: 9, Rejects: 3},
	})
	// Only this origin is in the snapshot, so exactly one series per
	// collector exists.
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerActive))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerStarving))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerPending))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerEMA))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerAdmitsTotal))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerRejectsTotal))

	// The origin drops out of the snapshot entirely: replaced by an
	// unrelated origin so the publish is a realistic one rather than an
	// empty pool.
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		other: {Pending: 0, Active: 1, Starving: 0, EMA: 0.5},
	})
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerActive))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerStarving))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerPending))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerEMA))
	assert.Equal(t, float64(1), testutil.ToFloat64(CacheSchedulerActive.WithLabelValues(other)))
	// "other" reported no admits or rejects, so both counter vecs are empty.
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerAdmitsTotal))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerRejectsTotal))

	// Dropping every origin empties the labeled collectors completely.
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{})
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerActive))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerStarving))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerPending))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerEMA))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerAdmitsTotal))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerRejectsTotal))
}

// TestPublishCacheSchedulerSnapshotResetsAfterReappearance pins the
// behavior when an evicted origin comes back. The scheduler forgets an
// idle tag's per-tag counters when it evicts it, so the next snapshot
// reports small totals again rather than continuing from where the old
// tag left off. The publisher must have forgotten its own last-seen
// totals at prune time too; otherwise the smaller total would look like a
// negative delta (and Prometheus counters cannot go backwards).
func TestPublishCacheSchedulerSnapshotResetsAfterReappearance(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "reappears.example.com"
	global := SchedulerGlobalStats{WorkerCount: 4, StarvingCap: 1, ActiveCap: 2, TotalTags: 1}

	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
		origin: {Active: 1, Admits: 10, Rejects: 10},
	})
	assert.Equal(t, float64(10), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(10), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))

	// Idle long enough to be evicted.
	PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{})

	// Back with freshly zeroed per-tag counters.
	assert.NotPanics(t, func() {
		PublishCacheSchedulerSnapshot(global, map[string]SchedulerPerTagStats{
			origin: {Active: 1, Admits: 2, Rejects: 2},
		})
	})
	assert.Equal(t, float64(2), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(2), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerAdmitsTotal))
}

// TestPublishCacheSchedulerSnapshotPoolRejectBreakdown pins the cause
// breakdown for rejections. The per-tag snapshot cannot say why a fetch was
// rejected, so the "global pending buffer was full" versus "this origin's own
// queue was full" split is published pool-wide on its own metric, and like
// the per-origin counters it is fed the difference between successive
// snapshots.
//
// The breakdown deliberately does not share a metric name with the
// per-origin rejections: publishing both views under one name would make
// sum(rate(...)) over that name double every rejection.
func TestPublishCacheSchedulerSnapshotPoolRejectBreakdown(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "breakdown.example.com"
	tags := map[string]SchedulerPerTagStats{origin: {Active: 1, Rejects: 30}}

	PublishCacheSchedulerSnapshot(SchedulerGlobalStats{
		WorkerCount:        4,
		StarvingCap:        1,
		ActiveCap:          2,
		TotalTags:          1,
		TotalRejects:       30,
		TotalRejectsGlobal: 20,
		TotalRejectsPerTag: 10,
	}, tags)
	assert.Equal(t, float64(20), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(10), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))

	PublishCacheSchedulerSnapshot(SchedulerGlobalStats{
		WorkerCount:        4,
		StarvingCap:        1,
		ActiveCap:          2,
		TotalTags:          1,
		TotalRejects:       37,
		TotalRejectsGlobal: 23,
		TotalRejectsPerTag: 14,
	}, map[string]SchedulerPerTagStats{origin: {Active: 1, Rejects: 37}})

	assert.Equal(t, float64(23), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(14), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))

	// Unchanged pool totals add nothing.
	PublishCacheSchedulerSnapshot(SchedulerGlobalStats{
		WorkerCount:        4,
		StarvingCap:        1,
		ActiveCap:          2,
		TotalTags:          1,
		TotalRejects:       37,
		TotalRejectsGlobal: 23,
		TotalRejectsPerTag: 14,
	}, map[string]SchedulerPerTagStats{origin: {Active: 1, Rejects: 37}})
	assert.Equal(t, float64(23), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(14), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))

	// The two views live in separate metrics, so summing either one alone
	// gives the true count rather than twice it.
	assert.Equal(t, float64(37), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerRejectsTotal))
	assert.Equal(t, 2, testutil.CollectAndCount(CacheSchedulerRejectsByCauseTotal))
}

// TestResetCacheSchedulerMetrics pins that shutting a scheduler down clears
// the exposition. The gauges describe instantaneous state, so leaving the
// last pre-shutdown values in place would report a scheduler that no longer
// exists as though it were still holding transfers.
func TestResetCacheSchedulerMetrics(t *testing.T) {
	resetSchedulerMetrics(t)
	const origin = "reset.example.com"

	PublishCacheSchedulerSnapshot(SchedulerGlobalStats{
		WorkerCount:        8,
		StarvingCap:        2,
		ActiveCap:          7,
		TotalPending:       3,
		TotalTags:          1,
		TotalRejectsGlobal: 5,
		TotalRejectsPerTag: 6,
	}, map[string]SchedulerPerTagStats{
		origin: {Pending: 3, Active: 4, Starving: 1, EMA: 2.0, Admits: 11, Rejects: 11},
	})
	assert.Equal(t, 1, testutil.CollectAndCount(CacheSchedulerActive))

	ResetCacheSchedulerMetrics()

	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerActive))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerStarving))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerPending))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerEMA))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerAdmitsTotal))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerRejectsTotal))
	assert.Equal(t, 0, testutil.CollectAndCount(CacheSchedulerRejectsByCauseTotal))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPoolSize))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPoolPending))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPoolTags))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPoolStarvingCap))
	assert.Equal(t, float64(0), testutil.ToFloat64(CacheSchedulerPoolActiveCap))

	// The delta bookkeeping was reset too, so a scheduler created afterwards
	// counts from zero rather than being diffed against the dead instance.
	//
	// The totals here are deliberately LARGER than the dead instance's. Smaller
	// ones would prove nothing: counterDelta already treats a decrease as a
	// restart, so they would come out right whether or not the tracker was
	// cleared. Diffing 20 against a retained 11 would yield 9.
	PublishCacheSchedulerSnapshot(SchedulerGlobalStats{
		WorkerCount:        8,
		TotalTags:          1,
		TotalRejectsGlobal: 9,
		TotalRejectsPerTag: 12,
	}, map[string]SchedulerPerTagStats{
		origin: {Active: 1, Admits: 20, Rejects: 20},
	})
	assert.Equal(t, float64(20), testutil.ToFloat64(CacheSchedulerAdmitsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(20), testutil.ToFloat64(CacheSchedulerRejectsTotal.WithLabelValues(origin)))
	assert.Equal(t, float64(9), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("global")))
	assert.Equal(t, float64(12), testutil.ToFloat64(CacheSchedulerRejectsByCauseTotal.WithLabelValues("per_tag")))
}
