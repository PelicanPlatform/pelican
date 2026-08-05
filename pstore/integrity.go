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

// Scheduled integrity checking.
//
// The cache scans itself continuously, and an origin needs it more, not less:
// a cache that discovers a corrupt object re-fetches it, while an origin has
// nowhere to re-fetch from.  Corruption that is only discovered when a client
// asks for the object has already been undetected for however long it sat
// there -- possibly long enough to have propagated into every backup that
// covers it.
//
// Two passes run on their own schedules, because they cost very different
// amounts:
//
//   - the index check reads only the catalog, so it is cheap and frequent;
//   - the data scan reads every block back and verifies it against the
//     checksums recorded at ingest, so it is rate-limited and infrequent.
//
// Both are scheduled from the *end* of the previous run rather than on a fixed
// cadence -- see runPeriodically, which the metadata backup loop in backup.go
// shares for the same reason.
//
// Neither modifies anything.  Repair stays a deliberate operator action
// through `pstore fsck --repair`, because the right response to a corrupt
// object is a judgment call -- restore it, re-ingest it, or accept the loss
// -- and not one a background task should be making at three in the morning.
//
// That is worth stating precisely, because the scan is the cache's and the
// cache's policy is the opposite one.  The cache deletes an object whose data
// no longer matches its checksums, which is exactly right for a cache: the
// next request re-fetches it from the origin and the object is repaired.  An
// origin has no upstream, so the same delete destroys the only copy -- and
// with it the only record of the object's path, size, and checksums, after
// which `fsck --repair` reclassifies the surviving entry as dangling and
// removes that too.  The scan is therefore configured with
// PreserveCorruptObjects, and with SkipChecksumBackfill so that the one other
// write it would make -- recording checksums for an object that has none --
// does not happen either.

package pstore

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

// IntegrityConfig schedules the background checks.
type IntegrityConfig struct {
	// IndexInterval is how often the catalog-only check runs.  Zero disables
	// it.
	IndexInterval time.Duration
	// DataInterval is how often every object is read back and verified.
	// Zero disables it.
	DataInterval time.Duration
	// DataScanBytesPerSec caps the verification read rate so the scan does
	// not compete with serving.  Zero selects the block store's default.
	DataScanBytesPerSec int64
}

// StartIntegrityChecks runs the scheduled checks until the context is
// cancelled.
func (s *Store) StartIntegrityChecks(ctx context.Context, egrp *errgroup.Group, cfg IntegrityConfig) {
	if cfg.IndexInterval > 0 {
		egrp.Go(func() error {
			s.runIndexCheckLoop(ctx, cfg.IndexInterval, realSchedule())
			return nil
		})
	}
	if cfg.DataInterval > 0 {
		egrp.Go(func() error {
			s.runDataScanLoop(ctx, cfg, realSchedule())
			return nil
		})
	}
	if cfg.IndexInterval > 0 || cfg.DataInterval > 0 {
		log.Infof("pstore integrity checks: index every %s, data every %s",
			cfg.IndexInterval, cfg.DataInterval)
	}
}

// indexCheckOrphanShards is how many slices of the instance-hash space the
// background index check spreads its orphan search over.
//
// Everything else the check does streams; the orphan search is the one part
// that must hold a set of referenced versions in memory, and at the millions
// of objects this design targets that set is the whole cost of the pass.
// Covering one sixteenth of the space per run bounds it to a sixteenth of the
// store while still sweeping everything within a day at the default hourly
// interval -- and orphans are residue, not a failure mode that needs
// detecting inside the hour.
const indexCheckOrphanShards = 16

// runIndexCheckLoop periodically checks the catalog against itself.
func (s *Store) runIndexCheckLoop(ctx context.Context, interval time.Duration, sched schedule) {
	shard := 0
	runPeriodically(ctx, interval, sched, "index check", func() {
		pass := beginPass(metrics.PStorePassIndexCheck, interval, sched)

		report, err := s.FsckWith(ctx, FsckOptions{
			OrphanShardOf: indexCheckOrphanShards,
			OrphanShard:   shard,
		})
		shard = (shard + 1) % indexCheckOrphanShards
		pass.finish(err == nil)
		if err != nil {
			log.Warnf("pstore index check failed: %v", err)
			return
		}
		if report.Healthy() {
			log.Debugf("pstore index check: %d entries, no problems", report.EntriesScanned)
			return
		}
		// Loud, because an inconsistent index means some object is either
		// unreachable or holding space nothing accounts for.
		log.Errorf("pstore index check found problems: %d dangling entries, "+
			"%d incomplete writes, %d orphaned versions, drift in %d directories. "+
			"Run `pelican-server origin pstore fsck` for detail.",
			len(report.DanglingEntries), len(report.MissingData),
			len(report.OrphanedInstances), len(report.UsageDrift))
	})
}

// runDataScanLoop periodically reads every object back and verifies it.
func (s *Store) runDataScanLoop(ctx context.Context, cfg IntegrityConfig, sched schedule) {
	checker := local_cache.NewConsistencyChecker(s.db, s.storage, newPStoreScanConfig(cfg.DataScanBytesPerSec))

	runPeriodically(ctx, cfg.DataInterval, sched, "data scan", func() {
		pass := beginPass(metrics.PStorePassDataScan, cfg.DataInterval, sched)

		// The checker accumulates its statistics across every scan it has ever
		// run, so the absolute count stays above zero forever once a single
		// mismatch has been seen.  Compare against the count going in, so what
		// is reported is what *this* pass found.
		before := checker.GetStats()

		// The block store's own scan does the reading and rate limiting;
		// reimplementing that here would be a second thing to keep correct.
		if err := checker.RunDataScan(ctx, nil); err != nil {
			pass.finish(false)
			if ctx.Err() == nil {
				log.Warnf("pstore data scan failed: %v", err)
			}
			return
		}
		pass.finish(true)

		// The same differencing carries the pstore-named counters.  The
		// checker's own pelican_cache_data_scan_* series are suppressed for a
		// pstore (see newPStoreScanConfig), so this is the only place an
		// origin's scan is reported and nothing is counted twice.
		after := checker.GetStats()
		observeDataScan(before, after)

		if found := after.ChecksumMismatches - before.ChecksumMismatches; found > 0 {
			log.Errorf("pstore data scan found %d object(s) whose data no longer "+
				"matches their checksums. Run `pelican-server origin pstore fsck --deep` "+
				"to identify them; an origin cannot re-fetch what it has lost. "+
				"The objects have been left in place -- restore them from backup "+
				"or re-ingest them.", found)
		}
	})
}

// ---------------------------------------------------------------------------
// Observing a scheduled pass
// ---------------------------------------------------------------------------

// passObserver reports one run of a scheduled maintenance loop.
//
// The three loops -- index check, data scan, metadata backup -- differ in what
// they do and hardly at all in what an operator needs to know about them: did
// it run, did it work, how long did it take, and is it still finishing inside
// its interval.  So they share one set of series distinguished by a `pass`
// label, and this is the only place that writes them.
//
// It deliberately does not live inside runPeriodically.  That helper is driven
// directly by tests, and threading a metric label through it would put an
// argument on every one of those call sites for the benefit of none of them --
// while the backup loop's startup snapshot, which runs *before* the first
// scheduled pass, would still need its own path.  Wrapping the work instead
// covers both with one mechanism.
type passObserver struct {
	pass     string
	interval time.Duration
	sched    schedule
	started  time.Time
}

// beginPass records an attempt and starts the clock.
func beginPass(pass string, interval time.Duration, sched schedule) passObserver {
	metrics.PStoreScheduledPassesTotal.WithLabelValues(pass).Inc()
	return passObserver{pass: pass, interval: interval, sched: sched, started: sched.now()}
}

// finish records how the run ended.
//
// Only a successful run advances the last-success timestamp, which is the
// entire value of that gauge: an alert on its age has to keep firing while a
// loop fails every interval, rather than being reset by the attempt.  A
// metadata backup that has been failing for a week is invisible under any
// other arrangement.
func (p passObserver) finish(ok bool) {
	elapsed := p.sched.now().Sub(p.started)
	metrics.PStoreScheduledPassLastDurationSeconds.
		WithLabelValues(p.pass).Set(elapsed.Seconds())

	// Counted for a failed run too: a pass that overruns and then errors is
	// still a pass the configured interval cannot accommodate, and it is
	// usually the more interesting of the two facts.
	if p.interval > 0 && elapsed > p.interval {
		metrics.PStoreScheduledPassOverrunsTotal.WithLabelValues(p.pass).Inc()
	}

	if !ok {
		metrics.PStoreScheduledPassFailuresTotal.WithLabelValues(p.pass).Inc()
		return
	}
	metrics.PStoreScheduledPassLastSuccessTime.
		WithLabelValues(p.pass).Set(float64(p.sched.now().Unix()))
}

// observeDataScan publishes what one completed data scan covered.
//
// The checker's statistics are cumulative over the life of the process, so
// every figure here is a difference across the pass -- the same treatment the
// mismatch count already needed for its log message, applied to the rest.
// Publishing the absolute values instead would produce counters that jump to
// the running total on the first scrape after a restart.
func observeDataScan(before, after local_cache.ConsistencyStats) {
	add := func(c prometheus.Counter, delta int64) {
		if delta > 0 {
			c.Add(float64(delta))
		}
	}
	add(metrics.PStoreDataScanMismatchesTotal, after.ChecksumMismatches-before.ChecksumMismatches)
	add(metrics.PStoreDataScanObjectsTotal, after.ObjectsVerified-before.ObjectsVerified)
	add(metrics.PStoreDataScanBytesTotal, after.BytesVerified-before.BytesVerified)
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

// periodicTimer is the part of time.Timer a scheduled loop needs.
//
// It is an interface so a test can supply its own.  What these loops have to
// get right is *when* the next wait is armed relative to the work finishing,
// and that ordering cannot be observed by sleeping and watching -- a test that
// tried would be both slow and flaky, and this repository does not allow
// sleep-based synchronization in the first place.
type periodicTimer interface {
	// Chan is the channel that fires when the wait is over.
	Chan() <-chan time.Time
	// Reset arms the timer to fire d from now.  It is only ever called on a
	// timer that has already fired and been drained, so the usual
	// Stop-then-drain dance around time.Timer.Reset does not apply.
	Reset(d time.Duration)
	// Stop releases the timer.
	Stop()
}

// realTimer is the production periodicTimer.
type realTimer struct{ t *time.Timer }

func (r realTimer) Chan() <-chan time.Time { return r.t.C }
func (r realTimer) Reset(d time.Duration)  { r.t.Reset(d) }
func (r realTimer) Stop()                  { r.t.Stop() }

// schedule supplies a periodic loop with its sense of time.
type schedule struct {
	// newTimer creates the timer the loop waits on, armed for the first run.
	newTimer func(time.Duration) periodicTimer
	// now reads the clock, which the loop uses only to measure how long a run
	// took.
	now func() time.Time
}

// realSchedule is the wall clock, which is what every caller outside a test
// wants.
func realSchedule() schedule {
	return schedule{
		newTimer: func(d time.Duration) periodicTimer { return realTimer{t: time.NewTimer(d)} },
		now:      time.Now,
	}
}

// runPeriodically calls work forever, leaving at least interval between the
// *end* of one run and the *start* of the next, and returns when ctx is done.
//
// The gap, rather than the cadence, is the whole point.  A time.Ticker -- which
// all three of these loops used to use -- fires on a fixed period no matter how
// long the body takes.  Go drops ticks that pile up, so it does not queue an
// unbounded backlog, but it does leave one tick pending: a data scan configured
// to run every 24 hours that takes 24 hours to finish finds a tick already
// waiting the moment it returns and starts again immediately.  The origin then
// scans continuously, competing with what it is meant to be protecting, and
// nothing in the configuration says that is what will happen.  Arming the timer
// after the work completes makes the interval mean what an operator reads it to
// mean.
//
// An overrun is logged, because it is the operator's only signal that the
// interval is set faster than the store's size allows.  Nothing else changes:
// the run is not cancelled and the next one is not skipped.  The message says
// what the consequence is, since "took longer than the interval" on its own does
// not tell anyone whether that is a problem.
//
// work is expected to honor ctx itself; the loop bounds when it starts, not how
// long it runs.
func runPeriodically(ctx context.Context, interval time.Duration, sched schedule, what string, work func()) {
	timer := sched.newTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.Chan():
		}

		started := sched.now()
		work()
		elapsed := sched.now().Sub(started)

		// Checked before the reset so the operator is told about the overrun
		// even on the pass that is about to be cancelled.
		if elapsed > interval {
			log.Warnf("The pstore %s took %s, which is longer than its configured interval "+
				"of %s. Runs are spaced from the end of one to the start of the next, so the "+
				"next %s begins %s from now rather than immediately -- but this store is large "+
				"enough that the check cannot actually run as often as configured. Lengthen "+
				"the interval to match reality, or raise the scan rate limit.",
				what, elapsed.Round(time.Second), interval, what, interval)
		}

		// Reset here, after the work, rather than letting a ticker run
		// underneath it: this is the line that makes the interval a gap.
		timer.Reset(interval)
	}
}

// newPStoreScanConfig builds the checker configuration a pstore must use.
//
// It is a function rather than a literal at each call site so that the two
// non-negotiable flags cannot be forgotten by a future caller: without them
// the cache's scan deletes an object on a checksum mismatch, which for a
// primary store is the data loss rather than the repair.
func newPStoreScanConfig(bytesPerSec int64) local_cache.ConsistencyConfig {
	return local_cache.ConsistencyConfig{
		// Match what is recorded at ingest, so verification compares against
		// checksums that actually exist.
		ChecksumTypes:       ingestAlgorithms,
		DataScanBytesPerSec: bytesPerSec,
		// An origin cannot re-fetch what it has lost.
		PreserveCorruptObjects: true,
		// Keep the pass genuinely read-only.
		SkipChecksumBackfill: true,
		// The checker is the cache's, and its metrics are named for a cache.
		// Left on, an origin's integrity scan would report itself as
		// pelican_cache_data_scan_* -- so a process serving only an origin
		// publishes cache series, and one serving both adds the origin's scan
		// to the cache's on the same graph.  The equivalent figures are
		// published under pelican_pstore_data_scan_* instead; see
		// observeDataScan.
		SuppressCacheMetrics: true,
	}
}
