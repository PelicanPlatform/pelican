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

package pstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

// The collectors are process-global, so these tests read them by gathering the
// default registry rather than by holding references.  That is deliberate: it
// checks the series an operator would actually scrape, including its name,
// which a direct read of the collector variable would not.

// seriesValue reads one series out of a metric family, matching every label
// given.  The bool reports whether the series exists at all, which is the
// difference between "published as zero" and "never published".
//
// Gauges and counters share one reader.  A family carries one or the other, so
// the unset accessor returns a nil message whose value is zero -- which makes
// the sum unambiguous, and saves a second copy of the label matching that is
// the only interesting part of this.
func seriesValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			matched := true
			for wantName, wantValue := range labels {
				found := false
				for _, l := range m.GetLabel() {
					if l.GetName() == wantName && l.GetValue() == wantValue {
						found = true
						break
					}
				}
				if !found {
					matched = false
					break
				}
			}
			if matched {
				return m.GetGauge().GetValue() + m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// gaugeValue is seriesValue where the caller cares whether the gauge was ever
// published.
func gaugeValue(t *testing.T, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	return seriesValue(t, name, labels)
}

// labeledCounterValue is seriesValue where an untouched counter and a counter
// at zero mean the same thing.
func labeledCounterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	v, _ := seriesValue(t, name, labels)
	return v
}

// TestCapacityGaugesPublishedFromRecoveredUsageAtOpen is the restart case.
//
// The capacity gauges describe a level, not an event, so a store that comes
// back up holding data must say so before anything is written to it.  Left to
// the write path they would read zero for however long it took the next PUT to
// arrive -- which is exactly the window in which an operator restarting a full
// origin looks at the dashboard.
func TestCapacityGaugesPublishedFromRecoveredUsageAtOpen(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	const limit = 8 << 20
	dir := t.TempDir()
	cfg := Config{
		BaseDir:     dir,
		StorageDirs: []local_cache.StorageDirConfig{{Path: dir, MaxSize: limit}},
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	egrp, _ := errgroup.WithContext(ctx)

	first, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)

	// Large enough to land in a storage directory rather than in the catalog,
	// so the per-directory gauge has something to report.
	writeObject(t, first, "/obj.bin", randomBytes(256<<10, 7))
	wantUsed, wantMax := first.Usage()
	require.Positive(t, wantUsed)
	require.NoError(t, first.Close())

	// Poison the gauges so that anything read below can only have come from
	// the reopen.  Without this the test would pass on the values the first
	// store left behind.
	const poison = -12345
	metrics.PStoreUsedBytes.Set(poison)
	metrics.PStoreLimitBytes.Set(poison)
	metrics.PStoreDirectoryUsedBytes.Reset()
	metrics.PStoreDirectoryLimitBytes.Reset()

	second, err := Open(ctx, egrp, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, second.Close()) })

	gotUsed, ok := gaugeValue(t, "pelican_pstore_used_bytes", nil)
	require.True(t, ok, "the aggregate usage gauge must be published at open")
	assert.Equal(t, float64(wantUsed), gotUsed,
		"the gauge must carry the usage the tracker recovered from the catalog, "+
			"not zero until the first write")

	gotMax, ok := gaugeValue(t, "pelican_pstore_limit_bytes", nil)
	require.True(t, ok)
	assert.Equal(t, float64(wantMax), gotMax)
	assert.Equal(t, float64(limit), gotMax, "the configured ceiling is the aggregate one")

	// The same for the directory the bytes actually landed in.  The label is
	// the configured path, not the block store's "objects" subdirectory.
	label, ok := second.dirLabels[storageIDForPath(t, second, dir)]
	require.True(t, ok)
	assert.Equal(t, dir, label, "the gauge is labeled with the directory as configured")

	dirUsed, ok := gaugeValue(t, "pelican_pstore_directory_used_bytes",
		map[string]string{"directory": label})
	require.True(t, ok, "the per-directory usage gauge must be published at open")
	assert.Positive(t, dirUsed)

	dirLimit, ok := gaugeValue(t, "pelican_pstore_directory_limit_bytes",
		map[string]string{"directory": label})
	require.True(t, ok)
	assert.Equal(t, float64(limit), dirLimit)

	// The inline pseudo-directory is reported too, under a name that is
	// deliberately not a path so it cannot be confused with a real one.
	_, ok = gaugeValue(t, "pelican_pstore_directory_used_bytes",
		map[string]string{"directory": metrics.PStoreDirectoryInline})
	assert.True(t, ok, "objects held in the catalog are accounted for as well")
}

// storageIDForPath finds the storage ID the block store assigned to a
// configured directory.
func storageIDForPath(t *testing.T, s *Store, path string) local_cache.StorageID {
	t.Helper()
	for id, label := range s.dirLabels {
		if label == path {
			return id
		}
	}
	t.Fatalf("no storage directory is labeled %s", path)
	return 0
}

// TestFailedBackupDoesNotAdvanceLastSuccess covers the one property the whole
// backup-freshness alert rests on.
//
// "Seconds since the last successful snapshot" is only a useful alert if a
// failing pass leaves the timestamp alone.  A pass that advanced it on every
// attempt would make an origin whose backups have been failing for a week look
// like one that backed up minutes ago -- which is precisely the failure the
// metric exists to catch, reported as health.
func TestFailedBackupDoesNotAdvanceLastSuccess(t *testing.T) {
	s := newTestStore(t)

	passLabels := map[string]string{"pass": metrics.PStorePassMetadataBackup}
	const (
		attemptsMetric = "pelican_pstore_scheduled_passes_total"
		failuresMetric = "pelican_pstore_scheduled_pass_failures_total"
		successMetric  = "pelican_pstore_scheduled_pass_last_success_timestamp_seconds"
	)

	attemptsBefore := labeledCounterValue(t, attemptsMetric, passLabels)
	failuresBefore := labeledCounterValue(t, failuresMetric, passLabels)
	successBefore, _ := gaugeValue(t, successMetric, passLabels)

	// A backup directory whose parent is a regular file cannot be created, so
	// the snapshot fails the way a wrong path or a bad owner would.
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	badCfg := BackupConfig{
		Dir:      filepath.Join(blocker, "backups"),
		Interval: time.Hour,
		Keep:     2,
		Keys:     testBackupKeys(t),
	}
	runOneBackup(t, s, badCfg)

	assert.Equal(t, attemptsBefore+1, labeledCounterValue(t, attemptsMetric, passLabels),
		"a failed pass is still an attempt")
	assert.Equal(t, failuresBefore+1, labeledCounterValue(t, failuresMetric, passLabels),
		"a failed backup increments the failure counter")

	successAfterFailure, _ := gaugeValue(t, successMetric, passLabels)
	assert.Equal(t, successBefore, successAfterFailure,
		"a failed backup must not advance the last-success timestamp")

	// And the counterpart: a snapshot that lands does advance it, and records
	// what it published.
	goodCfg := badCfg
	goodCfg.Dir = t.TempDir()
	runOneBackup(t, s, goodCfg)

	assert.Equal(t, failuresBefore+1, labeledCounterValue(t, failuresMetric, passLabels),
		"a successful backup does not increment failures")

	successAfterSuccess, ok := gaugeValue(t, successMetric, passLabels)
	require.True(t, ok)
	assert.Greater(t, successAfterSuccess, successAfterFailure,
		"a successful backup advances the last-success timestamp")

	size, ok := gaugeValue(t, "pelican_pstore_metadata_backup_last_size_bytes", nil)
	require.True(t, ok)
	assert.Positive(t, size, "the published snapshot's size is recorded")
}

// runOneBackup drives the real backup loop through exactly its startup
// snapshot.
//
// The context is already cancelled, so runPeriodically returns without arming
// anything: the loop runs once, synchronously, and nothing here waits on a
// clock.  Going through runBackupLoop rather than calling snapshotOnce is the
// point -- the instrumentation lives in the loop, and a test that bypassed it
// would pass with the loop unwired.
func runOneBackup(t *testing.T, s *Store, cfg BackupConfig) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	s.runBackupLoop(ctx, cfg, realSchedule())
}

// TestWriteTierCounterAttributesEachTier checks that a write is counted under
// the tier that actually stored it.
//
// The tier is not a property of the request: it is chosen by how much data
// arrives, and a declared length only pre-selects it.  Getting the attribution
// wrong would make the distribution -- the whole reason an operator looks at
// this -- describe something other than where their objects went.
func TestWriteTierCounterAttributesEachTier(t *testing.T) {
	s := newTestStore(t)

	inlineMax := int64(s.storage.InlineMaxBytes())
	require.Positive(t, inlineMax)
	require.Less(t, inlineMax, int64(spillThreshold),
		"the buffered tier only exists between these two thresholds")

	const metric = "pelican_pstore_writes_total"
	tierLabels := func(tier string) map[string]string { return map[string]string{"tier": tier} }

	before := map[string]float64{}
	for _, tier := range []string{
		metrics.PStoreTierInline, metrics.PStoreTierBuffered, metrics.PStoreTierStreamed,
	} {
		before[tier] = labeledCounterValue(t, metric, tierLabels(tier))
	}

	// One object per tier, sized by the same thresholds the write path uses.
	writeObject(t, s, "/inline.bin", randomBytes(int(inlineMax), 1))
	writeObject(t, s, "/buffered.bin", randomBytes(int(inlineMax)+1024, 2))
	writeObject(t, s, "/streamed.bin", randomBytes(spillThreshold+4096, 3))

	for _, tier := range []string{
		metrics.PStoreTierInline, metrics.PStoreTierBuffered, metrics.PStoreTierStreamed,
	} {
		assert.Equal(t, before[tier]+1, labeledCounterValue(t, metric, tierLabels(tier)),
			"exactly one write should have been attributed to the %q tier", tier)
	}

	// A write that never lands is not counted at all: the counter describes
	// what the store holds, not what was attempted.
	w, err := s.Create("/aborted.bin")
	require.NoError(t, err)
	_, err = w.Write(randomBytes(4096, 4))
	require.NoError(t, err)
	require.NoError(t, w.Abort())

	total := 0.0
	for _, tier := range []string{
		metrics.PStoreTierInline, metrics.PStoreTierBuffered, metrics.PStoreTierStreamed,
	} {
		total += labeledCounterValue(t, metric, tierLabels(tier)) - before[tier]
	}
	assert.Equal(t, 3.0, total, "an aborted write is not counted under any tier")
}

// TestReclamationBacklogIsCountedToTheEndOfTheQueue covers the measurement the
// backlog gauge depends on.
//
// collectGarbage stops at the batch size because it has to hold what it
// collects; queueDepth holds nothing and must therefore report the real
// number.  A count that saturated at the batch size would make a queue of half
// a million look identical to one of five hundred that is perfectly stable --
// the two cases the gauge exists to tell apart.
func TestReclamationBacklogIsCountedToTheEndOfTheQueue(t *testing.T) {
	s := newTestStore(t)

	instances, subtrees, err := s.queueDepth()
	require.NoError(t, err)
	assert.Zero(t, instances, "a fresh store has nothing queued")
	assert.Zero(t, subtrees)

	const objects = 5
	for i := range objects {
		name := "/obj" + string(rune('a'+i)) + ".bin"
		writeObject(t, s, name, randomBytes(2048, int64(i)))
		require.NoError(t, s.Remove(name))
	}
	// A detached subtree is queued under a different kind, and the two must
	// not be conflated: one is bytes waiting to be freed, the other is paths
	// that are refusing writes until the drain finishes.
	require.NoError(t, s.bdb.Update(func(txn *badger.Txn) error {
		return enqueueSubtree(txn, "/detached")
	}))

	instances, subtrees, err = s.queueDepth()
	require.NoError(t, err)
	assert.Equal(t, objects, instances, "every deleted version is waiting on the queue")
	assert.Equal(t, 1, subtrees)

	// The gauge follows, and the sweep drains what it counted.
	s.publishReclamationMetrics()
	pending, ok := gaugeValue(t, "pelican_pstore_reclamation_pending",
		map[string]string{"kind": metrics.PStoreReclaimKindInstance})
	require.True(t, ok)
	assert.Equal(t, float64(objects), pending)

	stats, err := s.RunGC(t.Context())
	require.NoError(t, err)
	assert.Equal(t, objects, stats.InstancesFreed)
	assert.Positive(t, stats.BytesFreed, "reclaimed bytes are reported alongside the count")

	instances, _, err = s.queueDepth()
	require.NoError(t, err)
	assert.Zero(t, instances, "the sweep drained what the gauge reported")
}

// TestFsckFindingsGaugeReflectsRepair covers the one piece of judgment in the
// fsck gauges: a repaired store must stop reporting the findings repair
// resolved.
//
// The report keeps its lists either way -- they are what the pass found -- but
// a gauge answers "is anything wrong now".  Left high after the unservable
// entries were unlinked, it would send an operator after a problem that no
// longer exists, every time they ran the fix.
func TestFsckFindingsGaugeReflectsRepair(t *testing.T) {
	s := newTestStore(t)

	writeObject(t, s, "/a.bin", []byte("one"))
	writeObject(t, s, "/b.bin", []byte("two"))

	// Delete one object's metadata behind the index's back, which is what a
	// dangling entry is.
	d, err := s.Stat("/a.bin")
	require.NoError(t, err)
	require.NoError(t, s.db.DeleteMetadata(instanceHashFor(s.db, d.Generation)))

	danglingLabels := map[string]string{"kind": metrics.PStoreFsckDanglingEntries}

	report, err := s.Fsck(t.Context(), false)
	require.NoError(t, err)
	require.Len(t, report.DanglingEntries, 1)

	dangling, ok := gaugeValue(t, "pelican_pstore_fsck_findings", danglingLabels)
	require.True(t, ok, "a completed pass publishes its findings")
	assert.Equal(t, 1.0, dangling)

	// The object count comes from the same index walk, so it costs no extra
	// scan and is available as soon as the first pass finishes.
	objects, ok := gaugeValue(t, "pelican_pstore_objects", nil)
	require.True(t, ok)
	assert.Equal(t, 2.0, objects, "two files, the root directory excluded")

	_, err = s.Fsck(t.Context(), true)
	require.NoError(t, err)

	dangling, ok = gaugeValue(t, "pelican_pstore_fsck_findings", danglingLabels)
	require.True(t, ok)
	assert.Zero(t, dangling, "repair unlinked the entry, so nothing is left to report")
}
