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

// Metrics for the Pelican store (`pstore`), the origin backend that drives the
// cache V2 block store directly.  See docs/pstore-design.md §11.7.
//
// These live here rather than in the pstore package for the reason the rest of
// this package exists: one place to read the whole exported surface, and one
// place a name collision is caught.  The collectors are package-level and
// registered by promauto at init, which is what makes them safe when several
// exports share one store -- they do -- and when a process runs both a cache
// and an origin.
//
// Three rules shaped the set:
//
//   - Nothing here is fed by a syscall or by work done inside a lock on a
//     serving path.  The capacity gauges are republished from figures the
//     store already keeps in memory, by the janitor and at open; the write
//     counters are a single atomic add per completed write.
//   - Gauges describe state, so they must be right after a restart rather than
//     after the first event.  The capacity gauges are published from what the
//     capacity tracker recovers from the catalog at open, not left at zero
//     until something is written.
//   - There is deliberately no `store` label.  `Origin.PStoreLocation` is a
//     single process-wide parameter, so a server process has exactly one
//     store; the offline CLI opens its own, in its own process, where nothing
//     is scraped.  Storage directories are owned exclusively by one store, so
//     the `directory` label stays unambiguous regardless.
//
// # Relationship to the `pelican_cache_*` scan series
//
// pstore's scheduled data scan is `local_cache.ConsistencyChecker.RunDataScan`,
// which is also the cache's, and which used to report an *origin's* integrity
// scan under `pelican_cache_data_scan_*`.  That is resolved at the source: the
// checker a pstore builds sets `ConsistencyConfig.SuppressCacheMetrics`, so the
// cache-named series are not touched by an origin and the equivalent figures
// are published here instead.  Nothing is counted twice, and a process running
// both a cache and a pstore origin reports each under its own name.
//
// The one difference an operator will notice: the cache updates its scan
// counters after every object, while `pelican_pstore_data_scan_*` is added to
// once per completed pass.  A pass over a large store can take a day, so these
// step rather than climb.  `pelican_pstore_scheduled_pass_last_success_timestamp_seconds`
// is what says a pass is in progress or stuck.

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Label values for the `pass` label on the scheduled-pass metrics below.
// They name the three loops in pstore that run work on a schedule.
const (
	PStorePassIndexCheck     = "index_check"
	PStorePassDataScan       = "data_scan"
	PStorePassMetadataBackup = "metadata_backup"
)

// Label values for the `tier` label on PStoreWritesTotal.  They are the three
// write tiers in docs/pstore-design.md §6.1.
const (
	PStoreTierInline   = "inline"
	PStoreTierBuffered = "buffered"
	PStoreTierStreamed = "streamed"
)

// Label values for the `reason` label on PStoreWriteFailuresTotal.
const (
	PStoreWriteFailureNoSpace  = "no_space"
	PStoreWriteFailureConflict = "conflict"
)

// Label values for the `kind` label on PStoreReclamationPending.
const (
	PStoreReclaimKindInstance = "instance"
	PStoreReclaimKindSubtree  = "subtree"
)

// Label values for the `kind` label on PStoreFsckFindings.
const (
	PStoreFsckDanglingEntries   = "dangling_entries"
	PStoreFsckMissingData       = "missing_data"
	PStoreFsckOrphanedInstances = "orphaned_instances"
	PStoreFsckPendingInstances  = "pending_instances"
	PStoreFsckCorruptObjects    = "corrupt_objects"
	PStoreFsckUsageDrift        = "usage_drift_directories"
)

// PStoreDirectoryInline is the `directory` label value for the pseudo-directory
// that holds objects stored inline in the catalog rather than in a storage
// directory.  It is deliberately not a path: inline objects live wherever the
// catalog does, which may be one of the real directories, and giving them that
// path would merge two different quantities into one series.
const PStoreDirectoryInline = "(inline)"

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

// A pstore never evicts.  When it fills, writes fail with ENOSPC and the origin
// answers 507, and until then nothing else in the process says the store is
// approaching that point -- the block files are encrypted and spread over
// several directories, so `du` does not answer it either.  These are gauges
// because they describe a level, and they are republished from the capacity
// tracker's in-memory figures (which are themselves seeded from the catalog at
// open) rather than measured, so nothing here costs a stat().
var (
	PStoreDirectoryUsedBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_directory_used_bytes",
		Help: "Bytes committed plus reserved in one pstore storage directory. " +
			"Cardinality is the number of configured directories, plus one for " +
			"\"" + PStoreDirectoryInline + "\", the objects held in the catalog itself.",
	}, []string{"directory"})

	PStoreDirectoryLimitBytes = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_directory_limit_bytes",
		Help: "Configured ceiling for one pstore storage directory (its MaxSize). " +
			"Zero means the directory is unbounded, which is also why the aggregate " +
			"limit is not the sum of these.",
	}, []string{"directory"})

	// The aggregate is a separate series rather than a sum() over the
	// per-directory ones because it cannot be derived from them: one unbounded
	// directory makes the whole store unbounded, so summing the limits would
	// invent a ceiling that does not exist.  It is also the figure that
	// actually refuses a write.
	PStoreUsedBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_pstore_used_bytes",
		Help: "Bytes committed plus reserved across the whole pstore. This is the " +
			"figure tested against the aggregate ceiling when a write is refused.",
	})

	PStoreLimitBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_pstore_limit_bytes",
		Help: "Aggregate ceiling for the pstore: the sum of the configured " +
			"per-directory limits, or zero when any directory is unbounded and " +
			"therefore the store as a whole is.",
	})

	// Sourced from the scheduled index check rather than kept incrementally.
	// There is no cheap count in the catalog, and maintaining one on the write
	// and delete paths would be a second thing to keep correct for a number
	// nobody alerts on -- so this is as of the last pass, and is absent until
	// the first one completes.
	PStoreObjects = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_pstore_objects",
		Help: "Objects in the pstore as of the last completed consistency pass " +
			"(Origin.PStoreIndexCheckInterval). Directories are excluded.",
	})
)

// ---------------------------------------------------------------------------
// Scheduled passes: index check, data scan, metadata backup
// ---------------------------------------------------------------------------

// The three background loops are the same shape -- run periodically, may fail,
// take a measurable time, may overrun their interval -- so they share one
// family with a `pass` label rather than three parallel sets of names.
//
// The metadata backup is the one that matters most and is invisible today.  An
// origin whose catalog backups silently stopped still serves perfectly until
// the catalog is lost, at which point the block files are unreadable bytes.
// The alert is on age:
//
//	time() - pelican_pstore_scheduled_pass_last_success_timestamp_seconds{pass="metadata_backup"}
//
// which is why the timestamp is advanced only by a pass that actually
// succeeded, and a failure moves the failure counter instead.
var (
	PStoreScheduledPassesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_pstore_scheduled_passes_total",
		Help: "Attempts at a pstore scheduled maintenance pass, by pass: " +
			"\"index_check\", \"data_scan\", or \"metadata_backup\".",
	}, []string{"pass"})

	PStoreScheduledPassFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_pstore_scheduled_pass_failures_total",
		Help: "Attempts at a pstore scheduled maintenance pass that returned an error. " +
			"A failed pass is logged and retried at the next interval; it never takes " +
			"the origin down, which is exactly why it needs to be visible here.",
	}, []string{"pass"})

	PStoreScheduledPassLastSuccessTime = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_scheduled_pass_last_success_timestamp_seconds",
		Help: "Unix time at which a pstore scheduled maintenance pass last completed " +
			"successfully. Zero (or absent) means no pass has ever succeeded in this " +
			"process. Alert on the age of pass=\"metadata_backup\".",
	}, []string{"pass"})

	PStoreScheduledPassLastDurationSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_scheduled_pass_last_duration_seconds",
		Help: "How long the last pstore scheduled maintenance pass took. A gauge " +
			"rather than a histogram: these run hours apart, so a distribution would " +
			"be several near-empty series describing a handful of samples a day.",
	}, []string{"pass"})

	// Runs are spaced from the end of one to the start of the next, so an
	// overrun does not compound -- but it does mean the store is too large for
	// the configured interval, and the loops only log that at warn level.
	PStoreScheduledPassOverrunsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_pstore_scheduled_pass_overruns_total",
		Help: "Passes that took longer than their configured interval. The next run " +
			"still waits a full interval, so nothing compounds; a rising count means " +
			"the check cannot actually run as often as configured.",
	}, []string{"pass"})

	PStoreMetadataBackupLastSizeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_pstore_metadata_backup_last_size_bytes",
		Help: "Size of the last snapshot the pstore metadata backup published. A " +
			"collapse in this against a store that is still growing is the shape of " +
			"a backup that succeeds while capturing nothing.",
	})
)

// ---------------------------------------------------------------------------
// Integrity findings
// ---------------------------------------------------------------------------

var (
	// Counted per pass rather than read from the checker's own totals, which
	// accumulate across every scan the process has ever run and so stay above
	// zero forever once a single mismatch has been seen.  runDataScanLoop
	// already takes that difference for its log message; this adds the same
	// difference here.
	PStoreDataScanMismatchesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_data_scan_mismatches_total",
		Help: "Objects whose stored data no longer matched the checksums recorded at " +
			"ingest, summed over completed data scans. An origin cannot re-fetch what " +
			"it has lost, so any increase is a restore-or-re-ingest decision.",
	})

	PStoreDataScanObjectsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_data_scan_objects_total",
		Help: "Objects read back and verified, summed over completed data scans. " +
			"Updated once per pass, not per object.",
	})

	PStoreDataScanBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_data_scan_bytes_total",
		Help: "Bytes read back and verified, summed over completed data scans. " +
			"Updated once per pass, not per object.",
	})

	// One gauge per finding class, set at the end of a pass.  Deliberately not
	// one series per finding: the findings are paths, and a store with a
	// hundred thousand dangling entries would otherwise put a hundred thousand
	// series into the registry at exactly the moment it is least able to
	// afford it.  The paths are in the fsck report and the log.
	PStoreFsckFindings = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_fsck_findings",
		Help: "Findings from the last pstore consistency pass, by class. " +
			"\"orphaned_instances\" and \"pending_instances\" are per examined slice " +
			"of the instance-hash space, not store-wide totals: the scheduled index " +
			"check covers one slice per pass to bound its memory. \"corrupt_objects\" " +
			"is only set by a deep pass, which is an operator action rather than a " +
			"scheduled one.",
	}, []string{"kind"})
)

// ---------------------------------------------------------------------------
// Reclamation
// ---------------------------------------------------------------------------

// Nothing in a pstore is evicted, so the janitor draining the `pg:` queue is
// the only thing that gives space back.  A queue that grows monotonically is a
// capacity leak that ends as a 507, and it is silent: each sweep is bounded
// work and simply falls further behind.
var (
	// Measured by a keys-only scan of the queue, taken at most once per resting
	// janitor interval so that a backlog -- the case where the scan is not free
	// -- cannot make the sweep rate pay for the measurement.
	PStoreReclamationPending = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_pstore_reclamation_pending",
		Help: "Work waiting in the pstore reclamation queue: \"instance\" for object " +
			"versions whose blocks are still to be freed, \"subtree\" for detached " +
			"directories still to be drained. Sampled at most once per janitor " +
			"resting interval.",
	}, []string{"kind"})

	PStoreDetachedSubtrees = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "pelican_pstore_detached_subtrees",
		Help: "Subtrees unlinked by a recursive delete that the janitor has not " +
			"finished draining. Paths beneath them are refused with a retryable " +
			"error, so a value that does not return to zero is user-visible.",
	})

	PStoreReclaimedObjectsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_reclaimed_objects_total",
		Help: "Object versions whose blocks the janitor has released.",
	})

	PStoreReclaimedBytesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_reclaimed_bytes_total",
		Help: "Bytes the janitor has released, from the metadata of each version it " +
			"freed. Compare against pelican_pstore_used_bytes to see reclamation " +
			"keeping up with deletion.",
	})

	// Its own counter rather than a label on the one above, because it counts a
	// different failure: a streaming upload that died before it reached the
	// queue at all.  A cache reclaims those from its eviction manager, which a
	// pstore never constructs, so this is the one path that used to leak
	// without any record.
	PStoreAbandonedWritesReclaimedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_abandoned_writes_reclaimed_total",
		Help: "Streaming writes whose writer never finished and whose space the " +
			"janitor has since released.",
	})
)

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

var (
	// The tier is chosen by how much data actually arrives, so this is the
	// distribution of object sizes as the store experiences it, and it says
	// whether the spill threshold suits the workload: a store whose writes are
	// nearly all "streamed" is buffering nothing and paying whole-chunk
	// reservations for objects that would fit in one file.
	PStoreWritesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_pstore_writes_total",
		Help: "Objects successfully written, by storage tier: \"inline\" (held in the " +
			"catalog), \"buffered\" (written in one piece at a known length), or " +
			"\"streamed\" (chunked through the append writer).",
	}, []string{"tier"})

	PStoreWriteFailuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_pstore_write_failures_total",
		Help: "Writes refused, by reason: \"no_space\" when the store is at its " +
			"ceiling (the origin answers 507), \"conflict\" when a write lost the race " +
			"for its path too many times to retry (the origin answers 409).",
	}, []string{"reason"})

	// Retries are separate from failures because they are not errors: the store
	// absorbing a concurrent PUT to the same path is the design working.  It is
	// worth seeing because a sustained retry rate is what precedes the
	// conflict failures above.
	PStoreWriteConflictRetriesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "pelican_pstore_write_conflict_retries_total",
		Help: "Commit attempts aborted by a concurrent write to the same path and " +
			"retried. Not an error: the retry is how the store absorbs concurrent " +
			"PUTs rather than answering them with a transaction conflict.",
	})
)
