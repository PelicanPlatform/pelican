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

// Consistency checking.
//
// fsck is a backstop, not a load-bearing part of correctness.  Every mutation
// that makes data unreachable also queues it for reclamation in the same
// transaction, so space cannot leak unless the janitor never runs.  What fsck
// catches is the residue of bugs, interrupted upgrades, and operator surgery:
// entries pointing at metadata that is gone, metadata no longer reachable from
// any entry, and usage counters that have drifted.
//
// It walks the index rather than the storage directories, so it is bounded by
// the number of objects rather than by their size, and it reports before it
// repairs.
//
// Two properties matter more than they look, because this runs on a schedule
// against stores holding millions of objects:
//
//   - No pass holds a read transaction open across the whole catalog.  Every
//     scan here is batched and resumable, so BadgerDB's read watermark
//     advances and value-log GC is never blocked for the length of a check.
//   - The one comparison that needs a set in memory -- object versions no
//     entry refers to -- is partitioned over the instance-hash space, so peak
//     memory is bounded by a budget rather than by the object count.  It needs
//     a set because the two sides are ordered differently: the versions in
//     question are discovered by walking the index, which is ordered by path,
//     while the metadata they are compared against is ordered by instance
//     hash, an HMAC with no relation to the path.  Where two sides *are*
//     ordered alike -- the reclamation queue and the metadata scan, both keyed
//     by instance hash -- they are merged instead, and cost no memory at all.
//     See queuedCursor.
//
// And one rule that matters more than either: nothing here treats a write
// that is still in flight as garbage.  An object that has been written but
// whose directory entry has not landed yet is indistinguishable, in the
// catalog, from the residue of a crash.  Reclaiming it would destroy a live
// upload, so instances are only reported as orphans once they have been
// complete for longer than a grace period and carry no in-flight marker.

package pstore

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

// reachableKey is the map key for the reachable-version set: the first 16
// bytes of an instance hash, decoded from its hex spelling.
//
// The set is large -- one entry per live version in the shard -- and the hash
// is a 64-character hex string, so the string key costs about 117 bytes per
// entry against 36 for a fixed-size array. At the budget below that is the
// difference between roughly 235 MiB and 72 MiB of resident memory for a
// scheduled backstop.
//
// Truncating to 128 bits is safe *in this direction specifically*, which is
// worth stating because the tool deletes data. The set is consulted as "in the
// set means leave it alone": a hash found here is skipped and never becomes a
// reclamation candidate. So a collision can only make an orphan look reachable
// and be passed over -- space that is not reclaimed until the next run with a
// different shard boundary. It can never do the reverse, because truncation is
// deterministic: every genuinely reachable hash puts its own prefix in the set,
// so a live version can never be missing from it and can never be reclaimed.
// The probability is negligible regardless -- about 2^-87 across the whole
// budget -- but the asymmetry is what makes it acceptable rather than the odds.
type reachableKey [16]byte

// truncateHash builds the map key. A hash that is not the expected hex
// spelling cannot be truncated meaningfully, so it falls back to copying the
// raw bytes: a malformed hash is fsck's business to report, not to silently
// alias onto another entry.
func truncateHash(hash local_cache.InstanceHash) reachableKey {
	var k reachableKey
	if n, err := hex.Decode(k[:], []byte(hash)[:min(len(hash), 2*len(k))]); err == nil && n == len(k) {
		return k
	}
	copy(k[:], hash)
	return k
}

const (
	// fsckBatchSize bounds how many keys a single read transaction covers.
	// Every scan below reopens a transaction per batch and resumes from the
	// last key, so no pass pins BadgerDB's read watermark for its duration.
	fsckBatchSize = 4096

	// fsckReachableBudget bounds how many instance hashes one pass keeps in
	// memory while looking for orphans.  Above it the comparison is split
	// across slices of the instance-hash space, trading repeated index walks
	// for a memory ceiling -- the walk is over the catalog, which is small
	// against the data, while an unbounded map is not.
	fsckReachableBudget = 2 << 20

	// fsckMaxShardWidth caps the partitioning at 256 slices (two hex digits),
	// so an enormous store degrades in scan time rather than in memory.
	fsckMaxShardWidth = 2

	// fsckDefaultMinAge is how long an unreferenced object version must have
	// been complete before it is called an orphan.
	//
	// The window is real: Create writes the object's metadata and blocks and
	// only then commits the directory entry, so between those two an entirely
	// healthy upload has metadata that no entry points at.  Without a grace
	// period `fsck --repair` would queue a live write for reclamation.  The
	// cache's own checker takes the same precaution for the same reason.
	fsckDefaultMinAge = 5 * time.Minute
)

// errFsckBatchFull unwinds a batched scan once its batch is full.
var errFsckBatchFull = errors.New("fsck batch full")

// FsckReport summarizes a consistency pass.
type FsckReport struct {
	// EntriesScanned is how many index entries were examined.
	EntriesScanned int
	// DirectoriesScanned is how many of those were directories.
	DirectoriesScanned int

	// DanglingEntries are files whose object version has no metadata.  The
	// entry is unreadable, so it is reported and, when repairing, removed.
	DanglingEntries []string
	// MissingData are objects whose metadata exists but whose blocks are
	// incomplete, meaning a write was interrupted before it committed.
	MissingData []string
	// OrphanedInstances are object versions no entry refers to, which have
	// been complete for longer than the grace period.  They hold space and
	// are queued for reclamation when repairing.
	OrphanedInstances []string
	// PendingInstances are object versions no entry refers to *yet*: a write
	// that has not completed, or one that completed within the grace period.
	//
	// These are reported for visibility and never repaired.  A live upload
	// looks exactly like a crash-window orphan from the catalog's point of
	// view, and reclaiming one would delete an object out from under the
	// client still writing it.  Reclamation of writes that really were
	// abandoned belongs to the append-intent sweep, which can tell the
	// difference.
	PendingInstances []string
	// CorruptObjects are objects whose stored data no longer matches the
	// checksums recorded when they were written.  Only populated by a deep
	// pass.
	CorruptObjects []string
	// ObjectsVerified counts the objects a deep pass read back.
	ObjectsVerified int

	// UsageDrift is the difference, per storage directory, between the
	// catalog's recorded usage and what the objects actually occupy.
	UsageDrift map[local_cache.StorageID]int64

	// OrphanScanPartial reports that the orphan comparison covered only a
	// slice of the instance-hash space, so its findings are not exhaustive.
	OrphanScanPartial bool
	// OrphanScanShards is how many slices the space was divided into, which
	// is the number of passes a caller must rotate through for full coverage.
	//
	// It can exceed what the caller asked for: the slices are hex prefixes of
	// the instance hash, so a request is rounded up to a power of sixteen.  A
	// caller that rotates over its own number instead of this one would leave
	// most of the store permanently unexamined.
	OrphanScanShards int

	// Repaired reports whether a repair pass ran.  It says nothing about
	// whether every finding was resolved -- see Resolved and Unresolved.
	Repaired bool
	// UsageResynced reports that the drift above was written back to the
	// catalog, not merely recomputed in memory.
	UsageResynced bool
}

// Healthy reports whether the pass found nothing wrong.
//
// Pending instances are deliberately excluded: a write in flight is what a
// busy origin looks like, not a fault.
func (r *FsckReport) Healthy() bool {
	return len(r.DanglingEntries) == 0 &&
		len(r.MissingData) == 0 &&
		len(r.OrphanedInstances) == 0 &&
		len(r.CorruptObjects) == 0 &&
		len(r.UsageDrift) == 0
}

// Resolved lists what a repair pass actually acted on.
//
// This exists because the two lists are not the same and reporting them as
// though they were is how an operator comes to believe a store was fixed.
// Repair can unlink an unreadable entry, queue an unreferenced version, and
// rewrite a drifted counter.  It cannot manufacture data that is gone, and it
// cannot un-corrupt a block.
func (r *FsckReport) Resolved() []string {
	if !r.Repaired {
		return nil
	}
	var out []string
	if len(r.DanglingEntries) > 0 {
		out = append(out, "Entries whose object data is missing (removed)")
	}
	if len(r.OrphanedInstances) > 0 {
		out = append(out, "Object versions no entry refers to (queued for reclamation)")
	}
	if r.UsageResynced && len(r.UsageDrift) > 0 {
		out = append(out, "Usage counter drift (rewritten from the catalog)")
	}
	return out
}

// Unresolved lists findings that survive a repair pass, so a caller can exit
// non-zero rather than reporting success.
func (r *FsckReport) Unresolved() []string {
	var out []string
	add := func(cond bool, label string) {
		if cond {
			out = append(out, label)
		}
	}
	if r.Repaired {
		// Repair unlinks dangling entries and queues orphans, so those are
		// gone.  These two it cannot touch: data that was never written
		// cannot be conjured, and a block that no longer matches its checksum
		// needs a decision -- restore, re-ingest, or accept the loss -- that
		// belongs to an operator.
		add(!r.UsageResynced && len(r.UsageDrift) > 0, "Usage counter drift")
	} else {
		add(len(r.DanglingEntries) > 0, "Entries whose object data is missing")
		add(len(r.OrphanedInstances) > 0, "Object versions no entry refers to")
		add(len(r.UsageDrift) > 0, "Usage counter drift")
	}
	add(len(r.MissingData) > 0, "Writes that never completed")
	add(len(r.CorruptObjects) > 0, "Objects whose data no longer matches its checksums")
	return out
}

// Fsck checks the store's internal consistency.
//
// When repair is false nothing is modified, which is the mode an operator
// should reach for first.  When true, dangling entries are removed, orphaned
// versions are queued for reclamation, and usage counters are resynced from
// the catalog.
func (s *Store) Fsck(ctx context.Context, repair bool) (*FsckReport, error) {
	return s.FsckWith(ctx, FsckOptions{Repair: repair})
}

// FsckOptions selects what a consistency pass checks.
type FsckOptions struct {
	// Repair acts on what the pass finds rather than only reporting it.
	Repair bool
	// Deep additionally reads every object back and verifies it against the
	// checksums recorded at ingest.
	//
	// This is the only check that detects at-rest corruption -- a flipped bit
	// in a block file, or a truncated chunk -- because everything else reads
	// only the catalog.  It costs a full pass over the data, so it is off by
	// default and belongs on a schedule rather than in a routine check.
	Deep bool

	// SkipOrphanScan omits the search for object versions no entry refers to.
	//
	// That search is the only part of a pass whose cost is not streaming: it
	// must hold the set of referenced versions while it scans the catalog.
	// Everything else -- unreadable entries, interrupted writes, counter
	// drift -- is a streaming check.  A frequent background pass therefore
	// skips it, or covers one slice at a time; an operator running fsck by
	// hand wants the whole answer and gets it.
	SkipOrphanScan bool

	// OrphanShardOf, when greater than one, splits the orphan comparison into
	// that many slices of the instance-hash space and examines only
	// OrphanShard.  Rotating the slice across successive passes gives full
	// coverage over time at a fraction of the memory.
	//
	// It is rounded up to a power of sixteen, because the slices are hex
	// prefixes of the instance hash.  Rotate over FsckReport.OrphanScanShards
	// rather than over this value: they differ whenever it is not already a
	// power of sixteen, and rotating over the smaller one would leave most of
	// the store permanently unexamined.
	OrphanShardOf int
	// OrphanShard selects the slice, modulo the effective slice count.
	OrphanShard int

	// MinAge is how long an unreferenced version must have been complete
	// before it counts as an orphan rather than a write still in flight.
	//
	// Zero selects fsckDefaultMinAge.  The zero value is the safe one on
	// purpose: a caller that forgets this field gets the grace period, not
	// the hazard it exists to prevent.  Pass FsckNoGracePeriod to switch it
	// off, which only a test with no concurrent writers should do.
	MinAge time.Duration
}

// FsckNoGracePeriod disables the in-flight-write grace period.
//
// Only safe when nothing can be writing to the store -- a test, or an offline
// pass an operator has taken responsibility for.
const FsckNoGracePeriod = time.Duration(-1)

// FsckWith checks the store's internal consistency with explicit options.
func (s *Store) FsckWith(ctx context.Context, opts FsckOptions) (*FsckReport, error) {
	report := &FsckReport{
		UsageDrift: make(map[local_cache.StorageID]int64),
		Repaired:   opts.Repair,
	}
	if opts.Repair {
		// Fail before doing any work rather than after, and do not rely on
		// BadgerDB's directory lock to be the thing that stops a repair pass
		// from running against a store someone else is writing.
		if err := s.checkWritable(); err != nil {
			return nil, err
		}
	}

	minAge := opts.MinAge
	switch {
	case minAge == 0:
		minAge = fsckDefaultMinAge
	case minAge < 0:
		minAge = 0
	}

	// Counter drift first: it is a streaming scan, and its object count is
	// what sizes the orphan comparison below.
	actual, objectCount, err := s.footprintByUsageKey(ctx)
	if err != nil {
		return nil, err
	}
	drift, err := s.usageDrift(actual)
	if err != nil {
		return nil, err
	}
	for key, d := range drift {
		if d != 0 {
			report.UsageDrift[key.StorageID] += d
		}
	}
	for id, d := range report.UsageDrift {
		if d == 0 {
			delete(report.UsageDrift, id)
		}
	}

	shards := []string{""}
	if !opts.SkipOrphanScan {
		shards = fsckShards(objectCount, opts.OrphanShardOf, opts.OrphanShard)
		if opts.OrphanShardOf > 1 {
			report.OrphanScanPartial = true
			report.OrphanScanShards = len(hexPrefixes(hexShardWidth(opts.OrphanShardOf)))
		} else {
			report.OrphanScanShards = 1
		}
	}

	// Built once: the checker carries rate limiters and metric handles, and a
	// deep pass would otherwise construct one per object.
	var checker *local_cache.ConsistencyChecker
	if opts.Deep {
		checker = s.consistencyChecker()
	}

	for i, shard := range shards {
		// The per-entry checks cover the whole index and do not depend on the
		// slice, so they run once no matter how many slices the orphan
		// comparison is split into.
		entryChecks := i == 0

		reachable := make(map[reachableKey]struct{})
		if err := s.scanIndexBatched(ctx, func(entryPath string, d *Dirent) error {
			if entryChecks {
				report.EntriesScanned++
				if d.IsDir() {
					report.DirectoriesScanned++
					return nil
				}
			} else if d.IsDir() {
				return nil
			}
			if d.Generation == "" {
				if entryChecks {
					report.DanglingEntries = append(report.DanglingEntries, entryPath)
				}
				return nil
			}

			hash := instanceHashFor(s.db, d.Generation)
			if !opts.SkipOrphanScan && strings.HasPrefix(string(hash), shard) {
				reachable[truncateHash(hash)] = struct{}{}
			}
			if !entryChecks {
				return nil
			}

			meta, mErr := s.db.GetMetadata(hash)
			if mErr != nil {
				return errors.Wrapf(mErr, "failed to read metadata for %s", entryPath)
			}
			if meta == nil {
				report.DanglingEntries = append(report.DanglingEntries, entryPath)
				return nil
			}
			// A version whose write never completed is not servable.
			if meta.Completed.IsZero() {
				report.MissingData = append(report.MissingData, entryPath)
				return nil
			}
			if opts.Deep {
				// Verified here rather than collected for later, so a deep
				// pass over ten million objects does not also build a
				// ten-million-entry slice of things to do.
				ok, vErr := checker.VerifyObject(hash)
				if vErr != nil {
					// A verification that cannot run is itself a finding: the
					// object is not readable.
					report.CorruptObjects = append(report.CorruptObjects, entryPath)
					return nil
				}
				report.ObjectsVerified++
				if !ok {
					report.CorruptObjects = append(report.CorruptObjects, entryPath)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}

		if opts.SkipOrphanScan {
			continue
		}
		if err := s.collectOrphans(ctx, shard, reachable, minAge, report); err != nil {
			return nil, err
		}
	}

	if !opts.Repair {
		observeFsck(report, opts, false)
		return report, nil
	}
	if err := s.repair(ctx, report, drift); err != nil {
		// A repair that stopped part-way leaves a mixture nothing here can
		// describe, so report the findings as the pass saw them: the operator
		// is being sent to look either way.
		observeFsck(report, opts, false)
		return report, err
	}
	observeFsck(report, opts, true)
	// Repair rewrote the drifted usage counters and reseeded the tracker from
	// them, so the capacity gauges are stale by exactly the amount that was
	// wrong.
	s.publishCapacityMetrics()

	return report, nil
}

// observeFsck publishes a completed pass's findings.
//
// A gauge per class, set at the end of a pass, rather than a series per
// finding: the findings are paths, and a store with a hundred thousand
// dangling entries would otherwise put a hundred thousand series into the
// registry at exactly the moment it can least afford it.  The paths are in the
// report and in the log; the gauges answer "is anything wrong, and is it
// getting worse".
//
// Two classes are conditional, because setting them from a pass that did not
// look would be worse than not setting them at all:
//
//   - corrupt objects are only visible to a deep pass, so a shallow pass
//     writing zero would erase what a deep one found;
//   - the object count comes from the index walk, which every pass does in
//     full -- so unlike the orphan comparison it is always store-wide.
//
// The orphan and pending counts *are* published from a sharded pass, and are
// then per-slice rather than store-wide.  That is stated in the metric's help
// text.  The alternative -- publishing them only from an exhaustive pass --
// would leave them frozen forever in a server process, since the scheduled
// index check always shards.
//
// resolved says a repair pass completed, in which case the classes repair
// actually acts on are published as zero.  The report keeps its lists either
// way -- they are what was found -- but a gauge answers "is anything wrong
// now", and leaving it high after the entries have been unlinked and the
// orphans queued would report a repaired store as broken until the next
// scheduled pass.  The split is the same one FsckReport.Resolved and
// FsckReport.Unresolved make, and for the same reason: repair cannot
// manufacture data that is gone or un-corrupt a block.
func observeFsck(report *FsckReport, opts FsckOptions, resolved bool) {
	set := func(kind string, n int) {
		metrics.PStoreFsckFindings.WithLabelValues(kind).Set(float64(n))
	}
	cleared := func(n int) int {
		if resolved {
			return 0
		}
		return n
	}
	set(metrics.PStoreFsckDanglingEntries, cleared(len(report.DanglingEntries)))
	set(metrics.PStoreFsckOrphanedInstances, cleared(len(report.OrphanedInstances)))
	if resolved && report.UsageResynced {
		set(metrics.PStoreFsckUsageDrift, 0)
	} else {
		set(metrics.PStoreFsckUsageDrift, len(report.UsageDrift))
	}

	// Repair cannot touch these two, so they stand whatever it did.
	set(metrics.PStoreFsckMissingData, len(report.MissingData))
	set(metrics.PStoreFsckPendingInstances, len(report.PendingInstances))
	if opts.Deep {
		set(metrics.PStoreFsckCorruptObjects, len(report.CorruptObjects))
	}

	// The only count of the store's objects that does not cost a scan of its
	// own; the index walk has just done it.
	metrics.PStoreObjects.Set(float64(report.EntriesScanned - report.DirectoriesScanned))
}

// collectOrphans classifies the versions in one slice of the instance-hash
// space that no entry refers to.
func (s *Store) collectOrphans(
	ctx context.Context,
	shard string,
	reachable map[reachableKey]struct{},
	minAge time.Duration,
	report *FsckReport,
) error {
	// The reclamation queue is not only a list of dead versions.  A write in
	// progress tombstones its own instance before materializing it and clears
	// the entry in the transaction that installs it, so a `pg:i:` key can
	// belong to a live upload.  Skipping everything on the queue is therefore
	// doubly right: those versions are the janitor's business either way, and
	// the ones that are not garbage must not be touched at all.
	//
	// The queue is consulted with a cursor rather than loaded into a set,
	// because `pg:i:<hash>` and `m:<hash>` are ordered by the same hash, so the
	// two scans merge.  See queuedCursor.
	queued := s.newQueuedCursor(ctx, shard)

	// Keys only: deciding reachability needs the hash, not the record.  The
	// few candidates that survive are read individually below, which is far
	// cheaper than decoding every metadata value in the store.
	var candidates []local_cache.InstanceHash
	if err := s.scanMetadataHashes(ctx, shard, func(hash local_cache.InstanceHash) error {
		// Reachability first: in a healthy store nearly every version is
		// referenced, so this settles most hashes without touching the queue.
		// Consulting the cursor on only the survivors is still an ascending
		// sequence, which is all the merge requires.
		if _, ok := reachable[truncateHash(hash)]; ok {
			return nil
		}
		isQueued, err := queued.contains(hash)
		if err != nil {
			return err
		}
		if isQueued {
			return nil
		}
		candidates = append(candidates, hash)
		return nil
	}); err != nil {
		return errors.Wrap(err, "failed to scan object metadata")
	}

	cutoff := time.Now().Add(-minAge)
	for _, hash := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A streaming upload records an append intent before it has any
		// directory entry.  That marker is the reclamation handle for writes
		// that really were abandoned, and it belongs to the append sweep --
		// fsck must not race it.
		inFlight, err := s.hasAppendIntent(hash)
		if err != nil {
			return err
		}
		if inFlight {
			report.PendingInstances = append(report.PendingInstances, string(hash))
			continue
		}

		meta, err := s.db.GetMetadata(hash)
		if err != nil {
			return errors.Wrapf(err, "failed to read metadata for %s", hash)
		}
		if meta == nil {
			// It went away between the two scans, which is the janitor doing
			// its job.
			continue
		}
		if meta.Completed.IsZero() || meta.Completed.After(cutoff) {
			report.PendingInstances = append(report.PendingInstances, string(hash))
			continue
		}
		report.OrphanedInstances = append(report.OrphanedInstances, string(hash))
	}
	return nil
}

// repair acts on what Fsck found.
func (s *Store) repair(ctx context.Context, report *FsckReport, drift map[local_cache.StorageUsageKey]int64) error {
	if err := s.checkWritable(); err != nil {
		return err
	}

	// Unlink entries that cannot be served, so a client gets a clean 404
	// rather than an error mid-read.
	for _, entryPath := range report.DanglingEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.bdb.Update(func(txn *badger.Txn) error {
			return deleteDirent(txn, entryPath)
		}); err != nil {
			return errors.Wrapf(err, "failed to remove dangling entry %s", entryPath)
		}
	}

	// Hand orphans to the janitor rather than deleting inline, so reclamation
	// goes through the one path that also respects reader pins.
	for _, hash := range report.OrphanedInstances {
		if err := ctx.Err(); err != nil {
			return err
		}
		h := local_cache.InstanceHash(hash)
		if err := s.bdb.Update(func(txn *badger.Txn) error {
			return enqueueInstance(txn, h)
		}); err != nil {
			return errors.Wrapf(err, "failed to queue orphan %s", hash)
		}
	}

	// Write the corrected totals back to the catalog.
	//
	// Reseeding the in-memory counters alone was the whole of this step once,
	// and it repaired nothing: the counters are seeded *from* the catalog at
	// every open, so a drifted `u:` survived the repair and was read back on
	// the next start.  An over-counted directory therefore made the store
	// answer 507 forever with no operator remedy.  SetUsage overwrites the
	// key with a discard marker, so the old value cannot be summed back in.
	for key, d := range drift {
		if d == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		recorded, err := s.db.GetUsage(key.StorageID, key.NamespaceID)
		if err != nil {
			return errors.Wrapf(err, "failed to read usage for storage %d", key.StorageID)
		}
		if err := s.db.SetUsage(key.StorageID, key.NamespaceID, recorded+d); err != nil {
			return errors.Wrapf(err, "failed to rewrite usage for storage %d", key.StorageID)
		}
	}
	report.UsageResynced = true

	// Reseed the in-memory counters from the catalog we just corrected.
	for _, id := range s.capacity.storageIDs() {
		if err := s.capacity.resync(s.db, id); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Bounded scans
// ---------------------------------------------------------------------------

// scanIndexBatched visits every index entry, reopening a read transaction
// every fsckBatchSize keys and resuming from the last one.
//
// The callback runs outside the transaction, so a per-entry metadata lookup
// does not nest a second transaction inside a long-lived one, and BadgerDB's
// read watermark advances while the pass is running.
func (s *Store) scanIndexBatched(ctx context.Context, fn func(entryPath string, d *Dirent) error) error {
	type indexEntry struct {
		path string
		d    *Dirent
	}

	prefix := []byte(local_cache.PrefixDirent)
	seek := append([]byte(nil), prefix...)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		batch := make([]indexEntry, 0, fsckBatchSize)
		var lastKey []byte
		exhausted := true

		if err := s.bdb.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = prefix
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(seek); it.ValidForPrefix(prefix); it.Next() {
				item := it.Item()
				lastKey = item.KeyCopy(lastKey[:0])

				entryPath, ok := pathFromKey(item.Key())
				if ok {
					var d *Dirent
					if err := item.Value(func(val []byte) error {
						var dErr error
						d, dErr = decodeDirent(val)
						return dErr
					}); err != nil {
						return errors.Wrapf(err, "failed to read entry %s", entryPath)
					}
					batch = append(batch, indexEntry{path: entryPath, d: d})
				}
				// A key that does not decode is not ours to interpret; it is
				// skipped rather than guessed at, but it still advances the
				// resume point.
				if len(batch) >= fsckBatchSize {
					exhausted = false
					return nil
				}
			}
			return nil
		}); err != nil {
			return err
		}

		for _, e := range batch {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := fn(e.path, e.d); err != nil {
				return err
			}
		}
		if exhausted {
			return nil
		}
		seek = nextKeyAfter(lastKey)
	}
}

// scanMetadataHashes visits the instance hashes whose metadata key falls in
// one slice of the hash space, in bounded batches and without reading values.
func (s *Store) scanMetadataHashes(ctx context.Context, shard string, fn func(local_cache.InstanceHash) error) error {
	prefix := []byte(local_cache.PrefixMeta + shard)
	seek := append([]byte(nil), prefix...)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		batch := make([]local_cache.InstanceHash, 0, fsckBatchSize)
		var lastKey []byte
		exhausted := true

		if err := s.bdb.View(func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.Prefix = prefix
			opts.PrefetchValues = false
			it := txn.NewIterator(opts)
			defer it.Close()

			for it.Seek(seek); it.ValidForPrefix(prefix); it.Next() {
				key := it.Item().Key()
				lastKey = it.Item().KeyCopy(lastKey[:0])
				batch = append(batch, local_cache.InstanceHash(key[len(local_cache.PrefixMeta):]))
				if len(batch) >= fsckBatchSize {
					exhausted = false
					return nil
				}
			}
			return nil
		}); err != nil {
			return err
		}

		for _, h := range batch {
			if err := fn(h); err != nil {
				return err
			}
		}
		if exhausted {
			return nil
		}
		seek = nextKeyAfter(lastKey)
	}
}

// footprintByUsageKey totals what the objects really occupy, per usage
// counter, and counts them.
//
// This deliberately does not use CacheDB.ComputeActualUsage: that sums raw
// ContentLength, whereas the counters are charged CalculateFileSize -- the
// on-disk size including each block's authentication tag. Comparing the two
// reports phantom drift of exactly the MAC overhead on every healthy store.
// PerDirectoryBytes yields the same quantity the counters hold, and is what
// the write and reclaim paths already use.
func (s *Store) footprintByUsageKey(ctx context.Context) (map[local_cache.StorageUsageKey]int64, int, error) {
	out := make(map[local_cache.StorageUsageKey]int64)
	count := 0

	start := local_cache.InstanceHash("")
	for {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		n := 0
		var last local_cache.InstanceHash
		err := s.db.ScanMetadataFrom(start, func(hash local_cache.InstanceHash, meta *local_cache.CacheMetadata) error {
			for id, bytes := range meta.PerDirectoryBytes() {
				out[local_cache.StorageUsageKey{StorageID: id, NamespaceID: meta.NamespaceID}] += bytes
			}
			count++
			n++
			last = hash
			if n >= fsckBatchSize {
				return errFsckBatchFull
			}
			return nil
		})
		if err != nil && !errors.Is(err, errFsckBatchFull) {
			return nil, 0, errors.Wrap(err, "failed to total object footprints")
		}
		if err == nil {
			return out, count, nil
		}
		start = last
	}
}

// usageDrift reports actual-minus-recorded per usage counter.
func (s *Store) usageDrift(actual map[local_cache.StorageUsageKey]int64) (map[local_cache.StorageUsageKey]int64, error) {
	recorded, err := s.db.GetAllUsage()
	if err != nil {
		return nil, errors.Wrap(err, "failed to read recorded usage")
	}

	drift := make(map[local_cache.StorageUsageKey]int64)
	for key, v := range actual {
		// StorageIDInline is the catalog itself, not a storage directory, so
		// it is excluded from both sides of the comparison.
		if key.StorageID == local_cache.StorageIDInline {
			continue
		}
		drift[key] += v
	}
	for key, v := range recorded {
		if key.StorageID == local_cache.StorageIDInline {
			continue
		}
		drift[key] -= v
	}
	for key, d := range drift {
		if d == 0 {
			delete(drift, key)
		}
	}
	return drift, nil
}

// queuedCursor answers "is this version on the reclamation queue?" by merging
// the queue with the metadata scan instead of loading it into a set.
//
// "Queued" rather than "awaiting reclamation": the same key is the crash-window
// tombstone a write in flight sets on itself, so membership means only that
// fsck must leave the version alone.  That ambiguity is what queuedInstance
// encodes, and the cursor deals in that type throughout -- it reports a bool and
// never yields a hash, so skipping everything queued stays the only thing fsck
// can do with the queue.
//
// The merge is possible because `pg:i:<hash>` and `m:<hash>` are both keyed by
// the instance hash, in the same fixed-width hex encoding behind a fixed-length
// prefix -- so BadgerDB's byte order over the two prefixes is the same order,
// and two cursors walking forward together answer every membership question in
// one pass with no set at all.  (The *reachable* set above cannot be merged
// this way: it is discovered by walking `pd:`, which is ordered by path, and
// the instance hash is an HMAC that deliberately bears no relation to the path.
// That mismatch is the whole reason that comparison needs a set, and why the
// set is partitioned over a memory budget.)
//
// The gain is not speed -- the old set was one bounded scan too -- it is that
// the queue is no longer held in memory.  It had no budget, and it is the one
// structure here that can be arbitrarily large at exactly the moment fsck is
// most likely to run: draining a detached subtree enqueues one `pg:i:` key per
// version it unlinks, so a recursive delete of a million objects puts a million
// keys on the queue until the janitor works through it.
//
// Callers must present hashes in ascending order.  The cursor only ever moves
// forward, so a caller that goes backwards would silently get false.
type queuedCursor struct {
	ctx    context.Context
	s      *Store
	prefix []byte
	trim   int

	// seek is where the next batch resumes; buf holds the current one.  Like
	// every other scan here it is batched, so no read transaction stays open
	// across the pass.
	//
	// The batch is []queuedInstance rather than []local_cache.InstanceHash for
	// the reason the type exists: a raw scan of `pg:i:` is exactly the thing a
	// future change must not be able to feed to a delete, and membership is all
	// this cursor ever needs to answer.  The two are the same size, so the merge
	// costs what it always did.
	seek []byte
	buf  []queuedInstance
	pos  int
	done bool
}

// newQueuedCursor opens a cursor over the reclamation queue within one slice
// of the instance-hash space.
func (s *Store) newQueuedCursor(ctx context.Context, shard string) *queuedCursor {
	prefix := []byte(local_cache.PrefixGarbage + garbageKindInstance + shard)
	return &queuedCursor{
		ctx:    ctx,
		s:      s,
		prefix: prefix,
		trim:   len(local_cache.PrefixGarbage + garbageKindInstance),
		seek:   append([]byte(nil), prefix...),
	}
}

// contains reports whether hash is on the queue, advancing past every queued
// version that sorts before it.
func (c *queuedCursor) contains(hash local_cache.InstanceHash) (bool, error) {
	for {
		if c.pos >= len(c.buf) {
			if c.done {
				return false, nil
			}
			if err := c.fill(); err != nil {
				return false, err
			}
			continue
		}
		switch cmp := c.buf[c.pos].compare(hash); {
		case cmp < 0:
			// Queued but with no metadata: already reclaimed, or queued by a
			// path that never wrote any.  Nothing to report either way.
			c.pos++
		case cmp == 0:
			return true, nil
		default:
			return false, nil
		}
	}
}

// fill loads the next batch.  It always makes progress: either buf gains
// entries or done is set, so contains cannot spin.
func (c *queuedCursor) fill() error {
	if err := c.ctx.Err(); err != nil {
		return err
	}

	c.buf = c.buf[:0]
	c.pos = 0
	var lastKey []byte

	if err := c.s.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = c.prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(c.seek); it.ValidForPrefix(c.prefix); it.Next() {
			item := it.Item()
			lastKey = item.KeyCopy(lastKey[:0])
			// A []byte-to-string conversion copies, so this does not retain
			// the iterator's buffer past Next.
			c.buf = append(c.buf, newQueuedInstance(string(item.Key()[c.trim:])))
			if len(c.buf) >= fsckBatchSize {
				return nil
			}
		}
		c.done = true
		return nil
	}); err != nil {
		return errors.Wrap(err, "failed to read the reclamation queue")
	}

	if len(c.buf) == 0 {
		c.done = true
		return nil
	}
	c.seek = nextKeyAfter(lastKey)
	return nil
}

// hasAppendIntent reports whether a streaming write is part-way through
// building this version.
func (s *Store) hasAppendIntent(hash local_cache.InstanceHash) (bool, error) {
	found := false
	err := s.bdb.View(func(txn *badger.Txn) error {
		_, gErr := txn.Get(local_cache.AppendIntentKey(hash))
		if errors.Is(gErr, badger.ErrKeyNotFound) {
			return nil
		}
		if gErr != nil {
			return gErr
		}
		found = true
		return nil
	})
	return found, errors.Wrapf(err, "failed to check for an in-flight write of %s", hash)
}

// nextKeyAfter returns the smallest key strictly greater than key, so a
// batched scan resumes without re-delivering the last entry.
func nextKeyAfter(key []byte) []byte {
	next := make([]byte, len(key)+1)
	copy(next, key)
	return next
}

// fsckShards picks the slices of the instance-hash space the orphan
// comparison runs over.
//
// With no explicit request the whole space is covered, split into as many
// slices as it takes to keep the referenced-version set under the budget.
// With one, a single slice is examined and the caller rotates.
func fsckShards(objectCount, shardOf, shard int) []string {
	if shardOf > 1 {
		width := hexShardWidth(shardOf)
		prefixes := hexPrefixes(width)
		if shard < 0 {
			shard = -shard
		}
		return []string{prefixes[shard%len(prefixes)]}
	}

	width := 0
	for objectCount > fsckReachableBudget && width < fsckMaxShardWidth {
		objectCount /= 16
		width++
	}
	return hexPrefixes(width)
}

// hexShardWidth is how many hex digits it takes to name n slices.
func hexShardWidth(n int) int {
	width := 0
	for total := 1; total < n && width < fsckMaxShardWidth; total *= 16 {
		width++
	}
	return width
}

// hexPrefixes enumerates every hex string of the given length.
func hexPrefixes(width int) []string {
	out := []string{""}
	for i := 0; i < width; i++ {
		next := make([]string, 0, len(out)*16)
		for _, p := range out {
			for _, c := range "0123456789abcdef" {
				next = append(next, p+string(c))
			}
		}
		out = next
	}
	return out
}

// consistencyChecker builds the cache's integrity checker over this store.
//
// The block store, its metadata, and its checksums are the cache's, so the
// machinery that verifies them is too -- reimplementing block-level
// verification here would be a second thing to keep correct.  What is *not*
// shared is policy: the cache's scan deletes an object whose data no longer
// matches its checksums, because for a cache that is the repair.  For a store
// holding the only copy it is the loss, so the checker is built with
// PreserveCorruptObjects and the backfill suppressed.  Only the verification
// entry points are used here in any case; pstore's index consistency is
// checked by Fsck above.
func (s *Store) consistencyChecker() *local_cache.ConsistencyChecker {
	return local_cache.NewConsistencyChecker(s.db, s.storage, newPStoreScanConfig(0))
}

// VerifyObject reads one object back and checks it against the checksums
// recorded when it was written.
//
// Returns false when the data no longer matches, which means at-rest
// corruption: every other check reads only the catalog and cannot see it.
func (s *Store) VerifyObject(name string) (bool, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return false, err
	}
	d, err := s.Stat(cleanPath)
	if err != nil {
		return false, err
	}
	if d.IsDir() {
		return false, ErrIsDir
	}
	return s.consistencyChecker().VerifyObject(instanceHashFor(s.db, d.Generation))
}
