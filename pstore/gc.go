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

// Garbage collection.
//
// Three things produce garbage: overwriting an object (the superseded
// version), aborting a write, and deleting.  In every case the entry becomes
// unreachable from the index and the bytes must be reclaimed afterwards.
//
// The queue entry is always written in the *same transaction* that makes the
// data unreachable.  That is what makes reclamation crash-safe: there is no
// window in which an orphan is both invisible to the index and absent from the
// queue, so space can only leak if the janitor never runs.  fsck is a backstop
// rather than a requirement.
//
// Two kinds of work are queued:
//
//	pg:i:<instanceHash>  an object version whose blocks should be freed
//	pg:t:<path>          a detached subtree whose entries should be removed
//
// The instance queue carries two meanings under the one key: a version that is
// dead, and a version a write is still building.  Telling them apart is what
// queuedInstance and its claim method exist for; nothing else in the package can
// turn a queue entry into something deletable.
//
// A subtree is queued rather than deleted inline because a large one cannot
// fit in a single transaction.  Unlinking its entry from the parent makes it
// unreachable immediately, and deletion need not be atomic — a partially
// drained subtree is invisible either way.

package pstore

import (
	"context"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

const (
	// garbageKindInstance queues one object version for block reclamation.
	garbageKindInstance = "i:"
	// garbageKindSubtree queues a detached directory for removal.
	garbageKindSubtree = "t:"

	// janitorInterval is the resting period between sweeps.
	janitorInterval = 30 * time.Second

	// janitorMinInterval is how fast the sweep may run while it is behind.
	// A sweep is bounded work, so backing off to this under a backlog drains
	// it in bounded time instead of leaving space reclaimed only as fast as
	// one batch per resting period.
	janitorMinInterval = 250 * time.Millisecond

	// janitorBatchSize bounds how many queue entries one sweep handles, so a
	// large backlog is drained over several passes instead of one long
	// transaction.
	janitorBatchSize = 512

	// subtreeBatchSize bounds how many entries are removed from a detached
	// subtree per transaction.
	subtreeBatchSize = 256

	// queueDepthInterval bounds how often the janitor measures the reclamation
	// backlog for pelican_pstore_reclamation_pending.
	//
	// The measurement is a keys-only scan of the pg: prefix, which is free
	// when the queue is short and proportional to the backlog when it is not
	// -- that is, it costs the most in exactly the situation that makes the
	// janitor sweep at janitorMinInterval.  Tying it to the resting period
	// rather than to the sweep keeps the cost flat no matter how far behind
	// the queue gets, at the price of a gauge that is at most this stale.  A
	// backlog worth alerting on persists for far longer than thirty seconds.
	queueDepthInterval = janitorInterval

	// appendReclaimGrace is how long a streaming write's append-in-flight
	// record must have been sitting before the janitor treats it as
	// abandoned.
	//
	// Two things protect an upload that is merely slow, and they cover
	// different failures.  The block store's live-writer registry covers this
	// process: an AppendWriter that exists is never reclaimed no matter how
	// long it takes.  The grace covers a restart, where that registry starts
	// empty and every record in the catalog looks abandoned -- so it has to be
	// long enough that a store coming back up cannot delete a write that
	// something else is still finishing.
	//
	// Ten minutes matches the value the cache's janitor uses, so an operator
	// reading either subsystem sees the same window, and it is deliberately
	// longer than fsck's five-minute orphan threshold: fsck reports before it
	// repairs and only deletes when asked, whereas this runs unattended.
	appendReclaimGrace = 10 * time.Minute
)

// garbageInstanceKey returns the queue key for an object version.
func garbageInstanceKey(h local_cache.InstanceHash) []byte {
	return []byte(local_cache.PrefixGarbage + garbageKindInstance + string(h))
}

// garbageSubtreeKey returns the queue key for a detached subtree.
func garbageSubtreeKey(cleanPath string) []byte {
	return []byte(local_cache.PrefixGarbage + garbageKindSubtree + cleanPath)
}

// enqueueInstance queues an object version for reclamation.  It must be called
// inside the transaction that makes the version unreachable.
func enqueueInstance(txn *badger.Txn, h local_cache.InstanceHash) error {
	if h == "" {
		return nil
	}
	return errors.Wrapf(txn.Set(garbageInstanceKey(h), nil),
		"failed to queue object version %s for reclamation", h)
}

// dequeueInstance removes an object version from the queue.  It must be called
// inside the transaction that makes the version reachable, so that a version is
// never simultaneously reachable and scheduled for reclamation.
func dequeueInstance(txn *badger.Txn, h local_cache.InstanceHash) error {
	if h == "" {
		return nil
	}
	return errors.Wrapf(txn.Delete(garbageInstanceKey(h)),
		"failed to clear the reclamation entry for object version %s", h)
}

// enqueueSubtree queues a detached directory for removal.  It must be called
// inside the transaction that unlinks the directory from its parent.
func enqueueSubtree(txn *badger.Txn, cleanPath string) error {
	return errors.Wrapf(txn.Set(garbageSubtreeKey(cleanPath), nil),
		"failed to queue subtree %s for removal", cleanPath)
}

// StartJanitor runs the reclamation sweep until the context is cancelled.
//
// The interval adapts to the backlog.  Each sweep handles a bounded batch, so
// a fixed period puts a ceiling on how fast space can come back: deleting a
// tree of a million objects at one batch per resting period would take days,
// during which the store stays full and refuses writes.  A sweep that fills
// its batch halves the wait, down to janitorMinInterval; a sweep that does not
// steps back toward the resting period.  Reclamation therefore accelerates
// exactly when there is something to reclaim and idles otherwise.
func (s *Store) StartJanitor(ctx context.Context, egrp *errgroup.Group) {
	egrp.Go(func() error {
		wait := janitorInterval
		timer := time.NewTimer(wait)
		defer timer.Stop()

		// The store publishes a backlog figure at open, so the first
		// measurement here is due a full interval later.
		lastDepth := time.Now()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
			}

			stats, err := s.RunGC(ctx)
			if err != nil {
				log.Warnf("pstore garbage collection pass failed: %v", err)
			}

			if time.Since(lastDepth) >= queueDepthInterval {
				s.publishReclamationMetrics()
				lastDepth = time.Now()
			}

			if stats.HitBatchLimit {
				wait /= 2
				if wait < janitorMinInterval {
					wait = janitorMinInterval
				}
			} else if wait < janitorInterval {
				// Ease back rather than snapping to the resting period, so a
				// bursty deleter does not oscillate between the two rates.
				wait *= 2
				if wait > janitorInterval {
					wait = janitorInterval
				}
			}
			timer.Reset(wait)
		}
	})
}

// GCStats reports what one sweep accomplished.
type GCStats struct {
	// InstancesFreed is the number of object versions whose blocks were
	// released.
	InstancesFreed int
	// InstancesPinned is the number skipped because a reader still holds
	// them; they are retried on a later pass.
	InstancesPinned int
	// SubtreeEntriesRemoved is the number of directory entries removed from
	// detached subtrees.
	SubtreeEntriesRemoved int
	// SubtreesCompleted is the number of detached subtrees fully drained.
	SubtreesCompleted int
	// AbandonedAppendsReclaimed is the number of streaming writes whose
	// writer never finished and whose space has now been released.
	AbandonedAppendsReclaimed int
	// BytesFreed is how much space the released object versions occupied,
	// summed from each version's metadata before it was deleted.  It excludes
	// abandoned streaming writes, whose footprint the block store refunds
	// directly without reporting it.
	BytesFreed int64

	// HitBatchLimit reports that the queue had more work than one sweep
	// handles, so another should follow sooner than the resting period.
	HitBatchLimit bool
}

// RunGC performs one reclamation pass and reports what it did.
//
// Safe to call directly; the janitor simply calls it on a timer.
func (s *Store) RunGC(ctx context.Context) (GCStats, error) {
	var stats GCStats

	instances, subtrees, saturated, err := s.collectGarbage()
	if err != nil {
		return stats, err
	}
	stats.HitBatchLimit = saturated

	for _, q := range instances {
		if err := ctx.Err(); err != nil {
			return stats, nil
		}
		// Every decision about whether this entry may be acted on lives in
		// reclaimInstance, which is the only thing a queuedInstance can be
		// passed to.  The sweep counts outcomes; it does not get a vote.
		outcome, freed, err := s.reclaimInstance(q)
		if err != nil {
			// The hash is already in the error: every failure path below
			// names the version it was working on.
			log.Warnf("Failed to reclaim a queued object version: %v", err)
			continue
		}
		switch outcome {
		case reclaimFreed:
			stats.InstancesFreed++
			stats.BytesFreed += freed
		case reclaimPinned:
			// Either a reader holds the version or a write is still building
			// it.  Both are retried on a later pass.
			stats.InstancesPinned++
		case reclaimWithdrawn:
			// Never was garbage; nothing to report.
		}
	}

	for _, root := range subtrees {
		if err := ctx.Err(); err != nil {
			return stats, nil
		}
		removed, done, err := s.drainSubtree(root)
		stats.SubtreeEntriesRemoved += removed
		if err != nil {
			log.Warnf("Failed to drain detached subtree %s: %v", root, err)
			continue
		}
		if done {
			// Nothing under this root remains in the index, so lookups no
			// longer need masking.
			s.detached.remove(root)
			stats.SubtreesCompleted++
		} else {
			// The subtree outran one batch, so there is more to do.
			stats.HitBatchLimit = true
		}
	}

	// A streaming write that died before Close never reached the reclamation
	// queue at all, so the pg: entries above cannot see it; the block store
	// tracks it separately.  Folding the sweep in here rather than giving it
	// its own ticker means it inherits the janitor's adaptive backoff and
	// there is still exactly one place that reclaims space.
	reclaimed, err := s.ReclaimAbandonedAppends(appendReclaimGrace)
	if err != nil {
		log.Warnf("Failed to reclaim abandoned streaming writes: %v", err)
	}
	stats.AbandonedAppendsReclaimed = reclaimed

	s.observeGC(stats)
	return stats, nil
}

// observeGC publishes what one sweep accomplished.
//
// The capacity gauges are refreshed here rather than from the write path
// because this is the one loop that runs whether or not anything is happening,
// so the levels stay current on an idle store and no serving path pays for
// them.  A sweep that freed nothing still republishes: usage moves on writes
// too, and this is what carries that.
func (s *Store) observeGC(stats GCStats) {
	if stats.InstancesFreed > 0 {
		metrics.PStoreReclaimedObjectsTotal.Add(float64(stats.InstancesFreed))
	}
	if stats.BytesFreed > 0 {
		metrics.PStoreReclaimedBytesTotal.Add(float64(stats.BytesFreed))
	}
	if stats.AbandonedAppendsReclaimed > 0 {
		metrics.PStoreAbandonedWritesReclaimedTotal.Add(float64(stats.AbandonedAppendsReclaimed))
	}
	metrics.PStoreDetachedSubtrees.Set(float64(s.detached.len()))
	s.publishCapacityMetrics()
}

// publishReclamationMetrics measures the reclamation backlog and publishes it.
//
// This is the only measurement in the whole set that is not already in memory:
// the pg: queue lives in the catalog, and its length is a keys-only prefix
// scan.  The scan is bounded by the backlog rather than by the store, which is
// the right shape -- a healthy store's queue is empty and the scan is a single
// seek -- but it is why the janitor rate-limits the call rather than making it
// once per sweep.  See queueDepthInterval.
func (s *Store) publishReclamationMetrics() {
	instances, subtrees, err := s.queueDepth()
	if err != nil {
		// A failure to observe is not a failure to serve.  The gauge keeps
		// its previous value, which is preferable to publishing a zero that
		// would read as "the backlog cleared".
		log.Debugf("Failed to measure the pstore reclamation backlog: %v", err)
		return
	}
	metrics.PStoreReclamationPending.
		WithLabelValues(metrics.PStoreReclaimKindInstance).Set(float64(instances))
	metrics.PStoreReclamationPending.
		WithLabelValues(metrics.PStoreReclaimKindSubtree).Set(float64(subtrees))
	metrics.PStoreDetachedSubtrees.Set(float64(s.detached.len()))
}

// queueDepth counts what is waiting in the reclamation queue.
//
// Separate from collectGarbage, which stops at janitorBatchSize because it has
// to hold what it collects: counting holds nothing, so it can afford to run to
// the end of the prefix and report a real number rather than one saturated at
// the batch size.  A gauge pinned at 512 would say "at least 512" while looking
// exactly like a queue that is genuinely 512 long and stable, which is the
// opposite of what this is for.
func (s *Store) queueDepth() (instances, subtrees int, err error) {
	prefix := []byte(local_cache.PrefixGarbage)

	err = s.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			rest := string(it.Item().Key()[len(prefix):])
			switch {
			case strings.HasPrefix(rest, garbageKindInstance):
				instances++
			case strings.HasPrefix(rest, garbageKindSubtree):
				subtrees++
			}
		}
		return nil
	})
	if err != nil {
		return 0, 0, errors.Wrap(err, "failed to read the pstore garbage queue")
	}
	return instances, subtrees, nil
}

// ReclaimAbandonedAppends releases capacity held by streaming writes whose
// writer never finished, and returns how many objects it freed.
//
// This closes the one gap the pg: queue cannot cover.  A write is queued for
// reclamation at the start of materialization (WriteHandle.beginMaterialize),
// which protects everything from there to the commit.  Before that point the
// object exists only as a partly written stream, and the block store records
// it under its own append-in-flight marker; a process that dies mid-upload
// leaves chunk files allocated and charged with nothing in the pg: queue
// pointing at them.  The cache reclaims those from its eviction manager, which
// a pstore deliberately never constructs -- so without this the store that
// makes the heaviest use of streaming writes was the one never cleaning up
// after them.
//
// The two mechanisms compose rather than double-count.  Deleting an object
// clears its append marker in the same transaction, so a version the pg: queue
// already reclaimed is found here with no metadata and only its stale marker
// is dropped; conversely an object reclaimed here is gone before any pg: entry
// could refer to it.
//
// minAge is the grace period; see appendReclaimGrace.  Passing zero reclaims
// every record with no live writer, which is for tooling and tests rather than
// the janitor.
func (s *Store) ReclaimAbandonedAppends(minAge time.Duration) (int, error) {
	if s.readOnly {
		return 0, nil
	}
	n, err := s.storage.ReclaimAbandonedAppends(minAge)
	if n > 0 {
		// The block store refunded the catalog's usage counters directly, so
		// the in-memory figures have to be re-read rather than adjusted: it
		// reports how many objects it freed, not which directories held them.
		for _, id := range s.capacity.storageIDs() {
			if rErr := s.capacity.resync(s.db, id); rErr != nil {
				log.Warnf("Failed to resync usage for storage directory %d: %v", id, rErr)
			}
		}
		log.Infof("Reclaimed %d object(s) left behind by interrupted streaming writes", n)
	}
	return n, errors.Wrap(err, "failed to reclaim abandoned streaming writes")
}

// queuedInstance is one `pg:i:` entry, exactly as it came off the reclamation
// queue: a hash that may or may not be garbage.
//
// The queue carries two meanings under the same key.  Originally an entry meant
// "this version is superseded or deleted; its bytes may be reclaimed".  A write
// in flight now writes that same key as a tombstone before it materializes
// anything (WriteHandle.beginMaterialize), so an entry can equally mean "a write
// is in progress and may or may not land".  Reclaiming the second kind deletes a
// live upload, which is the worst thing this package can do.
//
// Separating the two takes a specific check in a specific order -- see claim --
// and for a while nothing but a comment said so.  Hence a type that is *not* an
// instance hash.  What comes off the queue cannot be handed to
// StorageManager.DeleteIfUnpinned, to CacheDB.GetMetadata, or to any index
// mutation, because none of them accept it; the only way to obtain something
// they do accept is to call claim, which is the check.  A future caller that
// reads the queue therefore cannot skip the interlock without visibly rewriting
// this type.
//
// It is a struct rather than a defined string type on purpose: a defined type
// would convert to local_cache.InstanceHash in a single token.  The cost is
// nothing -- the struct is one string header, so a batch of queuedInstance
// allocates exactly what a batch of hashes did, which matters because the
// janitor walks this batch over potentially millions of entries.
type queuedInstance struct {
	// unsafeHash is the hash portion of the key, deliberately typed as a plain
	// string rather than as local_cache.InstanceHash: nothing that deletes data
	// accepts a string, so even inside this package a bypass has to be spelled
	// out as an explicit conversion rather than happening by accident.
	//
	// TestReclamationQueueEntriesCannotBypassTheInterlock fails if this field
	// is read outside a method of queuedInstance, if any method other than
	// claim yields a hash, or if the type is constructed anywhere but
	// newQueuedInstance.
	unsafeHash string
}

// newQueuedInstance wraps the hash portion of a `pg:i:` key.
func newQueuedInstance(hash string) queuedInstance {
	return queuedInstance{unsafeHash: hash}
}

// compare orders a queued entry against a metadata hash, reporting the usual
// negative, zero, or positive.
//
// Ordering is all fsck's merge needs, and ordering is all this gives it: a
// caller can learn that a version is on the queue without ever holding
// something it could delete.  See queuedCursor.
func (q queuedInstance) compare(h local_cache.InstanceHash) int {
	return strings.Compare(q.unsafeHash, string(h))
}

// claim runs the interlock that separates the queue's two meanings, and yields
// the hash only when the entry really is garbage.
//
// The batch an entry came from is a snapshot, and an entry can be *withdrawn*
// after it is taken: a write in progress queues its own version before
// materializing it and clears that entry in the transaction that installs it
// (see WriteHandle.beginMaterialize).  Acting on a stale snapshot would delete a
// live object out from under its own commit.
//
// Two observations in this order settle it.  The pin comes first.  The writer
// holds one from before its entry is visible until after the entry is cleared,
// and a reader holding the version would equally break if its metadata and block
// state vanished underneath it -- so a pinned version is left for a later pass
// either way, and the storage manager is asked because it is what hands out
// readers.  The re-read comes second.  Read the three facts in order: the caller
// saw the entry, then found it unpinned, and now the entry is still present.
// For that to describe a write in flight the writer would have had to release
// its pin before clearing the entry, which it never does -- so the version
// really is garbage.
//
// Both halves live here, rather than being split between here and the sweep, so
// that there is one place to read and one place a future caller has to go
// through.  The cost is unchanged: a pinned entry returns before any database
// read, and every other entry costs the single re-read it always did.
func (q queuedInstance) claim(s *Store) (local_cache.InstanceHash, reclaimOutcome, error) {
	h := local_cache.InstanceHash(q.unsafeHash)

	if s.storage.IsObjectPinned(h) {
		return "", reclaimPinned, nil
	}

	stillQueued, err := s.instanceQueued(h)
	if err != nil {
		return "", reclaimWithdrawn, err
	}
	if !stillQueued {
		return "", reclaimWithdrawn, nil
	}
	return h, reclaimEligible, nil
}

// collectGarbage reads a bounded batch of pending work from the queue.
//
// Object versions come back as queuedInstance rather than as instance hashes,
// which is what keeps this from being a source of deletable hashes: see
// queuedInstance.
func (s *Store) collectGarbage() ([]queuedInstance, []string, bool, error) {
	var (
		instances []queuedInstance
		subtrees  []string
		saturated bool
	)
	prefix := []byte(local_cache.PrefixGarbage)

	err := s.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			if len(instances)+len(subtrees) >= janitorBatchSize {
				saturated = true
				break
			}
			rest := string(it.Item().Key()[len(prefix):])
			switch {
			case strings.HasPrefix(rest, garbageKindInstance):
				instances = append(instances,
					newQueuedInstance(strings.TrimPrefix(rest, garbageKindInstance)))
			case strings.HasPrefix(rest, garbageKindSubtree):
				subtrees = append(subtrees, strings.TrimPrefix(rest, garbageKindSubtree))
			default:
				log.Warnf("Ignoring unrecognized pstore garbage queue entry %q", rest)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, false, errors.Wrap(err, "failed to read the pstore garbage queue")
	}
	return instances, subtrees, saturated, nil
}

// reclaimOutcome says what happened to one queued object version.
type reclaimOutcome int

const (
	// reclaimFreed means the version's blocks were released.
	reclaimFreed reclaimOutcome = iota
	// reclaimPinned means a reader holds it, or a write is still building it;
	// it stays queued for a later pass.
	reclaimPinned
	// reclaimWithdrawn means the queue entry is gone: the version was never
	// garbage after all.
	reclaimWithdrawn
	// reclaimEligible is not the outcome of a sweep but the verdict of the
	// interlock: the entry really is garbage and may be deleted.  It is what
	// queuedInstance.claim returns alongside the hash, and reclaimInstance
	// never reports it.
	reclaimEligible
)

// reclaimInstance frees a queued object version's blocks and dequeues it.
//
// This is the only consumer of a queuedInstance in the package, and it opens by
// asking claim whether the entry may be acted on at all; a caller holding a
// queue entry has no other way to reach a delete.  Everything below the claim is
// what happens once the interlock has said yes.
//
// It also reports how many bytes the version occupied, which is the same
// figure it credits back to the capacity counters -- so the reclaimed-bytes
// metric costs nothing beyond the addition, and cannot disagree with the
// accounting it is meant to describe.
func (s *Store) reclaimInstance(q queuedInstance) (reclaimOutcome, int64, error) {
	h, outcome, err := q.claim(s)
	if err != nil {
		return outcome, 0, err
	}
	if outcome != reclaimEligible {
		return outcome, 0, nil
	}

	// Record the space before deleting, so the in-memory capacity counters
	// can be credited: StorageManager.Delete updates the catalog's usage
	// counters but knows nothing about our reservations.
	meta, err := s.db.GetMetadata(h)
	if err != nil {
		return reclaimWithdrawn, 0, errors.Wrapf(err, "failed to read metadata for %s", h)
	}

	var freed int64
	if meta != nil {
		deleted, dErr := s.storage.DeleteIfUnpinned(h)
		if dErr != nil {
			return reclaimWithdrawn, 0, errors.Wrapf(dErr, "failed to delete object version %s", h)
		}
		if !deleted {
			return reclaimPinned, 0, nil
		}
		for storageID, bytes := range meta.PerDirectoryBytes() {
			s.capacity.release(storageID, bytes)
			freed += bytes
		}
	}

	// Wrapped with the hash because the sweep no longer holds one to name in
	// its log line: a queuedInstance is not a hash, on purpose.
	return reclaimFreed, freed, errors.Wrapf(s.bdb.Update(func(txn *badger.Txn) error {
		return txn.Delete(garbageInstanceKey(h))
	}), "failed to clear the reclamation entry for object version %s", h)
}

// instanceQueued reports whether an object version is still listed for
// reclamation.
func (s *Store) instanceQueued(h local_cache.InstanceHash) (bool, error) {
	found := false
	err := s.bdb.View(func(txn *badger.Txn) error {
		_, gErr := txn.Get(garbageInstanceKey(h))
		if errors.Is(gErr, badger.ErrKeyNotFound) {
			return nil
		}
		if gErr != nil {
			return gErr
		}
		found = true
		return nil
	})
	if err != nil {
		return false, errors.Wrapf(err, "failed to re-read the reclamation entry for %s", h)
	}
	return found, nil
}

// drainSubtree removes up to subtreeBatchSize entries from a detached
// subtree, queueing each file's object version for reclamation as it goes.
//
// It reports how many entries it removed and whether the subtree is now
// empty; when it is, the queue entry is dropped.  A subtree larger than one
// batch is finished by later passes.
func (s *Store) drainSubtree(root string) (int, bool, error) {
	removed := 0
	done := false

	err := s.bdb.Update(func(txn *badger.Txn) error {
		var batch []string
		var instances []local_cache.InstanceHash

		if wErr := walkSubtree(txn, root, func(entryPath string, d *Dirent) error {
			if len(batch) >= subtreeBatchSize {
				return errStopWalk
			}
			batch = append(batch, entryPath)
			if !d.IsDir() && d.Generation != "" {
				instances = append(instances, instanceHashFor(s.db, d.Generation))
			}
			return nil
		}); wErr != nil && !errors.Is(wErr, errStopWalk) {
			return wErr
		}

		for _, p := range batch {
			if dErr := deleteDirent(txn, p); dErr != nil {
				return dErr
			}
		}
		for _, h := range instances {
			if eErr := enqueueInstance(txn, h); eErr != nil {
				return eErr
			}
		}
		removed = len(batch)

		// Nothing left to walk means the subtree is fully drained, so the
		// work item itself can go.
		if len(batch) < subtreeBatchSize {
			done = true
			return txn.Delete(garbageSubtreeKey(root))
		}
		return nil
	})
	if err != nil {
		return removed, false, err
	}
	return removed, done, nil
}

// errStopWalk halts a subtree walk once a batch is full.  It never escapes
// drainSubtree.
var errStopWalk = errors.New("stop walk")

// collectAllSubtrees returns every queued subtree root, unbounded, for
// rebuilding the detached set at open.
func (s *Store) collectAllSubtrees() ([]string, error) {
	var subtrees []string
	prefix := []byte(local_cache.PrefixGarbage + garbageKindSubtree)

	err := s.bdb.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			subtrees = append(subtrees, string(it.Item().Key()[len(prefix):]))
		}
		return nil
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to read queued subtrees")
	}
	return subtrees, nil
}

// requireDirResolved verifies dir exists and is a directory, honoring
// detached subtrees.
func (s *Store) requireDirResolved(txn *badger.Txn, dir string) error {
	if isRootPath(dir) {
		return nil
	}
	d, err := s.resolve(txn, dir)
	if err != nil {
		return err
	}
	if !d.IsDir() {
		return ErrNotDir
	}
	return nil
}

// deleteSubtreeInline removes an entire subtree within the caller's
// transaction, queueing each object version for reclamation.
//
// It reports false without modifying anything when the subtree is larger than
// one transaction should carry, leaving the caller to detach and defer.  The
// bound is deliberately the same batch size the janitor uses: a removal that
// the janitor would handle in a single pass may as well complete immediately,
// which keeps the paths free for reuse.
func deleteSubtreeInline(txn *badger.Txn, db *local_cache.CacheDB, root string) (bool, error) {
	var (
		paths     []string
		instances []local_cache.InstanceHash
		tooBig    bool
	)

	if err := walkSubtree(txn, root, func(entryPath string, d *Dirent) error {
		if len(paths) >= subtreeBatchSize {
			tooBig = true
			return errStopWalk
		}
		paths = append(paths, entryPath)
		if !d.IsDir() && d.Generation != "" {
			instances = append(instances, instanceHashFor(db, d.Generation))
		}
		return nil
	}); err != nil && !errors.Is(err, errStopWalk) {
		return false, err
	}
	if tooBig {
		return false, nil
	}

	for _, p := range paths {
		if err := deleteDirent(txn, p); err != nil {
			return false, err
		}
	}
	for _, h := range instances {
		if err := enqueueInstance(txn, h); err != nil {
			return false, err
		}
	}
	return true, nil
}

// checkNotDraining refuses to create an entry inside a subtree that has been
// removed but not yet drained.
//
// Those descendants still occupy the keys the new entries would use, and the
// drain will delete whatever it finds there, so allowing the write would lose
// it. Only subtrees too large to remove inline are ever in this state, and the
// janitor accelerates while a backlog exists, so the wait is bounded.
func (s *Store) checkNotDraining(cleanPath string) error {
	if !s.detached.contains(cleanPath) {
		return nil
	}
	return errors.Wrapf(ErrDraining,
		"%s is still being reclaimed after a recursive delete; retry shortly", cleanPath)
}
