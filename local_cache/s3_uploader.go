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

package local_cache

import (
	"context"
	rand "math/rand/v2"
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	// s3UploadWorkers is the number of concurrent tiering uploads.
	s3UploadWorkers = 4
	// s3UploadQueueDepth bounds the pending-upload queue.  When full,
	// candidates are dropped; the periodic S3 sweep re-enqueues eligible
	// objects, so a drop only delays tiering.
	s3UploadQueueDepth = 1024
	// s3RelocateRetries bounds retries of the relocation transaction on
	// BadgerDB write conflicts (e.g. racing an LRU update).
	s3RelocateRetries = 5
	// s3RescanBaseInterval is the steady-state gap between backfill rescans.
	s3RescanBaseInterval = 1 * time.Hour
	// s3RescanMinInterval is the floor the adaptive rescan sleep halves
	// toward while there is still deferred work to enqueue.
	s3RescanMinInterval = 1 * time.Minute
	// s3CleanupTimeout bounds the bucket delete issued when an upload is
	// abandoned.  It runs on a context detached from the request/shutdown
	// context, so it needs its own deadline.
	s3CleanupTimeout = 2 * time.Minute
)

// s3Uploader tiers completed objects from local storage directories to S3
// storage targets.  Objects become candidates when they complete (via the
// StorageManager's onObjectComplete hook), at startup (backfill scan), and
// during the periodic S3 consistency sweep.
type s3Uploader struct {
	db        *CacheDB
	storage   *StorageManager
	eviction  *EvictionManager
	threshold int64

	queue chan InstanceHash
	ctx   context.Context

	// inflight guards against two workers tiering the same object at once
	// (completion notifications can fire more than once per object).
	inflightMu sync.Mutex
	inflight   map[InstanceHash]bool
}

// newS3Uploader creates the uploader.  threshold is the minimum object
// ContentLength for tiering.
func newS3Uploader(db *CacheDB, storage *StorageManager, eviction *EvictionManager, threshold int64) *s3Uploader {
	return &s3Uploader{
		db:        db,
		storage:   storage,
		eviction:  eviction,
		threshold: threshold,
		queue:     make(chan InstanceHash, s3UploadQueueDepth),
		inflight:  make(map[InstanceHash]bool),
	}
}

// Start runs crash recovery synchronously, then launches the upload
// workers and a background backfill scan.
func (u *s3Uploader) Start(ctx context.Context, egrp *errgroup.Group) error {
	u.ctx = ctx
	if err := u.recover(ctx); err != nil {
		return err
	}
	for i := 0; i < s3UploadWorkers; i++ {
		egrp.Go(func() error {
			u.workerLoop(ctx)
			return nil
		})
	}
	egrp.Go(func() error {
		u.backfillScan(ctx)
		return nil
	})
	egrp.Go(func() error {
		u.rescanLoop(ctx)
		return nil
	})
	return nil
}

// rescanLoop periodically re-enqueues eligible objects that were deferred
// (queue full, no room on any target) and aborts multipart uploads that
// outlived any plausible in-flight transfer.
//
// The sleep is adaptive: when a backfill pass leaves work behind (the queue
// filled before every eligible object was enqueued), the next pass runs
// sooner — the interval halves toward s3RescanMinInterval — so a large
// backlog drains in minutes rather than hours.  Once a pass enqueues
// everything eligible, the interval resets to the steady-state base.
func (u *s3Uploader) rescanLoop(ctx context.Context) {
	sleep := s3RescanBaseInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}

		_, deferred := u.backfillScan(ctx)

		// Finish local cleanup for objects that were still under a reader when
		// their relocation committed.
		u.finishDeferredReleases(ctx)

		// Only reconcile stale multipart uploads on full-interval passes so
		// catch-up cycles don't hammer the bucket's ListMultipartUploads.
		if sleep >= s3RescanBaseInterval {
			for _, target := range u.storage.s3Targets {
				if aborted, err := target.abortStaleMultipartUploads(ctx, 6*time.Hour); err != nil {
					log.Warnf("Failed to abort stale multipart uploads on %s: %v", target.cfg.DisplayURL(), err)
				} else if aborted > 0 {
					log.Infof("Aborted %d stale multipart upload(s) on %s", aborted, target.cfg.DisplayURL())
				}
			}
		}

		if deferred {
			sleep /= 2
			if sleep < s3RescanMinInterval {
				sleep = s3RescanMinInterval
			}
		} else {
			sleep = s3RescanBaseInterval
		}
	}
}

// MaybeEnqueue submits an object for tiering consideration.  Non-blocking;
// eligibility is checked by the worker.  Safe to call from completion
// callbacks.
func (u *s3Uploader) MaybeEnqueue(instanceHash InstanceHash) {
	select {
	case u.queue <- instanceHash:
	default:
		// Queue full — the periodic sweep will pick the object up later.
	}
}

func (u *s3Uploader) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case hash := <-u.queue:
			if err := u.processObject(ctx, hash); err != nil {
				log.Warnf("Failed to tier object %s to S3: %v", hash, err)
			}
		}
	}
}

// eligible checks whether an object should be tiered right now.  Chunked
// objects are eligible: large objects (the prime tiering candidates) are
// exactly the ones chunking splits across directories, and relocation
// flattens them into a single bucket blob.
func (u *s3Uploader) eligible(meta *CacheMetadata) bool {
	return meta != nil &&
		!meta.Completed.IsZero() &&
		meta.StorageID != StorageIDInline &&
		!u.storage.IsS3Backed(meta.StorageID) &&
		meta.ContentLength >= u.threshold
}

// chooseTarget randomly selects an S3 target that can currently hold the
// object, weighted by each target's estimated free space, so concurrent
// uploads spread across targets instead of all piling onto the single
// emptiest one.  Returns nil when no target fits.
//
// Concurrency: s3Targets is read-only after initialization and DirFree reads
// lock-free atomic counters, so this is safe to call from every worker
// without a lock.  The free-space figures are estimates that may be briefly
// stale relative to concurrent charges, but the authoritative capacity guard
// is the up-front usage charge in processObject (plus watermark eviction), so
// a stale estimate can at worst cause a transient overshoot that eviction
// corrects — never a lost or corrupted object.
func (u *s3Uploader) chooseTarget(size int64) *s3Target {
	type candidate struct {
		target *s3Target
		free   int64
	}
	var candidates []candidate
	var totalFree int64
	for id, target := range u.storage.s3Targets {
		if free := u.eviction.DirFree(id); free >= size {
			candidates = append(candidates, candidate{target: target, free: free})
			totalFree += free
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 || totalFree <= 0 {
		return candidates[0].target
	}
	// Weighted pick: land in the slice proportional to each target's free.
	r := rand.Int64N(totalFree)
	for _, c := range candidates {
		if r < c.free {
			return c.target
		}
		r -= c.free
	}
	return candidates[len(candidates)-1].target
}

// processObject performs one tiering operation:
//
//  1. re-check eligibility from current metadata
//  2. charge usage on the S3 target up front (the cache's usual model),
//     triggering eviction if the bucket crosses its high-water mark
//  3. record the upload intent in BadgerDB (crash safety: any bytes that
//     may exist in the bucket are always covered by an intent or by
//     relocated metadata)
//  4. stream the decrypted object to the bucket
//  5. relocate metadata (StorageID + LRU index) to the S3 target
//  6. release the local copy: usage refund, file deletion, cache invalidation
//  7. drop the intent
func (u *s3Uploader) processObject(ctx context.Context, instanceHash InstanceHash) error {
	u.inflightMu.Lock()
	if u.inflight[instanceHash] {
		u.inflightMu.Unlock()
		return nil // another worker is already tiering this object
	}
	u.inflight[instanceHash] = true
	u.inflightMu.Unlock()
	defer func() {
		u.inflightMu.Lock()
		delete(u.inflight, instanceHash)
		u.inflightMu.Unlock()
	}()

	meta, err := u.storage.GetMetadata(instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to load metadata")
	}
	if !u.eligible(meta) {
		return nil
	}
	localID := meta.StorageID
	fileSize := CalculateFileSize(meta.ContentLength)

	target := u.chooseTarget(fileSize)
	if target == nil {
		// No target currently fits; nudge eviction so space opens up and
		// let the periodic sweep retry.
		u.eviction.TriggerEviction()
		log.Debugf("No S3 target has room for %s (%d bytes); deferring", instanceHash, fileSize)
		return nil
	}

	// Charge the S3 target up front so concurrent uploads cannot
	// collectively overrun the bucket; refunded on failure.
	if err := u.db.AddUsage(target.id, meta.NamespaceID, fileSize); err != nil {
		return errors.Wrap(err, "failed to charge S3 usage")
	}
	u.eviction.NoteUsageIncrease(target.id, fileSize)
	refund := func() {
		if err := u.db.AddUsage(target.id, meta.NamespaceID, -fileSize); err != nil {
			log.Warnf("Failed to refund S3 usage for %s: %v", instanceHash, err)
		}
		u.eviction.NoteUsageDecrease(target.id, fileSize)
	}

	intent := &S3UploadIntent{
		TargetStorageID:        target.id,
		OriginalStorageID:      localID,
		OriginalChunkSizeCode:  meta.ChunkSizeCode,
		OriginalChunkLocations: meta.ChunkLocations,
		Key:                    target.objectKey(instanceHash),
		Size:                   meta.ContentLength,
		NamespaceID:            meta.NamespaceID,
		StartedAt:              time.Now(),
	}
	if err := u.db.SetS3UploadIntent(instanceHash, intent); err != nil {
		refund()
		return errors.Wrap(err, "failed to record upload intent")
	}

	// abandon cleans up bucket + intent + usage after a failure.
	//
	// The delete runs on a context detached from ctx: the common reason to
	// abandon an upload is that ctx was cancelled by shutdown, and reusing it
	// would fail the delete and strand bytes in the bucket.  If the delete
	// fails anyway the intent is kept, not dropped -- an intent is the only
	// record that those bytes exist, so removing it while they remain would
	// break the invariant that every object in the bucket is covered by an
	// intent or by relocated metadata.  Recovery retries it.
	abandon := func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s3CleanupTimeout)
		defer cancel()
		if delErr := target.deleteObject(cleanupCtx, instanceHash); delErr != nil {
			log.Warnf("Failed to clean up S3 object for %s after aborted tiering (keeping the intent so recovery retries): %v",
				instanceHash, delErr)
			return
		}
		refund()
		if delErr := u.db.DeleteS3UploadIntent(instanceHash); delErr != nil {
			log.Warnf("Failed to delete upload intent for %s: %v", instanceHash, delErr)
		}
	}

	reader, err := u.storage.NewObjectReader(instanceHash)
	if err != nil {
		abandon()
		return errors.Wrap(err, "failed to open object for upload")
	}
	uploadErr := target.uploadObject(ctx, instanceHash, meta.ContentType, meta.ContentLength, reader)
	reader.Close()
	if uploadErr != nil {
		abandon()
		return uploadErr
	}

	// Relocate metadata; retry on OCC conflicts with concurrent metadata
	// writers (LRU updates, checksum merges).
	var prev *CacheMetadata
	for attempt := 0; ; attempt++ {
		prev, err = u.db.RelocateObject(instanceHash, target.id)
		if err == nil {
			break
		}
		if errors.Is(err, badger.ErrConflict) && attempt < s3RelocateRetries {
			time.Sleep(time.Duration(attempt+1) * 5 * time.Millisecond)
			continue
		}
		// If a concurrent tiering pass already relocated the object here,
		// the bucket copy is live — refund only this pass's charge and
		// leave the object alone.
		if cur, curErr := u.storage.GetMetadata(instanceHash); curErr == nil && cur != nil && cur.StorageID == target.id {
			refund()
			if delErr := u.db.DeleteS3UploadIntent(instanceHash); delErr != nil {
				log.Warnf("Failed to delete upload intent for %s: %v", instanceHash, delErr)
			}
			return nil
		}
		// Relocation failed (e.g. object evicted mid-upload) — remove the
		// bucket copy so nothing is leaked.
		abandon()
		return errors.Wrap(err, "failed to relocate object metadata to S3 target")
	}

	// Record that the bucket copy is now authoritative before touching the
	// local one.  If the process dies anywhere below, recovery needs to know
	// that the bucket bytes belong to the object rather than to this intent.
	intent.RelocatedAt = time.Now()
	if err := u.db.SetS3UploadIntent(instanceHash, intent); err != nil {
		// Not fatal: recovery also treats "metadata already points at the
		// target" as proof the relocation committed.  Only the object-deleted
		// case needs the marker, so log and continue.
		log.Warnf("Failed to mark upload intent for %s as relocated: %v", instanceHash, err)
	}

	// Release the local copy, unless a reader is still working from it.
	if !u.releaseLocalCopy(instanceHash, prev) {
		// A reader holds this version.  Its RangeReader captured the
		// pre-relocation metadata, so it is still reading the local chunk
		// files; deleting them now would break the transfer.  Leave the
		// intent in place -- finishDeferredReleases retries once the reader
		// is gone, and crash recovery finishes the job after a restart.
		log.Debugf("Deferring local cleanup of tiered object %s: a reader still holds it", instanceHash)
		return nil
	}

	if err := u.db.DeleteS3UploadIntent(instanceHash); err != nil {
		log.Warnf("Failed to delete upload intent for %s: %v", instanceHash, err)
	}
	log.Debugf("Tiered object %s (%d bytes) to S3 target %d", instanceHash, meta.ContentLength, target.id)
	return nil
}

// releaseLocalCopy removes a tiered object's local files and returns their
// capacity to the directories that held them.  prev must be the object's
// pre-relocation metadata, which still carries the chunk layout, so that a
// chunked object's bytes are refunded to every directory that held a chunk.
//
// Returns false without touching anything when a reader is pinned on the
// version, leaving the caller to retry later.
func (u *s3Uploader) releaseLocalCopy(instanceHash InstanceHash, prev *CacheMetadata) bool {
	if u.storage.IsObjectPinned(instanceHash) {
		return false
	}
	// A reader could still arrive between the check and the deletes.  It would
	// have to read the relocated metadata to do so, which points at the
	// bucket, so it never reaches the local files -- unlike the reader this
	// check protects, which captured the layout before relocation.
	for sid, bytes := range prev.PerDirectoryBytes() {
		if err := u.db.AddUsage(sid, prev.NamespaceID, -bytes); err != nil {
			log.Warnf("Failed to release local usage for tiered object %s on storage %d: %v", instanceHash, sid, err)
		}
		u.eviction.NoteUsageDecrease(sid, bytes)
	}
	u.storage.invalidateObjectCaches(instanceHash, prev.ChunkCount())
	u.storage.deleteChunkFiles(instanceHash, prev.ContentLength, prev.StorageID, prev.ChunkSizeCode, prev.ChunkLocations)
	return true
}

// localCopyFromIntent reconstructs the pre-relocation metadata an intent
// recorded, for use with releaseLocalCopy.
func localCopyFromIntent(intent *S3UploadIntent) *CacheMetadata {
	return &CacheMetadata{
		StorageID:      intent.OriginalStorageID,
		ContentLength:  intent.Size,
		ChunkSizeCode:  intent.OriginalChunkSizeCode,
		ChunkLocations: intent.OriginalChunkLocations,
		NamespaceID:    intent.NamespaceID,
	}
}

// finishDeferredReleases completes the local cleanup for objects whose
// relocation committed but whose local copy was still under a reader at the
// time.  Only that state is retried here: it is unambiguous (an in-flight
// upload has not relocated yet, so its metadata still names local storage),
// which makes the pass safe to run at any point, unlike the broader
// reconciliation in recover().
func (u *s3Uploader) finishDeferredReleases(ctx context.Context) {
	intents, err := u.db.ListS3UploadIntents()
	if err != nil {
		log.Warnf("Failed to list S3 upload intents for deferred cleanup: %v", err)
		return
	}
	for hash, intent := range intents {
		if ctx.Err() != nil {
			return
		}
		meta, err := u.storage.GetMetadata(hash)
		if err != nil || meta == nil || meta.StorageID != intent.TargetStorageID {
			continue
		}
		if !u.releaseLocalCopy(hash, localCopyFromIntent(intent)) {
			continue // still pinned; try again next pass
		}
		if err := u.db.DeleteS3UploadIntent(hash); err != nil {
			log.Warnf("Failed to delete upload intent for %s: %v", hash, err)
			continue
		}
		log.Debugf("Completed deferred local cleanup of tiered object %s", hash)
	}
}

// recover reconciles upload intents left behind by a crash.  Invariant:
// any object bytes in a bucket are referenced either by relocated metadata
// or by an intent — so walking the intents finds every possible leak.
func (u *s3Uploader) recover(ctx context.Context) error {
	intents, err := u.db.ListS3UploadIntents()
	if err != nil {
		return errors.Wrap(err, "failed to list S3 upload intents")
	}
	for hash, intent := range intents {
		target := u.storage.getS3Target(intent.TargetStorageID)
		if target == nil {
			// Target no longer configured; drop the intent — the object
			// (if any) will be found if the bucket is ever re-attached.
			log.Warnf("Upload intent for %s references unknown S3 target %d; dropping", hash, intent.TargetStorageID)
			if err := u.db.DeleteS3UploadIntent(hash); err != nil {
				log.Warnf("Failed to delete stale upload intent for %s: %v", hash, err)
			}
			continue
		}

		meta, err := u.storage.GetMetadata(hash)
		if err != nil {
			return errors.Wrapf(err, "failed to load metadata for pending upload %s", hash)
		}
		switch {
		case meta == nil && !intent.RelocatedAt.IsZero():
			// The object was deleted after its relocation committed, so the
			// bucket bytes and their charge belonged to the object: whatever
			// deleted it already removed the bucket copy and refunded the
			// target.  Refunding again here would drive the counter negative.
			// What can remain is a local copy whose release was deferred
			// (reader pinned) and whose charge the deletion did not see,
			// because by then the metadata named only the bucket.
			u.releaseLocalCopy(hash, localCopyFromIntent(intent))
			// Belt and braces: the bucket object should already be gone.
			if err := target.deleteObject(ctx, hash); err != nil {
				log.Warnf("Failed to confirm removal of S3 object %s during recovery: %v", hash, err)
			}
		case meta == nil:
			// The object was deleted while the upload was still in flight, so
			// the bucket bytes are this intent's to reclaim, as is the charge
			// taken for them.  The deletion refunded only the local storage.
			if err := target.deleteObject(ctx, hash); err != nil {
				log.Warnf("Failed to delete orphaned S3 object %s during recovery: %v", hash, err)
				continue // keep the intent so a later pass retries
			}
			if err := u.db.AddUsage(intent.TargetStorageID, intent.NamespaceID, -CalculateFileSize(intent.Size)); err != nil {
				log.Warnf("Failed to refund S3 usage for %s during recovery: %v", hash, err)
			}
			u.eviction.NoteUsageDecrease(intent.TargetStorageID, CalculateFileSize(intent.Size))
		case meta.StorageID == intent.TargetStorageID:
			// Relocation committed but local cleanup didn't finish — remove
			// the leftover local file(s) and refund the capacity they still
			// hold.  The intent carries the original chunk layout, so every
			// chunk file is removed and every directory that held one is
			// credited, not just chunk 0's.
			if !u.releaseLocalCopy(hash, localCopyFromIntent(intent)) {
				continue // pinned; finishDeferredReleases will retry
			}
		default:
			// Upload did not commit.  Remove any partial/complete bucket
			// copy, refund the up-front charge, and re-queue the object.
			if err := target.deleteObject(ctx, hash); err != nil {
				log.Warnf("Failed to delete uncommitted S3 object %s during recovery: %v", hash, err)
				continue // keep the intent so a later pass retries
			}
			if err := u.db.AddUsage(intent.TargetStorageID, intent.NamespaceID, -CalculateFileSize(intent.Size)); err != nil {
				log.Warnf("Failed to refund S3 usage for %s during recovery: %v", hash, err)
			}
			u.eviction.NoteUsageDecrease(intent.TargetStorageID, CalculateFileSize(intent.Size))
			u.MaybeEnqueue(hash)
		}
		if err := u.db.DeleteS3UploadIntent(hash); err != nil {
			log.Warnf("Failed to delete upload intent for %s during recovery: %v", hash, err)
		}
	}

	// Abort any multipart uploads left over from a previous process.  The
	// identity object marks the bucket as owned by this cache, so nothing
	// else can have live multipart uploads under our prefix.
	for _, target := range u.storage.s3Targets {
		if aborted, err := target.abortStaleMultipartUploads(ctx, 0); err != nil {
			log.Warnf("Failed to abort stale multipart uploads on %s: %v", target.cfg.DisplayURL(), err)
		} else if aborted > 0 {
			log.Infof("Aborted %d stale multipart upload(s) on %s", aborted, target.cfg.DisplayURL())
		}
	}
	return nil
}

// backfillScan walks existing metadata once and enqueues completed local
// objects that meet the tiering threshold (e.g. objects cached before an S3
// target was configured, or deferred when the queue was previously full).
//
// It returns the number of objects queued and whether any eligible object
// could not be enqueued because the queue was full (deferred == true),
// signalling to the caller that more work remains.
func (u *s3Uploader) backfillScan(ctx context.Context) (queued int, deferred bool) {
	err := u.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !u.eligible(meta) {
			return nil
		}
		select {
		case u.queue <- instanceHash:
			queued++
		default:
			deferred = true // queue full; a later rescan will pick it up
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		log.Warnf("S3 tiering backfill scan failed: %v", err)
	}
	if queued > 0 {
		log.Infof("S3 tiering backfill: queued %d candidate object(s)", queued)
	}
	return queued, deferred
}
