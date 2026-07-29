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
	"sync"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const (
	// s3UploadWorkers is the number of concurrent tiering uploads.
	s3UploadWorkers = 2
	// s3UploadQueueDepth bounds the pending-upload queue.  When full,
	// candidates are dropped; the periodic S3 sweep re-enqueues eligible
	// objects, so a drop only delays tiering.
	s3UploadQueueDepth = 1024
	// s3RelocateRetries bounds retries of the relocation transaction on
	// BadgerDB write conflicts (e.g. racing an LRU update).
	s3RelocateRetries = 5
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
func (u *s3Uploader) rescanLoop(ctx context.Context) {
	const rescanInterval = 1 * time.Hour
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(rescanInterval):
		}
		u.backfillScan(ctx)
		for _, target := range u.storage.s3Targets {
			if aborted, err := target.abortStaleMultipartUploads(ctx, 6*time.Hour); err != nil {
				log.Warnf("Failed to abort stale multipart uploads on %s: %v", target.cfg.DisplayURL(), err)
			} else if aborted > 0 {
				log.Infof("Aborted %d stale multipart upload(s) on %s", aborted, target.cfg.DisplayURL())
			}
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

// eligible checks whether an object should be tiered right now.
func (u *s3Uploader) eligible(meta *CacheMetadata) bool {
	return meta != nil &&
		!meta.Completed.IsZero() &&
		!meta.IsChunked() &&
		meta.StorageID != StorageIDInline &&
		!u.storage.IsS3Backed(meta.StorageID) &&
		meta.ContentLength >= u.threshold
}

// chooseTarget picks the S3 target with the most estimated free space that
// can hold the object.  Returns nil when no target fits.
func (u *s3Uploader) chooseTarget(size int64) *s3Target {
	var best *s3Target
	var bestFree int64
	for id, target := range u.storage.s3Targets {
		free := u.eviction.DirFree(id)
		if free >= size && (best == nil || free > bestFree) {
			best = target
			bestFree = free
		}
	}
	return best
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
		TargetStorageID:   target.id,
		OriginalStorageID: localID,
		Key:               target.objectKey(instanceHash),
		Size:              meta.ContentLength,
		NamespaceID:       meta.NamespaceID,
		StartedAt:         time.Now(),
	}
	if err := u.db.SetS3UploadIntent(instanceHash, intent); err != nil {
		refund()
		return errors.Wrap(err, "failed to record upload intent")
	}

	// abandon cleans up bucket + intent + usage after a failure.
	abandon := func() {
		if delErr := target.deleteObject(ctx, instanceHash); delErr != nil {
			log.Warnf("Failed to clean up S3 object for %s after aborted tiering: %v", instanceHash, delErr)
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

	// Release the local copy.  The relocation left usage charged on the
	// original directory; move it out now that the authoritative copy is
	// in the bucket.
	if err := u.db.AddUsage(prev.StorageID, prev.NamespaceID, -fileSize); err != nil {
		log.Warnf("Failed to release local usage for tiered object %s: %v", instanceHash, err)
	}
	u.eviction.NoteUsageDecrease(prev.StorageID, fileSize)
	u.storage.invalidateObjectCaches(instanceHash, 1)
	u.storage.deleteChunkFiles(instanceHash, prev.ContentLength, prev.StorageID, ChunkingDisabled, nil)

	if err := u.db.DeleteS3UploadIntent(instanceHash); err != nil {
		log.Warnf("Failed to delete upload intent for %s: %v", instanceHash, err)
	}
	log.Debugf("Tiered object %s (%d bytes) to S3 target %d", instanceHash, meta.ContentLength, target.id)
	return nil
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
		case meta == nil:
			// Object was deleted while the upload was in flight — remove
			// any bucket copy and refund nothing (deletion already
			// adjusted usage for the metadata's storage).
			if err := target.deleteObject(ctx, hash); err != nil {
				log.Warnf("Failed to delete orphaned S3 object %s during recovery: %v", hash, err)
				continue // keep the intent so a later pass retries
			}
			if err := u.db.AddUsage(intent.TargetStorageID, intent.NamespaceID, -CalculateFileSize(intent.Size)); err != nil {
				log.Warnf("Failed to refund S3 usage for %s during recovery: %v", hash, err)
			}
		case meta.StorageID == intent.TargetStorageID:
			// Relocation committed but local cleanup didn't finish —
			// delete the leftover local file.
			u.storage.deleteChunkFiles(hash, intent.Size, intent.OriginalStorageID, ChunkingDisabled, nil)
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

// backfillScan walks existing metadata once at startup and enqueues any
// completed local objects that meet the tiering threshold (e.g. objects
// cached before an S3 target was configured).
func (u *s3Uploader) backfillScan(ctx context.Context) {
	count := 0
	err := u.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if u.eligible(meta) {
			u.MaybeEnqueue(instanceHash)
			count++
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		log.Warnf("S3 tiering backfill scan failed: %v", err)
	}
	if count > 0 {
		log.Infof("S3 tiering backfill: queued %d candidate object(s)", count)
	}
}
