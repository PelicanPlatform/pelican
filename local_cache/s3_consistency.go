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
	"time"

	log "github.com/sirupsen/logrus"
)

// s3ScanLoop runs the periodic S3 consistency sweep.  Started only when at
// least one S3 storage target is configured.
func (cc *ConsistencyChecker) s3ScanLoop(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return nil
	case <-cc.stopCh:
		return nil
	case <-time.After(10 * time.Minute):
	}

	const scanInterval = 1 * time.Hour

	for {
		if err := cc.RunS3Scan(ctx); err != nil {
			log.Warnf("S3 consistency scan error: %v", err)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-cc.stopCh:
			return nil
		case <-time.After(scanInterval):
		}
	}
}

// RunS3Scan reconciles each S3 storage target's bucket contents against the
// metadata store:
//
//   - objects in the bucket with no S3-resident metadata (and no in-flight
//     upload intent) are orphans and deleted from the bucket;
//   - S3-resident metadata whose bucket object is missing (or whose size
//     disagrees) is removed so the object is re-fetched from the origin on
//     the next request.
//
// Byte-level usage for S3 storage IDs is reconciled by the regular metadata
// scan (usageDuringScan covers every metadata entry regardless of backend).
func (cc *ConsistencyChecker) RunS3Scan(ctx context.Context) error {
	for sid, target := range cc.storage.s3Targets {
		if err := cc.scanS3Target(ctx, sid, target); err != nil {
			return err
		}
	}
	return nil
}

// s3BucketEntry is one object observed while listing a bucket.
type s3BucketEntry struct {
	hash     InstanceHash
	size     int64
	modified time.Time
}

// s3MaxOrphansPerScan bounds how many orphan candidates (in either
// direction) a single sweep collects before it stops accumulating and
// defers the rest to the next sweep.  This caps the sweep's memory
// regardless of how large or divergent the bucket is.
const s3MaxOrphansPerScan = 4096

// s3SweepOpTimeout bounds each individual S3 HeadObject / DeleteObject the
// sweep issues while reconciling, so one hung request cannot stall the pass.
const s3SweepOpTimeout = 2 * time.Minute

func (cc *ConsistencyChecker) scanS3Target(ctx context.Context, sid StorageID, target *s3Target) error {
	scanStart := time.Now()

	// Snapshot the in-flight upload intents; objects covered by an intent
	// are owned by the uploader and skipped entirely.
	intents, err := cc.db.ListS3UploadIntents()
	if err != nil {
		return err
	}

	// Stream the bucket listing (lexicographic key order == instance-hash
	// order thanks to the shared aa/bb/rest layout).  The producer goroutine
	// is bounded to this function: listCtx is cancelled on every return path
	// (defer), which unblocks the goroutine if it is parked on a channel
	// send, and listDone is buffered so its final send never blocks.  We
	// also join on listDone before returning (see below), so the goroutine
	// can never outlive scanS3Target — no errgroup needed.
	listChan := make(chan s3BucketEntry, 256)
	listDone := make(chan error, 1)
	listCtx, cancelList := context.WithCancel(ctx)
	go func() {
		defer close(listChan)
		listDone <- target.listObjects(listCtx, func(hash InstanceHash, size int64, modified time.Time) error {
			select {
			case listChan <- s3BucketEntry{hash: hash, size: size, modified: modified}:
				return nil
			case <-listCtx.Done():
				return listCtx.Err()
			}
		})
	}()

	// listErr is populated by the deferred join.  Guaranteeing the join on
	// every return path is what makes the goroutine unable to escape.  The
	// merge join below always consumes the listing to completion (it stops
	// appending once the orphan cap is hit, but keeps draining), so under
	// normal operation the producer finishes on its own and listErr carries
	// its real result; cancelList()/the drain only matter on an early error
	// return.
	var listErr error
	joined := false
	joinList := func() {
		if joined {
			return
		}
		joined = true
		cancelList()
		// Drain any buffered entries so the producer is never blocked on a
		// send while we wait for it to finish.
		for range listChan {
		}
		listErr = <-listDone
	}
	defer joinList()

	var orphanBucket []s3BucketEntry // in bucket, not in DB
	var orphanDB []InstanceHash      // in DB, not in bucket (or size mismatch)
	capped := false                  // hit s3MaxOrphansPerScan; more remains

	// considerBucketOrphan applies the grace period and intent check
	// before queuing a bucket object for deletion.
	considerBucketOrphan := func(e s3BucketEntry) {
		if _, uploading := intents[e.hash]; uploading {
			return
		}
		if cc.minAgeForCleanup > 0 && time.Since(e.modified) < cc.minAgeForCleanup {
			return
		}
		if len(orphanBucket) >= s3MaxOrphansPerScan {
			capped = true
			return
		}
		orphanBucket = append(orphanBucket, e)
	}

	// Merge join: DB metadata (restricted to this storage ID) vs listing.
	// The join always runs to completion so the listing producer finishes
	// on its own; once an orphan list reaches the cap it simply stops
	// appending (recording capped) rather than stopping the walk.
	current, listOk := <-listChan
	scanErr := cc.db.ScanMetadata(func(instanceHash InstanceHash, meta *CacheMetadata) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if meta.StorageID != sid {
			return nil
		}

		// Bucket keys sorting before this DB entry have no metadata.
		for listOk && current.hash < instanceHash {
			considerBucketOrphan(current)
			current, listOk = <-listChan
		}

		if listOk && current.hash == instanceHash {
			// Present in both — objects are stored plaintext, so the
			// bucket size must equal ContentLength exactly.
			if !meta.Completed.IsZero() && meta.ContentLength != current.size {
				log.Warnf("S3 object %s size mismatch (bucket %d, metadata %d); removing",
					instanceHash, current.size, meta.ContentLength)
				if len(orphanDB) >= s3MaxOrphansPerScan {
					capped = true
				} else {
					orphanDB = append(orphanDB, instanceHash)
				}
			}
			current, listOk = <-listChan
			return nil
		}

		// DB entry with no bucket object.  Grace period guards against
		// races with a relocation committing mid-listing.
		if _, uploading := intents[instanceHash]; uploading {
			return nil
		}
		if cc.minAgeForCleanup > 0 && !meta.Completed.IsZero() && time.Since(meta.Completed) < cc.minAgeForCleanup {
			return nil
		}
		if len(orphanDB) >= s3MaxOrphansPerScan {
			capped = true
			return nil
		}
		orphanDB = append(orphanDB, instanceHash)
		return nil
	})

	// Any remaining listing entries have no metadata at all.  Drain them all
	// (considerBucketOrphan stops appending once the cap is hit) so the
	// producer goroutine finishes on its own.
	for listOk {
		considerBucketOrphan(current)
		current, listOk = <-listChan
	}
	joinList()

	if scanErr != nil {
		return scanErr
	}
	if listErr != nil {
		// An incomplete listing would make every unseen DB entry look
		// orphaned — mirror the metadata scan's walk-error policy and
		// skip all deletions this pass.
		log.Warnf("S3 listing of %s failed; skipping deletions this pass: %v", target.cfg.DisplayURL(), listErr)
		return nil
	}

	deletedBucket, deletedDB := 0, 0

	// One fresh snapshot of the in-flight uploads for the whole deletion pass:
	// an upload that started since the listing began owns its bucket object,
	// and taking the snapshot here rather than inside the loop keeps this to a
	// single prefix scan instead of one per orphan.
	currentIntents, err := cc.db.ListS3UploadIntents()
	if err != nil {
		log.Warnf("Failed to re-read S3 upload intents; skipping deletions this pass: %v", err)
		return nil
	}

	// Delete bucket orphans, re-verifying against current metadata so a
	// relocation that landed during the scan is not clobbered.  Each S3
	// operation is given a finite timeout so a single hung request cannot
	// stall the sweep.
	for _, e := range orphanBucket {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		meta, err := cc.db.GetMetadata(e.hash)
		if err == nil && meta != nil && meta.StorageID == sid {
			continue // relocated here since the scan; no longer an orphan
		}
		if _, uploading := currentIntents[e.hash]; uploading {
			continue
		}
		opCtx, cancel := context.WithTimeout(ctx, s3SweepOpTimeout)
		err = target.deleteObject(opCtx, e.hash)
		cancel()
		if err != nil {
			log.Warnf("Failed to delete orphaned S3 object %s: %v", e.hash, err)
			continue
		}
		deletedBucket++
	}

	// Delete DB entries whose bucket object is gone, re-probing the bucket
	// first so an eventually-consistent listing doesn't nuke a live entry.
	for _, hash := range orphanDB {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		meta, err := cc.db.GetMetadata(hash)
		if err != nil || meta == nil || meta.StorageID != sid {
			continue
		}
		opCtx, cancel := context.WithTimeout(ctx, s3SweepOpTimeout)
		exists, err := target.objectExists(opCtx, hash)
		if err != nil {
			cancel()
			log.Warnf("Failed to verify S3 object %s before cleanup: %v", hash, err)
			continue
		}
		if exists && meta.ContentLength == 0 {
			cancel()
			continue
		}
		if exists {
			// Present after all — only remove when the size disagrees.
			mismatch := cc.s3SizeMismatch(opCtx, target, hash, meta)
			cancel()
			if !mismatch {
				continue
			}
		} else {
			cancel()
		}
		if err := cc.storage.Delete(hash); err != nil {
			log.Warnf("Failed to delete S3-orphaned DB entry %s: %v", hash, err)
			continue
		}
		deletedDB++
	}

	if deletedBucket > 0 || deletedDB > 0 {
		log.Infof("S3 consistency sweep of %s: removed %d orphaned bucket object(s), %d orphaned DB entr(ies) in %s",
			target.cfg.DisplayURL(), deletedBucket, deletedDB, time.Since(scanStart).Round(time.Millisecond))
	}
	if capped {
		log.Infof("S3 consistency sweep of %s hit the %d-orphan cap; remaining divergence will be handled on the next sweep",
			target.cfg.DisplayURL(), s3MaxOrphansPerScan)
	}

	cc.statsMu.Lock()
	cc.stats.OrphanedFiles += int64(deletedBucket)
	cc.stats.OrphanedDBEntries += int64(deletedDB)
	cc.statsMu.Unlock()
	return nil
}

// s3SizeMismatch re-checks an apparent size mismatch with a HeadObject
// probe (the listing snapshot may be stale).
func (cc *ConsistencyChecker) s3SizeMismatch(ctx context.Context, target *s3Target, hash InstanceHash, meta *CacheMetadata) bool {
	size, exists, err := target.objectSize(ctx, hash)
	if err != nil || !exists {
		return false
	}
	return size != meta.ContentLength
}
