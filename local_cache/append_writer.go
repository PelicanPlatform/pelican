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

// Streaming append support.
//
// The cache always knows an object's size before it stores it: a download
// starts from a Content-Length or a HEAD.  An origin does not — a WebDAV PUT
// may arrive with chunked transfer encoding and no length at all — so the
// pstore backend needs to write an object whose size is discovered only at
// the end.
//
// AppendWriter provides that.  It keeps the object's metadata carrying a
// provisional ContentLength that is always a whole number of chunks and always
// strictly greater than the bytes written so far, so every allocated chunk is
// exactly full-size and the existing chunk bookkeeping applies unchanged.
// Finalize then records the true length, truncates the tail chunk to fit, and
// refunds the difference to the usage counters.
//
// The "strictly greater" part is load-bearing.  WriteBlocks marks an object
// Completed as soon as every block of its recorded ContentLength is present,
// which is right for a download of known length and wrong for a stream: an
// interrupted append whose length happened to land on a chunk boundary would
// otherwise be left in the database claiming to be a whole object at a length
// the writer invented.  Keeping the provisional length one byte-range ahead of
// the stream means only Finalize can ever set Completed.
//
// Writes must be sequential from offset 0.  Pelican has no mid-file edit
// semantics, and neither does this writer.

package local_cache

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// appendReclaimGrace is how long an append-in-flight record must have been
// around before a reclamation pass will consider it abandoned, on top of the
// requirement that no live writer in this process owns it.  The live-writer
// registry is the real guard; the age is belt and braces for a consumer that
// somehow creates records outside NewAppendWriter.
const appendReclaimGrace = 10 * time.Minute

// AppendWriter streams an object of unknown length into chunked storage.
//
// It is not safe for concurrent use; a single writer owns one object version
// for the duration of the write.
type AppendWriter struct {
	sm           *StorageManager
	ctx          context.Context
	instanceHash InstanceHash
	namespaceID  NamespaceID
	chunkSize    int64
	sizeCode     ChunkSizeCode

	// written is the number of content bytes accepted from the caller.
	written int64
	// flushed is the number of content bytes already handed to WriteBlocks.
	// It is always a multiple of BlockDataSize.
	flushed int64
	// pending holds bytes not yet block-aligned enough to write.
	pending []byte

	// provisional is the ContentLength currently recorded in metadata, always
	// a whole number of chunks and always >= written.
	provisional int64

	closed bool
}

// NewAppendWriter initializes chunked storage for an object whose length is
// not yet known and returns a writer positioned at offset 0.
//
// chunkSizeCode selects the chunk size; ChunkingDisabled is rejected because
// growth is expressed in whole chunks.
func (sm *StorageManager) NewAppendWriter(
	ctx context.Context,
	instanceHash InstanceHash,
	namespaceID NamespaceID,
	chunkSizeCode ChunkSizeCode,
) (*AppendWriter, error) {
	if chunkSizeCode == ChunkingDisabled {
		return nil, errors.New("NewAppendWriter requires chunking enabled")
	}
	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	if chunkSize <= 0 {
		return nil, errors.Errorf("invalid chunk size code %d", chunkSizeCode)
	}

	// Register before anything is persisted so that a reclamation pass which
	// observes the intent record always also observes the live writer.
	sm.liveAppends.Store(instanceHash, struct{}{})
	rollback := func() { sm.liveAppends.Delete(instanceHash) }

	// Start with a single chunk's worth of provisional length; growTo extends
	// it as the stream advances.
	meta, err := sm.InitLazyChunkedStorage(ctx, instanceHash, chunkSize, chunkSizeCode)
	if err != nil {
		rollback()
		return nil, errors.Wrap(err, "failed to initialize chunked storage")
	}
	meta.NamespaceID = namespaceID
	if err := sm.db.SetMetadata(instanceHash, meta); err != nil {
		rollback()
		return nil, errors.Wrap(err, "failed to record namespace on new object")
	}

	// The intent record is what makes an interrupted append reclaimable: the
	// object has metadata and (soon) files but no LRU entry, so without it
	// neither eviction nor the consistency checker would ever look at it.
	if err := sm.db.SetAppendIntent(instanceHash, AppendIntent{
		StartedAt:   time.Now(),
		NamespaceID: namespaceID,
	}); err != nil {
		rollback()
		// Leave nothing half-built: the object is unreachable without the
		// writer we are declining to return.
		if delErr := sm.Delete(instanceHash); delErr != nil {
			log.Warnf("Failed to clean up %s after append-intent failure: %v", instanceHash, delErr)
		}
		return nil, errors.Wrap(err, "failed to record the append-in-flight marker")
	}

	return &AppendWriter{
		sm:           sm,
		ctx:          ctx,
		instanceHash: instanceHash,
		namespaceID:  namespaceID,
		chunkSize:    chunkSize,
		sizeCode:     chunkSizeCode,
		provisional:  chunkSize,
		pending:      make([]byte, 0, BlockDataSize*writeBatchBlocks),
	}, nil
}

// Written returns the number of content bytes accepted so far.
func (w *AppendWriter) Written() int64 { return w.written }

// Write appends data to the object.  It always consumes the whole slice.
//
// A flush failure is reported with the full byte count, not zero: by then the
// data is already in w.pending and already counted in w.written, so claiming
// nothing was accepted would invite an io.Copy-style caller to resend bytes
// this writer has already accounted for.  The writer is unusable after such an
// error; the caller should Abort.
func (w *AppendWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("write to a finalized AppendWriter")
	}
	if len(p) == 0 {
		return 0, nil
	}

	w.pending = append(w.pending, p...)
	w.written += int64(len(p))

	// Write out whole blocks, holding back any partial tail: WriteBlocks
	// requires block-aligned offsets and pstore never rewrites a block.
	full := (len(w.pending) / BlockDataSize) * BlockDataSize
	if full > 0 {
		if err := w.flush(w.pending[:full]); err != nil {
			return len(p), err
		}
		w.pending = append(w.pending[:0], w.pending[full:]...)
	}
	return len(p), nil
}

// flush writes a block-aligned run of bytes at the current offset, growing the
// provisional length first so that every chunk the write touches is allocated
// at full size.
func (w *AppendWriter) flush(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if err := w.growTo(w.flushed + int64(len(data))); err != nil {
		return err
	}
	if err := w.sm.WriteBlocks(w.instanceHash, w.flushed, data); err != nil {
		return errors.Wrapf(err, "failed to write %d bytes at offset %d", len(data), w.flushed)
	}
	w.flushed += int64(len(data))
	return nil
}

// growTo raises the provisional ContentLength so that it covers endOffset with
// at least one byte to spare, rounded up to a whole number of chunks, and
// extends ChunkLocations to match.
//
// Keeping the provisional length chunk-aligned means ChunkContentLength
// reports a full chunk for every allocated chunk, so AllocateChunk sizes each
// file correctly without knowing the object's real length.
//
// Keeping it strictly greater than endOffset is what stops writeBlocks from
// declaring the object finished.  Rounding endOffset *up* to a chunk boundary
// would make provisional == flushed exactly when the stream length is a
// multiple of the chunk size, at which point checkAndMarkComplete sees every
// block of the recorded ContentLength present and merges a Completed stamp
// onto a half-written object.  Only Finalize knows the real length, so only
// Finalize may mark completion.
//
// The extra chunk costs nothing on disk: growTo only lengthens the chunk
// table, and chunk files are created lazily by AllocateChunk when a write
// actually lands in them.
func (w *AppendWriter) growTo(endOffset int64) error {
	if endOffset < w.provisional {
		return nil
	}
	chunksNeeded := endOffset/w.chunkSize + 1
	newLength := chunksNeeded * w.chunkSize

	meta, err := w.sm.db.GetMetadata(w.instanceHash)
	if err != nil {
		return errors.Wrap(err, "failed to read metadata while growing object")
	}
	if meta == nil {
		return errors.Errorf("object %s disappeared while being written", w.instanceHash)
	}

	meta.ContentLength = newLength
	// ChunkLocations covers chunks 1..n-1; chunk 0 uses the base StorageID.
	if want := int(chunksNeeded) - 1; want > len(meta.ChunkLocations) {
		grown := make([]ChunkLocation, want)
		copy(grown, meta.ChunkLocations)
		meta.ChunkLocations = grown
	}

	if err := w.sm.db.SetMetadata(w.instanceHash, meta); err != nil {
		return errors.Wrap(err, "failed to grow object metadata")
	}
	// The cached copy carries the old length and chunk table.
	w.sm.diskCrypto.Delete(w.instanceHash)
	w.provisional = newLength
	return nil
}

// Finalize flushes any buffered tail, records the object's true length, trims
// the over-allocated tail chunk, and returns the completed metadata.
//
// After Finalize the writer is closed and further writes are rejected.
func (w *AppendWriter) Finalize() (*CacheMetadata, error) {
	if w.closed {
		return nil, errors.New("AppendWriter already finalized")
	}

	// The final partial block is written as-is; a short trailing block is
	// exactly how a non-chunk-aligned object ends.
	if len(w.pending) > 0 {
		if err := w.flush(w.pending); err != nil {
			return nil, err
		}
		w.pending = nil
	}
	w.closed = true

	actual := w.written
	meta, err := w.sm.db.GetMetadata(w.instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read metadata at finalize")
	}
	if meta == nil {
		return nil, errors.Errorf("object %s disappeared while being written", w.instanceHash)
	}

	if actual == 0 {
		return w.finalizeEmpty(meta)
	}

	// Chunks beyond the real length were never written to and must be dropped
	// so that reads and eviction see a consistent chunk table.
	realChunks := CalculateChunkCount(actual, w.sizeCode)
	if realChunks < 1 {
		realChunks = 1
	}
	if want := realChunks - 1; want < len(meta.ChunkLocations) {
		for i := want; i < len(meta.ChunkLocations); i++ {
			w.releaseUnusedChunk(meta, i+1)
		}
		meta.ChunkLocations = meta.ChunkLocations[:want]
	}

	// Shrink the tail chunk from a full chunk to the bytes it actually holds,
	// refunding the difference that AllocateChunk charged up front.
	if err := w.truncateTail(meta, actual, realChunks); err != nil {
		return nil, err
	}

	meta.ContentLength = actual
	meta.Completed = time.Now()
	if err := w.sm.db.SetMetadata(w.instanceHash, meta); err != nil {
		return nil, errors.Wrap(err, "failed to record final object metadata")
	}
	w.sm.diskCrypto.Delete(w.instanceHash)
	w.sm.invalidateObjectCaches(w.instanceHash, realChunks)
	w.clearIntent()

	return meta, nil
}

// finalizeEmpty completes an object that turned out to hold no bytes.
//
// Nothing was ever flushed, so no chunk was allocated and meta.StorageID is
// still StorageIDInline -- but ChunkSizeCode is set, so IsInline() is false and
// every reader takes the disk path and fails to open a file that was never
// created.  A zero-length PUT followed by a GET is an ordinary operation, so
// the object is instead stored the way the cache already stores a zero-byte
// download: inline, with no chunking.  That keeps IsInline() and IsDisk()
// exactly complementary rather than inventing a third state.
func (w *AppendWriter) finalizeEmpty(meta *CacheMetadata) (*CacheMetadata, error) {
	// Defensive: a chunk should not exist, but refund it if one does rather
	// than orphan the file.
	for i := len(meta.ChunkLocations); i >= 1; i-- {
		w.releaseUnusedChunk(meta, i)
	}
	meta.ChunkLocations = nil
	meta.ChunkSizeCode = ChunkingDisabled
	meta.StorageID = StorageIDInline

	if err := w.sm.StoreInline(w.ctx, w.instanceHash, meta, nil); err != nil {
		return nil, errors.Wrap(err, "failed to store the empty object")
	}
	w.sm.diskCrypto.Delete(w.instanceHash)
	w.sm.invalidateObjectCaches(w.instanceHash, 1)
	w.clearIntent()

	return meta, nil
}

// clearIntent drops the append-in-flight record and the live-writer
// registration.  The object is now either finished or gone, so there is
// nothing left for a reclamation pass to do.
func (w *AppendWriter) clearIntent() {
	w.sm.liveAppends.Delete(w.instanceHash)
	if err := w.sm.db.DeleteAppendIntent(w.instanceHash); err != nil {
		log.Warnf("Failed to clear the append-in-flight marker for %s: %v", w.instanceHash, err)
	}
}

// truncateTail shrinks the last chunk file to the bytes the object actually
// occupies and refunds the over-charge.
func (w *AppendWriter) truncateTail(meta *CacheMetadata, actual int64, realChunks int) error {
	tailIdx := realChunks - 1
	if !meta.IsChunkAllocated(tailIdx) {
		return nil
	}
	storageID := meta.GetChunkStorageID(tailIdx)

	tailContent := actual - int64(tailIdx)*w.chunkSize
	if tailContent < 0 {
		tailContent = 0
	}
	wantSize := CalculateFileSize(tailContent)
	haveSize := CalculateFileSize(w.chunkSize)
	if wantSize >= haveSize {
		return nil
	}

	path := w.sm.getChunkPath(storageID, w.instanceHash, tailIdx)
	// Drop cached descriptors first so the truncation is not racing a reader
	// holding a stale size.
	w.sm.invalidateObjectCaches(w.instanceHash, realChunks)
	if err := os.Truncate(path, wantSize); err != nil {
		if os.IsNotExist(err) {
			// Nothing was ever written to the tail chunk.
			return nil
		}
		return errors.Wrapf(err, "failed to trim chunk %d to %d bytes", tailIdx, wantSize)
	}
	if err := w.sm.db.AddUsage(storageID, w.namespaceID, wantSize-haveSize); err != nil {
		return errors.Wrap(err, "failed to refund usage for the trimmed chunk")
	}
	return nil
}

// releaseUnusedChunk removes a chunk file that the provisional length caused
// to be allocated but which the finished object does not reach.
func (w *AppendWriter) releaseUnusedChunk(meta *CacheMetadata, chunkIdx int) {
	if !meta.IsChunkAllocated(chunkIdx) {
		return
	}
	storageID := meta.GetChunkStorageID(chunkIdx)
	path := w.sm.getChunkPath(storageID, w.instanceHash, chunkIdx)
	if err := removeFileWithRetry(path); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove unused chunk %d of %s: %v", chunkIdx, w.instanceHash, err)
		return
	}
	if err := w.sm.db.AddUsage(storageID, w.namespaceID, -CalculateFileSize(w.chunkSize)); err != nil {
		log.Warnf("Failed to refund usage for unused chunk %d: %v", chunkIdx, err)
	}
}

// Abort discards a partially written object, removing its files and metadata.
func (w *AppendWriter) Abort() error {
	w.closed = true
	w.pending = nil
	// Delete drops the intent record inside the same transaction as the
	// metadata; this only clears the in-process registration.
	w.sm.liveAppends.Delete(w.instanceHash)
	return w.sm.Delete(w.instanceHash)
}

// ReclaimAbandonedAppends removes objects left behind by streaming appends
// that never reached Finalize or Abort -- the process died, or a consumer
// dropped the writer without cleaning up.
//
// Such an object is invisible to every other reclamation path: it has no LRU
// entry, so eviction never sees it; its usage charge is recomputed from live
// metadata, so the consistency checker re-affirms rather than releases it; and
// it has both metadata and files, so neither half of the metadata scan fires.
// The append-in-flight record written by NewAppendWriter is the only handle.
//
// A record is reclaimed only when no writer in this process owns it (the
// registry is populated before the record is written, so a live append is
// never mistaken for an orphan) and it is at least minAge old.  Pass 0 for
// minAge to reclaim purely on the registry.
//
// A record whose object is already Completed is dropped without touching the
// object: that is a Finalize that succeeded and then failed to tidy up.
//
// Returns the number of objects deleted.
func (sm *StorageManager) ReclaimAbandonedAppends(minAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-minAge)

	type orphan struct {
		hash    InstanceHash
		deleted bool
	}
	var orphans []orphan

	err := sm.db.ScanAppendIntents(func(hash InstanceHash, intent AppendIntent) error {
		if _, live := sm.liveAppends.Load(hash); live {
			return nil
		}
		if intent.StartedAt.After(cutoff) {
			return nil
		}
		meta, err := sm.db.GetMetadata(hash)
		if err != nil {
			log.Warnf("Failed to read metadata for abandoned append %s: %v", hash, err)
			return nil
		}
		orphans = append(orphans, orphan{
			hash:    hash,
			deleted: meta != nil && meta.Completed.IsZero(),
		})
		return nil
	})
	if err != nil {
		return 0, errors.Wrap(err, "failed to scan append-in-flight records")
	}

	reclaimed := 0
	for _, o := range orphans {
		if o.deleted {
			// Delete removes metadata, block state, chunk files, the usage
			// charge, and the intent record itself.
			if delErr := sm.Delete(o.hash); delErr != nil {
				log.Warnf("Failed to reclaim abandoned append %s: %v", o.hash, delErr)
				continue
			}
			log.Infof("Reclaimed abandoned streaming append %s", o.hash)
			reclaimed++
			continue
		}
		if delErr := sm.db.DeleteAppendIntent(o.hash); delErr != nil {
			log.Warnf("Failed to drop a stale append-in-flight marker for %s: %v", o.hash, delErr)
		}
	}
	return reclaimed, nil
}
