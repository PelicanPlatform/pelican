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

// Reading and writing object content.
//
// Objects are immutable.  A write always builds a complete new version and
// swaps it in at Close; there is no partial update, and a seek-then-write is
// refused rather than emulated.
//
// The write path has three tiers, chosen by how much data actually arrives:
//
//	<= InlineThreshold   stored directly in the catalog
//	<= spillThreshold    buffered, then written with the exact length known
//	>  spillThreshold    streamed through AppendWriter, length discovered at
//	                     the end
//
// The middle tier matters for capacity.  AppendWriter allocates whole chunks
// while streaming, so routing a 100 KB object through it would reserve a full
// chunk and hold it until Finalize refunds the difference — enough to
// spuriously fail a write on a near-full store.  Buffering to the spill
// threshold means only genuinely large objects take that path, where the
// overshoot is proportionally small.
//
// The chunk size is therefore not a constant: it is derived from the declared
// length when there is one, and bounded by minStreamChunkSize either way, so
// that the gap between "we stopped buffering" and "we reserve a whole chunk"
// stays a small factor rather than the 64× it would be at the block store's
// largest chunk size.  See streamChunkSizeCodeFor.

package pstore

import (
	"context"
	"io"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

const (
	// spillThreshold is how much of an object is buffered before switching to
	// streaming.  Below it the exact length is known at Close, so storage is
	// allocated once at the right size.
	//
	// The buffer is per in-flight write and cannot be evicted, so this trades
	// directly against concurrency: at 8 MiB a hundred concurrent uploads
	// could pin most of a gigabyte. 1 MiB keeps the common small-object case
	// on the exact-length path while bounding what a burst of writers holds.
	spillThreshold = 1 << 20

	// minStreamChunkSize is the smallest chunk the block store can encode
	// (ChunkSizeCode 1 is 2 MiB), and therefore the floor for anything
	// streamed.  Keeping it within a small factor of spillThreshold is what
	// makes a bounded store usable: AppendWriter pre-allocates and charges a
	// whole chunk the moment a stream touches it, so the chunk size is the
	// real minimum free space an object above the spill threshold demands.
	minStreamChunkSize = 2 << 20

	// maxStreamChunkSize caps the chunk size for a stream whose length is
	// declared.  A genuinely large upload wants large chunks -- a terabyte at
	// the minimum chunk size would be half a million files -- and it needs the
	// space anyway, so the over-reservation is proportionally nothing.
	maxStreamChunkSize = 64 << 20

	// defaultStreamChunkSize is used when the length is not declared at all,
	// which is what a chunked transfer-encoding PUT looks like.  There is no
	// way to size the chunk from the object, so this is a deliberate
	// compromise: eight times the spill threshold, so a store only needs
	// ~8 MiB of headroom in some directory to accept an unknown-length
	// object, at the cost of eight times as many chunk files as
	// maxStreamChunkSize would produce for a very large one.  A caller that
	// knows the length gets a chunk sized to it instead; see CreateSized.
	defaultStreamChunkSize = 8 << 20
)

// streamChunkSizeCodeFor picks the chunk size a streamed write should use.
//
// A declared length is honored up to maxStreamChunkSize so that an object
// just past the spill threshold reserves megabytes rather than the fixed
// 64 MiB the block store's largest chunk would cost -- the difference between
// a bounded store accepting a 2 MiB object and refusing every object over
// 1 MiB unless some directory happens to have 64 MiB free.
func streamChunkSizeCodeFor(declaredLen int64) local_cache.ChunkSizeCode {
	want := declaredLen
	if want <= 0 {
		want = defaultStreamChunkSize
	}
	if want < minStreamChunkSize {
		want = minStreamChunkSize
	}
	if want > maxStreamChunkSize {
		want = maxStreamChunkSize
	}

	// The encoded size is rounded down to a block boundary, so the chosen code
	// can land a few kilobytes under the request and an object sized exactly
	// at a chunk boundary spills into a second chunk.  That is deliberately
	// left alone: two chunks of N cost the same reservation as one chunk of
	// 2N, and stepping the code up would silently double the chunk size for
	// the undeclared case -- 8 MiB becoming 16 MiB -- which is the very
	// over-reservation this function exists to avoid.
	return local_cache.BytesToChunkSizeCode(uint64(want))
}

// chunkedFootprint is the on-disk size a streamed object of contentLen bytes
// occupies while it is being written: whole chunks, because AppendWriter keeps
// the provisional length chunk-aligned and every allocated chunk is
// pre-allocated and charged at full size.  Finalize trims the tail afterwards.
func chunkedFootprint(contentLen, chunkSize int64) int64 {
	chunks := (contentLen + chunkSize - 1) / chunkSize
	if chunks < 1 {
		chunks = 1
	}
	return chunks * local_cache.CalculateFileSize(chunkSize)
}

// plannedFootprint reports the bytes a write of contentLen will occupy and the
// largest single unit the block store has to fit into one directory.
//
// It is the one place that knows how a length maps onto a storage tier, so
// that the pre-flight check (HasCapacityFor) and the reservation the write
// actually takes cannot drift apart.
func (s *Store) plannedFootprint(contentLen int64) (need, unit int64) {
	if contentLen <= int64(s.storage.InlineMaxBytes()) {
		// Inline objects live in the catalog, are charged their content
		// length, and never occupy a storage directory -- so they count
		// against the aggregate but impose no per-directory requirement.
		return contentLen, 0
	}
	if contentLen < spillThreshold {
		need = local_cache.CalculateFileSize(contentLen)
		return need, need
	}
	chunkSize := int64(local_cache.ChunkSizeCodeToBytes(streamChunkSizeCodeFor(contentLen)))
	return chunkedFootprint(contentLen, chunkSize), local_cache.CalculateFileSize(chunkSize)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// WriteHandle accumulates a new version of an object and installs it at Close.
//
// Not safe for concurrent use.  Nothing the handle writes is visible to
// readers until Close returns successfully.
type WriteHandle struct {
	store *Store
	path  string

	generation   string
	instanceHash local_cache.InstanceHash

	buf     []byte
	spilled bool
	aw      *local_cache.AppendWriter

	// declaredSize is the length the caller promised, or -1 when unknown.  It
	// only sizes the storage tier and the streaming chunk; the object is
	// stored at whatever length actually arrives.
	declaredSize int64

	// chunkSize is the streaming chunk size, fixed at spill.  Zero until then.
	chunkSize int64

	// unpin releases the pin taken for the duration of materialization, which
	// is what keeps the janitor from reclaiming the half-built instance the
	// commit is about to make reachable.  Nil outside that window.
	unpin func()

	// written is atomic because Stat reads it while Write advances it.  The
	// handle is single-writer by contract, but webdav.handlePut stats the
	// file between writing and closing, and a caller is free to stat from
	// another goroutine; a torn read of an int64 is not worth the risk.
	written atomic.Int64

	// reserved is the capacity claimed so far; released or settled at the end.
	reserved int64

	// tier records which of the three storage tiers materialize actually
	// used, for pelican_pstore_writes_total.  It is set there rather than
	// recomputed from the handle's state at Close so that the counter cannot
	// drift from the decision it is reporting on -- the two conditions are
	// subtle enough (a spilled handle is streamed even if the content turned
	// out to be tiny) that a second copy of them would eventually disagree.
	tier string

	// digests hash the stream as it is written, so a later Want-Digest is a
	// metadata read rather than a re-read of the object.
	digests *ingestDigests

	// requireAbsent and requireGeneration carry conditional-write
	// preconditions evaluated in the commit transaction.
	requireAbsent     bool
	requireGeneration string

	done bool
}

// Create begins a new version of the object at name.  The parent directory
// must exist.  Nothing changes on disk until Close.
func (s *Store) Create(name string) (*WriteHandle, error) {
	if err := s.checkWritable(); err != nil {
		return nil, err
	}
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return nil, err
	}
	if isRootPath(cleanPath) {
		return nil, ErrIsDir
	}

	if err := s.checkNotDraining(cleanPath); err != nil {
		return nil, err
	}

	parent, _ := splitPath(cleanPath)
	err = s.bdb.View(func(txn *badger.Txn) error {
		if pErr := s.requireDirResolved(txn, parent); pErr != nil {
			return pErr
		}
		// Refuse up front when the target is a directory; the commit checks
		// again, since another writer could intervene.
		d, gErr := s.resolve(txn, cleanPath)
		if gErr == nil && d.IsDir() {
			return ErrIsDir
		}
		if gErr != nil && !errors.Is(gErr, ErrNotExist) {
			return gErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	generation, err := newGeneration()
	if err != nil {
		return nil, err
	}
	digests, err := newIngestDigests()
	if err != nil {
		return nil, err
	}

	return &WriteHandle{
		store:        s,
		path:         cleanPath,
		generation:   generation,
		instanceHash: instanceHashFor(s.db, generation),
		buf:          make([]byte, 0, 64<<10),
		digests:      digests,
		declaredSize: -1,
	}, nil
}

// CreateSized is Create for a caller that already knows the object's length.
//
// The size only selects the storage tier up front; it is a hint, not a
// promise, and the object is stored at whatever length actually arrives.  A
// declared size at or above the spill threshold goes straight to the streaming
// writer, so a large upload never buffers a megabyte first.
//
// A negative size means unknown and behaves exactly like Create.
//
// Declaring the size also sizes the streaming chunk, which is what lets a
// bounded store accept an object a little over the spill threshold: an
// undeclared write has to assume defaultStreamChunkSize.
func (s *Store) CreateSized(name string, size int64) (*WriteHandle, error) {
	w, err := s.Create(name)
	if err != nil {
		return nil, err
	}
	w.declaredSize = size
	if size >= spillThreshold {
		if sErr := w.spill(); sErr != nil {
			_ = w.Abort()
			return nil, sErr
		}
	}
	return w, nil
}

// RequireAbsent makes Close fail with ErrExist if the object already exists,
// implementing "If-None-Match: *".
func (w *WriteHandle) RequireAbsent() { w.requireAbsent = true }

// RequireGeneration makes Close fail with ErrPreconditionFailed unless the
// object still carries the given generation, implementing "If-Match".
func (w *WriteHandle) RequireGeneration(generation string) {
	w.requireGeneration = generation
}

// Generation returns the version token this write will install, which is also
// the object's ETag.
func (w *WriteHandle) Generation() string { return w.generation }

// Size returns how many bytes have been accepted so far.  The object is not
// visible at its path until Close, so this is the only way to observe the
// pending version's length.
func (w *WriteHandle) Size() int64 { return w.written.Load() }

// Path returns the object path this write will install to.
func (w *WriteHandle) Path() string { return w.path }

// Write appends to the new version.
func (w *WriteHandle) Write(p []byte) (int, error) {
	if w.done {
		return 0, ErrClosed
	}
	if len(p) == 0 {
		return 0, nil
	}

	if !w.spilled {
		if len(w.buf)+len(p) <= spillThreshold {
			if err := w.ensureReserved(int64(len(w.buf) + len(p))); err != nil {
				return 0, err
			}
			w.buf = append(w.buf, p...)
			w.written.Add(int64(len(p)))
			w.digests.Write(p)
			return len(p), nil
		}
		// Crossed the threshold: switch to streaming and hand over the
		// buffered prefix.
		if err := w.spill(); err != nil {
			return 0, err
		}
	}

	if err := w.ensureReserved(w.written.Load() + int64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.aw.Write(p)
	if err != nil {
		return n, err
	}
	w.written.Add(int64(n))
	w.digests.Write(p[:n])
	return n, nil
}

// spill switches from buffering to the streaming writer.
//
// The reservation is taken up to the streamed footprint *before* the buffered
// prefix is handed over, because that first write allocates and charges a
// whole chunk; reserving afterwards would let the charge land on a store that
// had no room for it.
func (w *WriteHandle) spill() error {
	sizeCode := streamChunkSizeCodeFor(w.declaredSize)
	w.chunkSize = int64(local_cache.ChunkSizeCodeToBytes(sizeCode))
	if w.chunkSize <= 0 {
		return errors.Errorf("invalid streaming chunk size code %d", sizeCode)
	}
	// From here the footprint is counted in whole chunks even if the writer
	// below fails to come up; discard releases whatever was claimed.
	w.spilled = true
	buffered := w.buf
	if err := w.ensureReserved(int64(len(buffered))); err != nil {
		return err
	}

	aw, err := w.store.storage.NewAppendWriter(
		context.Background(),
		w.instanceHash,
		w.store.namespaceID,
		sizeCode,
	)
	if err != nil {
		return err
	}
	if len(buffered) > 0 {
		if _, wErr := aw.Write(buffered); wErr != nil {
			_ = aw.Abort()
			return wErr
		}
	}
	w.aw = aw
	w.buf = nil
	return nil
}

// ensureReserved keeps the capacity reservation at least as large as the
// object's on-disk footprint will be, so a write that would overflow the
// store is refused before its bytes are committed.
//
// For a streamed object the footprint is whole chunks, not the content length:
// AppendWriter keeps its provisional length chunk-aligned, so every chunk the
// stream touches is pre-allocated and charged in full.  Reserving only the
// content length is how concurrent writers sail past the ceiling -- each ends
// up charged a fraction of what it actually holds.  Finalize trims the tail and
// settle refunds the difference once the real footprint is known.
//
// The unit passed alongside is the placement granularity: a streamed object is
// laid down one chunk at a time, each landing whole in a single directory, so
// some directory must have room for a chunk.  A buffered object is written in
// one piece and needs room for the whole thing.
func (w *WriteHandle) ensureReserved(contentLen int64) error {
	need := w.footprintFor(contentLen)
	if need <= w.reserved {
		return nil
	}
	unit := need
	if w.spilled {
		unit = local_cache.CalculateFileSize(w.chunkSize)
	}
	delta := need - w.reserved
	if err := w.store.capacity.reserve(delta, unit, w.reserved); err != nil {
		// Only the failure path is instrumented; the success path is the hot
		// one and stays a bare reservation.  This is the mid-write refusal --
		// the pre-flight one is counted in HasCapacityFor, and a request
		// cannot take both, because a pre-flight refusal never opens a handle.
		if errors.Is(err, ErrNoSpace) {
			metrics.PStoreWriteFailuresTotal.
				WithLabelValues(metrics.PStoreWriteFailureNoSpace).Inc()
		}
		return err
	}
	w.reserved += delta
	return nil
}

// footprintFor is the on-disk size contentLen bytes will occupy in the tier
// this handle is writing through.
func (w *WriteHandle) footprintFor(contentLen int64) int64 {
	if w.spilled {
		return chunkedFootprint(contentLen, w.chunkSize)
	}
	return local_cache.CalculateFileSize(contentLen)
}

// Close finalizes the object's data and installs it at its path.
//
// The install is one transaction: it re-checks preconditions, writes the new
// dirent, and queues the superseded version for reclamation.  Committing the
// swap and the queue entry together is what makes overwrite crash-safe.  A
// concurrent writer to the same path can abort that transaction, in which case
// it is retried against fresh state; see install.
func (w *WriteHandle) Close() error {
	if w.done {
		return ErrClosed
	}
	w.done = true

	if err := w.beginMaterialize(); err != nil {
		w.discard()
		return err
	}

	meta, err := w.materialize()
	if err != nil {
		w.discard()
		return err
	}

	now := time.Now()
	entry := &Dirent{
		Type:       EntryFile,
		Generation: w.generation,
		Size:       w.written.Load(),
		MTimeNanos: now.UnixNano(),
		Mode:       uint32(defaultFileMode),
	}

	if err := w.install(entry); err != nil {
		w.discard()
		return err
	}
	w.endMaterialize()

	// The write landed; convert the estimate into real per-directory usage.
	if meta != nil {
		w.store.capacity.settle(w.reserved, meta.PerDirectoryBytes())
	} else {
		w.store.capacity.settle(w.reserved, nil)
	}
	w.reserved = 0

	// Counted only once the object is installed, so the tier distribution
	// describes what the store holds rather than what was attempted.  One
	// atomic add per object; the capacity gauges are deliberately *not*
	// republished here, since that would put four gauge writes on every write
	// to publish a level nobody samples more than once a minute.
	if w.tier != "" {
		metrics.PStoreWritesTotal.WithLabelValues(w.tier).Inc()
	}
	return nil
}

// maxInstallAttempts bounds how many times Close retries the transaction that
// swaps the new version into the namespace.
//
// The index is serializable, so two commits touching the same entry cannot
// both succeed: BadgerDB aborts the second rather than serializing it.  That
// is the right database behavior and the wrong client behavior -- a
// concurrent PUT to the same path is an ordinary thing for an origin to
// receive, and answering it with a transaction-conflict error is asking the
// client to do work the store can do itself.
const maxInstallAttempts = 8

// install swaps the new version into the namespace, retrying a lost race.
//
// Every attempt is a fresh transaction that re-reads the current entry, so the
// conditional-write preconditions are evaluated against the state at the
// moment of the commit that actually lands -- never against a snapshot taken
// before an earlier attempt.  That distinction is the whole point: reusing the
// first attempt's read would let a RequireAbsent writer overwrite an object
// another writer installed in between, turning a refused write into a silent
// lost update.  A retry is therefore free to conclude ErrExist or
// ErrPreconditionFailed where the first attempt would have succeeded, and that
// is the correct answer.
//
// Nothing is committed by a losing attempt, so the pg: bookkeeping stays
// consistent across retries: the entry beginMaterialize wrote is only cleared
// by the transaction that also makes the version reachable.
func (w *WriteHandle) install(entry *Dirent) error {
	var lastErr error
	for attempt := range maxInstallAttempts {
		if attempt > 0 {
			// Counted here rather than where the conflict is detected so that
			// it measures retries taken, not conflicts observed: the final
			// attempt's conflict does not lead to a retry and is reported as a
			// failure below instead.
			metrics.PStoreWriteConflictRetriesTotal.Inc()

			// Yield rather than sleep.  The writer that won the previous round
			// has already committed -- that is why this one was aborted -- so
			// there is nothing to wait for beyond letting it get on with the
			// rest of its Close.
			runtime.Gosched()
		}

		err := w.store.bdb.Update(func(txn *badger.Txn) error {
			var superseded local_cache.InstanceHash

			parent, _ := splitPath(w.path)
			if pErr := w.store.requireDirResolved(txn, parent); pErr != nil {
				return pErr
			}

			existing, gErr := w.store.resolve(txn, w.path)
			switch {
			case gErr == nil:
				if existing.IsDir() {
					return ErrIsDir
				}
				if w.requireAbsent {
					return ErrExist
				}
				if w.requireGeneration != "" && existing.Generation != w.requireGeneration {
					return ErrPreconditionFailed
				}
				if existing.Generation != "" {
					superseded = instanceHashFor(w.store.db, existing.Generation)
				}
			case errors.Is(gErr, ErrNotExist):
				if w.requireGeneration != "" {
					return ErrPreconditionFailed
				}
			default:
				return gErr
			}

			if pErr := putDirent(txn, w.path, entry); pErr != nil {
				return pErr
			}
			// The version stops being an orphan and starts being reachable in
			// the same transaction, so the crash window beginMaterialize
			// opened closes exactly when it is no longer needed.
			if dErr := dequeueInstance(txn, w.instanceHash); dErr != nil {
				return dErr
			}
			// Same transaction as the swap: the old version must never be
			// unreachable and unqueued at the same time.
			return enqueueInstance(txn, superseded)
		})
		if err == nil {
			return nil
		}
		// Match on what BadgerDB actually returns rather than on the package
		// sentinel, so this keeps working if ErrConflict stops aliasing it.
		if !errors.Is(err, badger.ErrConflict) {
			return err
		}
		lastErr = err
	}
	// Losing this many rounds in a row means the path is under sustained
	// contention rather than a momentary overlap.  ErrConflict is retryable and
	// says so; origin_serve reports it as 409 rather than an opaque 500.
	metrics.PStoreWriteFailuresTotal.WithLabelValues(metrics.PStoreWriteFailureConflict).Inc()
	return errors.Wrapf(ErrConflict,
		"failed to install %s after %d attempts (%v)", w.path, maxInstallAttempts, lastErr)
}

// beginMaterialize opens the window in which a half-built object version
// exists on disk but is not yet reachable from the index.
//
// materialize writes the metadata record, the block state, the data files, and
// the usage charge before the commit transaction runs.  Process death anywhere
// in there would otherwise leave exactly the orphan the design promises cannot
// happen: bytes charged to the usage counters, no dirent pointing at them, and
// nothing in the reclamation queue -- recoverable only by an offline fsck.
//
// Queueing the version for reclamation *first* inverts that.  A crash leaves a
// queue entry the janitor picks up on its own, and a successful commit removes
// the entry in the very transaction that makes the version reachable.
//
// The price is that a `pg:i:` entry no longer means only "this is garbage": it
// now also means "a write is in flight", and the janitor must not confuse the
// two.  The pin taken here is the first half of what distinguishes them, held
// from before the entry is visible until after it is cleared.  The second half
// is a re-read on the janitor's side; both live in queuedInstance.claim, which
// is the only thing that can turn a queue entry back into a deletable hash.
func (w *WriteHandle) beginMaterialize() error {
	if err := w.store.checkWritable(); err != nil {
		return err
	}
	// Pin before the queue entry is visible, so a janitor that sees the entry
	// necessarily sees the pin too.
	w.unpin = w.store.storage.PinObject(w.instanceHash)
	if err := w.store.bdb.Update(func(txn *badger.Txn) error {
		return enqueueInstance(txn, w.instanceHash)
	}); err != nil {
		w.endMaterialize()
		return errors.Wrapf(err, "failed to record the pending write for %s", w.path)
	}
	return nil
}

// endMaterialize closes the window beginMaterialize opened.
func (w *WriteHandle) endMaterialize() {
	if w.unpin != nil {
		w.unpin()
		w.unpin = nil
	}
}

// materialize writes the buffered or streamed content into block storage and
// returns the finished metadata.  Inline objects have no per-directory
// footprint and return nil.
func (w *WriteHandle) materialize() (*local_cache.CacheMetadata, error) {
	ctx := context.Background()

	if w.spilled {
		w.tier = metrics.PStoreTierStreamed
		meta, err := w.aw.Finalize()
		if err != nil {
			return nil, errors.Wrap(err, "failed to finalize the streamed object")
		}
		if err := w.recordDigests(meta); err != nil {
			return nil, err
		}
		return meta, nil
	}

	inlineMax := int64(w.store.storage.InlineMaxBytes())
	written := w.written.Load()
	if written <= inlineMax {
		w.tier = metrics.PStoreTierInline
		meta := &local_cache.CacheMetadata{
			ContentLength: written,
			NamespaceID:   w.store.namespaceID,
			Completed:     time.Now(),
			Checksums:     w.digests.checksums(),
		}
		if err := w.store.storage.StoreInline(ctx, w.instanceHash, meta, w.buf); err != nil {
			return nil, errors.Wrap(err, "failed to store the object inline")
		}
		// Returned so the caller settles capacity: an inline object still
		// occupies disk (in the catalog) and StoreInline charges it to
		// StorageIDInline, which PerDirectoryBytes attributes correctly.
		// Dropping it here would let small objects fill a store without ever
		// counting against its ceiling.
		return meta, nil
	}

	// The exact length is known, so allocate once at the right size instead
	// of growing and trimming.
	//
	// This tier picks its own directory rather than going through the block
	// store's chooseDir hook, which only fires for chunk allocation.  It must
	// still ask the capacity tracker: DirIDs() is sorted, so taking the first
	// entry would pour every 4 KiB–1 MiB object into one directory until it
	// blew past its MaxSize while the others sat empty.
	w.tier = metrics.PStoreTierBuffered
	meta, err := w.store.storage.InitDiskStorage(
		ctx, w.instanceHash, written, w.store.capacity.chooseDir(), w.store.namespaceID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to allocate object storage")
	}
	if err := w.store.storage.WriteBlocks(w.instanceHash, 0, w.buf); err != nil {
		return nil, errors.Wrap(err, "failed to write object data")
	}
	meta.Completed = time.Now()
	meta.Checksums = w.digests.checksums()
	if err := w.store.db.SetMetadata(w.instanceHash, meta); err != nil {
		return nil, errors.Wrap(err, "failed to record object metadata")
	}
	return meta, nil
}

// recordDigests attaches the ingest checksums to an object whose metadata was
// written by AppendWriter.Finalize.
func (w *WriteHandle) recordDigests(meta *local_cache.CacheMetadata) error {
	meta.Checksums = w.digests.checksums()
	if err := w.store.db.SetMetadata(w.instanceHash, meta); err != nil {
		return errors.Wrap(err, "failed to record object checksums")
	}
	return nil
}

// Abort discards the pending version without touching the namespace.
func (w *WriteHandle) Abort() error {
	if w.done {
		return nil
	}
	w.done = true
	w.discard()
	return nil
}

// discard releases everything a failed or abandoned write claimed.
//
// Storage is always cleaned up, never only when bytes were written: a
// zero-length object still gets an inline metadata record from materialize, so
// a refused commit on an empty write would otherwise leave an m: record behind
// with nothing referencing it.  Deleting an instance that was never created is
// already tolerated, so there is nothing to gain from guessing.
func (w *WriteHandle) discard() {
	if w.aw != nil {
		if err := w.aw.Abort(); err != nil {
			log.Warnf("Failed to discard partial object %s: %v", w.path, err)
		}
	} else if err := w.store.storage.Delete(w.instanceHash); err != nil {
		log.Debugf("Nothing to discard for %s: %v", w.path, err)
	}
	// The pg: entry beginMaterialize wrote is deliberately left in place: it
	// costs one janitor visit against an instance that is already gone, and
	// keeping it is what covers a crash between here and now.
	w.endMaterialize()
	if w.reserved > 0 {
		w.store.capacity.releaseReservation(w.reserved)
		w.reserved = 0
	}
	w.buf = nil
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

// ReadHandle streams an object version.
//
// The underlying ObjectReader pins the version for its own lifetime, so the
// janitor cannot reclaim it mid-read; nothing extra is needed here.
type ReadHandle struct {
	*local_cache.ObjectReader
	dirent *Dirent
}

// Dirent returns the entry the handle was opened from.
func (r *ReadHandle) Dirent() *Dirent { return r.dirent }

// Close releases the reader, and with it the pin it holds.
func (r *ReadHandle) Close() error {
	return r.ObjectReader.Close()
}

// openRaceRetries bounds how many times OpenRead re-resolves an object whose
// version vanished between the lookup and the open.  Losing the race twice in
// a row against the same generation means the version is genuinely missing,
// not being overwritten.
const openRaceRetries = 3

// OpenRead opens the current version of an object for reading.
//
// Resolving the path and opening the version are two steps, and an overwrite
// can land between them: the swap commits, the superseded version is queued,
// the janitor finds it unpinned, and the open then fails on a generation that
// was current a microsecond earlier.  That surfaces as a 500 on an object that
// existed the whole time.
//
// Two things close that.  The pin is taken inside the resolving transaction,
// so a janitor that can see the version is superseded can also see that
// somebody holds it — queuedInstance.claim refuses pinned versions.  And the
// open is retried against a freshly resolved generation, which covers the
// residual window between the read snapshot and the pin actually landing.
// Retrying is safe because it is idempotent and bounded, and it terminates:
// either the path resolves to a version that opens, or it stops changing.
func (s *Store) OpenRead(name string) (*ReadHandle, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return nil, err
	}

	var lastGeneration string
	for attempt := 0; ; attempt++ {
		var (
			entry *Dirent
			hash  local_cache.InstanceHash
			unpin func()
		)
		if vErr := s.bdb.View(func(txn *badger.Txn) error {
			d, gErr := s.resolve(txn, cleanPath)
			if gErr != nil {
				return gErr
			}
			if d.IsDir() {
				return ErrIsDir
			}
			entry = d
			hash = instanceHashFor(s.db, d.Generation)
			unpin = s.storage.PinObject(hash)
			return nil
		}); vErr != nil {
			return nil, vErr
		}

		reader, oErr := s.storage.NewObjectReader(hash)
		// NewObjectReader took a pin of its own for the reader's lifetime, so
		// this one has done its job either way.
		unpin()
		if oErr != nil {
			if attempt < openRaceRetries && entry.Generation != lastGeneration {
				lastGeneration = entry.Generation
				continue
			}
			return nil, errors.Wrapf(oErr, "failed to open %s", cleanPath)
		}

		// Refresh the access time.  UpdateLRU debounces internally, so a hot
		// object pays a single metadata read rather than an index write.
		if lErr := s.db.UpdateLRU(hash, atimeDebounce); lErr != nil {
			log.Debugf("Failed to record access time for %s: %v", cleanPath, lErr)
		}

		return &ReadHandle{ObjectReader: reader, dirent: entry}, nil
	}
}

// AccessTime returns when an object was last read, as maintained by the LRU
// index (§8).
//
// This is deliberately not surfaced through FileInfo: it lives on the object's
// metadata rather than its directory entry, so reporting it from Stat would
// add a metadata read to every lookup to answer a question almost no caller
// asks.  Operators get it from `pelican-server origin pstore stat`.
//
// A zero time means the object has not been read since it was written, or was
// read within the debounce window before any access was recorded.
func (s *Store) AccessTime(name string) (time.Time, error) {
	cleanPath, err := cleanRelative(name)
	if err != nil {
		return time.Time{}, err
	}
	d, err := s.Stat(cleanPath)
	if err != nil {
		return time.Time{}, err
	}
	if d.IsDir() {
		return time.Time{}, ErrIsDir
	}
	meta, err := s.db.GetMetadata(instanceHashFor(s.db, d.Generation))
	if err != nil {
		return time.Time{}, err
	}
	if meta == nil {
		return time.Time{}, ErrNotExist
	}
	return meta.LastAccessTime, nil
}

// ReadAll is a convenience wrapper that returns an object's whole content.
func (s *Store) ReadAll(name string) ([]byte, error) {
	r, err := s.OpenRead(name)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
