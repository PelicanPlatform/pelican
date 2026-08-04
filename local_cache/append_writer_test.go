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
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// newAppendTestStorage builds a bare CacheDB + StorageManager pair, the same
// standalone construction pstore uses.
func newAppendTestStorage(t *testing.T, dirCount int) (*CacheDB, *StorageManager) {
	t.Helper()
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	db, err := NewCacheDB(ctx, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	dirs := make([]string, dirCount)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	egrp, _ := errgroup.WithContext(ctx)
	sm, err := NewStorageManager(db, dirs, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(sm.Close)

	return db, sm
}

// appendAndVerify streams size bytes of pseudo-random data through an
// AppendWriter without declaring the length up front, then reads the object
// back and compares.
func appendAndVerify(t *testing.T, sm *StorageManager, chunkSize uint64, size int64, writeChunk int) {
	t.Helper()
	ctx := t.Context()

	sizeCode := BytesToChunkSizeCode(chunkSize)
	hash := InstanceHash(randomHexForTest(t, 32))

	data := make([]byte, size)
	rng := rand.New(rand.NewSource(size))
	_, err := rng.Read(data)
	require.NoError(t, err)

	w, err := sm.NewAppendWriter(ctx, hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)

	for off := 0; off < len(data); off += writeChunk {
		end := off + writeChunk
		if end > len(data) {
			end = len(data)
		}
		n, wErr := w.Write(data[off:end])
		require.NoError(t, wErr)
		require.Equal(t, end-off, n)
	}

	meta, err := w.Finalize()
	require.NoError(t, err)
	assert.Equal(t, size, meta.ContentLength, "finalized length must be the bytes actually written")
	assert.False(t, meta.Completed.IsZero(), "finalize marks the object complete")

	reader, err := sm.NewObjectReader(hash)
	require.NoError(t, err)
	defer reader.Close()

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, size, int64(len(got)), "read back the same number of bytes")
	assert.True(t, bytes.Equal(data, got), "round-tripped content must match")
}

// randomHexForTest returns a fresh 2n-character hex string.
//
// It must actually be random, not derived from n: every caller passes the same
// n, so a deterministic string would hand every subtest of every table-driven
// test below the same instance hash in a shared store.  Each would silently
// overwrite its predecessor, and no assertion here could notice.
func randomHexForTest(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	_, err := crand.Read(buf)
	require.NoError(t, err)
	return hex.EncodeToString(buf)
}

// countStoredFiles returns the number of regular files across every configured
// storage directory.  Used to prove a torn-off write leaves no chunk behind.
func countStoredFiles(t *testing.T, sm *StorageManager) int {
	t.Helper()
	count := 0
	for _, dir := range sm.dirs {
		err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if !d.IsDir() {
				count++
			}
			return nil
		})
		require.NoError(t, err)
	}
	return count
}

// totalDirUsage sums the charged bytes across every namespace of a directory.
func totalDirUsage(t *testing.T, db *CacheDB, storageID StorageID) int64 {
	t.Helper()
	usage, err := db.GetDirUsage(storageID)
	require.NoError(t, err)
	var total int64
	for _, v := range usage {
		total += v
	}
	return total
}

// TestAppendWriterUnknownLength is the core case: an origin PUT arrives with
// no Content-Length, so the object's size is known only once the stream ends.
func TestAppendWriterUnknownLength(t *testing.T) {
	_, sm := newAppendTestStorage(t, 2)

	const chunkSize = 2 * 1024 * 1024
	cases := []struct {
		name string
		size int64
	}{
		{"partial block", 100},
		{"exact block", BlockDataSize},
		{"several blocks", BlockDataSize * 10},
		{"just under a chunk", chunkSize - 1},
		{"exactly one chunk", chunkSize},
		{"just over a chunk", chunkSize + 1},
		{"spanning three chunks", chunkSize*2 + 12345},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			appendAndVerify(t, sm, chunkSize, tc.size, 64*1024)
		})
	}
}

// TestAppendWriterOddWriteSizes exercises the block-alignment buffering: the
// caller's write boundaries have no relationship to BlockDataSize.
func TestAppendWriterOddWriteSizes(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)

	const chunkSize = 2 * 1024 * 1024
	for _, writeSize := range []int{1, 7, BlockDataSize - 1, BlockDataSize + 1, 100000} {
		t.Run("write size "+strconv.Itoa(writeSize), func(t *testing.T) {
			appendAndVerify(t, sm, chunkSize, chunkSize+9999, writeSize)
		})
	}
}

// TestAppendWriterRefundsOverAllocation checks the accounting half of
// Finalize.  The writer allocates whole chunks while streaming, so a small
// object briefly reserves a full chunk; once the true length is known the
// excess must be given back or the store would leak capacity on every write.
func TestAppendWriterRefundsOverAllocation(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	const chunkSize = 2 * 1024 * 1024
	sizeCode := BytesToChunkSizeCode(chunkSize)
	hash := InstanceHash(randomHexForTest(t, 31))
	nsID := NamespaceID(7)

	w, err := sm.NewAppendWriter(t.Context(), hash, nsID, sizeCode)
	require.NoError(t, err)

	payload := make([]byte, 4096)
	_, err = w.Write(payload)
	require.NoError(t, err)

	meta, err := w.Finalize()
	require.NoError(t, err)
	require.Equal(t, int64(len(payload)), meta.ContentLength)

	total := totalDirUsage(t, db, meta.StorageID)

	// 4096 content bytes span two 4080-byte blocks: a full block (4080 + a
	// 16-byte tag) plus 16 content bytes and their tag.  Spelled out rather
	// than recomputed with CalculateFileSize, which is the function the writer
	// itself used -- deriving the expectation from the implementation would
	// only prove two call sites agree.
	assert.Equal(t, int64(4128), total,
		"usage must reflect the finished object, not the chunk reserved while streaming")
	assert.Less(t, total, int64(chunkSize),
		"the over-allocated chunk must be refunded")
}

// TestAppendWriterAbort confirms a torn-off write leaves nothing behind: no
// metadata, no chunk files, and no charged capacity.
func TestAppendWriterAbort(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	baselineUsage := totalDirUsage(t, db, StorageIDFirstDisk)
	baselineFiles := countStoredFiles(t, sm)

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write(make([]byte, 128*1024))
	require.NoError(t, err)

	// Sanity: the write really did reserve something, so the assertions below
	// are not passing because nothing ever happened.
	require.Greater(t, countStoredFiles(t, sm), baselineFiles,
		"a partial append should have created a chunk file")

	require.NoError(t, w.Abort())

	got, err := db.GetMetadata(hash)
	require.NoError(t, err)
	assert.Nil(t, got, "an aborted write leaves no metadata behind")

	intent, err := db.GetAppendIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent, "an aborted write leaves no append-in-flight marker")

	assert.Equal(t, baselineUsage, totalDirUsage(t, db, StorageIDFirstDisk),
		"an aborted write must not leave capacity charged")
	assert.Equal(t, baselineFiles, countStoredFiles(t, sm),
		"an aborted write must not leave chunk files on disk")
}

func TestAppendWriterRejectsUseAfterFinalize(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write([]byte("hello"))
	require.NoError(t, err)
	_, err = w.Finalize()
	require.NoError(t, err)

	_, err = w.Write([]byte("more"))
	assert.ErrorContains(t, err, "write to a finalized AppendWriter")
	_, err = w.Finalize()
	assert.ErrorContains(t, err, "already finalized")
}

func TestAppendWriterRejectsChunkingDisabled(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)

	_, err := sm.NewAppendWriter(t.Context(), InstanceHash(randomHexForTest(t, 32)),
		NamespaceID(1), ChunkingDisabled)
	assert.ErrorContains(t, err, "requires chunking enabled")
}

// TestAppendWriterZeroByteObject covers a zero-length PUT followed by a GET.
//
// Nothing is ever flushed, so no chunk is allocated and the object's StorageID
// stays 0.  That combination has to resolve to exactly one storage mode: an
// object that is neither inline (because ChunkSizeCode is set) nor readable
// from disk (because no file was ever created) opens as "no such file or
// directory".
func TestAppendWriterZeroByteObject(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)

	meta, err := w.Finalize()
	require.NoError(t, err)
	assert.Equal(t, int64(0), meta.ContentLength)
	assert.False(t, meta.Completed.IsZero(), "an empty object is still a finished object")
	assert.True(t, meta.IsInline(), "a zero-byte object must land in exactly one storage mode")
	assert.False(t, meta.IsDisk())

	reader, err := sm.NewObjectReader(hash)
	require.NoError(t, err, "a zero-byte object must be readable")
	defer reader.Close()

	got, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Empty(t, got)

	// The stored metadata, not just the returned copy, has to be coherent.
	stored, err := db.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.IsInline())
	assert.Equal(t, int64(0), stored.ContentLength)

	// A zero-byte write also has to be a zero-byte charge.
	assert.Zero(t, totalDirUsage(t, db, StorageIDFirstDisk))

	intent, err := db.GetAppendIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent, "finalize clears the append-in-flight marker")
}

// TestAppendWriterCompletedOnlyAtFinalize holds down that an in-flight object
// is never stamped Completed at a length the writer merely reserved.
//
// growTo advances the provisional ContentLength as the stream arrives.  If it
// ever advanced past what has been flushed -- by rounding up to a chunk
// boundary, say -- then for a stream whose length lands on that boundary the
// provisional length equals the flushed length, writeBlocks sees every block of
// the recorded length present, and merges a Completed stamp.  A connection
// dropped at that moment leaves the database claiming a whole object.
func TestAppendWriterCompletedOnlyAtFinalize(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	const chunkSize = 2 * 1024 * 1024
	sizeCode := BytesToChunkSizeCode(chunkSize)
	// The chunk size in content bytes is rounded down to a whole number of
	// blocks; this is the boundary the sizes below are chosen around.
	chunkContent := int64(ChunkSizeCodeToBytes(sizeCode))
	require.Positive(t, chunkContent)

	cases := []struct {
		name string
		size int64
	}{
		{"exactly one chunk", chunkContent},
		{"exactly two chunks", chunkContent * 2},
		{"one block short of a chunk", chunkContent - BlockDataSize},
		{"one block into the second chunk", chunkContent + BlockDataSize},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := InstanceHash(randomHexForTest(t, 32))
			w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
			require.NoError(t, err)

			// Write in block-sized pieces so every byte is flushed; a
			// tail left in the buffer would keep the flushed length short
			// of the provisional one no matter what growTo did.
			buf := make([]byte, BlockDataSize)
			for written := int64(0); written < tc.size; written += BlockDataSize {
				n, wErr := w.Write(buf)
				require.NoError(t, wErr)
				require.Equal(t, BlockDataSize, n)
			}

			// Abandon the writer here, exactly as a dropped connection would.
			mid, err := db.GetMetadata(hash)
			require.NoError(t, err)
			require.NotNil(t, mid)
			assert.True(t, mid.Completed.IsZero(),
				"an unfinalized object must never be marked complete")
			assert.Greater(t, mid.ContentLength, tc.size,
				"the provisional length must stay ahead of the stream so no block set can look complete")

			meta, err := w.Finalize()
			require.NoError(t, err)
			assert.Equal(t, tc.size, meta.ContentLength)
			assert.False(t, meta.Completed.IsZero(), "finalize is what marks completion")
		})
	}
}

// TestReclaimAbandonedAppends covers the writer that is never finalized and
// never aborted -- the process died mid-PUT.  Such an object has metadata and
// chunk files but no LRU entry, so nothing else in the cache would ever free
// it: eviction cannot see it, and the consistency checker recomputes its usage
// charge from the very metadata that is the problem.
func TestReclaimAbandonedAppends(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	const chunkSize = 2 * 1024 * 1024
	sizeCode := BytesToChunkSizeCode(chunkSize)
	hash := InstanceHash(randomHexForTest(t, 32))

	baselineUsage := totalDirUsage(t, db, StorageIDFirstDisk)
	baselineFiles := countStoredFiles(t, sm)

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(3), sizeCode)
	require.NoError(t, err)
	_, err = w.Write(make([]byte, int(ChunkSizeCodeToBytes(sizeCode))))
	require.NoError(t, err)

	require.Greater(t, totalDirUsage(t, db, StorageIDFirstDisk), baselineUsage,
		"the in-flight append should have charged capacity")

	// A live writer is never an orphan, however old the record looks.
	reclaimed, err := sm.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Zero(t, reclaimed, "a writer this process still owns must not be reclaimed")
	present, err := sm.HasObject(hash)
	require.NoError(t, err)
	assert.True(t, present)

	// Simulate the process dying: the persisted record survives, the
	// in-memory registration does not.
	sm.liveAppends.Delete(hash)

	reclaimed, err = sm.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Equal(t, 1, reclaimed)

	present, err = sm.HasObject(hash)
	require.NoError(t, err)
	assert.False(t, present, "the abandoned object's metadata must be gone")

	intent, err := db.GetAppendIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent, "the intent record must be gone too")

	assert.Equal(t, baselineUsage, totalDirUsage(t, db, StorageIDFirstDisk),
		"reclamation must return the charged capacity")
	assert.Equal(t, baselineFiles, countStoredFiles(t, sm),
		"reclamation must remove the chunk files")

	// A second pass has nothing left to do.
	reclaimed, err = sm.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Zero(t, reclaimed)
}

// TestReclaimAbandonedAppendsKeepsFinishedObjects guards the other direction:
// a crash between Finalize's metadata write and its marker cleanup must not
// cost the operator a complete object.
func TestReclaimAbandonedAppendsKeepsFinishedObjects(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write([]byte("finished"))
	require.NoError(t, err)
	_, err = w.Finalize()
	require.NoError(t, err)

	// Re-create the marker Finalize removed, as a crash in between would.
	require.NoError(t, db.SetAppendIntent(hash, AppendIntent{StartedAt: time.Now()}))

	reclaimed, err := sm.ReclaimAbandonedAppends(0)
	require.NoError(t, err)
	assert.Zero(t, reclaimed, "a completed object must survive the janitor")

	present, err := sm.HasObject(hash)
	require.NoError(t, err)
	assert.True(t, present)

	intent, err := db.GetAppendIntent(hash)
	require.NoError(t, err)
	assert.Nil(t, intent, "the stale marker is still cleaned up")
}

// TestReclaimAbandonedAppendsHonorsMinAge checks that a young record is left
// alone even when no writer claims it, so a reclamation pass cannot race a
// consumer that builds writers some other way.
func TestReclaimAbandonedAppendsHonorsMinAge(t *testing.T) {
	db, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write(make([]byte, 8192))
	require.NoError(t, err)
	sm.liveAppends.Delete(hash)

	reclaimed, err := sm.ReclaimAbandonedAppends(time.Hour)
	require.NoError(t, err)
	assert.Zero(t, reclaimed, "a record younger than minAge must be left alone")

	present, err := sm.HasObject(hash)
	require.NoError(t, err)
	assert.True(t, present)

	// Backdate the record and it becomes reclaimable.
	require.NoError(t, db.SetAppendIntent(hash, AppendIntent{
		StartedAt: time.Now().Add(-2 * time.Hour),
	}))
	reclaimed, err = sm.ReclaimAbandonedAppends(time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, reclaimed)
}

// TestAppendWriterWriteReportsBytesOnError checks the io.Writer contract on a
// failing flush: the bytes are already in the writer's buffer and already
// counted, so reporting zero would invite an io.Copy-style caller to resend
// them.
func TestAppendWriterWriteReportsBytesOnError(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)

	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)

	// Delete the object out from under the writer so the next flush fails
	// inside growTo, which reads metadata that is no longer there.
	require.NoError(t, sm.Delete(hash))

	payload := make([]byte, BlockDataSize*2)
	n, err := w.Write(payload)
	require.Error(t, err, "the flush must fail once the object is gone")
	assert.Equal(t, len(payload), n,
		"a failed write still reports the bytes it consumed and counted")
	assert.Equal(t, int64(len(payload)), w.Written())
}
