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
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// diskID returns the storage ID of the environment's one directory.
func (e *tornBlockEnv) diskID() StorageID {
	for id := range e.storage.GetDirs() {
		return id
	}
	return 0
}

// reinit makes a new instance of the object under the same hash, as a fetch
// of the same version after the old one was deleted does.
func (e *tornBlockEnv) reinit(t *testing.T) {
	t.Helper()
	_, err := e.storage.InitDiskStorage(context.Background(), e.hash, int64(len(e.data)), e.diskID(), 1)
	require.NoError(t, err)
}

// requireStartsClean checks that the instance under the hash has nothing an
// older instance's writer could have left it: no block, no completion.
func (e *tornBlockEnv) requireStartsClean(t *testing.T) {
	t.Helper()
	assert.Empty(t, e.presentBlocks(t), "a writer of the deleted instance marked blocks of the new one")
	meta, err := e.db.GetMetadata(e.hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.True(t, meta.Completed.IsZero(), "a writer of the deleted instance completed the new one")
	state, err := e.storage.GetSharedBlockState(e.hash)
	require.NoError(t, err)
	assert.Zero(t, state.GetCardinality(), "the new instance's block state must start empty")
}

// testWriterFence joins the instance's write fence for a test that stands in
// for one of its writers, leaving it when the test ends.
func testWriterFence(t *testing.T, sm *StorageManager, hash InstanceHash) *writeFence {
	t.Helper()
	fence := sm.fences.join(hash)
	t.Cleanup(fence.leave)
	return fence
}

// TestEvictionFencesARunningWriter checks that a writer still running when
// LRU eviction deletes its instance writes nothing more of it: not when the
// instance is gone, and not into a new instance fetched under the same hash
// in the meantime.
func TestEvictionFencesARunningWriter(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	require.NoError(t, env.db.UpdateLRU(env.hash, 0))

	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)

	evicted, _, _, err := env.storage.EvictByLRU(env.diskID(), 1, 0, 1<<30)
	require.NoError(t, err)
	require.Len(t, evicted, 1)
	meta, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	require.Nil(t, meta)

	env.reinit(t)
	// The old writer goes on to write, and complete, the whole object.
	_, err = bw.Write(env.data[2*BlockDataSize:])
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	env.requireStartsClean(t)
	assert.Zero(t, env.storage.fences.size(), "no fence may outlive its writers and deletions")
}

// TestEvictionFencesAWriterToADeletedObject is the same race with nothing
// fetched again: the writer, completing the object, must not recreate a
// record of it (MergeMetadata makes one where none exists).
func TestEvictionFencesAWriterToADeletedObject(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	require.NoError(t, env.db.UpdateLRU(env.hash, 0))

	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)
	evicted, _, _, err := env.storage.EvictByLRU(env.diskID(), 1, 0, 1<<30)
	require.NoError(t, err)
	require.Len(t, evicted, 1)

	_, err = bw.Write(env.data[2*BlockDataSize:])
	require.NoError(t, err)
	require.NoError(t, bw.Close())

	meta, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, meta, "a phantom record of the deleted object")
	assert.Empty(t, env.presentBlocks(t), "phantom blocks of the deleted object")
	assert.Zero(t, env.storage.fences.size())
}

// TestCondemnDeleteFencesAWriterPastItsCheck checks the window the condemned
// check leaves: a writer already past it when another writer condemns the
// object and drops it -- here forced by running the condemnation and the
// delete, and a fetch of the same version again, at the start of the
// writer's fenced write.  The writer must write nothing.
func TestCondemnDeleteFencesAWriterPastItsCheck(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)

	fired := false
	env.storage.fences.beforeWrite = func(h InstanceHash) {
		if fired {
			return
		}
		fired = true
		state, err := env.storage.GetSharedBlockState(h)
		require.NoError(t, err)
		state.condemn(errors.New("another writer's checksum mismatch"))
		require.NoError(t, env.storage.Delete(h))
		env.reinit(t)
	}
	bw.StopEarly() // flushes the two whole blocks
	require.True(t, fired, "the flush must have gone through the fence")

	env.requireStartsClean(t)
	assert.Zero(t, env.storage.fences.size())
}

// TestWriteBlocksIsFenced checks the other block writer, WriteBlocks: an
// object deleted while a call is writing it gets nothing from the call, and
// the caller is told.
func TestWriteBlocksIsFenced(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.fences.beforeWrite = func(h InstanceHash) {
		require.NoError(t, env.storage.Delete(h))
		env.reinit(t)
	}
	err := env.storage.WriteBlocks(env.hash, 0, env.data)
	require.ErrorIs(t, err, errInstanceDeleted)

	env.storage.fences.beforeWrite = nil
	env.requireStartsClean(t)
	assert.Zero(t, env.storage.fences.size())
}

// TestWriteFenceOrdersAWriteAgainstADeletion checks the fence itself: a
// writer that joined before a deletion writes nothing after it, one that
// joined after writes, and the registry forgets every fence once its
// writers have left.
func TestWriteFenceOrdersAWriteAgainstADeletion(t *testing.T) {
	fs := newInstanceFences()
	const h = InstanceHash("h")
	before := fs.join(h)
	release := fs.exclude(h)
	release(true)
	after := fs.join(h)
	assert.False(t, before.write(func() { t.Error("a write after the deletion ran") }))
	assert.True(t, after.write(func() {}))

	// A deletion that did not happen fences nothing.
	release = fs.exclude(h)
	release(false)
	assert.True(t, after.write(func() {}))

	// A clone writes at its writer's generation, and is dead once the
	// writer's fence is gone.
	clone := before.clone()
	assert.False(t, clone.write(func() { t.Error("a clone's write after the deletion ran") }))
	clone.leave()
	before.leave()
	after.leave()
	assert.Zero(t, fs.size())
	late := after.clone()
	assert.False(t, late.write(func() { t.Error("a clone of a forgotten fence wrote") }))
	late.leave()
	assert.Zero(t, fs.size())
}

// TestExcludeAsShutsOutOnlyTheWritersInstance checks excludeAs, a deletion
// on behalf of a writer: it goes ahead while the instance is the one the
// writer joined, and is refused once that instance has been deleted -- the
// hash may name a new one -- without fencing off the new instance's writers.
func TestExcludeAsShutsOutOnlyTheWritersInstance(t *testing.T) {
	fs := newInstanceFences()
	const h = InstanceHash("h")
	w := fs.join(h)
	release := fs.excludeAs(w)
	require.NotNil(t, release)
	release(true)
	assert.Nil(t, fs.excludeAs(w), "a writer whose instance was deleted must not delete its successor")
	successor := fs.join(h)
	assert.True(t, successor.write(func() {}), "a refused deletion must fence nothing off")
	w.leave()
	successor.leave()
	late := successor.clone()
	assert.Nil(t, fs.excludeAs(late), "a clone too late to be fenced must not delete")
	late.leave()
	assert.Zero(t, fs.size())
}

// raceRefetchAgainstFileDeletion runs deleteObject, a deletion of the
// environment's object, and holds it just as it is about to delete the
// object's files; meanwhile the same version is fetched again (reinit).
// The fetch must either be held off until the deletion is over or not
// happen in its middle -- either way, once both are done, the new instance
// has its record and its file.
func raceRefetchAgainstFileDeletion(t *testing.T, env *tornBlockEnv, deleteObject func() error) {
	t.Helper()
	atFiles := make(chan struct{})
	proceed := make(chan struct{})
	fired := false
	env.storage.beforeDeleteFiles = func(InstanceHash) {
		if fired {
			return
		}
		fired = true
		close(atFiles)
		<-proceed
	}
	deleted := make(chan error, 1)
	go func() { deleted <- deleteObject() }()
	<-atFiles

	created := make(chan error, 1)
	go func() {
		_, err := env.storage.InitDiskStorage(context.Background(), env.hash, int64(len(env.data)), env.diskID(), 1)
		created <- err
	}()
	// Wait until the fetch is either done or held off by the fence.
	var createErr error
	createDone := false
	require.Eventually(t, func() bool {
		select {
		case createErr = <-created:
			createDone = true
			return true
		default:
			return env.storage.fences.waiters(env.hash) > 0
		}
	}, 10*time.Second, time.Millisecond)
	close(proceed)
	require.NoError(t, <-deleted)
	if !createDone {
		createErr = <-created
	}
	require.NoError(t, createErr)

	meta, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the new instance's record")
	_, err = os.Stat(env.storage.getObjectPathForDir(env.diskID(), env.hash))
	assert.NoError(t, err, "the new instance's file was deleted by the old instance's deletion")
	assert.Zero(t, env.storage.fences.size())
}

// TestDeleteKeepsTheFilesOfARefetch checks that Delete removes an object's
// files inside its fence, so that a fetch of the same version racing the
// deletion never loses its new file to it.
func TestDeleteKeepsTheFilesOfARefetch(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	raceRefetchAgainstFileDeletion(t, env, func() error { return env.storage.Delete(env.hash) })
}

// TestEvictionKeepsTheFilesOfARefetch is the same for LRU eviction.
func TestEvictionKeepsTheFilesOfARefetch(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	require.NoError(t, env.db.UpdateLRU(env.hash, 0))
	raceRefetchAgainstFileDeletion(t, env, func() error {
		evicted, _, _, err := env.storage.EvictByLRU(env.diskID(), 1, 0, 1<<30)
		if err == nil && len(evicted) != 1 {
			return errors.Errorf("evicted %d objects; expected 1", len(evicted))
		}
		return err
	})
}

// TestScanRecordsNothingForADeletedObject checks that the consistency
// scan's records of what it verified -- a checksum it computed, the time it
// verified the data -- are not written for an object deleted while it was
// being verified: a bare record would pass for a cached copy.
func TestScanRecordsNothingForADeletedObject(t *testing.T) {
	env := newTornBlockEnv(t, int64(tornObjectBlocks*BlockDataSize-17))
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data)
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	meta, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	require.False(t, meta.Completed.IsZero())

	cc := NewConsistencyChecker(env.db, env.storage, ConsistencyConfig{SkipVerifiedData: true, SuppressCacheMetrics: true})
	cc.beforeMetadataWrite = func(h InstanceHash) {
		if m, _ := env.db.GetMetadata(h); m != nil {
			require.NoError(t, env.storage.Delete(h))
		}
	}
	require.NoError(t, cc.calculateAndStoreChecksums(context.Background(), env.hash, meta, rate.NewLimiter(rate.Inf, 0)))
	got, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, got, "a record made from the checksum of a deleted object")

	cc.markDataVerified(env.hash)
	got, err = env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.Nil(t, got, "a record made from the verification time of a deleted object")
}

// TestMergeExistingMetadataMergesOnlyIntoARecord checks the merge the scan
// uses: it updates an existing record, and makes none.
func TestMergeExistingMetadataMergesOnlyIntoARecord(t *testing.T) {
	env := newTornBlockEnv(t, int64(tornObjectBlocks*BlockDataSize-17))
	now := time.Now()
	found, err := env.db.MergeExistingMetadata(env.hash, &CacheMetadata{DataVerified: now})
	require.NoError(t, err)
	assert.True(t, found)
	meta, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	assert.WithinDuration(t, now, meta.DataVerified, time.Second)

	const absent = InstanceHash("absent")
	found, err = env.db.MergeExistingMetadata(absent, &CacheMetadata{DataVerified: now})
	require.NoError(t, err)
	assert.False(t, found)
	meta, err = env.db.GetMetadata(absent)
	require.NoError(t, err)
	assert.Nil(t, meta)
}

// TestNewBlockWriterMakesNoFileForADeletedObject checks that a writer whose
// object is deleted as it is being made -- after it has read the object's
// record, before it opens the file -- does not create the file again.
func TestNewBlockWriterMakesNoFileForADeletedObject(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.beforeWriterOpens = func(h InstanceHash) {
		require.NoError(t, env.storage.Delete(h))
	}
	_, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.ErrorIs(t, err, errInstanceDeleted)
	_, err = os.Stat(env.storage.getObjectPathForDir(env.diskID(), env.hash))
	assert.True(t, os.IsNotExist(err), "the deleted object's file was made again")
	assert.Zero(t, env.storage.fences.size())
}

// TestAppendWriterWritesNothingIntoARefetch checks that an AppendWriter
// whose object is deleted, and then made again under the same hash, writes
// neither blocks nor its record into the new instance.
func TestAppendWriterWritesNothingIntoARefetch(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)
	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))
	data := make([]byte, 4*BlockDataSize)
	for i := range data {
		data[i] = byte(i % 251)
	}

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write(data[:2*BlockDataSize])
	require.NoError(t, err)

	require.NoError(t, sm.Delete(hash))
	_, err = sm.InitLazyChunkedStorage(t.Context(), hash, int64(len(data)), sizeCode)
	require.NoError(t, err)

	_, err = w.Write(data[2*BlockDataSize:])
	assert.ErrorIs(t, err, errInstanceDeleted)
	_, err = w.Finalize()
	assert.ErrorIs(t, err, errInstanceDeleted)
	require.NoError(t, w.Abort())

	meta, err := sm.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta, "the old writer's Abort deleted the new instance")
	assert.True(t, meta.Completed.IsZero(), "the old writer completed the new instance")
	assert.Equal(t, int64(len(data)), meta.ContentLength, "the old writer rewrote the new instance's record")
	bm, err := sm.db.GetBlockState(hash)
	require.NoError(t, err)
	assert.Zero(t, bm.GetCardinality(), "the old writer wrote blocks of the new instance")
	assert.Zero(t, sm.fences.size())
}

// TestAppendWriterFinalizesNothingOfARefetch checks Finalize: an
// AppendWriter whose blocks were all written before its object was deleted
// and made again must not finish the new instance's record.
func TestAppendWriterFinalizesNothingOfARefetch(t *testing.T) {
	_, sm := newAppendTestStorage(t, 1)
	sizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	hash := InstanceHash(randomHexForTest(t, 32))
	data := make([]byte, 2*BlockDataSize)

	w, err := sm.NewAppendWriter(t.Context(), hash, NamespaceID(1), sizeCode)
	require.NoError(t, err)
	_, err = w.Write(data)
	require.NoError(t, err)

	require.NoError(t, sm.Delete(hash))
	const newLength = 5 * BlockDataSize
	_, err = sm.InitLazyChunkedStorage(t.Context(), hash, newLength, sizeCode)
	require.NoError(t, err)

	_, err = w.Finalize()
	assert.ErrorIs(t, err, errInstanceDeleted)
	meta, err := sm.GetMetadata(hash)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.True(t, meta.Completed.IsZero(), "the old writer completed the new instance")
	assert.Equal(t, int64(newLength), meta.ContentLength, "the old writer rewrote the new instance's record")
	assert.Zero(t, sm.fences.size())
}

// writeWhole writes the whole object through a new BlockWriter and closes it.
func (e *tornBlockEnv) writeWhole(t *testing.T) {
	t.Helper()
	bw, err := e.storage.NewBlockWriter(e.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(e.data)
	require.NoError(t, err)
	require.NoError(t, bw.Close())
}

// requireReadable checks that the object's first block reads back, through
// whatever descriptor the descriptor cache holds for it.
func (e *tornBlockEnv) requireReadable(t *testing.T) {
	t.Helper()
	got, err := e.storage.ReadBlocks(e.hash, 0, BlockDataSize)
	require.NoError(t, err, "a read of the object must not go to a deleted file")
	assert.Equal(t, e.data[:BlockDataSize], got)
}

// TestAFencedOffWriterCachesNoDescriptor checks that a writer whose instance
// was deleted does not, on closing, put its descriptor -- of the deleted
// file -- into the descriptor cache, where a new instance under the same
// hash would find it and fail every read.
func TestAFencedOffWriterCachesNoDescriptor(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.fdCacheMaxSize = 1024
	require.NoError(t, env.db.UpdateLRU(env.hash, 0))

	old, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = old.Write(env.data[:2*BlockDataSize])
	require.NoError(t, err)
	evicted, _, _, err := env.storage.EvictByLRU(env.diskID(), 1, 0, 1<<30)
	require.NoError(t, err)
	require.Len(t, evicted, 1)

	// The same version is fetched again and written in full; then the old
	// writer, fenced off, closes.
	env.reinit(t)
	env.writeWhole(t)
	require.NoError(t, old.Close())

	env.requireReadable(t)
	assert.Zero(t, env.storage.fences.size())
}

// TestAReaderCachesNoDescriptorOfADeletedFile checks the same for a reader
// that opens the object's file on a miss of the descriptor cache: a deletion
// and a fetch of the same version again, landing between its open and its
// caching, must not leave the deleted file's descriptor cached.  The hook
// starts the deletion and the fetch at that point and lets the reader go on
// once they have finished -- or, with the reader holding the fence, once
// the deletion is waiting for it.
func TestAReaderCachesNoDescriptorOfADeletedFile(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.fdCacheMaxSize = 1024
	env.writeWhole(t)
	env.storage.openFiles.Delete(chunkFileKey{instanceHash: env.hash, chunkIndex: 0})

	done := make(chan struct{})
	fired := false
	env.storage.beforeFileCached = func(InstanceHash) {
		if fired {
			return
		}
		fired = true
		go func() {
			defer close(done)
			assert.NoError(t, env.storage.Delete(env.hash))
			env.reinit(t)
			env.writeWhole(t)
		}()
		require.Eventually(t, func() bool {
			select {
			case <-done:
				return true
			default:
				return env.storage.fences.waiters(env.hash) > 0
			}
		}, 10*time.Second, time.Millisecond)
	}
	// This read opens the old file; what it reads does not matter.
	_, _ = env.storage.ReadBlocks(env.hash, 0, BlockDataSize)
	<-done
	env.storage.beforeFileCached = nil

	env.requireReadable(t)
}

// TestAutoRepairClearsNothingOfARefetch checks that an auto-repair clears
// the blocks it found corrupt only in the instance its reader read: if the
// object is deleted and the same version fetched again between the repair
// finding the blocks corrupt and clearing them, the blocks it would clear
// are the new instance's, which are whole.
func TestAutoRepairClearsNothingOfARefetch(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.writeWhole(t)
	_, err := NewChaosInjector(env.db, env.storage).CorruptBlock("", "", string(env.hash), 1, 0)
	require.NoError(t, err)

	rr, err := NewRangeReader(env.storage, env.hash, 0, -1, func(context.Context, uint32, uint32) error {
		return errors.New("this test has no origin")
	})
	require.NoError(t, err)
	defer rr.Close()

	fired := false
	env.storage.beforeClearCorrupt = func(InstanceHash) {
		if fired {
			return
		}
		fired = true
		require.NoError(t, env.storage.Delete(env.hash))
		env.reinit(t)
		env.writeWhole(t)
	}
	_, err = rr.Seek(BlockDataSize, io.SeekStart)
	require.NoError(t, err)
	_, err = rr.Read(make([]byte, BlockDataSize))
	require.Error(t, err, "the reader's copy is corrupt and was deleted; there is nothing to read")
	require.True(t, fired, "the repair should have found block 1 corrupt")

	all := make([]uint32, tornObjectBlocks)
	for i := range all {
		all[i] = uint32(i)
	}
	assert.Equal(t, all, env.presentBlocks(t), "a repair of the deleted instance cleared blocks of the new one")
	state, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.Equal(t, uint64(tornObjectBlocks), state.GetCardinality(), "nor may it clear them from the new instance's block state")
	got, err := env.storage.ReadBlocks(env.hash, BlockDataSize, BlockDataSize)
	require.NoError(t, err)
	assert.Equal(t, env.data[BlockDataSize:2*BlockDataSize], got)
	assert.Zero(t, env.storage.fences.size())
}

// TestObjectPathsOnlyFromWellFormedHashes checks that an object's path is
// built only from a well-formed instance hash -- 64 lowercase hex digits,
// as the cache computes them -- so that no other string can name a file,
// let alone one outside the storage directory, and that creating an object
// under any other hash fails.
func TestObjectPathsOnlyFromWellFormedHashes(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	good := InstanceHash(strings.Repeat("ab", 32))
	assert.NotEmpty(t, env.storage.getObjectPathForDir(env.diskID(), good))
	for _, bad := range []InstanceHash{
		"",
		"../../../../etc/passwd",
		InstanceHash("../" + strings.Repeat("a", 61)),
		InstanceHash(strings.Repeat("a", 63)),
		InstanceHash(strings.Repeat("A", 64)),
		InstanceHash(strings.Repeat("a", 62) + "/x"),
	} {
		require.Empty(t, env.storage.getObjectPathForDir(env.diskID(), bad), "%q", bad)
		assert.Empty(t, env.storage.getChunkPath(env.diskID(), bad, 2), "%q", bad)
		_, err := env.storage.InitDiskStorage(context.Background(), bad, 100, env.diskID(), 1)
		assert.Error(t, err, "%q", bad)
	}
}

// TestCachingADescriptorReleasesTheOneItReplaces checks that caching a
// descriptor under a key the cache already holds releases the cache's
// reference to the one it replaces.  The cache's own Set replaces a value
// without its eviction callback, so that descriptor stayed open for the
// life of the process -- and on Windows, where an open file cannot be
// deleted, kept the object's file from ever being removed.
func TestCachingADescriptorReleasesTheOneItReplaces(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.fdCacheMaxSize = 1024
	path := env.storage.getObjectPathForDir(env.diskID(), env.hash)
	key := chunkFileKey{instanceHash: env.hash, chunkIndex: 0}
	open := func() *refCountedFile {
		f, err := os.Open(path)
		require.NoError(t, err)
		return newRefCountedFile(f)
	}

	first := open()
	env.storage.cacheFile(key, first)
	first.Release() // the opener's reference; the cache's remains
	require.EqualValues(t, 1, first.refs.Load())

	second := open()
	env.storage.cacheFile(key, second)
	second.Release()

	// The cache releases an evicted descriptor on a goroutine of its own.
	require.Eventually(t, func() bool { return first.refs.Load() == 0 }, 10*time.Second, time.Millisecond,
		"the replaced descriptor's cache reference must be released")
	// A closed file fails Stat on every platform, with an error that
	// differs between them (os.ErrClosed is Unix's).
	_, err := first.File().Stat()
	assert.Error(t, err, "the replaced descriptor must be closed")
	assert.EqualValues(t, 1, second.refs.Load())
}

// TestCloseClosesEveryCachedDescriptor checks that the storage manager's
// Close has closed every cached descriptor by the time it returns.  The
// cache closes them on goroutines of its own; a file still open after
// Close cannot be deleted on Windows.
func TestCloseClosesEveryCachedDescriptor(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	env.storage.fdCacheMaxSize = 1024
	f, err := os.Open(env.storage.getObjectPathForDir(env.diskID(), env.hash))
	require.NoError(t, err)
	rc := newRefCountedFile(f)
	env.storage.cacheFile(chunkFileKey{instanceHash: env.hash, chunkIndex: 0}, rc)
	rc.Release()

	env.storage.Close()
	assert.EqualValues(t, 0, rc.refs.Load(), "Close must not return before the cache has released its descriptors")
	_, err = rc.File().Stat()
	assert.Error(t, err, "the descriptor must be closed")
}
