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
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TestMetadataScanSparesAFileItsObjectMovedTo checks that the metadata scan
// re-reads an object's record before deleting one of its files as misplaced.
// The scan decides against a snapshot that can be seconds old; an object
// relocated to another directory in the meantime owns exactly the file the
// snapshot says is in the wrong place.
func TestMetadataScanSparesAFileItsObjectMovedTo(t *testing.T) {
	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dirA, dirB := t.TempDir(), t.TempDir()
	db, err := NewCacheDB(ctx, dirA)
	require.NoError(t, err)
	defer db.Close()
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dirA, dirB}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()
	ids := storage.DirIDs()
	require.Len(t, ids, 2)
	from, to := ids[0], ids[1]

	hash := InstanceHash(fmt.Sprintf("%064d", 5))
	require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
		ContentLength: 100,
		NamespaceID:   1,
		StorageID:     from,
		Completed:     time.Now().Add(-time.Hour),
	}))
	// The file is already where the object is about to be moved.
	path := storage.getObjectPathForDir(to, hash)
	f, err := createFile(path)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{MetadataScanActiveMs: 1000, MinAgeForCleanup: 0})
	checker.beforeMetadataDeletions = func() {
		meta, err := db.GetMetadata(hash)
		require.NoError(t, err)
		meta.StorageID = to
		require.NoError(t, db.SetMetadata(hash, meta))
	}
	require.NoError(t, checker.RunMetadataScan(ctx, nil))

	_, err = os.Stat(path)
	assert.NoError(t, err, "the file the object now lives in must not be deleted")
	meta, err := db.GetMetadata(hash)
	require.NoError(t, err)
	assert.NotNil(t, meta, "the object is consistent again and must not be dropped")
}

// scanEnv is a cache with two storage directories, for metadata-scan tests.
func scanEnv(t *testing.T) (context.Context, *CacheDB, *StorageManager, StorageID, StorageID) {
	t.Helper()
	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dirA, dirB := t.TempDir(), t.TempDir()
	db, err := NewCacheDB(ctx, dirA)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dirA, dirB}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(func() { storage.Close() })
	ids := storage.DirIDs()
	require.Len(t, ids, 2)
	return ctx, db, storage, ids[0], ids[1]
}

// oldFile creates a file last modified two hours ago.
func oldFile(t *testing.T, path string) {
	t.Helper()
	f, err := createFile(path)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(path, old, old))
}

// TestMetadataScanSparesTheFilesOfAYoungEntry checks that the files of an
// entry too young to check are passed over with it, even when no later entry
// follows to claim them.  A file is often much older than its entry's
// Completed time: the first chunk of a large object is written long before
// the last, and a repair completes the object again.
func TestMetadataScanSparesTheFilesOfAYoungEntry(t *testing.T) {
	ctx, db, storage, a, _ := scanEnv(t)
	hash := InstanceHash(strings.Repeat("f", 64)) // the last entry in key order
	require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
		ContentLength: 100, NamespaceID: 1, StorageID: a, Completed: time.Now(),
	}))
	path := storage.getObjectPathForDir(a, hash)
	oldFile(t, path)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{MetadataScanActiveMs: 1000, MinAgeForCleanup: time.Minute})
	require.NoError(t, checker.RunMetadataScan(ctx, nil))
	_, err := os.Stat(path)
	assert.NoError(t, err, "the file of a live object must not be deleted")
}

// TestMetadataScanKeepsTheChunksAnEntryExpects checks that deleting a
// misplaced base file does not take with it a chunk file beside it that the
// object's record expects in that directory.
func TestMetadataScanKeepsTheChunksAnEntryExpects(t *testing.T) {
	ctx, db, storage, a, b := scanEnv(t)
	hash := InstanceHash(strings.Repeat("3", 64))
	require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
		ContentLength:  3 << 20,
		NamespaceID:    1,
		StorageID:      b,                               // chunk 0 lives in B
		ChunkSizeCode:  1,                               // 2 MB chunks, so two of them
		ChunkLocations: []ChunkLocation{{StorageID: a}}, // chunk 1 lives in A
		Completed:      time.Now().Add(-time.Hour),
	}))
	oldFile(t, storage.getChunkPath(b, hash, 0))
	stale := storage.getChunkPath(a, hash, 0) // left behind, misplaced
	oldFile(t, stale)
	wanted := storage.getChunkPath(a, hash, 1)
	oldFile(t, wanted)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{MetadataScanActiveMs: 1000, MinAgeForCleanup: 0})
	require.NoError(t, checker.RunMetadataScan(ctx, nil))
	_, err := os.Stat(stale)
	assert.True(t, os.IsNotExist(err), "the misplaced base file must be removed")
	_, err = os.Stat(wanted)
	assert.NoError(t, err, "the chunk the record expects in A must be kept")
}

// TestMetadataScanRemovesEveryChunkOfAnOrphan checks that the scan removes
// each chunk file of an object it has no use for -- in any directory, out of
// order, beside a base file or without one -- from the walk alone, without
// listing a base file's directory to find them.
func TestMetadataScanRemovesEveryChunkOfAnOrphan(t *testing.T) {
	ctx, db, storage, a, b := scanEnv(t)

	// No record at all: a base file and chunks 1 and 10 in A, chunk 2 in B.
	orphan := InstanceHash(strings.Repeat("1", 64))
	orphanFiles := []string{
		storage.getChunkPath(a, orphan, 0),
		storage.getChunkPath(a, orphan, 1),
		storage.getChunkPath(a, orphan, 10),
		storage.getChunkPath(b, orphan, 2),
	}

	// A record that puts both chunks in B, and a stale copy of both in A.
	moved := InstanceHash(strings.Repeat("2", 64))
	require.NoError(t, db.SetMetadata(moved, &CacheMetadata{
		ContentLength:  3 << 20,
		NamespaceID:    1,
		StorageID:      b,
		ChunkSizeCode:  1, // 2 MB chunks, so two of them
		ChunkLocations: []ChunkLocation{{StorageID: b}},
		Completed:      time.Now().Add(-time.Hour),
	}))
	staleFiles := []string{storage.getChunkPath(a, moved, 0), storage.getChunkPath(a, moved, 1)}
	liveFiles := []string{storage.getChunkPath(b, moved, 0), storage.getChunkPath(b, moved, 1)}

	for _, path := range append(append(append([]string{}, orphanFiles...), staleFiles...), liveFiles...) {
		oldFile(t, path)
	}

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{MetadataScanActiveMs: 1000, MinAgeForCleanup: 0})
	require.NoError(t, checker.RunMetadataScan(ctx, nil))
	for _, path := range append(append([]string{}, orphanFiles...), staleFiles...) {
		_, err := os.Stat(path)
		assert.True(t, os.IsNotExist(err), "%s must be removed", path)
	}
	for _, path := range liveFiles {
		_, err := os.Stat(path)
		assert.NoError(t, err, "%s is the object's and must be kept", path)
	}
}

// TestMetadataScanForgetsTheBlockStateOfAnEntryItDrops checks that when the
// scan drops an entry whose files are gone, it drops the in-memory block
// state too -- even one a reader still holds.  Otherwise the object, fetched
// again under the same hash with a new data key and an empty file, would be
// handed the old state and take blocks it does not have for present.
func TestMetadataScanForgetsTheBlockStateOfAnEntryItDrops(t *testing.T) {
	env := newTornBlockEnv(t, tornObjectBlocks*BlockDataSize-17)
	bw, err := env.storage.NewBlockWriter(env.hash, 0, nil, nil)
	require.NoError(t, err)
	_, err = bw.Write(env.data[:BlockDataSize])
	require.NoError(t, err)
	require.NoError(t, bw.Close())
	held, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	require.True(t, held.Contains(0))

	// The object's file goes missing.
	meta, err := env.storage.GetMetadata(env.hash)
	require.NoError(t, err)
	require.NoError(t, env.storage.MergeMetadata(env.hash, &CacheMetadata{Completed: time.Now().Add(-time.Hour)}))
	require.NoError(t, os.Remove(env.storage.getObjectPathForDir(meta.StorageID, env.hash)))

	checker := NewConsistencyChecker(env.db, env.storage, ConsistencyConfig{MetadataScanActiveMs: 1000, MinAgeForCleanup: 0})
	require.NoError(t, checker.RunMetadataScan(context.Background(), nil))
	gone, err := env.db.GetMetadata(env.hash)
	require.NoError(t, err)
	require.Nil(t, gone, "the scan drops an entry whose file is missing")

	_, err = env.storage.InitDiskStorage(context.Background(), env.hash, tornObjectBlocks*BlockDataSize-17, meta.StorageID, 1)
	require.NoError(t, err)
	fresh, err := env.storage.GetSharedBlockState(env.hash)
	require.NoError(t, err)
	assert.False(t, fresh.Contains(0), "the re-created object must not inherit the dropped one's blocks")
	runtime.KeepAlive(held)
}
