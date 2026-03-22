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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestChunkSizeEncoding(t *testing.T) {
	// Test the ChunkSizeCode encoding and decoding

	t.Run("ChunkSizeCodeZero", func(t *testing.T) {
		// Code 0 means chunking is disabled
		bytes := ChunkSizeCodeToBytes(0)
		assert.Equal(t, uint64(0), bytes, "Code 0 should represent 0 (disabled)")
	})

	t.Run("SmallPowerOfTwo", func(t *testing.T) {
		// Codes 1-6 are ~2^code MB, rounded down to block boundary
		// BlockDataSize = 4080, so sizes are (N_MB / 4080) * 4080
		expectedSizes := []uint64{
			(2 * 1024 * 1024 / BlockDataSize) * BlockDataSize,  // ~2MB
			(4 * 1024 * 1024 / BlockDataSize) * BlockDataSize,  // ~4MB
			(8 * 1024 * 1024 / BlockDataSize) * BlockDataSize,  // ~8MB
			(16 * 1024 * 1024 / BlockDataSize) * BlockDataSize, // ~16MB
			(32 * 1024 * 1024 / BlockDataSize) * BlockDataSize, // ~32MB
			(64 * 1024 * 1024 / BlockDataSize) * BlockDataSize, // ~64MB
		}
		for i, expected := range expectedSizes {
			code := ChunkSizeCode(i + 1)
			bytes := ChunkSizeCodeToBytes(code)
			assert.Equal(t, expected, bytes, "Code %d should be block-aligned ~%dMB", code, 1<<(i+1))
		}
	})

	t.Run("BlockAligned", func(t *testing.T) {
		// All chunk sizes should be block-aligned
		for code := ChunkSizeCode(1); code <= 50; code++ {
			bytes := ChunkSizeCodeToBytes(code)
			assert.Equal(t, uint64(0), bytes%BlockDataSize, "Code %d size should be block-aligned", code)
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		// Test round-trip encoding for various sizes
		testSizes := []uint64{
			2 * 1024 * 1024,    // 2MB
			64 * 1024 * 1024,   // 64MB
			128 * 1024 * 1024,  // 128MB
			256 * 1024 * 1024,  // 256MB
			1024 * 1024 * 1024, // 1GB
		}
		for _, size := range testSizes {
			code := BytesToChunkSizeCode(size)
			decoded := ChunkSizeCodeToBytes(code)
			// Due to block alignment, decoded may be slightly less than the nominal size
			// but should be large enough to hold at least size - BlockDataSize bytes
			assert.Greater(t, decoded+BlockDataSize, size, "Decoded size should be close to original for size %d", size)
		}
	})
}

func TestCalculateChunkCount(t *testing.T) {
	t.Run("ChunkingDisabled", func(t *testing.T) {
		// ChunkSizeCode 0 means disabled, always 1 chunk
		count := CalculateChunkCount(1000*1024*1024, 0)
		assert.Equal(t, 1, count)
	})

	t.Run("SmallObject", func(t *testing.T) {
		// Object smaller than chunk size
		chunkSize := BytesToChunkSizeCode(64 * 1024 * 1024) // 64MB
		count := CalculateChunkCount(10*1024*1024, chunkSize)
		assert.Equal(t, 1, count, "10MB object with 64MB chunks should have 1 chunk")
	})

	t.Run("ExactMultiple", func(t *testing.T) {
		chunkSizeCode := BytesToChunkSizeCode(uint64(64 * 1024 * 1024)) // Request ~64MB
		actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))   // Get block-aligned size
		contentLength := actualChunkSize * 2                            // Exactly 2 chunks
		count := CalculateChunkCount(contentLength, chunkSizeCode)
		assert.Equal(t, 2, count, "Object with exactly 2 block-aligned chunks should have 2 chunks")
	})

	t.Run("PartialChunk", func(t *testing.T) {
		chunkSizeCode := BytesToChunkSizeCode(uint64(64 * 1024 * 1024)) // Request ~64MB
		actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))   // Get block-aligned size
		contentLength := actualChunkSize + (actualChunkSize / 2)        // 1.5 chunks
		count := CalculateChunkCount(contentLength, chunkSizeCode)
		assert.Equal(t, 2, count, "Object with 1.5 chunks should have 2 chunks")
	})
}

func TestChunkPathNaming(t *testing.T) {
	basePath := "/data/ab/cd/ef0123456789"

	t.Run("ChunkZero", func(t *testing.T) {
		path := GetChunkPath(basePath, 0)
		assert.Equal(t, basePath, path, "Chunk 0 should use base path")
	})

	t.Run("ChunkOne", func(t *testing.T) {
		path := GetChunkPath(basePath, 1)
		assert.Equal(t, basePath+"-2", path, "Chunk 1 should have -2 suffix")
	})

	t.Run("ChunkTwo", func(t *testing.T) {
		path := GetChunkPath(basePath, 2)
		assert.Equal(t, basePath+"-3", path, "Chunk 2 should have -3 suffix")
	})
}

func TestChunkedObjectWriteRead(t *testing.T) {
	InitIssuerKeyForTests(t)

	// Create three directories for multi-disk chunking
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dir3 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2, dir3}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 3, "Should have 3 storage directories")

	// Create test data: 3 chunks worth
	chunkSizeBytes := int64(2 * 1024 * 1024) // 2MB per chunk for testing
	chunkSizeCode := BytesToChunkSizeCode(uint64(chunkSizeBytes))
	objectSize := chunkSizeBytes*2 + 500*1024 // 2.5 chunks worth

	// Generate test data with a pattern we can verify
	testData := make([]byte, objectSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0x12345678))

	// Initialize lazy chunked storage and allocate all chunks
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.Equal(t, chunkSizeCode, meta.ChunkSizeCode)
	assert.Len(t, meta.ChunkLocations, 2, "Should have 2 chunk locations (for chunks 1 and 2)")

	chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
	for i := 0; i < chunkCount; i++ {
		meta, err = storage.AllocateChunk(ctx, instanceHash, meta, i)
		require.NoError(t, err)
	}

	// Write all data
	err = storage.WriteBlocks(instanceHash, 0, testData)
	require.NoError(t, err)

	// Mark as completed
	meta.Completed = time.Now()
	err = storage.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Verify all chunk files exist
	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		storageID := meta.GetChunkStorageID(chunkIdx)
		chunkPath := storage.getChunkPath(storageID, instanceHash, chunkIdx)
		_, err := os.Stat(chunkPath)
		require.NoError(t, err, "Chunk %d file should exist at %s", chunkIdx, chunkPath)
	}

	// Read back all data and verify
	readData, err := storage.ReadBlocks(instanceHash, 0, int(objectSize))
	require.NoError(t, err)
	assert.Equal(t, len(testData), len(readData), "Should read all bytes")
	assert.Equal(t, testData, readData, "Read data should match written data")

	t.Run("ReadAcrossChunkBoundary", func(t *testing.T) {
		// Read data that spans chunk 0 and chunk 1
		boundaryStart := chunkSizeBytes - 1000
		boundaryLen := 2000

		// Read from the boundary start
		boundaryData, err := storage.ReadBlocks(instanceHash, boundaryStart, boundaryLen)
		require.NoError(t, err)
		require.Greater(t, len(boundaryData), 0)

		// Extract the expected data from testData
		expected := testData[boundaryStart : boundaryStart+int64(boundaryLen)]
		assert.Equal(t, expected, boundaryData[:boundaryLen], "Data across chunk boundary should match")
	})
}

func TestChunkedObjectEviction(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create a chunked object using actual block-aligned chunk size
	chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024))
	actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	objectSize := actualChunkSize * 2 // 2 full chunks

	testData := make([]byte, objectSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xABCD))

	// Initialize lazy chunked storage and allocate all chunks
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
	for i := 0; i < chunkCount; i++ {
		meta, err = storage.AllocateChunk(ctx, instanceHash, meta, i)
		require.NoError(t, err)
	}

	err = storage.WriteBlocks(instanceHash, 0, testData)
	require.NoError(t, err)

	meta.Completed = time.Now()
	meta.NamespaceID = 1
	err = storage.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Record chunk paths before deletion
	var chunkPaths []string
	for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
		storageID := meta.GetChunkStorageID(chunkIdx)
		chunkPath := storage.getChunkPath(storageID, instanceHash, chunkIdx)
		chunkPaths = append(chunkPaths, chunkPath)
		// Verify chunks exist
		_, err := os.Stat(chunkPath)
		require.NoError(t, err, "Chunk %d should exist before deletion", chunkIdx)
	}

	// Delete the object
	err = storage.Delete(instanceHash)
	require.NoError(t, err)

	// Verify all chunk files are deleted
	for chunkIdx, chunkPath := range chunkPaths {
		_, err := os.Stat(chunkPath)
		assert.True(t, os.IsNotExist(err), "Chunk %d should be deleted: %s", chunkIdx, chunkPath)
	}

	// Verify metadata is deleted
	gotMeta, err := storage.GetMetadata(instanceHash)
	require.NoError(t, err)
	assert.Nil(t, gotMeta, "Metadata should be deleted")
}

func TestChunkedObjectEvictByLRU(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create multiple chunked objects using actual block-aligned chunk size
	chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024))
	actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))

	type objectRecord struct {
		instanceHash InstanceHash
		chunkPaths   []string
	}
	var objects []objectRecord

	for i := 0; i < 3; i++ {
		objectSize := actualChunkSize * 2 // 2 chunks each

		testData := make([]byte, objectSize)
		for j := range testData {
			testData[j] = byte((i + j) % 256)
		}

		instanceHash := InstanceHash(fmt.Sprintf("%064x", i+0x100))

		// Initialize lazy chunked storage and allocate all chunks
		meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
		require.NoError(t, err)

		chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
		for ci := 0; ci < chunkCount; ci++ {
			meta, err = storage.AllocateChunk(ctx, instanceHash, meta, ci)
			require.NoError(t, err)
		}

		err = storage.WriteBlocks(instanceHash, 0, testData)
		require.NoError(t, err)

		meta.Completed = time.Now()
		meta.NamespaceID = 1
		err = storage.SetMetadata(instanceHash, meta)
		require.NoError(t, err)

		// Update LRU access time with small difference
		err = db.UpdateLRU(instanceHash, time.Duration(i)*time.Second)
		require.NoError(t, err)

		// Record chunk paths
		var chunkPaths []string
		for chunkIdx := 0; chunkIdx < chunkCount; chunkIdx++ {
			storID := meta.GetChunkStorageID(chunkIdx)
			chunkPath := storage.getChunkPath(storID, instanceHash, chunkIdx)
			chunkPaths = append(chunkPaths, chunkPath)
		}

		objects = append(objects, objectRecord{
			instanceHash: instanceHash,
			chunkPaths:   chunkPaths,
		})
	}

	// Evict the oldest object (first one)
	evicted, totalFreed, err := storage.EvictByLRU(StorageIDFirstDisk, 1, 1, actualChunkSize*2)
	require.NoError(t, err)
	assert.Len(t, evicted, 1, "Should evict 1 object")
	assert.Greater(t, totalFreed, uint64(0), "Should free some bytes")

	// Verify the evicted object's chunk files are gone
	for _, chunkPath := range objects[0].chunkPaths {
		_, err := os.Stat(chunkPath)
		assert.True(t, os.IsNotExist(err), "Evicted chunk should be deleted: %s", chunkPath)
	}

	// Verify non-evicted objects still exist
	for i := 1; i < len(objects); i++ {
		for _, chunkPath := range objects[i].chunkPaths {
			_, err := os.Stat(chunkPath)
			assert.NoError(t, err, "Non-evicted chunk should still exist: %s", chunkPath)
		}
	}
}

func TestChunkLocationDistribution(t *testing.T) {
	// This test verifies that chunk metadata correctly captures distributed storage IDs
	// by manually creating a chunked object with chunks spread across directories
	InitIssuerKeyForTests(t)

	// Create 4 directories to test distribution
	dirs := make([]string, 4)
	for i := range dirs {
		dirs[i] = t.TempDir()
	}
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, dirs, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	require.Len(t, storage.GetDirs(), 4, "Should have 4 storage directories")

	// Create a large chunked object using actual block-aligned chunk size
	chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024))
	actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	objectSize := actualChunkSize * 5 // 5 full chunks

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xDEADBEEF))

	// Initialize lazy chunked storage and allocate all chunks
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
	for i := 0; i < chunkCount; i++ {
		meta, err = storage.AllocateChunk(ctx, instanceHash, meta, i)
		require.NoError(t, err)
	}

	// Verify chunks are tracked as distributed across different directories
	allIDs := meta.AllStorageIDs()
	usedStorageIDs := make(map[StorageID]bool)
	for _, id := range allIDs {
		usedStorageIDs[id] = true
	}

	// With 5 chunks and 4 directories, we expect at least 2 directories to be used
	assert.Greater(t, len(usedStorageIDs), 1, "Chunks should be distributed across multiple directories")

	t.Logf("Chunk distribution uses %d unique storage IDs: %v", len(usedStorageIDs), allIDs)
}

func TestChunkedObjectConsistencyVerification(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, egCtx := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create a chunked object using actual block-aligned chunk size
	chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024))
	actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	objectSize := actualChunkSize * 2 // 2 full chunks

	testData := make([]byte, objectSize)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xCAFE))

	// Initialize lazy chunked storage and allocate all chunks
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	chunkCount := CalculateChunkCount(objectSize, chunkSizeCode)
	for i := 0; i < chunkCount; i++ {
		meta, err = storage.AllocateChunk(ctx, instanceHash, meta, i)
		require.NoError(t, err)
	}

	err = storage.WriteBlocks(instanceHash, 0, testData)
	require.NoError(t, err)

	meta.Completed = time.Now()
	meta.NamespaceID = 1
	err = storage.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Create consistency checker
	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MinAgeForCleanup: 0, // Allow immediate cleanup for tests
	})

	t.Run("AllChunksPresent", func(t *testing.T) {
		valid, err := checker.VerifyObject(instanceHash)
		require.NoError(t, err)
		assert.True(t, valid, "Object with all chunks present should be valid")
	})

	t.Run("MissingChunk", func(t *testing.T) {
		// Delete the second chunk file
		chunkPath := storage.getChunkPath(meta.ChunkLocations[0].StorageID, instanceHash, 1)
		err := os.Remove(chunkPath)
		require.NoError(t, err)

		valid, err := checker.VerifyObject(instanceHash)
		require.NoError(t, err)
		assert.False(t, valid, "Object with missing chunk should be invalid")
	})

	t.Run("MetadataScanDetectsMissingChunks", func(t *testing.T) {
		// Run a metadata scan - it should detect the orphaned DB entry
		err := checker.RunMetadataScan(egCtx, nil)
		require.NoError(t, err)

		// The object should have been cleaned up (DB entry deleted)
		gotMeta, err := storage.GetMetadata(instanceHash)
		require.NoError(t, err)
		assert.Nil(t, gotMeta, "Orphaned DB entry should be cleaned up by metadata scan")
	})
}

func TestChunkContentOffsetMapping(t *testing.T) {
	chunkSizeCode := BytesToChunkSizeCode(uint64(64 * 1024 * 1024)) // Request 64MB
	actualChunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))   // Get block-aligned size

	testCases := []struct {
		offset         int64
		expectedChunk  int
		expectedGlobal uint32
	}{
		{0, 0, 0},                 // Start of file
		{BlockDataSize - 1, 0, 0}, // End of first block
		{BlockDataSize, 0, 1},     // Start of second block
		{actualChunkSize - 1, 0, ContentOffsetToBlock(actualChunkSize - 1)},                         // End of chunk 0
		{actualChunkSize, 1, ContentOffsetToBlock(actualChunkSize)},                                 // Start of chunk 1
		{actualChunkSize + BlockDataSize, 1, ContentOffsetToBlock(actualChunkSize + BlockDataSize)}, // Second block of chunk 1
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Offset_%d", tc.offset), func(t *testing.T) {
			chunkIdx := ContentOffsetToChunk(tc.offset, chunkSizeCode)
			assert.Equal(t, tc.expectedChunk, chunkIdx, "Chunk index mismatch")

			globalBlock := ContentOffsetToBlock(tc.offset)
			assert.Equal(t, tc.expectedGlobal, globalBlock, "Global block number mismatch")
		})
	}
}

func TestCacheMetadataChunkMethods(t *testing.T) {
	t.Run("NonChunked", func(t *testing.T) {
		meta := &CacheMetadata{
			StorageID:     StorageIDFirstDisk,
			ContentLength: 1000,
			ChunkSizeCode: 0, // Disabled
		}

		assert.False(t, meta.IsChunked())
		assert.Equal(t, 1, meta.ChunkCount())
		assert.Equal(t, StorageIDFirstDisk, meta.GetChunkStorageID(0))
	})

	t.Run("Chunked", func(t *testing.T) {
		chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024)) // 2MB
		meta := &CacheMetadata{
			StorageID:     StorageIDFirstDisk,
			ContentLength: 5 * 1024 * 1024, // 5MB = 3 chunks
			ChunkSizeCode: chunkSizeCode,
			ChunkLocations: []ChunkLocation{
				{StorageID: StorageIDFirstDisk + 1},
				{StorageID: StorageIDFirstDisk + 2},
			},
		}

		assert.True(t, meta.IsChunked())
		assert.Equal(t, 3, meta.ChunkCount())

		// Chunk 0 uses base StorageID
		assert.Equal(t, StorageIDFirstDisk, meta.GetChunkStorageID(0))
		// Chunks 1+ use ChunkLocations
		assert.Equal(t, StorageIDFirstDisk+1, meta.GetChunkStorageID(1))
		assert.Equal(t, StorageIDFirstDisk+2, meta.GetChunkStorageID(2))

		// AllStorageIDs should return all unique IDs
		allIDs := meta.AllStorageIDs()
		assert.Len(t, allIDs, 3)
	})
}

func TestOrphanedChunkFileCleanup(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, egCtx := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create orphaned chunk files (no DB entry)
	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xDEAD))
	objectsDir := filepath.Join(dir1, "objects")
	require.NoError(t, os.MkdirAll(objectsDir, 0755))

	// Create subdirectories for the file path
	basePath := filepath.Join(objectsDir, GetInstanceStoragePath(instanceHash))
	require.NoError(t, os.MkdirAll(filepath.Dir(basePath), 0755))

	// Create orphaned chunk files
	require.NoError(t, os.WriteFile(basePath, []byte("chunk0"), 0644))
	require.NoError(t, os.WriteFile(basePath+"-2", []byte("chunk1"), 0644))
	require.NoError(t, os.WriteFile(basePath+"-3", []byte("chunk2"), 0644))

	// Set modification time to past (to pass age check)
	pastTime := time.Now().Add(-10 * time.Minute)
	require.NoError(t, os.Chtimes(basePath, pastTime, pastTime))
	require.NoError(t, os.Chtimes(basePath+"-2", pastTime, pastTime))
	require.NoError(t, os.Chtimes(basePath+"-3", pastTime, pastTime))

	// Create consistency checker
	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MinAgeForCleanup: 0, // Allow immediate cleanup for tests
	})

	// Run metadata scan
	err = checker.RunMetadataScan(egCtx, nil)
	require.NoError(t, err)

	// Verify all chunk files are removed
	_, err = os.Stat(basePath)
	assert.True(t, os.IsNotExist(err), "Base chunk file should be removed")
	_, err = os.Stat(basePath + "-2")
	assert.True(t, os.IsNotExist(err), "Chunk 1 file should be removed")
	_, err = os.Stat(basePath + "-3")
	assert.True(t, os.IsNotExist(err), "Chunk 2 file should be removed")
}

// TestOrphanedChunkFilesWithoutBaseFile verifies that orphaned chunk suffix files
// are cleaned up even when chunk 0 (the base file) doesn't exist.
// This can happen when a user starts downloading from the middle of a file
// using byte-range requests.
func TestOrphanedChunkFilesWithoutBaseFile(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, egCtx := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create orphaned chunk files WITHOUT the base file (chunk 0)
	// This simulates a user who started downloading from the middle
	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xBEEF))
	objectsDir := filepath.Join(dir1, "objects")
	require.NoError(t, os.MkdirAll(objectsDir, 0755))

	// Create subdirectories for the file path
	basePath := filepath.Join(objectsDir, GetInstanceStoragePath(instanceHash))
	require.NoError(t, os.MkdirAll(filepath.Dir(basePath), 0755))

	// Only create chunk suffix files, NOT the base file (chunk 0)
	require.NoError(t, os.WriteFile(basePath+"-2", []byte("chunk1"), 0644))
	require.NoError(t, os.WriteFile(basePath+"-3", []byte("chunk2"), 0644))

	// Set modification time to past (to pass age check)
	pastTime := time.Now().Add(-10 * time.Minute)
	require.NoError(t, os.Chtimes(basePath+"-2", pastTime, pastTime))
	require.NoError(t, os.Chtimes(basePath+"-3", pastTime, pastTime))

	// Create consistency checker
	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MinAgeForCleanup: 0, // Allow immediate cleanup for tests
	})

	// Run metadata scan
	err = checker.RunMetadataScan(egCtx, nil)
	require.NoError(t, err)

	// Verify orphaned chunk files are removed even without base file
	_, err = os.Stat(basePath + "-2")
	assert.True(t, os.IsNotExist(err), "Orphaned chunk 1 file should be removed")
	_, err = os.Stat(basePath + "-3")
	assert.True(t, os.IsNotExist(err), "Orphaned chunk 2 file should be removed")
}

// TestOrphanedNonSequentialChunkFiles verifies that orphaned chunk suffix files
// are cleaned up when there are gaps in chunk indices (e.g. chunk -3 exists
// but chunk -2 does not). This tests the fix for the non-sequential chunk
// allocation pattern.
func TestOrphanedNonSequentialChunkFiles(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, egCtx := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	// Create orphaned chunk files with a gap: base + chunk -3 but NO chunk -2
	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xFACE))
	objectsDir := filepath.Join(dir1, "objects")
	require.NoError(t, os.MkdirAll(objectsDir, 0755))

	basePath := filepath.Join(objectsDir, GetInstanceStoragePath(instanceHash))
	require.NoError(t, os.MkdirAll(filepath.Dir(basePath), 0755))

	require.NoError(t, os.WriteFile(basePath, []byte("chunk0"), 0644))
	// Skip -2, create -3 and -4
	require.NoError(t, os.WriteFile(basePath+"-3", []byte("chunk2"), 0644))
	require.NoError(t, os.WriteFile(basePath+"-4", []byte("chunk3"), 0644))

	pastTime := time.Now().Add(-10 * time.Minute)
	require.NoError(t, os.Chtimes(basePath, pastTime, pastTime))
	require.NoError(t, os.Chtimes(basePath+"-3", pastTime, pastTime))
	require.NoError(t, os.Chtimes(basePath+"-4", pastTime, pastTime))

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MinAgeForCleanup: 0,
	})

	err = checker.RunMetadataScan(egCtx, nil)
	require.NoError(t, err)

	// All orphaned chunk files should be removed, including the ones after the gap
	_, err = os.Stat(basePath)
	assert.True(t, os.IsNotExist(err), "Base file should be removed")
	_, err = os.Stat(basePath + "-3")
	assert.True(t, os.IsNotExist(err), "Chunk -3 should be removed despite gap")
	_, err = os.Stat(basePath + "-4")
	assert.True(t, os.IsNotExist(err), "Chunk -4 should be removed despite gap")
}

// TestLazyChunkAllocation verifies that chunk storage IDs can be lazily allocated
// and that files are only created when chunks are written.
func TestLazyChunkAllocation(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dir3 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2, dir3}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xCAFE))
	objectSize := int64(4 * 1024 * 1024) // 4MB
	chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	expectedChunks := CalculateChunkCount(objectSize, chunkSizeCode)

	// Initialize lazy chunked storage (no files created)
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	// Verify initial state: all chunks unallocated
	assert.Equal(t, ChunkSizeCode(chunkSizeCode), meta.ChunkSizeCode)
	assert.Equal(t, expectedChunks, meta.ChunkCount())
	for i := 0; i < expectedChunks; i++ {
		assert.False(t, meta.IsChunkAllocated(i), "Chunk %d should be unallocated", i)
	}

	// Verify no files exist yet
	for storageID := StorageIDFirstDisk; storageID <= StorageIDFirstDisk+2; storageID++ {
		for chunkIdx := 0; chunkIdx < expectedChunks; chunkIdx++ {
			chunkPath := storage.getChunkPath(storageID, instanceHash, chunkIdx)
			_, err := os.Stat(chunkPath)
			assert.True(t, os.IsNotExist(err), "Chunk %d should not exist yet", chunkIdx)
		}
	}

	// Allocate chunk 1 first (out of order, simulating byte-range download)
	meta, err = storage.AllocateChunk(ctx, instanceHash, meta, 1)
	require.NoError(t, err)

	// Verify chunk 1 is now allocated but chunk 0 is not
	assert.False(t, meta.IsChunkAllocated(0), "Chunk 0 should still be unallocated")
	assert.True(t, meta.IsChunkAllocated(1), "Chunk 1 should be allocated")
	chunk1StorageID := meta.GetChunkStorageID(1)
	assert.NotEqual(t, StorageIDInline, chunk1StorageID, "Chunk 1 should have a real storage ID")

	// Verify only chunk 1 file exists
	chunk1Path := storage.getChunkPath(chunk1StorageID, instanceHash, 1)
	_, err = os.Stat(chunk1Path)
	assert.NoError(t, err, "Chunk 1 file should exist after allocation")

	// Verify chunk 0 file doesn't exist anywhere
	for storageID := StorageIDFirstDisk; storageID <= StorageIDFirstDisk+2; storageID++ {
		chunk0Path := storage.getChunkPath(storageID, instanceHash, 0)
		_, err := os.Stat(chunk0Path)
		assert.True(t, os.IsNotExist(err), "Chunk 0 file should not exist")
	}

	// Allocate chunk 0
	meta, err = storage.AllocateChunk(ctx, instanceHash, meta, 0)
	require.NoError(t, err)

	// Verify both chunks are now allocated
	assert.True(t, meta.IsChunkAllocated(0), "Chunk 0 should be allocated")
	assert.True(t, meta.IsChunkAllocated(1), "Chunk 1 should be allocated")
	chunk0StorageID := meta.GetChunkStorageID(0)
	assert.NotEqual(t, StorageIDInline, chunk0StorageID, "Chunk 0 should have a real storage ID")

	// Verify both chunk files exist
	chunk0Path := storage.getChunkPath(chunk0StorageID, instanceHash, 0)
	_, err = os.Stat(chunk0Path)
	assert.NoError(t, err, "Chunk 0 file should exist after allocation")
	_, err = os.Stat(chunk1Path)
	assert.NoError(t, err, "Chunk 1 file should still exist")

	// Verify chunks are distributed across different directories (round-robin)
	t.Logf("Chunk 0 in storage %d, Chunk 1 in storage %d", chunk0StorageID, chunk1StorageID)
}

// TestLazyAllocationWritePath verifies that writeBlocks automatically
// allocates chunks when writing to unallocated chunks.
func TestLazyAllocationWritePath(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xBEEF))
	objectSize := int64(4 * 1024 * 1024) // 4MB = 2 chunks with 2MB chunk size
	chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))

	// Initialize lazy chunked storage
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	// Also set namespace ID for block state tracking
	meta.NamespaceID = 1
	err = storage.db.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Prepare data for chunk 1 (write to middle of file first)
	chunk1Data := make([]byte, chunkSize)
	for i := range chunk1Data {
		chunk1Data[i] = byte(i % 256)
	}

	// Write to chunk 1 (should auto-allocate)
	err = storage.WriteBlocks(instanceHash, chunkSize, chunk1Data)
	require.NoError(t, err)

	// Verify chunk 1 was allocated
	meta, err = storage.GetMetadata(instanceHash)
	require.NoError(t, err)
	assert.True(t, meta.IsChunkAllocated(1), "Chunk 1 should be allocated after write")

	// Note: chunk 0 might also be allocated depending on implementation
	// The key point is that the write succeeded without pre-allocating all chunks

	// Read back the data
	readData, err := storage.ReadBlocks(instanceHash, chunkSize, int(chunkSize))
	require.NoError(t, err)
	assert.Equal(t, chunk1Data, readData, "Data should match after write and read")
}

// TestLazyChunkedEviction verifies that evicting a lazily-allocated chunked object
// correctly deletes only the allocated chunk files and skips unallocated ones.
func TestLazyChunkedEviction(t *testing.T) {
	InitIssuerKeyForTests(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	instanceHash := InstanceHash(fmt.Sprintf("%064x", 0xAAAA))
	chunkSizeCode := BytesToChunkSizeCode(2 * 1024 * 1024)
	chunkSize := int64(ChunkSizeCodeToBytes(chunkSizeCode))
	objectSize := chunkSize * 3 // 3 chunks
	expectedChunks := CalculateChunkCount(objectSize, chunkSizeCode)
	require.Equal(t, 3, expectedChunks)

	// Initialize lazy storage — no files created
	meta, err := storage.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	// Allocate only chunks 0 and 2 (skip chunk 1)
	meta, err = storage.AllocateChunk(ctx, instanceHash, meta, 0)
	require.NoError(t, err)
	meta, err = storage.AllocateChunk(ctx, instanceHash, meta, 2)
	require.NoError(t, err)

	// Verify chunk 1 is unallocated
	assert.False(t, meta.IsChunkAllocated(1), "Chunk 1 should still be unallocated")

	// Record the paths of allocated chunks
	chunk0Path := storage.getChunkPath(meta.GetChunkStorageID(0), instanceHash, 0)
	chunk2Path := storage.getChunkPath(meta.GetChunkStorageID(2), instanceHash, 2)

	// Verify allocated chunks exist on disk
	_, err = os.Stat(chunk0Path)
	require.NoError(t, err, "Chunk 0 file should exist")
	_, err = os.Stat(chunk2Path)
	require.NoError(t, err, "Chunk 2 file should exist")

	// Set metadata for LRU tracking
	meta.NamespaceID = 1
	meta.Completed = time.Now()
	require.NoError(t, storage.SetMetadata(instanceHash, meta))
	require.NoError(t, db.UpdateLRU(instanceHash, 0))

	// Evict the object.  Only chunks 0 and 2 are allocated, so
	// totalFreed should be the sum of their on-disk file sizes.
	evicted, totalFreed, err := storage.EvictByLRU(meta.GetChunkStorageID(0), 1, 1, objectSize)
	require.NoError(t, err)
	assert.Len(t, evicted, 1)
	expectedFreed := uint64(CalculateFileSize(chunkSize)) * 2 // 2 allocated chunks
	assert.Equal(t, expectedFreed, totalFreed)

	// Verify allocated chunk files are deleted
	_, err = os.Stat(chunk0Path)
	assert.True(t, os.IsNotExist(err), "Chunk 0 file should be deleted")
	_, err = os.Stat(chunk2Path)
	assert.True(t, os.IsNotExist(err), "Chunk 2 file should be deleted")

	// Verify metadata is gone
	metaAfter, err := storage.GetMetadata(instanceHash)
	assert.NoError(t, err)
	assert.Nil(t, metaAfter, "Metadata should be deleted after eviction")
}
