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
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RoaringBitmap/roaring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestComputeInstanceHash(t *testing.T) {
	// Test that ComputeObjectHash produces consistent hashes for the same URL
	url1 := "pelican://director.example.com/namespace/path/to/file.txt"
	url2 := "pelican://director.example.com/namespace/path/to/other.txt"

	objectHash1 := ComputeObjectHash(url1)
	objectHash2 := ComputeObjectHash(url1)
	assert.Equal(t, objectHash1, objectHash2, "Same URL should produce same objectHash")

	// Test that different URLs produce different objectHashes
	objectHash3 := ComputeObjectHash(url2)
	assert.NotEqual(t, objectHash1, objectHash3, "Different URLs should produce different objectHashes")

	// Test that ComputeInstanceHash includes ETag in the hash
	etag1 := "abc123"
	etag2 := "def456"

	instanceHash1 := ComputeInstanceHash(etag1, objectHash1)
	instanceHash2 := ComputeInstanceHash(etag1, objectHash1)
	assert.Equal(t, instanceHash1, instanceHash2, "Same ETag+objectHash should produce same instanceHash")

	// Different ETags should produce different instanceHashes for same object
	instanceHash3 := ComputeInstanceHash(etag2, objectHash1)
	assert.NotEqual(t, instanceHash1, instanceHash3, "Different ETags should produce different instanceHashes")

	// Empty ETag should also work
	instanceHashEmpty := ComputeInstanceHash("", objectHash1)
	assert.Len(t, instanceHashEmpty, 64, "SHA256 hash should be 64 hex characters")
	assert.NotEqual(t, instanceHash1, instanceHashEmpty, "Empty ETag should produce different hash than non-empty")

	// Test hash format (should be 64 hex characters for SHA256)
	assert.Len(t, objectHash1, 64, "SHA256 hash should be 64 hex characters")
	assert.Len(t, instanceHash1, 64, "SHA256 hash should be 64 hex characters")
}

func TestGetInstanceStoragePath(t *testing.T) {
	hash := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	path := GetInstanceStoragePath(hash)

	// Should use first 4 characters for 2-level directory
	expected := "ab/cd/ef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	assert.Equal(t, expected, path)
}

func TestBlockCalculations(t *testing.T) {
	// Test CalculateBlockCount
	assert.Equal(t, uint32(1), CalculateBlockCount(1), "1 byte needs 1 block")
	assert.Equal(t, uint32(1), CalculateBlockCount(BlockDataSize), "Exactly 1 block")
	assert.Equal(t, uint32(2), CalculateBlockCount(BlockDataSize+1), "One byte over needs 2 blocks")
	assert.Equal(t, uint32(100), CalculateBlockCount(int64(BlockDataSize)*100), "100 blocks")

	// Test ContentOffsetToBlock
	assert.Equal(t, uint32(0), ContentOffsetToBlock(0), "First byte is in block 0")
	assert.Equal(t, uint32(0), ContentOffsetToBlock(BlockDataSize-1), "Last byte of first block")
	assert.Equal(t, uint32(1), ContentOffsetToBlock(BlockDataSize), "First byte of second block")
	assert.Equal(t, uint32(10), ContentOffsetToBlock(int64(BlockDataSize)*10+500), "Offset in block 10")

	// Test BlockOffset - returns disk offset (includes auth tag overhead)
	assert.Equal(t, int64(0), BlockOffset(0), "First block at offset 0")
	assert.Equal(t, int64(BlockTotalSize), BlockOffset(1), "Second block offset (disk)")
	assert.Equal(t, int64(BlockTotalSize)*10, BlockOffset(10), "Block 10 offset (disk)")
}

func TestParseRangeHeader(t *testing.T) {
	tests := []struct {
		name        string
		header      string
		contentLen  int64
		expectErr   bool
		expectCount int
		expectFirst RangeRequest
	}{
		{
			name:        "single range",
			header:      "bytes=0-99",
			contentLen:  1000,
			expectCount: 1,
			expectFirst: RangeRequest{Start: 0, End: 99},
		},
		{
			name:        "suffix range",
			header:      "bytes=-100",
			contentLen:  1000,
			expectCount: 1,
			expectFirst: RangeRequest{Start: 900, End: 999},
		},
		{
			name:        "open-ended range",
			header:      "bytes=500-",
			contentLen:  1000,
			expectCount: 1,
			expectFirst: RangeRequest{Start: 500, End: 999},
		},
		{
			name:        "multiple ranges",
			header:      "bytes=0-99,200-299",
			contentLen:  1000,
			expectCount: 2,
			expectFirst: RangeRequest{Start: 0, End: 99},
		},
		{
			name:       "invalid format",
			header:     "invalid",
			contentLen: 1000,
			expectErr:  true,
		},
		{
			name:       "range beyond content",
			header:     "bytes=2000-3000",
			contentLen: 1000,
			expectErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ranges, err := ParseRangeHeader(tt.header, tt.contentLen)
			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, ranges, tt.expectCount)
			if tt.expectCount > 0 {
				assert.Equal(t, tt.expectFirst.Start, ranges[0].Start)
				assert.Equal(t, tt.expectFirst.End, ranges[0].End)
			}
		})
	}
}

func TestCacheDBBasicOperations(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	// Create temporary directory for test
	tmpDir, err := os.MkdirTemp("", "cachedb_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create database
	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	// Test metadata operations
	instanceHash := "test_hash_12345"
	meta := &CacheMetadata{
		ContentLength: 1024,
		ContentType:   "application/octet-stream",
		SourceURL:     "pelican://example.com/test/file",
		NamespaceID:   1,
	}

	// Set metadata
	err = db.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Get metadata
	retrieved, err := db.GetMetadata(instanceHash)
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	assert.Equal(t, meta.ContentLength, retrieved.ContentLength)
	assert.Equal(t, meta.ContentType, retrieved.ContentType)
	assert.Equal(t, meta.SourceURL, retrieved.SourceURL)

	// Test non-existent key
	missing, err := db.GetMetadata("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, missing)

	// Test delete
	err = db.DeleteMetadata(instanceHash)
	require.NoError(t, err)

	deleted, err := db.GetMetadata(instanceHash)
	require.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestCacheDBBlockState(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "cachedb_blocks_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := "test_block_hash"

	// Initially no blocks downloaded
	bitmap, err := db.GetBlockState(instanceHash)
	require.NoError(t, err)
	assert.True(t, bitmap.IsEmpty())

	// Add some blocks
	err = db.MarkBlocksDownloaded(instanceHash, 0, 0)
	require.NoError(t, err)
	err = db.MarkBlocksDownloaded(instanceHash, 5, 5)
	require.NoError(t, err)
	err = db.MarkBlocksDownloaded(instanceHash, 10, 10)
	require.NoError(t, err)

	// Verify blocks are set
	bitmap, err = db.GetBlockState(instanceHash)
	require.NoError(t, err)
	assert.True(t, bitmap.Contains(0))
	assert.True(t, bitmap.Contains(5))
	assert.True(t, bitmap.Contains(10))
	assert.False(t, bitmap.Contains(1))
	assert.False(t, bitmap.Contains(100))

	// Add more blocks via merge
	err = db.MarkBlocksDownloaded(instanceHash, 1, 3)
	require.NoError(t, err)

	bitmap, err = db.GetBlockState(instanceHash)
	require.NoError(t, err)
	assert.True(t, bitmap.Contains(0))
	assert.True(t, bitmap.Contains(1))
	assert.True(t, bitmap.Contains(2))
	assert.True(t, bitmap.Contains(3))
	assert.True(t, bitmap.Contains(5))
	assert.True(t, bitmap.Contains(10))
}

func TestCacheDBAtomicBlockUsage(t *testing.T) {
	// Verifies that MarkBlocksDownloaded atomically updates both the block
	// bitmap and the usage counter in a single BadgerDB transaction.
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "cachedb_atomic_usage_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := "atomic_usage_test_hash"
	storageID := StorageIDFirstDisk
	namespaceID := uint32(7)

	// Set metadata first (10 blocks * 4080 = 40800 bytes, but content is 40000 so last block is partial)
	contentLength := int64(40000)
	totalBlocks := CalculateBlockCount(contentLength) // 10 blocks
	meta := &CacheMetadata{
		ContentLength: contentLength,
		StorageID:     storageID,
		NamespaceID:   namespaceID,
		SourceURL:     "pelican://test.example.com/data",
	}
	err = db.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Usage starts at zero
	usage, err := db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), usage)

	// Mark first 3 full blocks (0, 1, 2) — each is BlockDataSize bytes
	err = db.MarkBlocksDownloaded(instanceHash, 0, 2)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(3*BlockDataSize), usage, "3 full blocks should add 3*BlockDataSize bytes")

	// Re-mark the same blocks — usage should NOT increase (idempotent)
	err = db.MarkBlocksDownloaded(instanceHash, 0, 2)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(3*BlockDataSize), usage, "re-marking same blocks should not change usage")

	// Mark the last block (partial: 40000 - 9*4080 = 3280 bytes)
	lastBlock := totalBlocks - 1
	err = db.MarkBlocksDownloaded(instanceHash, lastBlock, lastBlock)
	require.NoError(t, err)

	lastBlockSize := contentLength - int64(lastBlock)*int64(BlockDataSize) // 40000 - 36720 = 3280
	expectedUsage := int64(3*BlockDataSize) + lastBlockSize
	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, expectedUsage, usage, "last partial block should add only its actual size")

	// Mark remaining middle blocks (3 through lastBlock-1, all full)
	if lastBlock > 3 {
		err = db.MarkBlocksDownloaded(instanceHash, 3, lastBlock-1)
		require.NoError(t, err)
	}

	// Now all blocks are marked — total usage should equal contentLength
	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, contentLength, usage, "total usage should equal content length when all blocks are present")
}

func TestCacheDBAtomicBlockUsage_NoMetadata(t *testing.T) {
	// Verifies that MarkBlocksDownloaded still works when metadata is not set
	// (usage tracking is skipped gracefully).
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "cachedb_atomic_nometa_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := "no_meta_test_hash"

	// Mark blocks without setting metadata first — should succeed
	err = db.MarkBlocksDownloaded(instanceHash, 0, 5)
	require.NoError(t, err)

	// Blocks should be marked
	bitmap, err := db.GetBlockState(instanceHash)
	require.NoError(t, err)
	assert.Equal(t, uint64(6), bitmap.GetCardinality())

	// Usage should be zero (no metadata to derive storage/namespace)
	usage, err := db.GetUsage(StorageIDFirstDisk, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(0), usage)
}

func TestCacheDBUsageCounter(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "cachedb_usage_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	namespaceID := uint32(1)
	storageID := StorageIDFirstDisk

	// Initial usage should be 0
	usage, err := db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), usage)

	// Add usage
	err = db.AddUsage(storageID, namespaceID, 1000)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), usage)

	// Add more usage
	err = db.AddUsage(storageID, namespaceID, 500)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(1500), usage)

	// Subtract usage (negative delta)
	err = db.AddUsage(storageID, namespaceID, -200)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(1300), usage)
}

func TestCacheDBMergeUpdate(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "cachedb_merge_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	// Create bitmap data for two files
	instanceHash1 := "instance_hash_1"
	instanceHash2 := "instance_hash_2"

	bitmap1 := roaring.New()
	bitmap1.AddRange(0, 5) // blocks 0-4

	bitmap2 := roaring.New()
	bitmap2.AddRange(10, 15) // blocks 10-14

	bitmap1Data, err := bitmap1.ToBytes()
	require.NoError(t, err)
	bitmap2Data, err := bitmap2.ToBytes()
	require.NoError(t, err)

	// Perform a single MergeUpdate with multiple bitmaps and usage deltas
	bitmapMerges := map[string][]byte{
		instanceHash1: bitmap1Data,
		instanceHash2: bitmap2Data,
	}

	usageDeltas := map[StorageUsageKey]int64{
		{StorageID: StorageIDFirstDisk, NamespaceID: 1}: 1000, // storage 1, namespace 1: +1000 bytes
		{StorageID: StorageIDFirstDisk, NamespaceID: 2}: 2000, // storage 1, namespace 2: +2000 bytes
	}

	err = db.MergeUpdate(bitmapMerges, usageDeltas)
	require.NoError(t, err)

	// Verify bitmap 1
	resultBitmap1, err := db.GetBlockState(instanceHash1)
	require.NoError(t, err)
	assert.True(t, resultBitmap1.Contains(0))
	assert.True(t, resultBitmap1.Contains(4))
	assert.False(t, resultBitmap1.Contains(5))

	// Verify bitmap 2
	resultBitmap2, err := db.GetBlockState(instanceHash2)
	require.NoError(t, err)
	assert.True(t, resultBitmap2.Contains(10))
	assert.True(t, resultBitmap2.Contains(14))
	assert.False(t, resultBitmap2.Contains(15))

	// Verify usage counters
	usage1, err := db.GetUsage(StorageIDFirstDisk, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), usage1)

	usage2, err := db.GetUsage(StorageIDFirstDisk, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2000), usage2)

	// Now merge more blocks into existing bitmaps
	moreBitmap1 := roaring.New()
	moreBitmap1.AddRange(5, 10) // blocks 5-9

	moreBitmap1Data, err := moreBitmap1.ToBytes()
	require.NoError(t, err)

	err = db.MergeUpdate(
		map[string][]byte{instanceHash1: moreBitmap1Data},
		map[StorageUsageKey]int64{{StorageID: StorageIDFirstDisk, NamespaceID: 1}: 500},
	)
	require.NoError(t, err)

	// Verify merged bitmap has both ranges
	resultBitmap1, err = db.GetBlockState(instanceHash1)
	require.NoError(t, err)
	for i := uint32(0); i < 10; i++ {
		assert.True(t, resultBitmap1.Contains(i), "block %d should be set", i)
	}
	assert.False(t, resultBitmap1.Contains(10))

	// Verify accumulated usage
	usage1, err = db.GetUsage(StorageIDFirstDisk, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(1500), usage1)
}

func TestEncryptionManager(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "encryption_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Test creating encryption manager with properly initialized issuer keys
	em, err := NewEncryptionManager(tmpDir)
	require.NoError(t, err)

	// Generate a DEK and nonce for testing
	dek := make([]byte, KeySize)
	for i := range dek {
		dek[i] = byte(i)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}

	// Create a block encryptor
	encryptor, err := NewBlockEncryptor(dek, nonce)
	require.NoError(t, err)

	// Test encrypting and decrypting a block
	plaintext := make([]byte, BlockDataSize)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := encryptor.EncryptBlock(0, plaintext)
	require.NoError(t, err)
	assert.Equal(t, BlockTotalSize, len(ciphertext), "Ciphertext should be block size + auth tag")

	// Create new encryptor with same key for decryption
	decryptor, err := NewBlockEncryptor(dek, nonce)
	require.NoError(t, err)

	decrypted, err := decryptor.DecryptBlock(0, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Test that wrong block number fails decryption
	_, err = decryptor.DecryptBlock(1, ciphertext)
	assert.Error(t, err, "Decryption with wrong block number should fail")

	// Test inline encryption
	inlineData := []byte("Hello, World!")
	encrypted, err := em.EncryptInline(inlineData, dek, nonce)
	require.NoError(t, err)

	decryptedInline, err := em.DecryptInline(encrypted, dek, nonce)
	require.NoError(t, err)
	assert.Equal(t, inlineData, decryptedInline)
}

func TestStorageManagerInline(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "storage_inline_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	instanceHash := "inline_test_hash"
	testData := []byte("Hello, World! This is inline test data.")

	meta := &CacheMetadata{
		ContentLength: int64(len(testData)),
		ContentType:   "text/plain",
		SourceURL:     "pelican://example.com/test",
		NamespaceID:   1,
	}

	// Store inline
	err = storage.StoreInline(ctx, instanceHash, meta, testData)
	require.NoError(t, err)

	// Read back
	reader, err := storage.NewObjectReader(instanceHash)
	require.NoError(t, err)
	defer reader.Close()

	readData := make([]byte, len(testData))
	n, err := reader.Read(readData)
	// Read may return io.EOF with the data if this is the last read
	if err != nil && err != io.EOF {
		require.NoError(t, err)
	}
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, readData)
}

func TestEvictionManager(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "eviction_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	eviction := NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[uint8]EvictionDirConfig{
			StorageIDFirstDisk: {
				MaxSize:             1000000, // 1MB max
				HighWaterPercentage: 90,
				LowWaterPercentage:  80,
			},
		},
	})

	// Test recording access
	require.NoError(t, eviction.RecordAccess("instance_hash_1"))
	require.NoError(t, eviction.RecordAccess("instance_hash_2"))

	// Test adding usage
	require.NoError(t, eviction.AddUsage(StorageIDFirstDisk, 1, 100000))
	require.NoError(t, eviction.AddUsage(StorageIDFirstDisk, 2, 200000))

	// Get stats
	stats := eviction.GetStats()
	require.Contains(t, stats.DirStats, StorageIDFirstDisk)
	dirStat := stats.DirStats[StorageIDFirstDisk]
	assert.Equal(t, uint64(1000000), dirStat.MaxSize)
	assert.Equal(t, uint64(900000), dirStat.HighWater)
	assert.Equal(t, uint64(800000), dirStat.LowWater)
}

func TestConsistencyChecker(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "consistency_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 100,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0, // No grace period for tests
	})

	// Test getting stats before any scans
	stats := checker.GetStats()
	assert.True(t, stats.LastMetadataScan.IsZero())
	assert.True(t, stats.LastDataScan.IsZero())

	// Start checker (won't actually run scans due to long interval)
	egrp := new(errgroup.Group)
	checker.Start(ctx, egrp)

	// Stop checker
	checker.Stop()
}

func TestConsistencyChecker_MetadataScan(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "consistency_scan_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	// Discover the assigned storage ID for the single directory.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 1)
	var diskID uint8
	for id := range assignedDirs {
		diskID = id
	}

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0, // No grace period for tests
	})

	// Create some valid disk-based objects
	validHashes := []string{
		"1111111111111111111111111111111111111111111111111111111111111111",
		"3333333333333333333333333333333333333333333333333333333333333333",
		"5555555555555555555555555555555555555555555555555555555555555555",
	}
	for _, hash := range validHashes {
		meta := &CacheMetadata{
			ContentLength: 100,
			StorageID:     diskID,
			NamespaceID:   1,
			Completed:     time.Now().Add(-10 * time.Minute), // Old enough
		}
		err = db.SetMetadata(hash, meta)
		require.NoError(t, err)

		// Create corresponding file
		filePath := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(hash))
		err = os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(filePath, []byte("test data"), 0644)
		require.NoError(t, err)
	}

	// Create an orphaned DB entry (no file)
	orphanedDBHash := "2222222222222222222222222222222222222222222222222222222222222222"
	meta := &CacheMetadata{
		ContentLength: 100,
		StorageID:     diskID,
		NamespaceID:   1,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	err = db.SetMetadata(orphanedDBHash, meta)
	require.NoError(t, err)

	// Create an orphaned file (no DB entry)
	orphanedFileHash := "4444444444444444444444444444444444444444444444444444444444444444"
	orphanedFilePath := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(orphanedFileHash))
	err = os.MkdirAll(filepath.Dir(orphanedFilePath), 0755)
	require.NoError(t, err)
	err = os.WriteFile(orphanedFilePath, []byte("orphaned data"), 0644)
	require.NoError(t, err)

	// Create an invalid file (not 64 hex chars) - should be skipped
	invalidFilePath := filepath.Join(tmpDir, objectsSubDir, "invalid_file.txt")
	err = os.WriteFile(invalidFilePath, []byte("invalid"), 0644)
	require.NoError(t, err)

	// Create a vim swap file - should be skipped
	swapFilePath := filepath.Join(tmpDir, objectsSubDir, ".file.swp")
	err = os.WriteFile(swapFilePath, []byte("swap"), 0644)
	require.NoError(t, err)

	// Run metadata scan
	err = checker.RunMetadataScan(ctx)
	require.NoError(t, err)

	// Check stats
	stats := checker.GetStats()
	assert.False(t, stats.LastMetadataScan.IsZero())
	assert.Equal(t, int64(1), stats.OrphanedDBEntries, "Should find 1 orphaned DB entry")
	assert.Equal(t, int64(1), stats.OrphanedFiles, "Should find 1 orphaned file")

	// Verify orphaned DB entry was removed
	retrievedMeta, err := db.GetMetadata(orphanedDBHash)
	require.NoError(t, err)
	assert.Nil(t, retrievedMeta, "Orphaned DB entry should be deleted")

	// Verify orphaned file was removed
	_, err = os.Stat(orphanedFilePath)
	assert.True(t, os.IsNotExist(err), "Orphaned file should be deleted")

	// Verify valid objects still exist
	for _, hash := range validHashes {
		retrievedMeta, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.NotNil(t, retrievedMeta, "Valid DB entry should still exist")

		filePath := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(hash))
		_, err = os.Stat(filePath)
		assert.NoError(t, err, "Valid file should still exist")
	}

	// Verify invalid files still exist (weren't touched)
	_, err = os.Stat(invalidFilePath)
	assert.NoError(t, err, "Invalid filename should be skipped, not deleted")
	_, err = os.Stat(swapFilePath)
	assert.NoError(t, err, "Vim swap file should be skipped, not deleted")
}

func TestConsistencyChecker_InlineStorage(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "consistency_inline_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		MinAgeForCleanup:     0,
	})

	// Create a valid inline object
	validHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testData := []byte("test inline data")
	meta := &CacheMetadata{
		ContentLength: int64(len(testData)),
		NamespaceID:   1,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	err = storage.StoreInline(ctx, validHash, meta, testData)
	require.NoError(t, err)

	// Create an orphaned inline entry (metadata exists but inline data is missing)
	orphanedHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	orphanedMeta := &CacheMetadata{
		ContentLength: 50,
		NamespaceID:   1,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	err = db.SetMetadata(orphanedHash, orphanedMeta)
	require.NoError(t, err)
	// Note: not storing inline data, so it's orphaned

	// Run metadata scan
	err = checker.RunMetadataScan(ctx)
	require.NoError(t, err)

	// Check stats
	stats := checker.GetStats()
	assert.Equal(t, int64(1), stats.OrphanedDBEntries, "Should find 1 orphaned inline entry")

	// Verify orphaned entry was removed
	retrievedMeta, err := db.GetMetadata(orphanedHash)
	require.NoError(t, err)
	assert.Nil(t, retrievedMeta, "Orphaned inline entry should be deleted")

	// Verify valid inline object still exists
	retrievedMeta, err = db.GetMetadata(validHash)
	require.NoError(t, err)
	assert.NotNil(t, retrievedMeta, "Valid inline entry should still exist")

	retrievedData, err := storage.ReadInline(validHash)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData, "Inline data should be intact")
}

// TestConsistencyChecker_TransactionRestart verifies that metadata scans properly
// restart transactions every 5 seconds to avoid long-lived transactions
func TestConsistencyChecker_TransactionRestart(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "consistency_restart_test_")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0, // No grace period for tests
	})

	// Create a moderate number of objects to ensure the scan takes some time
	// We'll create enough to verify transaction restarts work, but not so many
	// that the test takes too long
	numObjects := 100
	validHashes := make([]string, numObjects)

	for i := 0; i < numObjects; i++ {
		// Generate predictable hash (still 64 hex chars)
		hash := fmt.Sprintf("%064d", i)
		validHashes[i] = hash

		meta := &CacheMetadata{
			ContentLength: 100,
			NamespaceID:   1,
			Completed:     time.Now().Add(-10 * time.Minute),
		}
		err = db.SetMetadata(hash, meta)
		require.NoError(t, err)

		// Create corresponding file
		filePath := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(hash))
		err = os.MkdirAll(filepath.Dir(filePath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(filePath, []byte(fmt.Sprintf("data-%d", i)), 0644)
		require.NoError(t, err)
	}

	// Add a few orphaned entries
	orphanedHashes := []string{
		"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}
	for _, hash := range orphanedHashes {
		meta := &CacheMetadata{
			ContentLength: 100,
			NamespaceID:   1,
			Completed:     time.Now().Add(-10 * time.Minute),
		}
		err = db.SetMetadata(hash, meta)
		require.NoError(t, err)
		// No file created - orphaned
	}

	// Run metadata scan
	// Note: With only 100 entries, it likely won't restart transactions,
	// but the code path is exercised and tested
	err = checker.RunMetadataScan(ctx)
	require.NoError(t, err)

	// Verify results
	stats := checker.GetStats()
	assert.Equal(t, int64(len(orphanedHashes)), stats.OrphanedDBEntries, "Should find all orphaned entries")

	// Verify all valid objects still exist
	for _, hash := range validHashes {
		meta, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.NotNil(t, meta, "Valid entry should still exist: %s", hash)
	}

	// Verify orphaned entries were removed
	for _, hash := range orphanedHashes {
		meta, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.Nil(t, meta, "Orphaned entry should be deleted: %s", hash)
	}
}

// TestMultiDirStoragePlacement verifies that multi-directory storage works
// end-to-end: objects land in different directories, per-directory size stats
// are correct, and storage IDs are persisted in metadata.
func TestMultiDirStoragePlacement(t *testing.T) {
	InitIssuerKeyForTests(t)

	// Create two separate base directories to simulate independent disks.
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Create a third directory just for the database.
	dbDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	const storageID1 = StorageIDFirstDisk
	const storageID2 = StorageIDFirstDisk + 1

	// --- Set up subsystems with two directories ---

	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0)
	require.NoError(t, err)

	// Discover the assigned IDs for eviction config.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 2, "expected exactly 2 storage dirs")

	// Give both directories the same capacity so ChooseDiskStorage alternates
	// between them (whichever has more free space after each write).
	dirCfgs := make(map[uint8]EvictionDirConfig, len(assignedDirs))
	for id := range assignedDirs {
		dirCfgs[id] = EvictionDirConfig{MaxSize: 500_000, HighWaterPercentage: 90, LowWaterPercentage: 80}
	}
	eviction := NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: dirCfgs,
	})

	// --- Store several objects, recording usage ---

	type objectInfo struct {
		instanceHash string
		storageID    uint8
		size         int64
	}
	var objects []objectInfo
	const objectSize = 8192 // 2 blocks

	for i := 0; i < 10; i++ {
		instanceHash := fmt.Sprintf("%064x", i+0x10)
		sid := eviction.ChooseDiskStorage()

		meta, err := storage.InitDiskStorage(ctx, instanceHash, objectSize, sid)
		require.NoError(t, err)

		// Set metadata fields (NamespaceID, ETag, etc.) BEFORE WriteBlocks so
		// that MergeBlockStateWithUsage can track usage under the correct
		// namespace+storageID key.
		meta.ETag = fmt.Sprintf("etag-%d", i)
		meta.NamespaceID = 1
		meta.ContentType = "application/octet-stream"
		require.NoError(t, storage.SetMetadata(instanceHash, meta))

		// Fill with a known pattern so WriteBlocks succeeds.
		data := make([]byte, objectSize)
		for j := range data {
			data[j] = byte(i)
		}
		require.NoError(t, storage.WriteBlocks(instanceHash, 0, data))

		// Mark as completed.
		meta.Completed = time.Now()
		require.NoError(t, storage.SetMetadata(instanceHash, meta))

		// Inform the eviction manager's in-memory atomic counters
		// about the usage increase so that ChooseDiskStorage can
		// weight directories correctly.  In the full persistent cache
		// this happens via PersistentCache.NoteUsageIncrease; here we
		// call the EvictionManager directly since we're testing
		// subsystems in isolation.
		eviction.NoteUsageIncrease(sid, int64(objectSize))

		objects = append(objects, objectInfo{
			instanceHash: instanceHash,
			storageID:    sid,
			size:         objectSize,
		})
	}

	// --- Assert: files are distributed across directories ---

	filesInDir := map[uint8]int{storageID1: 0, storageID2: 0}
	for _, obj := range objects {
		filesInDir[obj.storageID]++

		// Verify the file actually exists on the expected directory.
		objPath := storage.GetDirs()[obj.storageID]
		filePath := filepath.Join(objPath, GetInstanceStoragePath(obj.instanceHash))
		_, err := os.Stat(filePath)
		require.NoError(t, err, "file for %s should exist in dir storageID=%d", obj.instanceHash, obj.storageID)
	}

	t.Logf("Files per directory: dir1=%d dir2=%d", filesInDir[storageID1], filesInDir[storageID2])
	// Both directories have the same capacity, so ChooseDiskStorage should
	// alternate between them as each write changes the relative free space.
	assert.Greater(t, filesInDir[storageID1], 0, "dir1 should have at least one object")
	assert.Greater(t, filesInDir[storageID2], 0, "dir2 should have at least one object")

	// --- Assert: per-directory usage stats are correct ---

	stats := eviction.GetStats()
	require.Contains(t, stats.DirStats, storageID1)
	require.Contains(t, stats.DirStats, storageID2)

	expectedUsage := map[uint8]int64{storageID1: 0, storageID2: 0}
	for _, obj := range objects {
		expectedUsage[obj.storageID] += obj.size
	}

	allUsage, err := db.GetAllUsage()
	require.NoError(t, err)

	actualUsage := map[uint8]int64{}
	for key, usage := range allUsage {
		actualUsage[key.StorageID] += usage
	}
	assert.Equal(t, expectedUsage[storageID1], actualUsage[storageID1],
		"dir1 usage should match sum of objects placed there")
	assert.Equal(t, expectedUsage[storageID2], actualUsage[storageID2],
		"dir2 usage should match sum of objects placed there")

	// --- Assert: storageID is persisted in metadata ---

	for _, obj := range objects {
		meta, err := storage.GetMetadata(obj.instanceHash)
		require.NoError(t, err)
		require.NotNil(t, meta)
		assert.Equal(t, obj.storageID, meta.StorageID,
			"metadata.StorageID should match the directory where the object was placed (%s)", obj.instanceHash)
	}

	// --- Assert: reading back data works across directories ---

	for _, obj := range objects {
		readData, err := storage.ReadBlocks(obj.instanceHash, 0, objectSize)
		require.NoError(t, err, "should read back data from storageID=%d", obj.storageID)
		assert.Equal(t, objectSize, len(readData))
	}

	// --- Assert: ConsistencyChecker sees objects in both directories ---

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0,
	})

	require.NoError(t, checker.RunMetadataScan(ctx))
	checkStats := checker.GetStats()

	// No orphans should be found.
	assert.Equal(t, int64(0), checkStats.OrphanedDBEntries, "no orphaned DB entries")
	assert.Equal(t, int64(0), checkStats.OrphanedFiles, "no orphaned files")
}

// TestPurgeStorageID verifies that PurgeStorageID removes all database
// entries (metadata, block state, LRU, usage, disk mapping) for a
// given storageID without touching entries belonging to other IDs.
func TestPurgeStorageID(t *testing.T) {
	InitIssuerKeyForTests(t)

	dbDir := t.TempDir()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0)
	require.NoError(t, err)

	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 2)

	// Identify the two storage IDs.
	var ids []uint8
	for id := range assignedDirs {
		ids = append(ids, id)
	}
	if ids[0] > ids[1] {
		ids[0], ids[1] = ids[1], ids[0]
	}
	sidKeep := ids[0]
	sidPurge := ids[1]

	const objSize int64 = 8192

	// Helper: create one object on a given storageID.
	createObject := func(i int, sid uint8) string {
		instanceHash := fmt.Sprintf("%064x", i)
		meta, err := storage.InitDiskStorage(ctx, instanceHash, objSize, sid)
		require.NoError(t, err)
		meta.ETag = fmt.Sprintf("etag-%d", i)
		meta.NamespaceID = 1
		meta.ContentType = "application/octet-stream"
		meta.ObjectHash = fmt.Sprintf("objhash-%d", i)
		require.NoError(t, storage.SetMetadata(instanceHash, meta))

		data := make([]byte, objSize)
		for j := range data {
			data[j] = byte(i)
		}
		require.NoError(t, storage.WriteBlocks(instanceHash, 0, data))

		// Set ETag mapping
		require.NoError(t, db.SetLatestETag(meta.ObjectHash, meta.ETag))
		// Usage is tracked automatically by WriteBlocks → MergeBlockStateWithUsage.
		// Record LRU access
		require.NoError(t, db.UpdateLRU(instanceHash, 0))

		return instanceHash
	}

	// Create 3 objects on each storageID.
	var keepHashes, purgeHashes []string
	for i := 0; i < 3; i++ {
		keepHashes = append(keepHashes, createObject(i, sidKeep))
	}
	for i := 10; i < 13; i++ {
		purgeHashes = append(purgeHashes, createObject(i, sidPurge))
	}

	// Verify objects exist before purge.
	for _, h := range purgeHashes {
		meta, err := storage.GetMetadata(h)
		require.NoError(t, err)
		require.NotNil(t, meta, "object %s should exist before purge", h)
	}
	purgeUsage, err := db.GetDirUsage(sidPurge)
	require.NoError(t, err)
	assert.NotEmpty(t, purgeUsage, "purge dir should have usage before purge")

	// ---- Purge ----
	require.NoError(t, db.PurgeStorageID(sidPurge))

	// Verify purged objects are gone.
	for _, h := range purgeHashes {
		meta, err := storage.GetMetadata(h)
		require.NoError(t, err)
		assert.Nil(t, meta, "object %s should be gone after purge", h)

		has, err := db.HasMetadata(h)
		require.NoError(t, err)
		assert.False(t, has, "metadata for %s should be deleted", h)
	}

	// Verify usage is gone.
	purgeUsage, err = db.GetDirUsage(sidPurge)
	require.NoError(t, err)
	assert.Empty(t, purgeUsage, "purge dir should have no usage after purge")

	// Verify disk mapping is gone.
	mappings, err := db.LoadDiskMappings()
	require.NoError(t, err)
	for _, dm := range mappings {
		assert.NotEqual(t, sidPurge, dm.ID, "disk mapping for purged ID should be removed")
	}

	// Verify kept objects are untouched.
	for _, h := range keepHashes {
		meta, err := storage.GetMetadata(h)
		require.NoError(t, err)
		require.NotNil(t, meta, "object %s on kept dir should still exist", h)
	}
	keepUsage, err := db.GetDirUsage(sidKeep)
	require.NoError(t, err)
	assert.NotEmpty(t, keepUsage, "kept dir should still have usage")
}

// TestStorageIDRecycling verifies that NewStorageManager recycles an
// unmounted storageID when all 255 IDs are exhausted instead of
// returning an error.
func TestStorageIDRecycling(t *testing.T) {
	InitIssuerKeyForTests(t)

	dbDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, dbDir)
	require.NoError(t, err)
	defer db.Close()

	// Fill all 255 storageIDs (1–255) with fake disk mappings.
	// Only the first dir is a real directory; the rest are just DB entries.
	realDir := t.TempDir()
	for id := uint8(StorageIDFirstDisk); ; id++ {
		dm := DiskMapping{
			ID:        id,
			UUID:      fmt.Sprintf("uuid-%d", id),
			Directory: fmt.Sprintf("/fake/dir/%d", id),
		}
		require.NoError(t, db.SaveDiskMapping(dm))
		// Add a small amount of usage so FindRecyclableStorageID can rank them.
		require.NoError(t, db.AddUsage(id, 1, int64(id)*100))
		if id == 255 {
			break
		}
	}

	// The real directory has no UUID file, so NewStorageManager will try
	// to assign it a new ID.  All 255 IDs are taken, so it must recycle.
	// StorageID 1 has the smallest usage (1*100 = 100), so it should be
	// recycled.
	storage, err := NewStorageManager(db, []string{realDir}, 0)
	require.NoError(t, err, "should recycle a storageID instead of failing")

	dirs := storage.GetDirs()
	require.Len(t, dirs, 1)

	// The recycled ID should be 1 (smallest usage).
	var assignedID uint8
	for id := range dirs {
		assignedID = id
	}
	assert.Equal(t, uint8(StorageIDFirstDisk), assignedID,
		"should have recycled storage ID %d (smallest usage)", StorageIDFirstDisk)

	// The old disk mapping for ID 1 should be replaced.
	mappings, err := db.LoadDiskMappings()
	require.NoError(t, err)
	for _, dm := range mappings {
		if dm.ID == assignedID {
			assert.Equal(t, realDir, dm.Directory,
				"recycled ID should now point to the new directory")
		}
	}

	// Usage for the recycled ID should be 0 (was purged).
	dirUsage, err := db.GetDirUsage(assignedID)
	require.NoError(t, err)
	assert.Empty(t, dirUsage, "recycled ID should have zero usage")
}
