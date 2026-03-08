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
	"crypto/sha256"
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

	"github.com/dgraph-io/badger/v4"
)

// seedUsage is a test helper to directly write a usage delta to the DB
// without going through the production AddUsage API (which was removed
// to prevent double-counting).
func seedUsage(db *CacheDB, storageID StorageID, namespaceID NamespaceID, delta int64) error {
	return db.db.Update(func(txn *badger.Txn) error {
		return addUsageInTxn(txn, storageID, namespaceID, delta)
	})
}

func TestComputeInstanceHash(t *testing.T) {
	// Test that ComputeObjectHash produces consistent hashes for the same URL
	url1 := "pelican://director.example.com/namespace/path/to/file.txt"
	url2 := "pelican://director.example.com/namespace/path/to/other.txt"

	salt := []byte("test-salt-value")

	objectHash1 := ComputeObjectHash(salt, url1)
	objectHash2 := ComputeObjectHash(salt, url1)
	assert.Equal(t, objectHash1, objectHash2, "Same URL should produce same objectHash")

	// Test that different URLs produce different objectHashes
	objectHash3 := ComputeObjectHash(salt, url2)
	assert.NotEqual(t, objectHash1, objectHash3, "Different URLs should produce different objectHashes")

	// Test that ComputeInstanceHash includes ETag in the hash
	etag1 := "abc123"
	etag2 := "def456"

	instanceHash1 := ComputeInstanceHash(salt, etag1, objectHash1)
	instanceHash2 := ComputeInstanceHash(salt, etag1, objectHash1)
	assert.Equal(t, instanceHash1, instanceHash2, "Same ETag+objectHash should produce same instanceHash")

	// Different ETags should produce different instanceHashes for same object
	instanceHash3 := ComputeInstanceHash(salt, etag2, objectHash1)
	assert.NotEqual(t, instanceHash1, instanceHash3, "Different ETags should produce different instanceHashes")

	// Empty ETag should also work
	instanceHashEmpty := ComputeInstanceHash(salt, "", objectHash1)
	assert.Len(t, instanceHashEmpty, 64, "SHA256 hash should be 64 hex characters")
	assert.NotEqual(t, instanceHash1, instanceHashEmpty, "Empty ETag should produce different hash than non-empty")

	// Test hash format (should be 64 hex characters for SHA256)
	assert.Len(t, objectHash1, 64, "SHA256 hash should be 64 hex characters")
	assert.Len(t, instanceHash1, 64, "SHA256 hash should be 64 hex characters")

	// Test that different salts produce different hashes
	salt2 := []byte("different-salt")
	objectHash4 := ComputeObjectHash(salt2, url1)
	assert.NotEqual(t, objectHash1, objectHash4, "Different salts should produce different hashes")
}

func TestGetInstanceStoragePath(t *testing.T) {
	hash := InstanceHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

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
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Create database
	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	// Test metadata operations
	instanceHash := InstanceHash("test_hash_12345")
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

func TestMergeMetadata(t *testing.T) {
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	t.Run("CreatesWhenMissing", func(t *testing.T) {
		hash := InstanceHash("merge_create")
		now := time.Now().Truncate(time.Millisecond)
		incoming := &CacheMetadata{
			ETag:          "etag-create",
			ContentType:   "text/plain",
			ContentLength: 512,
			SourceURL:     "pelican://example.com/create",
			StorageID:     1,
			NamespaceID:   1,
			LastValidated: now,
		}
		require.NoError(t, db.MergeMetadata(hash, incoming))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "etag-create", got.ETag)
		assert.Equal(t, "text/plain", got.ContentType)
		assert.Equal(t, int64(512), got.ContentLength)
		assert.Equal(t, "pelican://example.com/create", got.SourceURL)
	})

	t.Run("MaxTimeAdvancesForward", func(t *testing.T) {
		hash := InstanceHash("merge_maxtime")
		t0 := time.Now().Truncate(time.Millisecond)
		t1 := t0.Add(10 * time.Second)
		tEarlier := t0.Add(-5 * time.Second)

		// Seed with t0 timestamps
		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			LastModified:   t0,
			LastValidated:  t0,
			Completed:      t0,
			Expires:        t0,
			LastAccessTime: t0,
		}))

		// Merge with t1 for LastValidated, tEarlier for LastModified
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			LastValidated: t1,
			LastModified:  tEarlier,
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, t1, got.LastValidated, "LastValidated should advance to t1")
		assert.Equal(t, t0, got.LastModified, "LastModified should stay at t0 (tEarlier is older)")
		assert.Equal(t, t0, got.Completed, "Completed should be unchanged")
		assert.Equal(t, t0, got.Expires, "Expires should be unchanged")
		assert.Equal(t, t0, got.LastAccessTime, "LastAccessTime should be unchanged")
	})

	t.Run("AdditiveChecksums", func(t *testing.T) {
		hash := InstanceHash("merge_checksums")

		// Seed with a SHA-256 checksum
		sha256Val := []byte("sha256-existing")
		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			Checksums: []Checksum{
				{Type: ChecksumSHA256, Value: sha256Val, OriginVerified: false},
			},
		}))

		// Merge an MD5 checksum — should be unioned
		md5Val := []byte("md5-incoming")
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			Checksums: []Checksum{
				{Type: ChecksumMD5, Value: md5Val},
			},
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		require.Len(t, got.Checksums, 2, "should have both SHA-256 and MD5")

		byType := make(map[ChecksumType]Checksum)
		for _, c := range got.Checksums {
			byType[c.Type] = c
		}
		assert.Equal(t, sha256Val, byType[ChecksumSHA256].Value)
		assert.Equal(t, md5Val, byType[ChecksumMD5].Value)
	})

	t.Run("ChecksumOriginVerifiedWins", func(t *testing.T) {
		hash := InstanceHash("merge_cksum_ov")

		localVal := []byte("local-sha256")
		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			Checksums: []Checksum{
				{Type: ChecksumSHA256, Value: localVal, OriginVerified: false},
			},
		}))

		// Merge a SHA-256 with OriginVerified=true — should replace
		originVal := []byte("origin-sha256")
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			Checksums: []Checksum{
				{Type: ChecksumSHA256, Value: originVal, OriginVerified: true},
			},
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		require.Len(t, got.Checksums, 1)
		assert.Equal(t, originVal, got.Checksums[0].Value)
		assert.True(t, got.Checksums[0].OriginVerified)
	})

	t.Run("LastWriterWins", func(t *testing.T) {
		hash := InstanceHash("merge_lww")

		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			ContentType:   "text/plain",
			ContentLength: 100,
			CCFlags:       0x01,
			CCMaxAge:      300,
			VaryHeaders:   []string{"Accept"},
		}))

		// Merge with new values — they should replace
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			ContentType:   "application/json",
			ContentLength: 200,
			CCFlags:       0x02,
			CCMaxAge:      600,
			VaryHeaders:   []string{"Accept-Encoding"},
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.Equal(t, "application/json", got.ContentType)
		assert.Equal(t, int64(200), got.ContentLength)
		assert.Equal(t, uint8(0x02), got.CCFlags)
		assert.Equal(t, int32(600), got.CCMaxAge)
		assert.Equal(t, []string{"Accept-Encoding"}, got.VaryHeaders)
	})

	t.Run("LastWriterWinsZeroNoOverwrite", func(t *testing.T) {
		hash := InstanceHash("merge_lww_zero")

		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			ContentType:   "text/plain",
			ContentLength: 100,
		}))

		// Merge with zero-value fields — existing should be preserved
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.Equal(t, "text/plain", got.ContentType, "zero incoming should not overwrite")
		assert.Equal(t, int64(100), got.ContentLength, "zero incoming should not overwrite")
	})

	t.Run("SetOnceSameValueOK", func(t *testing.T) {
		hash := InstanceHash("merge_setonce_same")

		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			ETag:        "etag-1",
			SourceURL:   "pelican://example.com/obj",
			StorageID:   2,
			NamespaceID: 3,
			DataKey:     []byte("dek-abc"),
		}))

		// Re-merge with identical values — should succeed
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			ETag:        "etag-1",
			SourceURL:   "pelican://example.com/obj",
			StorageID:   2,
			NamespaceID: 3,
			DataKey:     []byte("dek-abc"),
		}))
	})

	t.Run("SetOnceConflictErrors", func(t *testing.T) {
		cases := []struct {
			name     string
			initial  *CacheMetadata
			incoming *CacheMetadata
		}{
			{
				name:     "ETag",
				initial:  &CacheMetadata{ETag: "etag-a"},
				incoming: &CacheMetadata{ETag: "etag-b"},
			},
			{
				name:     "SourceURL",
				initial:  &CacheMetadata{SourceURL: "pelican://a.com/x"},
				incoming: &CacheMetadata{SourceURL: "pelican://b.com/y"},
			},
			{
				name:     "StorageID",
				initial:  &CacheMetadata{StorageID: 1},
				incoming: &CacheMetadata{StorageID: 2},
			},
			{
				name:     "NamespaceID",
				initial:  &CacheMetadata{NamespaceID: 1},
				incoming: &CacheMetadata{NamespaceID: 2},
			},
			{
				name:     "DataKey",
				initial:  &CacheMetadata{DataKey: []byte("key-1")},
				incoming: &CacheMetadata{DataKey: []byte("key-2")},
			},
		}

		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				hash := InstanceHash(fmt.Sprintf("merge_conflict_%d", i))
				require.NoError(t, db.SetMetadata(hash, tc.initial))
				err := db.MergeMetadata(hash, tc.incoming)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.name)
			})
		}
	})

	t.Run("SetOnceZeroToValueOK", func(t *testing.T) {
		hash := InstanceHash("merge_setonce_zero2val")

		// Start with empty metadata
		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{}))

		// Merge set-once fields into the empty record
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			ETag:        "etag-new",
			SourceURL:   "pelican://example.com/new",
			StorageID:   5,
			NamespaceID: 10,
			DataKey:     []byte("new-dek"),
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.Equal(t, "etag-new", got.ETag)
		assert.Equal(t, "pelican://example.com/new", got.SourceURL)
		assert.Equal(t, StorageID(5), got.StorageID)
		assert.Equal(t, NamespaceID(10), got.NamespaceID)
		assert.Equal(t, []byte("new-dek"), got.DataKey)
	})

	t.Run("CombinedMerge", func(t *testing.T) {
		hash := InstanceHash("merge_combined")
		t0 := time.Now().Truncate(time.Millisecond)

		// Initial metadata
		require.NoError(t, db.SetMetadata(hash, &CacheMetadata{
			ETag:          "etag-combo",
			SourceURL:     "pelican://combo.com/file",
			StorageID:     1,
			NamespaceID:   1,
			ContentType:   "application/octet-stream",
			ContentLength: 4096,
			LastValidated: t0,
			Checksums: []Checksum{
				{Type: ChecksumMD5, Value: []byte("md5-v1")},
			},
		}))

		// Merge: advance LastValidated, add SHA-256, update ContentType
		t1 := t0.Add(30 * time.Second)
		require.NoError(t, db.MergeMetadata(hash, &CacheMetadata{
			ETag:          "etag-combo", // same — OK
			SourceURL:     "pelican://combo.com/file",
			ContentType:   "text/html",
			LastValidated: t1,
			Completed:     t1,
			Checksums: []Checksum{
				{Type: ChecksumSHA256, Value: []byte("sha256-v1"), OriginVerified: true},
			},
		}))

		got, err := db.GetMetadata(hash)
		require.NoError(t, err)
		assert.Equal(t, t1, got.LastValidated)
		assert.Equal(t, t1, got.Completed)
		assert.Equal(t, "text/html", got.ContentType)
		assert.Equal(t, int64(4096), got.ContentLength, "ContentLength should stay (incoming was 0)")
		assert.Len(t, got.Checksums, 2, "should have MD5 + SHA-256")
	})
}

func TestCacheDBBlockState(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := InstanceHash("test_block_hash")

	// Initially no blocks downloaded
	bitmap, err := db.GetBlockState(instanceHash)
	require.NoError(t, err)
	assert.True(t, bitmap.IsEmpty())

	// Add some blocks
	err = db.MarkBlocksDownloaded(instanceHash, 0, 0, 0, 0, -1)
	require.NoError(t, err)
	err = db.MarkBlocksDownloaded(instanceHash, 5, 5, 0, 0, -1)
	require.NoError(t, err)
	err = db.MarkBlocksDownloaded(instanceHash, 10, 10, 0, 0, -1)
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
	err = db.MarkBlocksDownloaded(instanceHash, 1, 3, 0, 0, -1)
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

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := InstanceHash("atomic_usage_test_hash")
	storageID := StorageIDFirstDisk
	namespaceID := NamespaceID(7)

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
	err = db.MarkBlocksDownloaded(instanceHash, 0, 2, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(3*BlockDataSize), usage, "3 full blocks should add 3*BlockDataSize bytes")

	// Re-mark the same blocks — usage should NOT increase (idempotent)
	err = db.MarkBlocksDownloaded(instanceHash, 0, 2, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(3*BlockDataSize), usage, "re-marking same blocks should not change usage")

	// Mark the last block (partial: 40000 - 9*4080 = 3280 bytes)
	lastBlock := totalBlocks - 1
	err = db.MarkBlocksDownloaded(instanceHash, lastBlock, lastBlock, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	lastBlockSize := contentLength - int64(lastBlock)*int64(BlockDataSize) // 40000 - 36720 = 3280
	expectedUsage := int64(3*BlockDataSize) + lastBlockSize
	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, expectedUsage, usage, "last partial block should add only its actual size")

	// Mark remaining middle blocks (3 through lastBlock-1, all full)
	if lastBlock > 3 {
		err = db.MarkBlocksDownloaded(instanceHash, 3, lastBlock-1, storageID, namespaceID, contentLength)
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

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	instanceHash := InstanceHash("no_meta_test_hash")

	// Mark blocks without setting metadata first — should succeed
	err = db.MarkBlocksDownloaded(instanceHash, 0, 5, 0, 0, -1)
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
	// Test that usage counters work correctly through the MarkBlocksDownloaded path
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	namespaceID := NamespaceID(1)
	storageID := StorageIDFirstDisk

	// Initial usage should be 0
	usage, err := db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), usage)

	// Set up metadata for an instance so MarkBlocksDownloaded can track usage
	instanceHash := InstanceHash("usage_counter_test_hash")
	contentLength := int64(3 * BlockDataSize) // 3 full blocks
	meta := &CacheMetadata{
		ContentLength: contentLength,
		StorageID:     storageID,
		NamespaceID:   namespaceID,
		SourceURL:     "pelican://test.example.com/usage",
	}
	err = db.SetMetadata(instanceHash, meta)
	require.NoError(t, err)

	// Mark 2 blocks — usage should increase by 2*BlockDataSize
	err = db.MarkBlocksDownloaded(instanceHash, 0, 1, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(2*BlockDataSize), usage)

	// Mark the same blocks again — idempotent, usage should NOT increase
	err = db.MarkBlocksDownloaded(instanceHash, 0, 1, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, int64(2*BlockDataSize), usage)

	// Mark third block — usage should increase by 1*BlockDataSize
	err = db.MarkBlocksDownloaded(instanceHash, 2, 2, storageID, namespaceID, contentLength)
	require.NoError(t, err)

	usage, err = db.GetUsage(storageID, namespaceID)
	require.NoError(t, err)
	assert.Equal(t, contentLength, usage)
}

func TestEncryptionManager(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

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

	// --- Negative tests ---

	// Wrong DEK: decryption should fail with authentication error
	wrongDEK := make([]byte, KeySize)
	for i := range wrongDEK {
		wrongDEK[i] = byte(i + 42)
	}
	wrongKeyDecryptor, err := NewBlockEncryptor(wrongDEK, nonce)
	require.NoError(t, err)
	_, err = wrongKeyDecryptor.DecryptBlock(0, ciphertext)
	assert.Error(t, err, "Decryption with wrong DEK should fail")

	// Wrong nonce: decryption should fail with authentication error
	wrongNonce := make([]byte, NonceSize)
	for i := range wrongNonce {
		wrongNonce[i] = byte(i + 200)
	}
	wrongNonceDecryptor, err := NewBlockEncryptor(dek, wrongNonce)
	require.NoError(t, err)
	_, err = wrongNonceDecryptor.DecryptBlock(0, ciphertext)
	assert.Error(t, err, "Decryption with wrong nonce should fail")

	// Corrupt ciphertext: flip a byte in the middle of the block
	corruptCiphertext := make([]byte, len(ciphertext))
	copy(corruptCiphertext, ciphertext)
	corruptCiphertext[len(corruptCiphertext)/2] ^= 0xFF
	_, err = decryptor.DecryptBlock(0, corruptCiphertext)
	assert.Error(t, err, "Decryption of corrupt data should fail")

	// Corrupt auth tag: flip the last byte (part of the GCM tag)
	corruptTag := make([]byte, len(ciphertext))
	copy(corruptTag, ciphertext)
	corruptTag[len(corruptTag)-1] ^= 0xFF
	_, err = decryptor.DecryptBlock(0, corruptTag)
	assert.Error(t, err, "Decryption with corrupt auth tag should fail")

	// Wrong DEK for inline decryption
	_, err = em.DecryptInline(encrypted, wrongDEK, nonce)
	assert.Error(t, err, "Inline decryption with wrong DEK should fail")

	// Wrong nonce for inline decryption
	_, err = em.DecryptInline(encrypted, dek, wrongNonce)
	assert.Error(t, err, "Inline decryption with wrong nonce should fail")
}

// TestZeroBlockReadFailure verifies that reading from an uninitialized
// (all-zero) disk block fails.  This simulates a crash or I/O error
// after the first block was written but before subsequent blocks were
// flushed — the file was pre-allocated but the remaining blocks contain
// zeros.  AES-GCM authentication must reject such blocks.
func TestZeroBlockReadFailure(t *testing.T) {
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	instanceHash := InstanceHash("zero_block_test_0123456789abcdef0123456789abcdef01")

	// Generate encryption keys.
	encMgr := db.GetEncryptionManager()
	dek, err := encMgr.GenerateDataKey()
	require.NoError(t, err)
	encryptedDEK, err := encMgr.EncryptDataKey(dek)
	require.NoError(t, err)

	// Create a file spanning 3 blocks.
	dataSize := int64(BlockDataSize*2 + 100)
	meta := &CacheMetadata{
		ContentLength: dataSize,
		ContentType:   "application/octet-stream",
		SourceURL:     "pelican://example.com/zero_block_test",
		StorageID:     StorageIDFirstDisk,
		NamespaceID:   1,
		DataKey:       encryptedDEK,
	}
	require.NoError(t, db.SetMetadata(instanceHash, meta))

	// Create directory for the object file and pre-allocate it with
	// zeros (simulates how NewBlockWriter pre-allocates).
	objPath := storage.getObjectPath(instanceHash)
	require.NoError(t, os.MkdirAll(filepath.Dir(objPath), 0750))
	totalSize := BlockOffset(CalculateBlockCount(dataSize))
	fp, err := os.OpenFile(objPath, os.O_RDWR|os.O_CREATE, 0600)
	require.NoError(t, err)
	require.NoError(t, fp.Truncate(totalSize))
	fp.Close()

	// Write only the first block with real data.
	firstBlockData := make([]byte, BlockDataSize)
	for i := range firstBlockData {
		firstBlockData[i] = byte(i % 251)
	}
	require.NoError(t, storage.WriteBlocks(instanceHash, 0, firstBlockData))

	// Lie to the bitmap: mark blocks 1 and 2 as downloaded.
	require.NoError(t, db.MarkBlocksDownloaded(instanceHash, 1, 2, StorageIDFirstDisk, 1, dataSize))

	// Reading block 0 (real data) should succeed.
	data, err := storage.ReadBlocks(instanceHash, 0, BlockDataSize)
	require.NoError(t, err)
	assert.Equal(t, firstBlockData, data)

	// Reading block 1 (all zeros on disk) must fail — AES-GCM
	// authentication should reject the zero ciphertext.
	_, err = storage.ReadBlocks(instanceHash, int64(BlockDataSize), BlockDataSize)
	require.Error(t, err, "reading an uninitialized (zero) block must fail")
	assert.Contains(t, err.Error(), "decrypt", "error should mention decryption failure")
}

func TestStorageManagerInline(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	instanceHash := InstanceHash("inline_test_hash")
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

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	eviction := NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
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

	// Test adding usage — seed via addUsageInTxn (the DB-level helper)
	require.NoError(t, seedUsage(db, StorageIDFirstDisk, 1, 100000))
	require.NoError(t, seedUsage(db, StorageIDFirstDisk, 2, 200000))

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

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
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
	checker.Start(ctx, egrp)

	// Stop checker
	checker.Stop()
}

func TestConsistencyChecker_MetadataScan(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	// Discover the assigned storage ID for the single directory.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 1)
	var diskID StorageID
	for id := range assignedDirs {
		diskID = id
	}

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0, // No grace period for tests
	})

	// Create some valid disk-based objects
	validHashes := []InstanceHash{
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
	orphanedDBHash := InstanceHash("2222222222222222222222222222222222222222222222222222222222222222")
	meta := &CacheMetadata{
		ContentLength: 100,
		StorageID:     diskID,
		NamespaceID:   1,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	err = db.SetMetadata(orphanedDBHash, meta)
	require.NoError(t, err)

	// Create an orphaned file (no DB entry)
	orphanedFileHash := InstanceHash("4444444444444444444444444444444444444444444444444444444444444444")
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

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		MinAgeForCleanup:     0,
	})

	// Create a valid inline object
	validHash := InstanceHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	testData := []byte("test inline data")
	meta := &CacheMetadata{
		ContentLength: int64(len(testData)),
		NamespaceID:   1,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	err = storage.StoreInline(ctx, validHash, meta, testData)
	require.NoError(t, err)

	// Create an orphaned inline entry (metadata exists but inline data is missing)
	orphanedHash := InstanceHash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
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

// TestConsistencyChecker_OrphanCleanup verifies that metadata scans detect
// entries whose on-disk files have been removed and cleans them up.
func TestConsistencyChecker_OrphanCleanup(t *testing.T) {
	// Initialize issuer keys for encryption
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
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
	validHashes := make([]InstanceHash, numObjects)

	for i := 0; i < numObjects; i++ {
		// Generate predictable hash (still 64 hex chars)
		hash := InstanceHash(fmt.Sprintf("%064d", i))
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
	orphanedHashes := []InstanceHash{
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

// TestConsistencyChecker_UsageReconciliation verifies that the metadata
// scan detects and corrects drifted usage counters.  It seeds objects with
// known block state, deliberately skews the stored usage counter by more
// than 5 %, and asserts that RunMetadataScan corrects the value.
func TestConsistencyChecker_UsageReconciliation(t *testing.T) {
	InitIssuerKeyForTests(t)

	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	// Discover assigned storage ID.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 1)
	var diskID StorageID
	for id := range assignedDirs {
		diskID = id
	}

	nsID := NamespaceID(1)

	// Create two objects with known block state.
	// Object 1: 3 full blocks = 3*BlockDataSize bytes.
	hash1 := InstanceHash("aaaa111111111111111111111111111111111111111111111111111111111111")
	contentLen1 := int64(3 * BlockDataSize)
	meta1 := &CacheMetadata{
		ContentLength: contentLen1,
		StorageID:     diskID,
		NamespaceID:   nsID,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	require.NoError(t, db.SetMetadata(hash1, meta1))
	// Mark all 3 blocks downloaded.
	bm1 := roaring.NewBitmap()
	bm1.AddRange(0, uint64(CalculateBlockCount(contentLen1)))
	require.NoError(t, db.SetBlockState(hash1, bm1))
	// Create the file so the metadata scan doesn't delete it as an orphan.
	filePath1 := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(hash1))
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath1), 0755))
	require.NoError(t, os.WriteFile(filePath1, make([]byte, contentLen1), 0644))

	// Object 2: 2 full blocks = 2*BlockDataSize bytes.
	hash2 := InstanceHash("bbbb222222222222222222222222222222222222222222222222222222222222")
	contentLen2 := int64(2 * BlockDataSize)
	meta2 := &CacheMetadata{
		ContentLength: contentLen2,
		StorageID:     diskID,
		NamespaceID:   nsID,
		Completed:     time.Now().Add(-10 * time.Minute),
	}
	require.NoError(t, db.SetMetadata(hash2, meta2))
	bm2 := roaring.NewBitmap()
	bm2.AddRange(0, uint64(CalculateBlockCount(contentLen2)))
	require.NoError(t, db.SetBlockState(hash2, bm2))
	filePath2 := filepath.Join(tmpDir, objectsSubDir, GetInstanceStoragePath(hash2))
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath2), 0755))
	require.NoError(t, os.WriteFile(filePath2, make([]byte, contentLen2), 0644))

	// The actual total usage should be 5*BlockDataSize.
	expectedUsage := int64(5 * BlockDataSize)

	// --- Case 1: stored counter is too high (>5 % drift) ---
	inflated := expectedUsage * 2 // 100 % over, far beyond 5 %
	require.NoError(t, db.SetUsage(diskID, nsID, inflated))

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  100 * 1024 * 1024,
		MinAgeForCleanup:     0,
	})
	require.NoError(t, checker.RunMetadataScan(ctx))

	corrected, err := db.GetUsage(diskID, nsID)
	require.NoError(t, err)
	assert.Equal(t, expectedUsage, corrected, "inflated usage should be corrected")

	// --- Case 2: stored counter is too low (>5 % drift) ---
	deflated := expectedUsage / 2 // 50 % under, far beyond 5 %
	require.NoError(t, db.SetUsage(diskID, nsID, deflated))

	require.NoError(t, checker.RunMetadataScan(ctx))

	corrected, err = db.GetUsage(diskID, nsID)
	require.NoError(t, err)
	assert.Equal(t, expectedUsage, corrected, "deflated usage should be corrected")

	// --- Case 3: within tolerance — no correction ---
	withinTolerance := expectedUsage + (expectedUsage * 4 / 100) // 4 % over, under 5 %
	require.NoError(t, db.SetUsage(diskID, nsID, withinTolerance))

	require.NoError(t, checker.RunMetadataScan(ctx))

	// Should remain unchanged (within tolerance).
	unchanged, err := db.GetUsage(diskID, nsID)
	require.NoError(t, err)
	assert.Equal(t, withinTolerance, unchanged, "within-tolerance usage should not change")
}

// ---------------------------------------------------------------------------
// Checksum (RFC 3230 Digest) tests through the persistent cache
// ---------------------------------------------------------------------------

// storeTestObject is a helper that creates a disk-backed object with known
// data, marks all blocks as downloaded, and returns the data that was
// written.  The caller can optionally attach checksums to the metadata
// before or after this call.
func storeTestObject(
	t *testing.T,
	ctx context.Context,
	storage *StorageManager,
	instanceHash InstanceHash,
	data []byte,
	storageID StorageID,
	namespaceID NamespaceID,
) {
	t.Helper()
	contentLength := int64(len(data))

	meta, err := storage.InitDiskStorage(ctx, instanceHash, contentLength, storageID)
	require.NoError(t, err)
	meta.NamespaceID = namespaceID
	meta.Completed = time.Now().Add(-10 * time.Minute)
	require.NoError(t, storage.SetMetadata(instanceHash, meta))

	// Write data blocks
	require.NoError(t, storage.WriteBlocks(instanceHash, 0, data))

	// Mark all blocks downloaded in DB
	totalBlocks := CalculateBlockCount(contentLength)
	bm := roaring.NewBitmap()
	bm.AddRange(0, uint64(totalBlocks))
	require.NoError(t, storage.db.SetBlockState(instanceHash, bm))
}

// TestVerifyObject_CorrectChecksum creates a disk-backed object with a
// correct SHA-256 checksum and verifies that VerifyObject returns true.
func TestVerifyObject_CorrectChecksum(t *testing.T) {
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	// Deterministic test data: 2.5 blocks worth of bytes.
	data := make([]byte, BlockDataSize*2+BlockDataSize/2)
	for i := range data {
		data[i] = byte(i % 251) // prime-cycle pattern
	}

	hash := InstanceHash("aaaa000000000000000000000000000000000000000000000000000000000001")
	storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

	// Compute the correct SHA-256 over the plaintext.
	sum := sha256.Sum256(data)

	// Attach the checksum to metadata.
	meta, err := storage.GetMetadata(hash)
	require.NoError(t, err)
	meta.Checksums = []Checksum{{
		Type:           ChecksumSHA256,
		Value:          sum[:],
		OriginVerified: true,
	}}
	require.NoError(t, storage.SetMetadata(hash, meta))

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  1 << 30,
		MinAgeForCleanup:     0,
	})

	valid, err := checker.VerifyObject(hash)
	require.NoError(t, err)
	assert.True(t, valid, "object with correct checksum should verify")
}

// TestVerifyObject_WrongChecksum creates a disk-backed object with an
// incorrect SHA-256 checksum and verifies that VerifyObject returns false.
func TestVerifyObject_WrongChecksum(t *testing.T) {
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	data := make([]byte, BlockDataSize*2+BlockDataSize/2)
	for i := range data {
		data[i] = byte(i % 251)
	}

	hash := InstanceHash("bbbb000000000000000000000000000000000000000000000000000000000002")
	storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

	// Attach a deliberately wrong checksum.
	wrongSum := sha256.Sum256([]byte("wrong data"))
	meta, err := storage.GetMetadata(hash)
	require.NoError(t, err)
	meta.Checksums = []Checksum{{
		Type:           ChecksumSHA256,
		Value:          wrongSum[:],
		OriginVerified: true,
	}}
	require.NoError(t, storage.SetMetadata(hash, meta))

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  1 << 30,
		MinAgeForCleanup:     0,
	})

	valid, err := checker.VerifyObject(hash)
	require.NoError(t, err)
	assert.False(t, valid, "object with wrong checksum should NOT verify")
}

// TestDataScan_CorrectChecksum runs a full data integrity scan with
// objects that have correct checksums and verifies nothing is flagged.
func TestDataScan_CorrectChecksum(t *testing.T) {
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	// Create 3 objects with correct SHA-256 checksums.
	for i := 0; i < 3; i++ {
		data := make([]byte, BlockDataSize+int(i)*100)
		for j := range data {
			data[j] = byte((i*7 + j) % 251)
		}
		hash := InstanceHash(fmt.Sprintf("cccc%060x", i+1))

		storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

		sum := sha256.Sum256(data)
		meta, err := storage.GetMetadata(hash)
		require.NoError(t, err)
		meta.Checksums = []Checksum{{
			Type:           ChecksumSHA256,
			Value:          sum[:],
			OriginVerified: true,
		}}
		require.NoError(t, storage.SetMetadata(hash, meta))
	}

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  1 << 30,
		MinAgeForCleanup:     0,
		ChecksumTypes:        []ChecksumType{ChecksumSHA256},
	})

	require.NoError(t, checker.RunDataScan(ctx))

	stats := checker.GetStats()
	assert.Equal(t, int64(0), stats.ChecksumMismatches, "no mismatches expected")
	assert.Equal(t, int64(3), stats.ObjectsVerified, "all 3 objects should be verified")
	assert.Greater(t, stats.BytesVerified, int64(0), "should have verified some bytes")
}

// TestDataScan_WrongChecksum runs a full data integrity scan with an object
// whose checksum deliberately does not match, and verifies the scan detects
// the mismatch and deletes the corrupt object.
func TestDataScan_WrongChecksum(t *testing.T) {
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	// Object with WRONG checksum — should be detected and deleted.
	data := make([]byte, BlockDataSize*2)
	for i := range data {
		data[i] = byte(i % 251)
	}
	corruptHash := InstanceHash("dddd000000000000000000000000000000000000000000000000000000000001")

	storeTestObject(t, ctx, storage, corruptHash, data, diskID, NamespaceID(1))

	wrongSum := sha256.Sum256([]byte("not the right data"))
	meta, err := storage.GetMetadata(corruptHash)
	require.NoError(t, err)
	meta.Checksums = []Checksum{{
		Type:           ChecksumSHA256,
		Value:          wrongSum[:],
		OriginVerified: true,
	}}
	require.NoError(t, storage.SetMetadata(corruptHash, meta))

	// Also create a VALID object to confirm it is not damaged.
	goodData := make([]byte, BlockDataSize)
	for i := range goodData {
		goodData[i] = byte(i % 199)
	}
	goodHash := InstanceHash("dddd000000000000000000000000000000000000000000000000000000000002")
	storeTestObject(t, ctx, storage, goodHash, goodData, diskID, NamespaceID(1))

	goodSum := sha256.Sum256(goodData)
	goodMeta, err := storage.GetMetadata(goodHash)
	require.NoError(t, err)
	goodMeta.Checksums = []Checksum{{
		Type:           ChecksumSHA256,
		Value:          goodSum[:],
		OriginVerified: true,
	}}
	require.NoError(t, storage.SetMetadata(goodHash, goodMeta))

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  1 << 30,
		MinAgeForCleanup:     0,
		ChecksumTypes:        []ChecksumType{ChecksumSHA256},
	})

	require.NoError(t, checker.RunDataScan(ctx))

	stats := checker.GetStats()
	assert.Equal(t, int64(1), stats.ChecksumMismatches, "one mismatch expected")

	// The corrupt object's disk file should have been deleted.
	corruptPath := storage.getObjectPathForDir(diskID, corruptHash)
	_, statErr := os.Stat(corruptPath)
	assert.True(t, os.IsNotExist(statErr), "corrupt object file should be removed")

	// The good object should still be intact and verifiable.
	valid, err := checker.VerifyObject(goodHash)
	require.NoError(t, err)
	assert.True(t, valid, "good object should still verify after scan")
}

// TestDataScan_MissingChecksum verifies that when an object has no stored
// checksums, the data scan calculates and stores them.
func TestDataScan_MissingChecksum(t *testing.T) {
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}

	data := make([]byte, BlockDataSize+500)
	for i := range data {
		data[i] = byte(i % 211)
	}
	hash := InstanceHash("eeee000000000000000000000000000000000000000000000000000000000001")
	storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

	// Verify no checksums stored yet.
	meta, err := storage.GetMetadata(hash)
	require.NoError(t, err)
	assert.Empty(t, meta.Checksums, "no checksums should be present initially")

	checker := NewConsistencyChecker(db, storage, ConsistencyConfig{
		MetadataScanActiveMs: 1000,
		DataScanBytesPerSec:  1 << 30,
		MinAgeForCleanup:     0,
		ChecksumTypes:        []ChecksumType{ChecksumSHA256},
	})

	require.NoError(t, checker.RunDataScan(ctx))

	// After the scan, checksum should be calculated and stored.
	meta, err = storage.GetMetadata(hash)
	require.NoError(t, err)
	require.Len(t, meta.Checksums, 1, "data scan should calculate one checksum")
	assert.Equal(t, ChecksumSHA256, meta.Checksums[0].Type)

	// The stored checksum should match the SHA-256 of the original data.
	expected := sha256.Sum256(data)
	assert.Equal(t, expected[:], meta.Checksums[0].Value,
		"stored checksum should match SHA-256 of original data")
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

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)

	// Discover the assigned IDs for eviction config.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 2, "expected exactly 2 storage dirs")

	// Give both directories the same capacity so ChooseDiskStorage alternates
	// between them (whichever has more free space after each write).
	dirCfgs := make(map[StorageID]EvictionDirConfig, len(assignedDirs))
	for id := range assignedDirs {
		dirCfgs[id] = EvictionDirConfig{MaxSize: 500_000, HighWaterPercentage: 90, LowWaterPercentage: 80}
	}
	eviction := NewEvictionManager(db, storage, EvictionConfig{
		DirConfigs: dirCfgs,
	})

	// --- Store several objects, recording usage ---

	type objectInfo struct {
		instanceHash InstanceHash
		storageID    StorageID
		size         int64
	}
	var objects []objectInfo
	const objectSize = 8192 // 2 blocks

	for i := 0; i < 10; i++ {
		instanceHash := InstanceHash(fmt.Sprintf("%064x", i+0x10))
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

	filesInDir := map[StorageID]int{storageID1: 0, storageID2: 0}
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

	expectedUsage := map[StorageID]int64{storageID1: 0, storageID2: 0}
	for _, obj := range objects {
		expectedUsage[obj.storageID] += obj.size
	}

	allUsage, err := db.GetAllUsage()
	require.NoError(t, err)

	actualUsage := map[StorageID]int64{}
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

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{dir1, dir2}, 0, egrp)
	require.NoError(t, err)

	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 2)

	// Identify the two storage IDs.
	var ids []StorageID
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
	createObject := func(i int, sid StorageID) InstanceHash {
		instanceHash := InstanceHash(fmt.Sprintf("%064x", i))
		meta, err := storage.InitDiskStorage(ctx, instanceHash, objSize, sid)
		require.NoError(t, err)
		meta.ETag = fmt.Sprintf("etag-%d", i)
		meta.NamespaceID = 1
		meta.ContentType = "application/octet-stream"
		meta.SourceURL = fmt.Sprintf("pelican://example.com/obj-%d", i)
		require.NoError(t, storage.SetMetadata(instanceHash, meta))

		data := make([]byte, objSize)
		for j := range data {
			data[j] = byte(i)
		}
		require.NoError(t, storage.WriteBlocks(instanceHash, 0, data))

		// Set ETag mapping
		objectHash := ComputeObjectHash(db.salt, meta.SourceURL)
		require.NoError(t, db.SetLatestETag(objectHash, meta.ETag, time.Now()))
		// Usage is tracked automatically by WriteBlocks → MergeBlockStateWithUsage.
		// Record LRU access
		require.NoError(t, db.UpdateLRU(instanceHash, 0))

		return instanceHash
	}

	// Create 3 objects on each storageID.
	var keepHashes, purgeHashes []InstanceHash
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
	for id := StorageID(StorageIDFirstDisk); ; id++ {
		dm := DiskMapping{
			ID:        id,
			UUID:      fmt.Sprintf("uuid-%d", id),
			Directory: fmt.Sprintf("/fake/dir/%d", id),
		}
		require.NoError(t, db.SaveDiskMapping(dm))
		// Add a small amount of usage so FindRecyclableStorageID can rank them.
		require.NoError(t, seedUsage(db, id, 1, int64(id)*100))
		if id == 255 {
			break
		}
	}

	// The real directory has no UUID file, so NewStorageManager will try
	// to assign it a new ID.  All 255 IDs are taken, so it must recycle.
	// StorageID 1 has the smallest usage (1*100 = 100), so it should be
	// recycled.
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{realDir}, 0, egrp)
	require.NoError(t, err, "should recycle a storageID instead of failing")

	dirs := storage.GetDirs()
	require.Len(t, dirs, 1)

	// The recycled ID should be 1 (smallest usage).
	var assignedID StorageID
	for id := range dirs {
		assignedID = id
	}
	assert.Equal(t, StorageIDFirstDisk, assignedID,
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
