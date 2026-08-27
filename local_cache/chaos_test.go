//go:build !windows

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// newChaosTestCache opens a read-write cache (database + storage) and returns
// it along with a disk storage ID.  The chaos injector wraps these same live
// handles, mirroring how the cache server uses it in-process.
func newChaosTestCache(t *testing.T) (*CacheDB, *StorageManager, StorageID) {
	t.Helper()
	InitIssuerKeyForTests(t)
	tmpDir := t.TempDir()
	ctx := context.Background()

	db, err := NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{tmpDir}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(storage.Close)

	var diskID StorageID
	for id := range storage.GetDirs() {
		diskID = id
	}
	return db, storage, diskID
}

// TestChaosCorruptBlock verifies that CorruptBlock flips on-disk bytes such
// that the targeted block can no longer be read back (its authentication tag
// fails).  Block 1 is corrupted and read cold (it is never read before
// corruption, so it is not served from the in-memory plaintext cache).
func TestChaosCorruptBlock(t *testing.T) {
	db, storage, diskID := newChaosTestCache(t)
	ctx := context.Background()

	data := make([]byte, 2*BlockDataSize)
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash("abab000000000000000000000000000000000000000000000000000000000001")
	storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

	ci := NewChaosInjector(db, storage)
	res, err := ci.CorruptBlock("", "", string(hash), 1, 0)
	require.NoError(t, err)
	assert.Equal(t, "corrupt-block", res.Operation)
	assert.Equal(t, int64(1), res.BlockNum)
	assert.Equal(t, AuthTagSize, res.BytesChanged)
	assert.Equal(t, res.OldFileSize, res.NewFileSize)

	// Block 1 (never read before corruption) now fails to decrypt.
	_, err = storage.ReadBlocks(hash, BlockDataSize, BlockDataSize)
	require.Error(t, err, "reading a corrupted block should fail the authentication check")
}

// TestChaosTruncateObject verifies that TruncateObject drops trailing blocks so
// that a removed block can no longer be read back.
func TestChaosTruncateObject(t *testing.T) {
	db, storage, diskID := newChaosTestCache(t)
	ctx := context.Background()

	data := make([]byte, 2*BlockDataSize)
	for i := range data {
		data[i] = byte(i % 251)
	}
	hash := InstanceHash("baba000000000000000000000000000000000000000000000000000000000001")
	storeTestObject(t, ctx, storage, hash, data, diskID, NamespaceID(1))

	ci := NewChaosInjector(db, storage)
	res, err := ci.TruncateObject("", "", string(hash), -1, 0)
	require.NoError(t, err)
	assert.Equal(t, "truncate", res.Operation)
	assert.Equal(t, res.OldFileSize-BlockTotalSize, res.NewFileSize,
		"default truncation drops one encrypted block")

	// The dropped (last) block can no longer be read.
	_, err = storage.ReadBlocks(hash, BlockDataSize, BlockDataSize)
	require.Error(t, err, "reading a truncated-away block should fail")
}

// TestChaosInlineRejected verifies that chaos injection refuses inline objects,
// which live in the database rather than on disk.
func TestChaosInlineRejected(t *testing.T) {
	db, storage, _ := newChaosTestCache(t)
	ctx := context.Background()

	hash := InstanceHash("acdc000000000000000000000000000000000000000000000000000000000001")
	small := []byte("small inline payload")
	meta := &CacheMetadata{ContentLength: int64(len(small)), StorageID: StorageIDInline, NamespaceID: NamespaceID(1)}
	require.NoError(t, storage.StoreInline(ctx, hash, meta, small))

	ci := NewChaosInjector(db, storage)
	_, err := ci.CorruptBlock("", "", string(hash), 0, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "inline")
}
