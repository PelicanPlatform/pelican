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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const pinTestNamespaceID = NamespaceID(1)

// newPinTestStorage builds a single-directory store for the pinning tests.
func newPinTestStorage(t *testing.T) (*StorageManager, *CacheDB, context.Context) {
	t.Helper()
	InitIssuerKeyForTests(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	db, err := NewCacheDB(ctx, t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(db, []string{t.TempDir()}, 0, egrp)
	require.NoError(t, err)
	t.Cleanup(storage.Close)

	return storage, db, ctx
}

// writePinTestObject stores one complete object and returns its instance hash.
// Hashes are ordered by idx, so the order these objects appear under a Badger
// prefix scan is the order they were created in.
func writePinTestObject(t *testing.T, sm *StorageManager, db *CacheDB, ctx context.Context, idx int) InstanceHash {
	t.Helper()
	return writePinTestObjectAs(t, sm, db, ctx, InstanceHash(fmt.Sprintf("%064x", idx+0x200)), idx, "")
}

// writePinTestObjectAs stores one complete object under a caller-chosen
// instance hash, optionally recording a source URL and the ETag entry that
// points at it -- the shape a real cached object has.
func writePinTestObjectAs(t *testing.T, sm *StorageManager, db *CacheDB, ctx context.Context, instanceHash InstanceHash, idx int, sourceURL string) InstanceHash {
	t.Helper()

	const objectSize = 4096
	chunkSizeCode := BytesToChunkSizeCode(uint64(2 * 1024 * 1024))

	meta, err := sm.InitLazyChunkedStorage(ctx, instanceHash, objectSize, chunkSizeCode)
	require.NoError(t, err)

	// Record the namespace before allocating, so the usage counters are
	// charged and refunded under the same key.  Setting it afterwards charges
	// namespace 0 and credits pinTestNamespaceID, which leaves the directory
	// permanently "full" and would make any usage assertion meaningless.
	meta.NamespaceID = pinTestNamespaceID
	meta.SourceURL = sourceURL
	require.NoError(t, sm.SetMetadata(instanceHash, meta))

	for ci := 0; ci < CalculateChunkCount(objectSize, chunkSizeCode); ci++ {
		meta, err = sm.AllocateChunk(ctx, instanceHash, meta, ci)
		require.NoError(t, err)
	}

	data := make([]byte, objectSize)
	for j := range data {
		data[j] = byte((idx + j) % 256)
	}
	require.NoError(t, sm.WriteBlocks(instanceHash, 0, data))

	meta.Completed = time.Now()
	require.NoError(t, sm.SetMetadata(instanceHash, meta))

	// Without an LRU entry the object is invisible to eviction, and the tests
	// below would pass for the wrong reason.
	require.NoError(t, db.UpdateLRU(instanceHash, 0))

	return instanceHash
}

func TestPinSetRefCounting(t *testing.T) {
	p := newPinSet()
	h := InstanceHash("abc")

	assert.False(t, p.isPinned(h))

	first := p.pin(h)
	second := p.pin(h)
	assert.True(t, p.isPinned(h))

	first()
	assert.True(t, p.isPinned(h), "the second reader still holds it")

	// A handle may be closed twice; that must not drop the other reader.
	first()
	assert.True(t, p.isPinned(h), "a repeated release must be a no-op")

	second()
	assert.False(t, p.isPinned(h))
}

// TestEvictByLRUSparesPinnedObjects verifies that eviction steps over an
// object with a live reader and takes the others instead.
func TestEvictByLRUSparesPinnedObjects(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)

	kept := writePinTestObject(t, sm, db, ctx, 0)
	for i := 1; i < 4; i++ {
		writePinTestObject(t, sm, db, ctx, i)
	}

	release := sm.PinObject(kept)

	// No object limit and a byte target large enough to take everything, so
	// the pin is the only thing that can save an object.
	evicted, _, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)
	assert.Equal(t, 1, skipped, "the pinned object should have been stepped over")
	assert.Len(t, evicted, 3, "every unpinned object should still go")
	for _, obj := range evicted {
		assert.NotEqual(t, kept, obj.instanceHash)
	}

	present, err := sm.HasObject(kept)
	require.NoError(t, err)
	assert.True(t, present, "a pinned object must survive eviction")

	// Once the reader finishes, the object is an ordinary candidate again.
	release()
	evicted, _, skipped, err = sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)
	assert.Zero(t, skipped)
	require.Len(t, evicted, 1)
	assert.Equal(t, kept, evicted[0].instanceHash)
}

// TestEvictByLRUMakesNoProgressWhenAllPinned verifies that a pass where every
// candidate is in use returns empty-handed rather than scanning indefinitely,
// and that a skip is not charged against maxObjects.
func TestEvictByLRUMakesNoProgressWhenAllPinned(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)

	var releases []func()
	for i := 0; i < 4; i++ {
		releases = append(releases, sm.PinObject(writePinTestObject(t, sm, db, ctx, i)))
	}

	evicted, freed, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 2, 0)
	require.NoError(t, err)
	assert.Empty(t, evicted)
	assert.Zero(t, freed)
	assert.Equal(t, 4, skipped,
		"a skip must not count against maxObjects, so all four are examined")

	for _, release := range releases {
		release()
	}
	evicted, _, _, err = sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 2, 0)
	require.NoError(t, err)
	assert.Len(t, evicted, 2, "maxObjects still bounds a pass that makes progress")
}

// TestDeleteIfUnpinnedRespectsReaders covers the pstore origin's delete path.
func TestDeleteIfUnpinnedRespectsReaders(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)
	h := writePinTestObject(t, sm, db, ctx, 0)

	release := sm.PinObject(h)
	deleted, err := sm.DeleteIfUnpinned(h)
	require.NoError(t, err)
	assert.False(t, deleted, "a pinned version must not be deleted")

	present, err := sm.HasObject(h)
	require.NoError(t, err)
	assert.True(t, present)

	release()
	deleted, err = sm.DeleteIfUnpinned(h)
	require.NoError(t, err)
	assert.True(t, deleted)

	present, err = sm.HasObject(h)
	require.NoError(t, err)
	assert.False(t, present)
}

// TestObjectReaderPinsAutomatically verifies the guarantee the mechanism rests
// on: opening a reader is enough to be protected, with no extra call.
func TestObjectReaderPinsAutomatically(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)
	h := writePinTestObject(t, sm, db, ctx, 0)

	reader, err := sm.NewObjectReader(h)
	require.NoError(t, err)
	assert.True(t, sm.IsObjectPinned(h), "opening a reader must pin the object")

	_, _, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)
	assert.Equal(t, 1, skipped)

	require.NoError(t, reader.Close())
	assert.False(t, sm.IsObjectPinned(h), "closing a reader must release the pin")
}

// TestEvictionClearsLatestETagPointer covers the ETag-table cleanup in
// deleteObjectInTxn.
//
// The e: entry names the current version of an object.  Evicting that version
// must take the entry with it -- an e: key is never itself evicted, so one left
// behind for an object whose data is gone is a key the database keeps forever.
// Evicting a superseded version must leave it alone, since it still points at
// something that is there.
//
// The comparison that decides between those two cases has to decode the stored
// entry: the value is [8-byte timestamp][etag] (see encodeETagEntry), so a raw
// byte comparison against meta.ETag matches nothing and quietly turns the whole
// cleanup into a no-op.
func TestEvictionClearsLatestETagPointer(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)

	const sourceURL = "pelican://example.org/ns/Mixed/Case/Data.txt"
	const oldETag = "\"v1\""
	const currentETag = "\"v2\""

	objectHash := db.ObjectHash(sourceURL)
	oldInstance := ComputeInstanceHash(db.Salt(), oldETag, objectHash)
	currentInstance := ComputeInstanceHash(db.Salt(), currentETag, objectHash)

	writePinTestObjectAs(t, sm, db, ctx, oldInstance, 0, sourceURL)
	writePinTestObjectAs(t, sm, db, ctx, currentInstance, 1, sourceURL)

	// The object's ETag record has to match what a real download writes, or
	// the metadata the deletion path compares against is not the one it sees.
	require.NoError(t, db.SetLatestETag(objectHash, currentETag, time.Now()))
	meta, err := sm.GetMetadata(oldInstance)
	require.NoError(t, err)
	meta.ETag = oldETag
	require.NoError(t, sm.SetMetadata(oldInstance, meta))
	meta, err = sm.GetMetadata(currentInstance)
	require.NoError(t, err)
	meta.ETag = currentETag
	require.NoError(t, sm.SetMetadata(currentInstance, meta))

	// Evicting the superseded version leaves the pointer to the current one.
	require.NoError(t, db.DeleteObject(oldInstance))
	etag, found, err := db.GetLatestETag(objectHash)
	require.NoError(t, err)
	assert.True(t, found, "an older version going away must not drop the pointer")
	assert.Equal(t, currentETag, etag)

	// Evicting the current version takes it.
	evicted, _, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)
	assert.Zero(t, skipped)
	got := make(map[InstanceHash]bool, len(evicted))
	for _, obj := range evicted {
		got[obj.instanceHash] = true
	}
	require.True(t, got[currentInstance], "the current version must be an eviction candidate")

	_, found, err = db.GetLatestETag(objectHash)
	require.NoError(t, err)
	assert.False(t, found, "evicting the current version must remove its ETag entry")

	assert.Zero(t, totalDirUsage(t, db, StorageIDFirstDisk),
		"the evicted objects' capacity must be returned")
}

// TestPurgeFirstDrainIgnoresSkipBudget covers the interaction between reader
// pinning and the admin evict API.
//
// The skip budget exists to stop a long run of protected objects at the head of
// the LRU index from turning a bounded eviction into a full index scan.  It has
// no business ending the purge-first drain: those objects are on an explicit
// list an operator (or the emergency low-space purge) asked to be removed, and
// abandoning the list because some of its entries happen to be under a reader
// silently ignores the request.
func TestPurgeFirstDrainIgnoresSkipBudget(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)

	// Lower the budget so the exhaustion path is reachable without building a
	// thousand objects.
	db.skipBudget = 2

	const total = 6
	const pinnedCount = 4
	hashes := make([]InstanceHash, total)
	for i := range hashes {
		hashes[i] = writePinTestObject(t, sm, db, ctx, i)
		require.NoError(t, db.MarkPurgeFirst(hashes[i]))
	}

	// Pin the objects that sort first, so a drain that stops at the budget
	// never reaches the two that could actually be freed.
	for i := 0; i < pinnedCount; i++ {
		release := sm.PinObject(hashes[i])
		t.Cleanup(release)
	}

	evicted, freed, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)

	got := make(map[InstanceHash]bool, len(evicted))
	for _, obj := range evicted {
		got[obj.instanceHash] = true
	}
	for i := pinnedCount; i < total; i++ {
		assert.True(t, got[hashes[i]],
			"purge-first object %d must be drained even though %d protected entries preceded it",
			i, pinnedCount)
	}
	for i := 0; i < pinnedCount; i++ {
		assert.False(t, got[hashes[i]], "a pinned object is still spared")
	}
	assert.Positive(t, freed)
	assert.GreaterOrEqual(t, skipped, pinnedCount,
		"every protected purge-first entry is still reported as skipped")
}

// TestEvictByLRUStopsLRUWalkAtSkipBudget is the other half of the split: the
// budget must still bound the LRU walk, which is the runaway-scan case it was
// added for.
func TestEvictByLRUStopsLRUWalkAtSkipBudget(t *testing.T) {
	sm, db, ctx := newPinTestStorage(t)
	db.skipBudget = 2

	for i := 0; i < 5; i++ {
		release := sm.PinObject(writePinTestObject(t, sm, db, ctx, i))
		t.Cleanup(release)
	}

	evicted, _, skipped, err := sm.EvictByLRU(StorageIDFirstDisk, pinTestNamespaceID, 0, 1<<30)
	require.NoError(t, err)
	assert.Empty(t, evicted)
	assert.Equal(t, 2, skipped,
		"the LRU walk must give up once the skip budget is spent rather than scan the whole index")
}
