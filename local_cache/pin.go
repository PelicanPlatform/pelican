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

// Reader pinning.
//
// Deleting an object that a reader is part-way through breaks that reader.
// refCountedFile keeps the file descriptor alive across the unlink, but the
// reader also needs the object's metadata, its data key, and its block state,
// and Delete removes all three.
//
// This lives beside the reader constructors and Delete rather than in a
// consumer, because those are the operations that have to agree: a pin taken
// anywhere else could always be taken a moment too late.  Every reader is
// pinned automatically -- NewObjectReader does it directly, and the cache's
// HTTP serving path does it in newFetchingRangeReader, which is where both
// GetRange and GetSeekableReader build their RangeReader -- so a consumer only
// has to decide whether its delete path respects pins.
//
// Both consumers respect it.  The pstore origin does through
// DeleteIfUnpinned, because it deletes exactly the version most likely to be
// under a reader: the one just superseded by an overwrite.  The cache's LRU
// eviction does through the skip predicate it hands to CacheDB.EvictByLRU;
// its victim is the least recently used object, so the overlap is small, but
// LRU timestamps are debounced by ten minutes and a slow reader on a large
// object can drift toward the head of the index.
//
// The cost is one mutex acquisition and one map operation per reader open and
// close, and one more per eviction candidate.  A reader open already involves
// a metadata read, a key unwrap, and a file open, and evicting an object
// costs a Badger delete plus an unlink per chunk, so the check is not
// measurable against either.  The map is sized by live readers, not by the
// number of objects in the store.

package local_cache

import "sync"

// pinSet counts live readers per object version.
type pinSet struct {
	mu    sync.Mutex
	count map[InstanceHash]int
}

func newPinSet() *pinSet {
	return &pinSet{count: make(map[InstanceHash]int)}
}

// pin registers a reader and returns the function that releases it.  The
// returned function is idempotent, so a handle may safely Close twice.
func (p *pinSet) pin(h InstanceHash) func() {
	p.mu.Lock()
	p.count[h]++
	p.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if n := p.count[h]; n <= 1 {
				delete(p.count, h)
			} else {
				p.count[h] = n - 1
			}
		})
	}
}

// isPinned reports whether any reader currently holds the version.
func (p *pinSet) isPinned(h InstanceHash) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.count[h]
	return ok
}

// PinObject holds an object version open, preventing DeleteIfUnpinned from
// reclaiming it, and returns the release function.
//
// NewObjectReader does this automatically; call it directly only when holding
// a version across something other than an ObjectReader.
func (sm *StorageManager) PinObject(instanceHash InstanceHash) func() {
	return sm.pins.pin(instanceHash)
}

// IsObjectPinned reports whether a reader currently holds the version.
func (sm *StorageManager) IsObjectPinned(instanceHash InstanceHash) bool {
	return sm.pins.isPinned(instanceHash)
}

// DeleteIfUnpinned deletes an object version unless a reader holds it.
//
// Returns false without deleting when the version is pinned, leaving the
// caller to retry later.  Use this wherever the object being deleted might
// plausibly be one somebody is reading.
func (sm *StorageManager) DeleteIfUnpinned(instanceHash InstanceHash) (bool, error) {
	if sm.pins.isPinned(instanceHash) {
		return false, nil
	}
	// A reader could still arrive between the check and the delete.  That
	// race is unavoidable without serializing every read against every
	// delete, and it is the same race the file descriptor already survives:
	// the reader either opens before the delete and holds a live handle, or
	// after it and gets a clean not-found.
	return true, sm.Delete(instanceHash)
}
