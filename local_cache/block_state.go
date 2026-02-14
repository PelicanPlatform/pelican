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
	"sync"

	"github.com/RoaringBitmap/roaring"
	"github.com/pkg/errors"
)

// ObjectBlockState holds the shared, thread-safe block availability state for
// a single cached object.  All RangeReaders serving the same instanceHash share
// one instance, ensuring that block additions (downloads) and removals
// (corruption repairs) are immediately visible to every goroutine.
//
// The repairMu mutex serializes repair operations: when multiple readers
// detect corruption simultaneously, only the first one performs the
// clear-fetch-verify cycle.  Subsequent callers acquire repairMu, re-check
// block availability, and skip the repair if it has already been done.
type ObjectBlockState struct {
	mu       sync.RWMutex
	bitmap   *roaring.Bitmap
	repairMu sync.Mutex
}

// NewObjectBlockState wraps an existing bitmap in a thread-safe container.
func NewObjectBlockState(bitmap *roaring.Bitmap) *ObjectBlockState {
	if bitmap == nil {
		bitmap = roaring.New()
	}
	return &ObjectBlockState{bitmap: bitmap}
}

// Contains returns true if the given block is marked as downloaded.
func (obs *ObjectBlockState) Contains(block uint32) bool {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	return obs.bitmap.Contains(block)
}

// ContainsRange returns true if every block in [start, end] is present.
func (obs *ObjectBlockState) ContainsRange(start, end uint32) bool {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	for b := start; b <= end; b++ {
		if !obs.bitmap.Contains(b) {
			return false
		}
	}
	return true
}

// MissingInRange returns the list of blocks in [start, end] that are not present.
func (obs *ObjectBlockState) MissingInRange(start, end uint32) []uint32 {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	var missing []uint32
	for b := start; b <= end; b++ {
		if !obs.bitmap.Contains(b) {
			missing = append(missing, b)
		}
	}
	return missing
}

// Add marks a single block as downloaded.
func (obs *ObjectBlockState) Add(block uint32) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	obs.bitmap.Add(block)
}

// AddRange marks all blocks in [start, end] as downloaded.
func (obs *ObjectBlockState) AddRange(start, end uint32) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	obs.bitmap.AddRange(uint64(start), uint64(end)+1)
}

// Remove marks a single block as not-downloaded.
func (obs *ObjectBlockState) Remove(block uint32) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	obs.bitmap.Remove(block)
}

// RemoveMany marks the given blocks as not-downloaded.
func (obs *ObjectBlockState) RemoveMany(blocks []uint32) {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	for _, b := range blocks {
		obs.bitmap.Remove(b)
	}
}

// Clone returns a point-in-time snapshot of the bitmap. The returned bitmap
// is independent (mutations to it do not affect the shared state).
func (obs *ObjectBlockState) Clone() *roaring.Bitmap {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	return obs.bitmap.Clone()
}

// GetCardinality returns the number of blocks that are downloaded.
func (obs *ObjectBlockState) GetCardinality() uint64 {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	return obs.bitmap.GetCardinality()
}

// LockRepair acquires the per-object repair mutex. Only one goroutine at a
// time may run the clear-fetch-verify repair cycle.
func (obs *ObjectBlockState) LockRepair() {
	obs.repairMu.Lock()
}

// UnlockRepair releases the per-object repair mutex.
func (obs *ObjectBlockState) UnlockRepair() {
	obs.repairMu.Unlock()
}

// GetSharedBlockState returns the shared, thread-safe block state for the
// given instanceHash. The state is loaded from the persistent database on first
// access and cached for the lifetime of the StorageManager. All callers
// for the same instanceHash receive the same *ObjectBlockState.
func (sm *StorageManager) GetSharedBlockState(instanceHash string) (*ObjectBlockState, error) {
	sm.blockStatesMu.Lock()
	defer sm.blockStatesMu.Unlock()

	if obs, exists := sm.blockStates[instanceHash]; exists {
		return obs, nil
	}

	bitmap, err := sm.db.GetBlockState(instanceHash)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load block state from database")
	}

	obs := NewObjectBlockState(bitmap)
	sm.blockStates[instanceHash] = obs
	return obs, nil
}

// InvalidateSharedBlockState removes the cached block state for a instanceHash,
// forcing the next GetSharedBlockState call to reload from the database.
// This should be called when an object is deleted.
func (sm *StorageManager) InvalidateSharedBlockState(instanceHash string) {
	sm.blockStatesMu.Lock()
	defer sm.blockStatesMu.Unlock()
	delete(sm.blockStates, instanceHash)
}
