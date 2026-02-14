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
	mu       sync.RWMutex    // protects bitmap, downloading
	bitmap   *roaring.Bitmap // guarded by mu
	repairMu sync.Mutex      // serializes repair operations; independent of mu

	// cond is broadcast whenever a block is added (via Add/AddRange)
	// or downloading transitions to false (via ClearDownloading).
	// Waiters hold mu.RLock via cond (cond is bound to mu.RLocker()).
	cond *sync.Cond

	// downloading is true while a background download is writing
	// blocks into this bitmap.  When true, WaitForBlock will block
	// until the requested block appears or downloading becomes false.
	// Guarded by mu (read under RLock, written under Lock).
	downloading bool
}

// NewObjectBlockState wraps an existing bitmap in a thread-safe container.
func NewObjectBlockState(bitmap *roaring.Bitmap) *ObjectBlockState {
	if bitmap == nil {
		bitmap = roaring.New()
	}
	obs := &ObjectBlockState{bitmap: bitmap}
	obs.cond = sync.NewCond(obs.mu.RLocker())
	return obs
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
	obs.bitmap.Add(block)
	obs.mu.Unlock()
	obs.cond.Broadcast()
}

// AddRange marks all blocks in [start, end] as downloaded.
func (obs *ObjectBlockState) AddRange(start, end uint32) {
	obs.mu.Lock()
	obs.bitmap.AddRange(uint64(start), uint64(end)+1)
	obs.mu.Unlock()
	obs.cond.Broadcast()
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

// SetDownloading marks this object as having a background download in
// progress.  WaitForBlock will block while downloading is true.
func (obs *ObjectBlockState) SetDownloading() {
	obs.mu.Lock()
	obs.downloading = true
	obs.mu.Unlock()
}

// ClearDownloading marks the background download as finished and wakes
// any goroutines waiting in WaitForBlock.
func (obs *ObjectBlockState) ClearDownloading() {
	obs.mu.Lock()
	obs.downloading = false
	obs.mu.Unlock()
	obs.cond.Broadcast()
}

// WaitForBlock waits until the specified block is available in the bitmap.
// It returns true if the block is available, false if the context was
// cancelled or the background download finished without producing the
// block.  This avoids starting duplicate range downloads when a full
// download is already in progress.
//
// The implementation spawns a goroutine to wait on the sync.Cond (which
// cannot be interrupted) and selects between it and ctx.Done().  On
// context cancellation, we signal the goroutine via a done channel and
// broadcast the cond, then wait for the goroutine to acknowledge exit
// before returning.  This guarantees no goroutine leak.
func (obs *ObjectBlockState) WaitForBlock(ctx context.Context, block uint32) bool {
	// Fast path: block already available
	obs.mu.RLock()
	if obs.bitmap.Contains(block) {
		obs.mu.RUnlock()
		return true
	}
	if !obs.downloading {
		obs.mu.RUnlock()
		return false
	}
	obs.mu.RUnlock()

	// Slow path: wait for the cond broadcast from Add/ClearDownloading.
	//
	// sync.Cond.Wait cannot be interrupted by context cancellation, so
	// we run the cond loop in a separate goroutine.  The done channel
	// lets the caller signal the goroutine to stop, and exited lets
	// the caller wait for the goroutine to release the RLock.
	ready := make(chan bool, 1)
	done := make(chan struct{})   // closed by caller on ctx cancellation
	exited := make(chan struct{}) // closed by goroutine on exit
	go func() {
		defer close(exited)
		obs.mu.RLock()
		defer obs.mu.RUnlock()
		for !obs.bitmap.Contains(block) && obs.downloading {
			// Check if the caller has cancelled before sleeping.
			select {
			case <-done:
				return
			default:
			}
			obs.cond.Wait()
		}
		select {
		case ready <- obs.bitmap.Contains(block):
		case <-done:
		}
	}()

	select {
	case found := <-ready:
		return found
	case <-ctx.Done():
		close(done)
		// Wake the goroutine so it unblocks from cond.Wait and sees done.
		obs.cond.Broadcast()
		// Wait for the goroutine to release the RLock and exit.
		<-exited
		return false
	}
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
