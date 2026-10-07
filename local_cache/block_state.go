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
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/RoaringBitmap/roaring"
	"github.com/jellydator/ttlcache/v3"
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
	mu       sync.RWMutex    // protects bitmap, downloading, fills
	bitmap   *roaring.Bitmap // guarded by mu
	repairMu sync.Mutex      // serializes repair operations; independent of mu

	// cond is broadcast whenever a block is added (via Add/AddRange),
	// downloading transitions to false (via ClearDownloading), or a fill
	// ends (via endFill).  Waiters hold mu.RLock via cond (cond is bound
	// to mu.RLocker()).
	cond *sync.Cond

	// downloading is true while a background download of the whole
	// object is writing blocks into this bitmap.  When true, WaitForBlock
	// will block until the requested block appears or downloading becomes
	// false.  Guarded by mu (read under RLock, written under Lock).
	downloading bool
	// downloadDone is closed when the download that set downloading ends.
	downloadDone chan struct{}

	// fills are the background fills of part of the object in progress
	// (see beginFill); WaitForBlock waits on one that covers its block as
	// it does on a whole-object download.  Guarded by mu.
	fills map[*blockFill]struct{}

	// condemned, once set, is why this instance's data was found bad and
	// the instance dropped (see condemn).  Guarded by mu.
	condemned error

	// waiting counts the goroutines asleep in WaitForBlock; it lets tests
	// know a reader is waiting.
	waiting atomic.Int32

	// readers counts the readers of the object that are open (see
	// AttachReader), and lastReaderChange is when one last attached or
	// detached (UnixNano).  A background fill of the object goes on while
	// any reader is open, and is idle once none has been for the fill's
	// timeout.
	readers          atomic.Int32
	lastReaderChange atomic.Int64

	// waitHooks, set only by tests, run at the two points of a cancelled
	// WaitForBlock whose ordering matters.
	waitHooks *blockWaitHooks
}

// blockWaitHooks let a test order a cancelled WaitForBlock's two goroutines.
type blockWaitHooks struct {
	beforeSleep func() // the waiter, holding the read lock, about to sleep
	onCancel    func() // the caller, its context done, about to wake it
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

// AttachReader records that a reader of the object is open and returns the
// function to call when it closes; calling that more than once is harmless.
//
// The count lives here, on the one state every reader of the object shares,
// rather than with whichever download or fetcher a reader happened to come
// through: a reader that arrived through a cache hit while a miss was still
// filling the object waits on this state, not on the miss's fetcher, and
// must keep that fill going just the same.
func (obs *ObjectBlockState) AttachReader() (detach func()) {
	obs.readers.Add(1)
	obs.lastReaderChange.Store(time.Now().UnixNano())
	return sync.OnceFunc(func() {
		obs.lastReaderChange.Store(time.Now().UnixNano())
		obs.readers.Add(-1)
	})
}

// readerActivity reports whether any reader is open and when one last
// attached or detached (the zero time if none ever has).
func (obs *ObjectBlockState) readerActivity() (open bool, last time.Time) {
	open = obs.readers.Load() > 0
	if ns := obs.lastReaderChange.Load(); ns != 0 {
		last = time.Unix(0, ns)
	}
	return open, last
}

// Contains returns true if the given block is marked as downloaded.
func (obs *ObjectBlockState) Contains(block uint32) bool {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	return obs.bitmap.Contains(block)
}

// ContainsRange returns true if every block in [start, end] is present.
// Creates a temporary range bitmap and checks if the intersection has
// the expected cardinality.  This is O(log n) for typical bitmap layouts.
func (obs *ObjectBlockState) ContainsRange(start, end uint32) bool {
	obs.mu.RLock()
	defer obs.mu.RUnlock()

	// Calculate expected count.  Handle overflow when end == MaxUint32.
	var expectedCount uint64
	if end >= start {
		expectedCount = uint64(end) - uint64(start) + 1
	} else {
		return false
	}

	// Create a range bitmap and intersect with what we have.
	rangeMap := roaring.New()
	if end == ^uint32(0) {
		// AddRange takes [start, end), so for MaxUint32 we need special handling.
		rangeMap.AddRange(uint64(start), uint64(end))
		rangeMap.Add(end)
	} else {
		rangeMap.AddRange(uint64(start), uint64(end)+1)
	}

	return obs.bitmap.AndCardinality(rangeMap) == expectedCount
}

// MissingInRange returns the list of blocks in [start, end] that are not present.
// Uses RoaringBitmap's iterator for efficiency instead of checking each block.
func (obs *ObjectBlockState) MissingInRange(start, end uint32) []uint32 {
	obs.mu.RLock()
	defer obs.mu.RUnlock()

	// Build a full-range bitmap and subtract what we have to find missing blocks.
	// This is more efficient than iterating every block for large ranges.
	fullRange := roaring.New()
	// AddRange takes [start, end) so add 1 to end.  Handle overflow.
	if end == ^uint32(0) {
		fullRange.AddRange(uint64(start), uint64(end))
		fullRange.Add(end)
	} else {
		fullRange.AddRange(uint64(start), uint64(end)+1)
	}

	missing := roaring.AndNot(fullRange, obs.bitmap)
	return missing.ToArray()
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
	if !obs.downloading {
		obs.downloadDone = make(chan struct{})
	}
	obs.downloading = true
	obs.mu.Unlock()
}

// ClearDownloading marks the background download as finished and wakes
// any goroutines waiting in WaitForBlock.  A download that failed in a way
// that condemns its data must condemn the state first (see condemn), so that
// the readers it wakes see why.
func (obs *ObjectBlockState) ClearDownloading() {
	obs.mu.Lock()
	obs.downloading = false
	if obs.downloadDone != nil {
		close(obs.downloadDone)
		obs.downloadDone = nil
	}
	obs.mu.Unlock()
	obs.cond.Broadcast()
}

// writersOver returns what is still due to write any of the given blocks:
// the done channel of every fill in progress that overlaps them, and that of
// the whole-object download, if one is in progress (nil when none).  A
// reader that served those blocks relies on these writers' verdicts as well
// as their bytes; see RangeReader.WaitForCompletion.
func (obs *ObjectBlockState) writersOver(blocks *roaring.Bitmap) (fills []<-chan struct{}, download <-chan struct{}) {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	for f := range obs.fills {
		if blocks.IntersectsWithInterval(uint64(f.start), uint64(f.end)+1) {
			fills = append(fills, f.done)
		}
	}
	if obs.downloading {
		download = obs.downloadDone
	}
	return fills, download
}

// blockFill is a background fill of blocks [start, end] of an object.
type blockFill struct {
	start, end uint32
	done       chan struct{} // closed by endFill
}

// condemn records that the instance's data was found bad and the instance
// is being dropped, so that its readers -- which hold this state, while the
// next request gets a fresh one -- fail with the reason instead of reading
// or completing it, and wakes any of them waiting for a block.
func (obs *ObjectBlockState) condemn(err error) {
	obs.mu.Lock()
	if obs.condemned == nil {
		obs.condemned = err
	}
	obs.mu.Unlock()
	obs.cond.Broadcast()
}

// waiters returns how many goroutines are asleep in WaitForBlock.
func (obs *ObjectBlockState) waiters() int32 {
	return obs.waiting.Load()
}

// Condemned returns why the instance was dropped as bad, or nil.
func (obs *ObjectBlockState) Condemned() error {
	obs.mu.RLock()
	defer obs.mu.RUnlock()
	return obs.condemned
}

// beingFilledLocked reports whether a background download or fill is due to
// write the block.  The caller holds mu.
func (obs *ObjectBlockState) beingFilledLocked(block uint32) bool {
	if obs.condemned != nil {
		return false
	}
	if obs.downloading {
		return true
	}
	for f := range obs.fills {
		if f.start <= block && block <= f.end {
			return true
		}
	}
	return false
}

// beginFill registers a background fill that starts at a missing block and
// runs up to the next block already present, or to last, whichever comes
// first.  It returns nil when the block is present, or a download or another
// fill is already due to write it: the caller should wait for it instead
// (see WaitForBlock).  It also returns nil once the object is condemned, so
// that no fill starts into an instance being dropped; the waiting caller then
// finds the reason.  Every fill begun must be ended with endFill.
func (obs *ObjectBlockState) beginFill(block, last uint32) *blockFill {
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if block > last || obs.condemned != nil || obs.bitmap.Contains(block) || obs.beingFilledLocked(block) {
		return nil
	}
	end := last
	it := obs.bitmap.Iterator()
	it.AdvanceIfNeeded(block)
	if it.HasNext() {
		if next := it.Next(); next-1 < end {
			end = next - 1
		}
	}
	// Stop short of another fill, too, rather than fetch its blocks twice.
	for f := range obs.fills {
		if f.start > block && f.start-1 < end {
			end = f.start - 1
		}
	}
	f := &blockFill{start: block, end: end, done: make(chan struct{})}
	if obs.fills == nil {
		obs.fills = make(map[*blockFill]struct{})
	}
	obs.fills[f] = struct{}{}
	return f
}

// endFill unregisters a fill begun with beginFill and wakes any goroutine
// waiting in WaitForBlock, which then finds its block written or falls back
// to fetching it itself.
func (obs *ObjectBlockState) endFill(f *blockFill) {
	obs.mu.Lock()
	delete(obs.fills, f)
	obs.mu.Unlock()
	close(f.done)
	obs.cond.Broadcast()
}

// WaitForBlock waits until the specified block is available in the bitmap.
// It returns true if the block is available, false if the context was
// cancelled, or no background download or fill is due to write the block
// (any more) and it is not there.  This avoids starting duplicate range
// downloads when a download or fill is already in progress.
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
	if !obs.beingFilledLocked(block) {
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
		for !obs.bitmap.Contains(block) && obs.beingFilledLocked(block) {
			// Check if the caller has cancelled before sleeping.
			select {
			case <-done:
				return
			default:
			}
			if obs.waitHooks != nil {
				obs.waitHooks.beforeSleep()
			}
			obs.waiting.Add(1)
			obs.cond.Wait()
			obs.waiting.Add(-1)
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
		if obs.waitHooks != nil {
			obs.waitHooks.onCancel()
		}
		// Close done under the write lock, then wake the goroutine so it
		// unblocks from cond.Wait and sees done.  The goroutine holds the
		// read lock from its check of done until cond.Wait has queued it
		// for a wakeup, so with the write lock it has either not checked
		// done yet or is queued; without it, the broadcast could land
		// between the check and the queueing, and be lost -- leaving this
		// call waiting below until something else broadcasts, which for a
		// stalled transfer is when the transfer gives up.
		obs.mu.Lock()
		close(done)
		obs.mu.Unlock()
		obs.cond.Broadcast()
		// Wait for the goroutine to release the RLock and exit.
		<-exited
		return false
	}
}

// blockStateTTL is how long an idle ObjectBlockState lives in the
// in-memory cache before being evicted.  Every GetSharedBlockState call
// touches the entry, so actively-used states stay resident.  Evicted
// states are simply reloaded from the database on next access -- unless
// something still holds the evicted one; see blockStateCache.
const blockStateTTL = 5 * time.Minute

// blockStateCache is the TTL cache of shared ObjectBlockStates, plus a
// record of every state still in use.
//
// Holders keep their *ObjectBlockState for as long as they work on the
// object: a RangeReader for its life, a fetcher for the life of its
// download or fill.  Writers
// update whichever state GetSharedBlockState returns at the time.  If the
// TTL dropped an idle entry while a holder still had it and a later load
// built a fresh one, the two would diverge for good: blocks written through
// the new state would never appear in the held one, and a holder waiting
// for them would wait forever.  So a load first looks for a state that is
// still referenced anywhere and hands that back; only a state nobody holds
// is rebuilt from the database.  Expiry thereby only ever frees memory.
//
// Explicit invalidation (InvalidateSharedBlockState) is different: it is
// called when the object's local data is going away, and deliberately
// starts a new state that does not share the old one's history.
type blockStateCache struct {
	*ttlcache.Cache[InstanceHash, *ObjectBlockState]
	// live maps a hash to a weak pointer to the state last issued for it.
	// An entry is removed when that state is collected or invalidated.
	live sync.Map
}

// newBlockStateCache creates the TTL cache for shared ObjectBlockState entries.
// The StorageManager calls this once during construction.
func newBlockStateCache(db *CacheDB) *blockStateCache {
	bc := &blockStateCache{}
	loader := ttlcache.LoaderFunc[InstanceHash, *ObjectBlockState](
		func(cache *ttlcache.Cache[InstanceHash, *ObjectBlockState], instanceHash InstanceHash) *ttlcache.Item[InstanceHash, *ObjectBlockState] {
			if held := bc.liveState(instanceHash); held != nil {
				return cache.Set(instanceHash, held, ttlcache.DefaultTTL)
			}
			bitmap, err := db.GetBlockState(instanceHash)
			if err != nil {
				// Return nil — the caller's Get will return nil and
				// GetSharedBlockState will propagate the error.
				return nil
			}
			obs := NewObjectBlockState(bitmap)
			wp := weak.Make(obs)
			bc.live.Store(instanceHash, wp)
			runtime.AddCleanup(obs, func(h InstanceHash) { bc.live.CompareAndDelete(h, wp) }, instanceHash)
			return cache.Set(instanceHash, obs, ttlcache.DefaultTTL)
		},
	)

	bc.Cache = ttlcache.New[InstanceHash, *ObjectBlockState](
		ttlcache.WithTTL[InstanceHash, *ObjectBlockState](blockStateTTL),
		ttlcache.WithLoader[InstanceHash, *ObjectBlockState](
			ttlcache.NewSuppressedLoader[InstanceHash, *ObjectBlockState](loader, nil),
		),
	)
	return bc
}

// liveState returns the state last issued for a hash if anything still
// holds it, or nil.
func (bc *blockStateCache) liveState(instanceHash InstanceHash) *ObjectBlockState {
	v, ok := bc.live.Load(instanceHash)
	if !ok {
		return nil
	}
	return v.(weak.Pointer[ObjectBlockState]).Value()
}

// invalidate drops a hash's state from the cache and forgets any holder's
// copy, so the next load starts afresh from the database.
func (bc *blockStateCache) invalidate(instanceHash InstanceHash) {
	bc.live.Delete(instanceHash)
	bc.Delete(instanceHash)
}

// GetSharedBlockState returns the shared, thread-safe block state for the
// given instanceHash.  The state is loaded from the persistent database on
// first access and cached in a TTL cache that evicts idle entries after
// blockStateTTL.  Every call touches the entry's TTL so actively-used
// states remain resident.  All callers for the same instanceHash receive
// the same *ObjectBlockState.
func (sm *StorageManager) GetSharedBlockState(instanceHash InstanceHash) (*ObjectBlockState, error) {
	item := sm.blockStates.Get(instanceHash) // auto-loads on miss via SuppressedLoader
	if item == nil {
		return nil, errors.New("failed to load block state from database")
	}
	return item.Value(), nil
}

// InvalidateSharedBlockState removes the cached block state for an instanceHash,
// forcing the next GetSharedBlockState call to reload from the database.
// This should be called when an object is deleted or evicted.
func (sm *StorageManager) InvalidateSharedBlockState(instanceHash InstanceHash) {
	sm.blockStates.invalidate(instanceHash)
}
