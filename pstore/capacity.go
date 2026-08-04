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

// Capacity accounting.
//
// A pstore has a fixed size and never evicts: once full, writes fail with
// ErrNoSpace (which the WebDAV layer maps to 507) until something is deleted.
//
// Enforcement is a reservation taken *before* bytes are written, because the
// block store charges usage only once a file has been created and
// pre-allocated — by which point it is too late to refuse.  Reservations live
// in memory rather than the catalog: a store owns its directories exclusively
// for its lifetime, so an in-process counter is exact, and it costs no writes
// on the hot path.  Counters are seeded from the catalog's persisted usage at
// startup, so a restart recovers the true figure.
//
// Note that this bounds total capacity only.  Path-based quotas are a separate
// feature and are deliberately not implemented here; see
// docs/pstore-design.md §7.2.

package pstore

import (
	"math"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/metrics"
)

// parentDir maps a storage manager's "objects" subdirectory back to the
// directory that was configured.
//
// This is a filesystem path, so it uses filepath rather than the path package
// the namespace index uses.  Getting that wrong is silent on Linux and broken
// on Windows, where path.Dir on "C:\\store\\objects" finds no separator,
// returns ".", and every configured size limit fails to match -- leaving the
// store unbounded.
func parentDir(p string) string {
	return filepath.Dir(p)
}

// dirCapacity tracks one storage directory's committed and reserved bytes.
type dirCapacity struct {
	// maxBytes is the hard ceiling; zero means unbounded.
	maxBytes int64
	// used is bytes already charged in the catalog plus bytes reserved by
	// writes currently in flight.
	used int64
}

// capacityTracker enforces the store's size bound.
//
// Enforcement has two halves, and a write has to clear both.  The aggregate
// must have room for the whole object.  And the largest single unit the block
// store will place -- one chunk for a streamed object, the entire file for
// anything smaller -- must fit in some individual directory, because a unit
// lands whole or not at all.  A store spanning a nearly-full small disk and a
// large one has aggregate headroom long after the small disk can take another
// chunk, so checking only the total would accept writes that then fail on the
// filesystem.
//
// Placement is not opaque to this tracker: Store.Open hands chooseDir to the
// block store through SetChooseDir, and the middle write tier asks for a
// directory directly, so the same headroom figures that refuse a write also
// decide where its bytes go.
//
// Two details make the arithmetic honest.  A streamed object reserves its
// chunk-rounded footprint rather than its content length, because AppendWriter
// pre-allocates and charges whole chunks and the difference is refunded at
// settle.  And reservations still in flight participate in the per-directory
// test, since a directory's committed figure only catches up when a write
// settles -- without that, concurrent writers each measure the same free space
// and collectively overrun it.
type capacityTracker struct {
	mu   sync.Mutex
	dirs map[local_cache.StorageID]*dirCapacity

	// total is committed-plus-reserved bytes across every directory.
	total int64
	// maxTotal is the aggregate ceiling; zero means unbounded.  It is the sum
	// of the configured per-directory limits, and is unbounded if any
	// directory is unbounded.
	maxTotal int64
	// reserved is bytes claimed by writes in flight, included in total.
	reserved int64
}

// newCapacityTracker seeds per-directory counters from persisted usage.
func newCapacityTracker(
	db *local_cache.CacheDB,
	storage *local_cache.StorageManager,
	cfgDirs []local_cache.StorageDirConfig,
) (*capacityTracker, error) {
	mounted := storage.GetDirs()

	// Storage IDs are assigned by NewStorageManager in the order directories
	// were configured, so match limits back by path.
	//
	// Both sides are cleaned before they meet.  GetDirs reports
	// filepath.Join(configured, "objects"), which is already clean, so a
	// configured path carrying a trailing separator ("/srv/pstore/") would
	// never match the cleaned form parentDir yields -- and a limit that
	// matches nothing silently leaves the directory unbounded, disabling
	// every ENOSPC and 507 path the operator asked for.
	limitByPath := make(map[string]uint64, len(cfgDirs))
	for _, d := range cfgDirs {
		limitByPath[filepath.Clean(d.Path)] = d.MaxSize
	}

	ct := &capacityTracker{dirs: make(map[local_cache.StorageID]*dirCapacity, len(mounted)+1)}

	// Inline objects live in the catalog rather than a storage directory, but
	// they still occupy disk and are charged to StorageIDInline.  Tracking
	// that pseudo-directory is what keeps a store from being filled without
	// limit by objects that are each below the inline threshold.  It carries
	// no ceiling of its own; it contributes to the aggregate.
	inlineUsed, err := usageForDir(db, local_cache.StorageIDInline)
	if err != nil {
		return nil, err
	}
	ct.dirs[local_cache.StorageIDInline] = &dirCapacity{used: inlineUsed}
	ct.total += inlineUsed

	anyUnbounded := false
	for id, objDir := range mounted {
		used, err := usageForDir(db, id)
		if err != nil {
			return nil, err
		}
		dc := &dirCapacity{used: used}
		// GetDirs reports the "objects" subdirectory; the configured path is
		// its parent.
		if limit, ok := limitByPath[filepath.Clean(parentDir(objDir))]; ok && limit > 0 {
			dc.maxBytes = int64(limit)
		} else {
			anyUnbounded = true
		}
		ct.dirs[id] = dc
		ct.total += used
		ct.maxTotal += dc.maxBytes
	}
	// A single unbounded directory means the store as a whole is unbounded;
	// summing the rest would invent a ceiling that does not exist.
	if anyUnbounded {
		ct.maxTotal = 0
	}
	return ct, nil
}

// usageForDir sums the catalog's per-namespace usage counters for one
// storage directory.
func usageForDir(db *local_cache.CacheDB, id local_cache.StorageID) (int64, error) {
	perNamespace, err := db.GetDirUsage(id)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to read usage for storage directory %d", id)
	}
	var total int64
	for _, v := range perNamespace {
		total += v
	}
	return total, nil
}

// reserve claims nBytes of store capacity, returning ErrNoSpace when it will
// not fit.  Every successful reservation must be matched by exactly one
// releaseReservation or settle.
//
// Two conditions have to hold, and checking only the first is not enough.  The
// aggregate must have room, obviously.  But the block store places each chunk
// in a single directory, so some directory must also have room for the largest
// unit that will be placed there -- otherwise a write can pass an aggregate
// check with plenty of total headroom and then fail against a directory that
// is individually full.  unit is that placement granularity: one chunk for a
// streamed object, the whole footprint for anything smaller.
//
// held is what the caller has already reserved for this same write.  It is
// excluded from the per-directory test because the aggregate test above
// already counts it; leaving it in would make a growing streamed write
// increasingly refuse to extend itself.  Every *other* writer's in-flight
// reservation does count, which is what stops N concurrent writers from each
// seeing the same free space and collectively overrunning the ceiling.
func (ct *capacityTracker) reserve(nBytes, unit, held int64) error {
	if nBytes <= 0 {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if err := ct.roomForLocked(nBytes, unit, held); err != nil {
		return err
	}

	ct.total += nBytes
	ct.reserved += nBytes
	return nil
}

// checkRoom reports whether a reservation of nBytes with the given placement
// unit would currently be accepted, without claiming anything.
func (ct *capacityTracker) checkRoom(nBytes, unit int64) error {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.roomForLocked(nBytes, unit, 0)
}

// roomForLocked is the shared ErrNoSpace test behind reserve and checkRoom.
func (ct *capacityTracker) roomForLocked(nBytes, unit, held int64) error {
	if ct.maxTotal > 0 && ct.total+nBytes > ct.maxTotal {
		return errors.Wrapf(ErrNoSpace,
			"the store is full (%d of %d bytes used, %d requested)",
			ct.total, ct.maxTotal, nBytes)
	}
	if unit > 0 && !ct.anyDirHasRoomLocked(unit, held) {
		return errors.Wrapf(ErrNoSpace,
			"no storage directory has room for %d bytes, though the store as a "+
				"whole is under its limit", unit)
	}
	return nil
}

// anyDirHasRoomLocked reports whether some bounded directory can still take
// nBytes.  An unbounded directory always can.
//
// A directory's committed figure lags reality while writes are in flight: the
// block store charges the catalog as it pre-allocates, but this tracker learns
// the real placement only at settle.  Counting the other writers' outstanding
// reservations against every candidate directory closes that gap -- it is
// pessimistic when the store spans several directories, which is the correct
// direction to be wrong in for a check whose job is to refuse writes that
// would not fit.
func (ct *capacityTracker) anyDirHasRoomLocked(nBytes, held int64) bool {
	inFlight := clampNonNegative(ct.reserved - held)
	for id, dc := range ct.dirs {
		if id == local_cache.StorageIDInline {
			continue
		}
		if dc.maxBytes <= 0 || dc.used+inFlight+nBytes <= dc.maxBytes {
			return true
		}
	}
	return false
}

// chooseDir picks the storage directory for the next chunk.
//
// It replaces the block store's default round-robin, which ignores how full
// each directory is: with directories of different sizes that walks straight
// into a full one. Preference goes to the directory with the most absolute
// headroom, so a store spanning a small disk and a large one fills the large
// one first rather than alternating until the small one overflows.
//
// Unbounded directories are treated as having unlimited headroom. When every
// directory is over its limit the least-full one is returned: refusing here
// would mean returning an invalid StorageID, and the reservation path has
// already declined the write.
func (ct *capacityTracker) chooseDir() local_cache.StorageID {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	var (
		best      local_cache.StorageID
		bestRoom  int64
		bestFound bool
	)
	for id, dc := range ct.dirs {
		if id == local_cache.StorageIDInline {
			continue
		}
		room := int64(math.MaxInt64)
		if dc.maxBytes > 0 {
			room = dc.maxBytes - dc.used
		}
		if !bestFound || room > bestRoom {
			best, bestRoom, bestFound = id, room, true
		}
	}
	return best
}

// releaseReservation returns capacity claimed by a write that never landed.
func (ct *capacityTracker) releaseReservation(nBytes int64) {
	if nBytes <= 0 {
		return
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.reserved = clampNonNegative(ct.reserved - nBytes)
	ct.total = clampNonNegative(ct.total - nBytes)
}

// settle converts a reservation into committed bytes once a write has landed
// and its real footprint is known, attributing them to the directories the
// block store actually chose.
func (ct *capacityTracker) settle(reserved int64, actual map[local_cache.StorageID]int64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Drop the estimate, then add what the object really occupies.
	ct.reserved = clampNonNegative(ct.reserved - reserved)
	ct.total = clampNonNegative(ct.total - reserved)

	for id, n := range actual {
		if dc, ok := ct.dirs[id]; ok {
			dc.used += n
		}
		ct.total += n
	}
}

// release accounts for bytes freed by a delete.
func (ct *capacityTracker) release(id local_cache.StorageID, nBytes int64) {
	if nBytes <= 0 {
		return
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if dc, ok := ct.dirs[id]; ok {
		dc.used = clampNonNegative(dc.used - nBytes)
	}
	ct.total = clampNonNegative(ct.total - nBytes)
}

// usageOf reports committed-plus-reserved bytes and the ceiling for one
// directory.  A ceiling of zero means unbounded.
func (ct *capacityTracker) usageOf(id local_cache.StorageID) (used, max int64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if dc, ok := ct.dirs[id]; ok {
		return dc.used, dc.maxBytes
	}
	return 0, 0
}

// aggregateUsage reports store-wide committed-plus-reserved bytes and the
// aggregate ceiling.  A ceiling of zero means unbounded.
func (ct *capacityTracker) aggregateUsage() (used, max int64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	return ct.total, ct.maxTotal
}

func clampNonNegative(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// resync replaces a directory's counter with the catalog's persisted figure.
//
// Reservations survive: the aggregate is adjusted by the delta rather than
// recomputed, so only the committed half of the figure is replaced.  That is
// what makes it safe to call while writes are in flight -- which the janitor
// does after the block store reclaims an abandoned streaming write, since that
// path refunds the catalog directly and does not say which directories it
// touched.
func (ct *capacityTracker) resync(db *local_cache.CacheDB, id local_cache.StorageID) error {
	used, err := usageForDir(db, id)
	if err != nil {
		return err
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if dc, ok := ct.dirs[id]; ok {
		ct.total = clampNonNegative(ct.total - dc.used + used)
		dc.used = used
	}
	return nil
}

// storageIDs returns the tracked directories.
func (ct *capacityTracker) storageIDs() []local_cache.StorageID {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ids := make([]local_cache.StorageID, 0, len(ct.dirs))
	for id := range ct.dirs {
		ids = append(ids, id)
	}
	return ids
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

// dirUsage is one directory's line in a capacity snapshot.
type dirUsage struct {
	id   local_cache.StorageID
	used int64
	max  int64
}

// snapshot reads the whole tracker under one lock.
//
// Publishing the gauges by calling aggregateUsage and then usageOf per
// directory would take and release the mutex once per series, and would report
// figures from different instants as though they were one measurement -- the
// aggregate not matching the sum of its parts is exactly the kind of thing an
// operator loses an afternoon to.  One acquisition of a mutex that is otherwise
// held for nanoseconds at a time is not a contention concern; this runs at
// open and once per janitor sweep, never on a serving path.
func (ct *capacityTracker) snapshot() (used, max int64, dirs []dirUsage) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	dirs = make([]dirUsage, 0, len(ct.dirs))
	for id, dc := range ct.dirs {
		dirs = append(dirs, dirUsage{id: id, used: dc.used, max: dc.maxBytes})
	}
	return ct.total, ct.maxTotal, dirs
}

// storageDirLabels maps each storage ID onto the label the capacity gauges
// report it under: the directory as it was configured, which is what an
// operator recognizes, rather than the "objects" subdirectory the block store
// works in or an opaque numeric ID.
//
// The inline pseudo-directory gets a name that is deliberately not a path.
// Inline objects live in the catalog, which sits in BaseDir and may therefore
// be one of the real directories; labeling them with that path would add two
// unrelated quantities together in one series.
func storageDirLabels(storage *local_cache.StorageManager) map[local_cache.StorageID]string {
	mounted := storage.GetDirs()
	labels := make(map[local_cache.StorageID]string, len(mounted)+1)
	for id, objDir := range mounted {
		labels[id] = parentDir(objDir)
	}
	labels[local_cache.StorageIDInline] = metrics.PStoreDirectoryInline
	return labels
}

// publishCapacityMetrics republishes the capacity gauges from the tracker's
// in-memory figures.
//
// Those figures are seeded from the catalog when the store opens, so calling
// this at open is what makes the gauges describe a restarted origin correctly
// instead of reading zero until the first write.  Afterwards the janitor
// refreshes them: the write path deliberately does not, because settling a
// write already holds the capacity lock and a store under load would then be
// updating four gauges per object to publish a level that is scraped once a
// minute.
func (s *Store) publishCapacityMetrics() {
	used, max, dirs := s.capacity.snapshot()
	metrics.PStoreUsedBytes.Set(float64(used))
	metrics.PStoreLimitBytes.Set(float64(max))

	for _, d := range dirs {
		label, ok := s.dirLabels[d.id]
		if !ok {
			// A directory the tracker knows and the label map does not cannot
			// happen -- both are built from the same storage manager at open
			// -- but reporting it under a made-up name would be worse than
			// omitting it.
			continue
		}
		metrics.PStoreDirectoryUsedBytes.WithLabelValues(label).Set(float64(d.used))
		metrics.PStoreDirectoryLimitBytes.WithLabelValues(label).Set(float64(d.max))
	}
}

// HasCapacityFor reports whether a write of contentLen content bytes could
// currently be accepted.
//
// It models exactly what the write path will reserve -- the per-block overhead,
// the chunk rounding a streamed object pays, and the per-directory placement
// unit -- via plannedFootprint.  Answering a different question here than the
// write path asks would be worse than not checking at all: the origin would
// accept a PUT it is about to fail with a 507 halfway through the body, or
// refuse one that would have fit.
//
// It remains advisory in one respect: a concurrent write may consume the
// headroom before this caller reserves it, so the write path enforces the
// limit independently.  Its purpose is to let the origin refuse a PUT before
// the client streams a body that cannot land.
func (s *Store) HasCapacityFor(contentLen int64) error {
	if contentLen <= 0 {
		return nil
	}
	if _, max := s.capacity.aggregateUsage(); max <= 0 {
		return nil
	}
	need, unit := s.plannedFootprint(contentLen)
	err := s.capacity.checkRoom(need, unit)
	if errors.Is(err, ErrNoSpace) {
		// Counted here rather than inside the tracker so the increment stays
		// outside the capacity lock.  There is no double count with the
		// increment in ensureReserved: a request refused here never reaches
		// the write path at all.
		metrics.PStoreWriteFailuresTotal.WithLabelValues(metrics.PStoreWriteFailureNoSpace).Inc()
	}
	return err
}

// Usage reports the store's committed-plus-reserved bytes and its ceiling.
// A ceiling of zero means the store is unbounded.
func (s *Store) Usage() (used, max int64) {
	return s.capacity.aggregateUsage()
}
