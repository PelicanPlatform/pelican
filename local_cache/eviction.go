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
	rand "math/rand/v2"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const rrTableSize = 1024

// EvictionManager handles fairness-aware cache eviction.
// Each storage directory has independent watermarks; eviction is triggered
// per-directory when a directory exceeds its high-water mark and proceeds
// until the directory's usage falls to its low-water mark.
type EvictionManager struct {
	db      *CacheDB
	storage *StorageManager

	// Per-directory size limits, keyed by storageID.  The map is
	// read-only after construction and requires no synchronisation.
	dirLimits map[uint8]*dirEvictionLimits

	// Per-directory usage estimates, keyed by storageID.  The map itself
	// is read-only after construction; each value is an atomic counter
	// that can be updated without locks.
	dirUsage map[uint8]*atomic.Int64

	// Sorted list of directory IDs.  Read-only after construction.
	dirIDs []uint8

	// Pre-computed shuffled lookup table for ChooseDiskStorage.
	// The table has rrTableSize entries, each containing a storageID.
	// Entries are assigned proportional to free space and then
	// shuffled, so a simple atomic increment through the table
	// produces a weighted, uniformly-spread distribution.
	rrTable      atomic.Pointer[[rrTableSize]uint8]
	rrIndex      atomic.Int64
	rrLastUpdate atomic.Int64 // UnixMilli of last rebuild

	// Eviction control
	evictMu   sync.Mutex
	evicting  bool
	evictChan chan struct{}
}

// dirEvictionLimits holds the size limits for a single storage directory.
type dirEvictionLimits struct {
	maxSize   uint64
	highWater uint64
	lowWater  uint64
}

// EvictionConfig holds configuration for the eviction manager
type EvictionConfig struct {
	// DirConfigs maps storageID to its eviction limits.
	// Each entry describes one storage directory.
	DirConfigs map[uint8]EvictionDirConfig
}

// EvictionDirConfig holds per-directory eviction configuration.
type EvictionDirConfig struct {
	MaxSize             uint64 // Maximum cache size in bytes for this directory
	HighWaterPercentage int    // Percentage at which eviction starts (0 = default 90)
	LowWaterPercentage  int    // Percentage at which eviction stops  (0 = default 80)
}

// NewEvictionManager creates a new eviction manager
func NewEvictionManager(db *CacheDB, storage *StorageManager, config EvictionConfig) *EvictionManager {
	dirLimits := make(map[uint8]*dirEvictionLimits, len(config.DirConfigs))

	for id, dcfg := range config.DirConfigs {
		hwp := dcfg.HighWaterPercentage
		if hwp <= 0 {
			hwp = 90
		}
		lwp := dcfg.LowWaterPercentage
		if lwp <= 0 {
			lwp = 80
		}
		dirLimits[id] = &dirEvictionLimits{
			maxSize:   dcfg.MaxSize,
			highWater: (dcfg.MaxSize * uint64(hwp)) / 100,
			lowWater:  (dcfg.MaxSize * uint64(lwp)) / 100,
		}
	}

	dirUsage := make(map[uint8]*atomic.Int64, len(config.DirConfigs))
	dirIDs := make([]uint8, 0, len(config.DirConfigs))
	for id := range config.DirConfigs {
		dirUsage[id] = &atomic.Int64{}
		dirIDs = append(dirIDs, id)
	}
	sort.Slice(dirIDs, func(i, j int) bool { return dirIDs[i] < dirIDs[j] })

	em := &EvictionManager{
		db:        db,
		storage:   storage,
		dirLimits: dirLimits,
		dirUsage:  dirUsage,
		dirIDs:    dirIDs,
		evictChan: make(chan struct{}, 1),
	}
	em.rebuildRRTable()
	return em
}

// Start begins the background eviction goroutine
func (em *EvictionManager) Start(ctx context.Context, egrp *errgroup.Group) {
	// Initialize per-directory usage counters from database
	em.recalculateDirUsage()

	egrp.Go(func() error {
		return em.evictionLoop(ctx)
	})
}

// evictionLoop runs the main eviction loop
func (em *EvictionManager) evictionLoop(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			em.checkAndEvict()
		case <-em.evictChan:
			em.checkAndEvict()
		}
	}
}

// TriggerEviction triggers an eviction check
func (em *EvictionManager) TriggerEviction() {
	select {
	case em.evictChan <- struct{}{}:
	default:
		// Eviction already pending
	}
}

// AddUsage tracks usage increase for a storage+namespace combination
func (em *EvictionManager) AddUsage(storageID uint8, namespaceID uint32, bytes int64) error {
	if err := em.db.AddUsage(storageID, namespaceID, bytes); err != nil {
		return err
	}

	counter, ok := em.dirUsage[storageID]
	if !ok {
		return nil
	}
	newVal := counter.Add(bytes)

	// Check if this directory needs eviction
	limits, lok := em.dirLimits[storageID]
	if lok && newVal > int64(limits.highWater) {
		em.TriggerEviction()
	}

	return nil
}

// NoteUsageIncrease updates the in-memory usage estimate and triggers an
// eviction check if the specified directory's high-water mark appears to
// be exceeded.  Unlike AddUsage it does NOT write to the persistent
// database — the caller is responsible for ensuring the DB was already
// updated (e.g., via MergeBlockStateWithUsage which tracks usage
// atomically alongside the bitmap merge).  The database usage updates
// handle race conditions where multiple writers may be updating the same
// blocks simultaneously.  This doesn't - hence the estimated usage is going
// to be potentially higher than the actual usage.
//
// The per-directory atomic counter is the fast path: if the counter
// is under the high-water mark no database call is made at all.
// When the counter indicates a possible threshold crossing we consult
// the database for the authoritative total, correct the counter, and
// only then decide whether to trigger eviction.
func (em *EvictionManager) NoteUsageIncrease(storageID uint8, bytes int64) {
	counter, ok := em.dirUsage[storageID]
	if !ok {
		return
	}
	newVal := counter.Add(bytes)

	// Fast path: check the atomic estimate against the watermark.
	limits, lok := em.dirLimits[storageID]
	if !lok || newVal <= int64(limits.highWater) {
		return
	}

	// Estimate says we crossed the threshold — consult the database for
	// the authoritative total and correct the atomic counter.
	dbUsage := em.getDirUsage(storageID)
	counter.Store(dbUsage)

	if dbUsage > int64(limits.highWater) {
		em.TriggerEviction()
	}
}

// GetTotalUsage returns the current total cache usage (sum of per-dir atomics).
func (em *EvictionManager) GetTotalUsage() uint64 {
	var total int64
	for _, counter := range em.dirUsage {
		total += counter.Load()
	}
	if total < 0 {
		return 0
	}
	return uint64(total)
}

// GetNamespaceUsage returns usage for a specific storage+namespace combination
func (em *EvictionManager) GetNamespaceUsage(storageID uint8, namespaceID uint32) (int64, error) {
	return em.db.GetUsage(storageID, namespaceID)
}

// GetAllNamespaceUsage returns usage for all storage+namespace combinations
func (em *EvictionManager) GetAllNamespaceUsage() (map[StorageUsageKey]int64, error) {
	return em.db.GetAllUsage()
}

// recalculateDirUsage queries the database for all usage counters and
// stores the per-directory totals into the atomic counters.
func (em *EvictionManager) recalculateDirUsage() {
	allUsage, err := em.db.GetAllUsage()
	if err != nil {
		log.Warnf("Failed to get all namespace usage: %v", err)
		return
	}

	// Accumulate per-directory totals from the DB.
	perDir := make(map[uint8]int64, len(em.dirUsage))
	var grand int64
	for key, usage := range allUsage {
		perDir[key.StorageID] += usage
		grand += usage
	}

	// Store into the atomic counters.  Directories not present in the
	// DB result get zeroed out.
	for sid, counter := range em.dirUsage {
		counter.Store(perDir[sid])
	}

	log.Debugf("Recalculated total cache usage: %d bytes", grand)
}

// getDirUsage returns the total usage for a single storageID by summing
// all namespace usage counters for that ID.
func (em *EvictionManager) getDirUsage(storageID uint8) int64 {
	nsUsage, err := em.db.GetDirUsage(storageID)
	if err != nil {
		log.Warnf("Failed to get usage for storage %d: %v", storageID, err)
		return 0
	}
	var total int64
	for _, usage := range nsUsage {
		total += usage
	}
	return total
}

// checkAndEvict checks each storage directory against its own watermarks
// and evicts from any directory that exceeds its high-water mark.
func (em *EvictionManager) checkAndEvict() {
	em.evictMu.Lock()
	if em.evicting {
		em.evictMu.Unlock()
		return
	}
	em.evicting = true
	em.evictMu.Unlock()

	defer func() {
		em.evictMu.Lock()
		em.evicting = false
		em.evictMu.Unlock()
	}()

	startTime := time.Now()
	totalEvictedBytes := uint64(0)
	totalEvictedObjects := 0

	for sid, limits := range em.dirLimits {
		dirUsage := em.getDirUsage(sid)
		if dirUsage <= int64(limits.highWater) {
			continue
		}

		log.Infof("Starting eviction for storage %d: usage %d > high water %d",
			sid, dirUsage, limits.highWater)

		for dirUsage = em.getDirUsage(sid); dirUsage > int64(limits.lowWater); dirUsage = em.getDirUsage(sid) {
			// Find the greediest namespace in this directory
			targetKey, targetUsage, err := em.findGreediestNamespaceInDir(sid)
			if err != nil {
				log.Warnf("Failed to find greediest namespace in storage %d: %v", sid, err)
				break
			}

			if targetUsage <= 0 {
				log.Warnf("No namespace with positive usage found in storage %d", sid)
				break
			}

			overhead := dirUsage - int64(limits.lowWater)
			log.Debugf("Evicting from storage %d namespace %d (usage: %d bytes, need to free: %d bytes)",
				targetKey.StorageID, targetKey.NamespaceID, targetUsage, overhead)

			bytes, count, err := em.evictFromNamespace(targetKey.StorageID, targetKey.NamespaceID, 0, overhead)
			if err != nil {
				log.Warnf("Error evicting from storage %d namespace %d: %v",
					targetKey.StorageID, targetKey.NamespaceID, err)
				continue
			}

			totalEvictedBytes += bytes
			totalEvictedObjects += count

			// Safety: don't run for too long
			if time.Since(startTime) > 30*time.Second {
				log.Warn("Eviction timeout - will continue next cycle")
				break
			}
		}
	}

	if totalEvictedObjects > 0 {
		log.Infof("Eviction complete: freed %d bytes from %d objects in %v",
			totalEvictedBytes, totalEvictedObjects, time.Since(startTime))
	}
}

// findGreediestNamespaceInDir finds the namespace with highest usage
// within a specific storage directory.
func (em *EvictionManager) findGreediestNamespaceInDir(storageID uint8) (StorageUsageKey, int64, error) {
	nsUsage, err := em.db.GetDirUsage(storageID)
	if err != nil {
		return StorageUsageKey{}, 0, errors.Wrap(err, "failed to get namespace usage")
	}

	var bestNS uint32
	var bestUsage int64
	for ns, usage := range nsUsage {
		if usage > bestUsage {
			bestUsage = usage
			bestNS = ns
		}
	}

	if bestUsage <= 0 {
		return StorageUsageKey{}, 0, nil
	}

	return StorageUsageKey{StorageID: storageID, NamespaceID: bestNS}, bestUsage, nil
}

// evictFromNamespace walks the LRU index for a storage+namespace and evicts
// the oldest objects until either maxObjects have been removed or maxBytes of
// content has been freed — whichever comes first.  Pass 0 for either limit to
// leave it unconstrained.  The eviction is allowed to go one object over the
// byte threshold to prevent starvation when only large objects remain.
//
// All DB mutations happen in a single BadgerDB transaction; filesystem
// deletes follow after the transaction commits.
// Returns total bytes freed and number of objects evicted.
func (em *EvictionManager) evictFromNamespace(storageID uint8, namespaceID uint32, maxObjects int, maxBytes int64) (uint64, int, error) {
	evicted, totalFreed, err := em.storage.EvictByLRU(storageID, namespaceID, maxObjects, maxBytes)
	if err != nil {
		return 0, 0, err
	}

	em.noteEvicted(evicted)

	for _, obj := range evicted {
		log.Debugf("Evicted object %s (%d bytes) from namespace %d", obj.instanceHash, obj.contentLen, obj.namespaceID)
	}

	return totalFreed, len(evicted), nil
}

// noteEvicted adjusts the per-directory in-memory atomic counters after
// a batch of objects has been removed from the DB.  The DB-level usage
// counters were already decremented inside the transaction; this keeps
// the in-memory estimates in sync.
func (em *EvictionManager) noteEvicted(evicted []evictedObject) {
	// Accumulate per-storageID totals to minimise atomic operations.
	perDir := make(map[uint8]int64, 2)
	for _, obj := range evicted {
		perDir[obj.storageID] += obj.contentLen
	}
	for sid, freed := range perDir {
		if counter, ok := em.dirUsage[sid]; ok {
			counter.Add(-freed)
		}
	}
}

// RecordAccess records an access to an object, updating LRU
func (em *EvictionManager) RecordAccess(instanceHash string) error {
	// Use 10 minute debounce as specified in design doc
	return em.db.UpdateLRU(instanceHash, 10*time.Minute)
}

// GetStats returns eviction manager statistics
func (em *EvictionManager) GetStats() EvictionStats {
	usage, _ := em.db.GetAllUsage()

	dirStats := make(map[uint8]DirEvictionStats, len(em.dirLimits))
	for id, limits := range em.dirLimits {
		dirStats[id] = DirEvictionStats{
			MaxSize:   limits.maxSize,
			HighWater: limits.highWater,
			LowWater:  limits.lowWater,
		}
	}

	return EvictionStats{
		TotalUsage:     em.GetTotalUsage(),
		DirStats:       dirStats,
		NamespaceUsage: usage,
	}
}

// EvictionStats contains eviction manager statistics
type EvictionStats struct {
	TotalUsage     uint64
	DirStats       map[uint8]DirEvictionStats
	NamespaceUsage map[StorageUsageKey]int64
}

// DirEvictionStats contains per-directory eviction statistics
type DirEvictionStats struct {
	MaxSize   uint64
	HighWater uint64
	LowWater  uint64
}

// HasSpace returns true if there's room for more data in at least one
// directory.  Uses the in-memory atomic estimates (no DB query).
func (em *EvictionManager) HasSpace(needed uint64) bool {
	for sid, limits := range em.dirLimits {
		used := em.dirUsage[sid].Load()
		if used < 0 {
			used = 0
		}
		if uint64(used)+needed <= limits.maxSize {
			return true
		}
	}
	return false
}

// rebuildRRTable recomputes the shuffled lookup table used by
// ChooseDiskStorage.  Each of the rrTableSize entries is assigned to
// a directory ID proportional to that directory's free space, then
// the table is shuffled so that a linear walk produces a uniform
// spread.
func (em *EvictionManager) rebuildRRTable() {
	var table [rrTableSize]uint8

	if len(em.dirIDs) == 1 {
		// Single-directory fast path: fill the entire table.
		for i := range table {
			table[i] = em.dirIDs[0]
		}
		em.rrTable.Store(&table)
		em.rrLastUpdate.Store(time.Now().UnixMilli())
		return
	}

	// Compute raw free-space per directory.
	type dirWeight struct {
		id   uint8
		free int64
	}
	raw := make([]dirWeight, 0, len(em.dirIDs))
	var rawTotal int64
	for _, sid := range em.dirIDs {
		used := em.dirUsage[sid].Load()
		if used < 0 {
			used = 0
		}
		free := int64(em.dirLimits[sid].maxSize) - used
		if free < 1 {
			free = 1
		}
		raw = append(raw, dirWeight{id: sid, free: free})
		rawTotal += free
	}

	// Assign slots proportional to free space.  Every directory
	// gets at least 1 slot; if that causes the total to exceed
	// rrTableSize we steal from the directories with the most
	// slots.
	slots := make([]int, len(raw))
	assigned := 0
	for i, dw := range raw {
		s := int(dw.free * rrTableSize / rawTotal)
		if s < 1 {
			s = 1
		}
		slots[i] = s
		assigned += s
	}

	// Trim excess: shrink the largest slots until we're at rrTableSize.
	for assigned > rrTableSize {
		maxIdx, maxVal := 0, slots[0]
		for i, s := range slots {
			if s > maxVal {
				maxIdx, maxVal = i, s
			}
		}
		slots[maxIdx]--
		assigned--
	}

	// Fill excess: grow the largest-free-space slots if rounding
	// left us short.
	for assigned < rrTableSize {
		maxIdx := 0
		var maxFree int64
		for i, dw := range raw {
			if dw.free > maxFree {
				maxIdx = i
				maxFree = dw.free
			}
		}
		slots[maxIdx]++
		assigned++
	}

	// Populate the table array.
	idx := 0
	for i, dw := range raw {
		for range slots[i] {
			table[idx] = dw.id
			idx++
		}
	}

	// Shuffle so consecutive increments hit different dirs.
	rand.Shuffle(rrTableSize, func(i, j int) {
		table[i], table[j] = table[j], table[i]
	})

	em.rrTable.Store(&table)
	em.rrLastUpdate.Store(time.Now().UnixMilli())
}

// ChooseDiskStorage selects a storage directory using a pre-computed,
// shuffled lookup table.  The table is rebuilt at most every 100 ms
// from the in-memory atomic usage estimates.  The hot path is a single
// atomic increment + array index, so many goroutines can call this
// concurrently with negligible contention.
func (em *EvictionManager) ChooseDiskStorage() uint8 {
	// Lazily refresh the table at most every 100ms.
	now := time.Now().UnixMilli()
	last := em.rrLastUpdate.Load()
	if now-last >= 100 {
		// CAS avoids a thundering herd: only one goroutine rebuilds.  To avoid
		// extra latency on the hot path we don't wait for the rebuild to complete;
		// but launch a goroutine to do it in the background.
		if em.rrLastUpdate.CompareAndSwap(last, now) {
			go em.rebuildRRTable()
		}
	}

	table := em.rrTable.Load()
	idx := em.rrIndex.Add(1)
	return table[idx%rrTableSize]
}

// ForcePurge forces an immediate purge down to the low water mark
func (em *EvictionManager) ForcePurge() error {
	em.evictMu.Lock()
	if em.evicting {
		em.evictMu.Unlock()
		return errors.New("eviction already in progress")
	}
	em.evicting = true
	em.evictMu.Unlock()

	defer func() {
		em.evictMu.Lock()
		em.evicting = false
		em.evictMu.Unlock()
	}()

	log.Info("Force purge initiated")
	startTime := time.Now()
	evictedBytes := uint64(0)
	evictedObjects := 0

	// Evict until all directories reach their low water marks.
	// EvictByLRU (called by evictFromNamespace) automatically drains
	// purge-first items before touching the regular LRU index.
	for sid, limits := range em.dirLimits {
		dirUsage := em.getDirUsage(sid)
		if dirUsage <= int64(limits.lowWater) {
			continue
		}

		for dirUsage > int64(limits.lowWater) {
			targetKey, targetUsage, err := em.findGreediestNamespaceInDir(sid)
			if err != nil || targetUsage <= 0 {
				break
			}

			overhead := dirUsage - int64(limits.lowWater)
			bytes, count, err := em.evictFromNamespace(targetKey.StorageID, targetKey.NamespaceID, 0, overhead)
			if err != nil {
				log.Warnf("Error evicting from storage %d namespace %d: %v", targetKey.StorageID, targetKey.NamespaceID, err)
				continue
			}

			evictedBytes += bytes
			evictedObjects += count

			if time.Since(startTime) > 60*time.Second {
				log.Warn("Force purge timeout - will continue next cycle")
				break
			}

			dirUsage = em.getDirUsage(sid)
		}
	}

	log.Infof("Force purge complete: freed %d bytes from %d objects in %v",
		evictedBytes, evictedObjects, time.Since(startTime))
	return nil
}

// MarkPurgeFirst marks an object to be purged first during next eviction
func (em *EvictionManager) MarkPurgeFirst(instanceHash string) error {
	return em.db.MarkPurgeFirst(instanceHash)
}
