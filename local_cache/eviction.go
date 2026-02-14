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
	"sort"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// EvictionManager handles fairness-aware cache eviction
// It evicts from the "greediest" tenant (namespace with highest usage)
type EvictionManager struct {
	db      *CacheDB
	storage *StorageManager

	// Cache size limits
	maxSize             uint64
	highWater           uint64
	lowWater            uint64
	highWaterPercentage int
	lowWaterPercentage  int
	configMu            sync.RWMutex // Protects watermark configuration

	// Current total usage
	totalUsage uint64
	usageMu    sync.RWMutex

	// Eviction control
	evictMu   sync.Mutex
	evicting  bool
	evictChan chan struct{}
}

// EvictionConfig holds configuration for the eviction manager
type EvictionConfig struct {
	MaxSize             uint64 // Maximum cache size in bytes
	HighWaterPercentage int    // Percentage at which eviction starts
	LowWaterPercentage  int    // Percentage at which eviction stops
}

// NewEvictionManager creates a new eviction manager
func NewEvictionManager(db *CacheDB, storage *StorageManager, config EvictionConfig) *EvictionManager {
	if config.HighWaterPercentage <= 0 {
		config.HighWaterPercentage = 90
	}
	if config.LowWaterPercentage <= 0 {
		config.LowWaterPercentage = 80
	}

	highWater := (config.MaxSize * uint64(config.HighWaterPercentage)) / 100
	lowWater := (config.MaxSize * uint64(config.LowWaterPercentage)) / 100

	return &EvictionManager{
		db:                  db,
		storage:             storage,
		maxSize:             config.MaxSize,
		highWater:           highWater,
		lowWater:            lowWater,
		highWaterPercentage: config.HighWaterPercentage,
		lowWaterPercentage:  config.LowWaterPercentage,
		evictChan:           make(chan struct{}, 1),
	}
}

// Start begins the background eviction goroutine
func (em *EvictionManager) Start(ctx context.Context, egrp *errgroup.Group) {
	// Initialize total usage from database
	em.recalculateTotalUsage()

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
	em.usageMu.Lock()
	em.totalUsage += uint64(bytes)
	em.usageMu.Unlock()

	if err := em.db.AddUsage(storageID, namespaceID, bytes); err != nil {
		return err
	}

	// Check if we need to evict
	em.configMu.RLock()
	highWater := em.highWater
	em.configMu.RUnlock()

	if em.GetTotalUsage() > highWater {
		em.TriggerEviction()
	}

	return nil
}

// NoteUsageIncrease updates the in-memory usage counter and triggers an
// eviction check if the high-water mark is exceeded.  Unlike AddUsage it does
// NOT write to the persistent database — the caller is responsible for ensuring
// the DB was already updated (e.g., via MergeBlockStateWithUsage which tracks
// usage atomically alongside the bitmap merge).
func (em *EvictionManager) NoteUsageIncrease(bytes int64) {
	em.usageMu.Lock()
	em.totalUsage += uint64(bytes)
	em.usageMu.Unlock()

	em.configMu.RLock()
	highWater := em.highWater
	em.configMu.RUnlock()

	if em.GetTotalUsage() > highWater {
		em.TriggerEviction()
	}
}

// SubtractUsage tracks usage decrease for a storage+namespace combination
func (em *EvictionManager) SubtractUsage(storageID uint8, namespaceID uint32, bytes int64) error {
	em.usageMu.Lock()
	if uint64(bytes) > em.totalUsage {
		em.totalUsage = 0
	} else {
		em.totalUsage -= uint64(bytes)
	}
	em.usageMu.Unlock()

	return em.db.AddUsage(storageID, namespaceID, -bytes)
}

// GetTotalUsage returns the current total cache usage
func (em *EvictionManager) GetTotalUsage() uint64 {
	em.usageMu.RLock()
	defer em.usageMu.RUnlock()
	return em.totalUsage
}

// GetNamespaceUsage returns usage for a specific storage+namespace combination
func (em *EvictionManager) GetNamespaceUsage(storageID uint8, namespaceID uint32) (int64, error) {
	return em.db.GetUsage(storageID, namespaceID)
}

// GetAllNamespaceUsage returns usage for all storage+namespace combinations
func (em *EvictionManager) GetAllNamespaceUsage() (map[StorageUsageKey]int64, error) {
	return em.db.GetAllUsage()
}

// recalculateTotalUsage recalculates total usage from the database
func (em *EvictionManager) recalculateTotalUsage() {
	allUsage, err := em.db.GetAllUsage()
	if err != nil {
		log.Warnf("Failed to get all namespace usage: %v", err)
		return
	}

	var total int64
	for _, usage := range allUsage {
		total += usage
	}

	em.usageMu.Lock()
	em.totalUsage = uint64(total)
	em.usageMu.Unlock()

	log.Debugf("Recalculated total cache usage: %d bytes", total)
}

// checkAndEvict checks if eviction is needed and performs it
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

	em.configMu.RLock()
	highWater := em.highWater
	lowWater := em.lowWater
	em.configMu.RUnlock()

	currentUsage := em.GetTotalUsage()
	if currentUsage <= highWater {
		return
	}

	log.Infof("Starting eviction: current usage %d > high water %d", currentUsage, highWater)

	startTime := time.Now()
	evictedBytes := uint64(0)
	evictedObjects := 0

	for em.GetTotalUsage() > lowWater {
		// Find the greediest storage+namespace combination
		targetKey, targetUsage, err := em.findGreediestNamespace()
		if err != nil {
			log.Warnf("Failed to find greediest namespace: %v", err)
			break
		}

		if targetUsage <= 0 {
			log.Warn("No namespace with positive usage found")
			break
		}

		log.Debugf("Evicting from storage %d namespace %d (usage: %d bytes)", targetKey.StorageID, targetKey.NamespaceID, targetUsage)

		// Evict oldest entries from this storage+namespace combination
		bytes, count, err := em.evictFromNamespace(targetKey.StorageID, targetKey.NamespaceID)
		if err != nil {
			log.Warnf("Error evicting from storage %d namespace %d: %v", targetKey.StorageID, targetKey.NamespaceID, err)
			continue
		}

		evictedBytes += bytes
		evictedObjects += count

		// Safety: don't run for too long
		if time.Since(startTime) > 30*time.Second {
			log.Warn("Eviction timeout - will continue next cycle")
			break
		}
	}

	log.Infof("Eviction complete: freed %d bytes from %d objects in %v",
		evictedBytes, evictedObjects, time.Since(startTime))
}

// namespaceUsageInfo holds storage+namespace usage information for sorting
type namespaceUsageInfo struct {
	key   StorageUsageKey
	usage int64
}

// findGreediestNamespace finds the storage+namespace combination with highest usage
func (em *EvictionManager) findGreediestNamespace() (StorageUsageKey, int64, error) {
	allUsage, err := em.db.GetAllUsage()
	if err != nil {
		return StorageUsageKey{}, 0, errors.Wrap(err, "failed to get namespace usage")
	}

	if len(allUsage) == 0 {
		return StorageUsageKey{}, 0, nil
	}

	// Sort by usage descending
	usageList := make([]namespaceUsageInfo, 0, len(allUsage))
	for key, usage := range allUsage {
		usageList = append(usageList, namespaceUsageInfo{key: key, usage: usage})
	}

	sort.Slice(usageList, func(i, j int) bool {
		return usageList[i].usage > usageList[j].usage
	})

	return usageList[0].key, usageList[0].usage, nil
}

// evictFromNamespace evicts the oldest entries from a storage+namespace combination
// Returns total bytes freed and number of objects evicted
func (em *EvictionManager) evictFromNamespace(storageID uint8, namespaceID uint32) (uint64, int, error) {
	// Get oldest entries for this storage+namespace combination
	const batchSize = 10
	entries, err := em.db.GetOldestLRUEntries(storageID, namespaceID, batchSize)
	if err != nil {
		return 0, 0, errors.Wrap(err, "failed to get oldest entries")
	}

	if len(entries) == 0 {
		return 0, 0, nil
	}

	totalFreed := uint64(0)
	evictedCount := 0

	for _, instanceHash := range entries {
		// Get object size before deleting
		meta, err := em.storage.GetMetadata(instanceHash)
		if err != nil {
			log.Warnf("Failed to get metadata for %s: %v", instanceHash, err)
			continue
		}
		if meta == nil {
			continue
		}

		objectSize := meta.ContentLength

		// Delete the object
		if err := em.storage.Delete(instanceHash); err != nil {
			log.Warnf("Failed to delete object %s: %v", instanceHash, err)
			continue
		}

		// Update usage tracking
		if err := em.SubtractUsage(storageID, namespaceID, objectSize); err != nil {
			log.Warnf("Failed to update usage after eviction: %v", err)
		}

		totalFreed += uint64(objectSize)
		evictedCount++

		log.Debugf("Evicted object %s (%d bytes) from namespace %d", instanceHash, objectSize, namespaceID)

		// Check if we've freed enough
		em.configMu.RLock()
		lowWater := em.lowWater
		em.configMu.RUnlock()

		if em.GetTotalUsage() <= lowWater {
			break
		}
	}

	return totalFreed, evictedCount, nil
}

// RecordAccess records an access to an object, updating LRU
func (em *EvictionManager) RecordAccess(instanceHash string) error {
	// Use 10 minute debounce as specified in design doc
	return em.db.UpdateLRU(instanceHash, 10*time.Minute)
}

// GetStats returns eviction manager statistics
func (em *EvictionManager) GetStats() EvictionStats {
	usage, _ := em.db.GetAllUsage()

	em.configMu.RLock()
	highWater := em.highWater
	lowWater := em.lowWater
	highWaterPct := em.highWaterPercentage
	lowWaterPct := em.lowWaterPercentage
	em.configMu.RUnlock()

	return EvictionStats{
		TotalUsage:          em.GetTotalUsage(),
		MaxSize:             em.maxSize,
		HighWater:           highWater,
		LowWater:            lowWater,
		HighWaterPercentage: highWaterPct,
		LowWaterPercentage:  lowWaterPct,
		NamespaceUsage:      usage,
	}
}

// EvictionStats contains eviction manager statistics
type EvictionStats struct {
	TotalUsage          uint64
	MaxSize             uint64
	HighWater           uint64
	LowWater            uint64
	HighWaterPercentage int
	LowWaterPercentage  int
	NamespaceUsage      map[StorageUsageKey]int64
}

// NeedsEviction returns true if cache usage exceeds high water mark
func (em *EvictionManager) NeedsEviction() bool {
	em.configMu.RLock()
	highWater := em.highWater
	em.configMu.RUnlock()
	return em.GetTotalUsage() > highWater
}

// HasSpace returns true if there's room for more data
func (em *EvictionManager) HasSpace(needed uint64) bool {
	return em.GetTotalUsage()+needed <= em.maxSize
}

// WaitForSpace blocks until there's room for the specified amount
// Returns an error if context is cancelled
func (em *EvictionManager) WaitForSpace(ctx context.Context, needed uint64) error {
	if em.HasSpace(needed) {
		return nil
	}

	// Trigger eviction
	em.TriggerEviction()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if em.HasSpace(needed) {
				return nil
			}
		}
	}
}

// ForceEvict forces eviction of a specific amount of bytes
func (em *EvictionManager) ForceEvict(targetBytes uint64) (uint64, error) {
	em.evictMu.Lock()
	if em.evicting {
		em.evictMu.Unlock()
		return 0, errors.New("eviction already in progress")
	}
	em.evicting = true
	em.evictMu.Unlock()

	defer func() {
		em.evictMu.Lock()
		em.evicting = false
		em.evictMu.Unlock()
	}()

	evictedTotal := uint64(0)
	startTime := time.Now()

	for evictedTotal < targetBytes {
		targetKey, targetUsage, err := em.findGreediestNamespace()
		if err != nil || targetUsage <= 0 {
			break
		}

		bytes, _, err := em.evictFromNamespace(targetKey.StorageID, targetKey.NamespaceID)
		if err != nil {
			log.Warnf("Error during forced eviction: %v", err)
			continue
		}

		evictedTotal += bytes

		if time.Since(startTime) > 60*time.Second {
			return evictedTotal, errors.New("forced eviction timeout")
		}
	}

	return evictedTotal, nil
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

	// First, evict items marked for priority purge
	purgeFirstItems, err := em.db.GetPurgeFirstItems()
	if err != nil {
		log.Warnf("Failed to get purge first items: %v", err)
	} else {
		for _, instanceHash := range purgeFirstItems {
			meta, err := em.storage.GetMetadata(instanceHash)
			if err != nil || meta == nil {
				continue
			}

			objectSize := meta.ContentLength

			if err := em.storage.Delete(instanceHash); err != nil {
				log.Warnf("Failed to delete purge first object %s: %v", instanceHash, err)
				continue
			}

			if err := em.SubtractUsage(meta.StorageID, meta.NamespaceID, objectSize); err != nil {
				log.Warnf("Failed to update usage after eviction: %v", err)
			}

			evictedBytes += uint64(objectSize)
			evictedObjects++
			log.Debugf("Evicted purge-first object %s (%d bytes)", instanceHash, objectSize)
		}
	}

	// Then, evict until we reach low water mark
	em.configMu.RLock()
	lowWater := em.lowWater
	em.configMu.RUnlock()

	for em.GetTotalUsage() > lowWater {
		targetKey, targetUsage, err := em.findGreediestNamespace()
		if err != nil || targetUsage <= 0 {
			break
		}

		bytes, count, err := em.evictFromNamespace(targetKey.StorageID, targetKey.NamespaceID)
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
	}

	log.Infof("Force purge complete: freed %d bytes from %d objects in %v",
		evictedBytes, evictedObjects, time.Since(startTime))
	return nil
}

// MarkPurgeFirst marks an object to be purged first during next eviction
func (em *EvictionManager) MarkPurgeFirst(instanceHash string) error {
	return em.db.MarkPurgeFirst(instanceHash)
}
