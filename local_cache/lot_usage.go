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
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// defaultLotUsageSyncInterval is how often the cache pushes its per-lot byte
// usage into the lotman core when no interval is configured.
const defaultLotUsageSyncInterval = time.Minute

// aggregateUsageByLot folds per-(StorageID, bucket) byte usage into per-lot
// totals, mapping each accounting bucket id back to its lot name. Buckets with
// no known name (e.g. stale namespace-prefix buckets left over from before lot
// tracking was enabled) are skipped.
func aggregateUsageByLot(usage map[StorageUsageKey]int64, idToName map[NamespaceID]string) map[string]int64 {
	perLot := make(map[string]int64)
	for key, bytes := range usage {
		if name, ok := idToName[key.NamespaceID]; ok {
			perLot[name] += bytes
		}
	}
	return perLot
}

// syncLotUsage pushes the cache's current per-lot byte usage into the lotman
// core so quota and eviction-priority queries reflect what the cache holds. It
// reads the per-(StorageID, bucket) byte counters (the bucket is the lot when
// lot tracking is on), aggregates across storage directories, and writes the
// absolute self usage for every lot known to the core — lots with no cached
// bytes are reset to 0. Object-count usage is not yet synced.
//
// It is safe to call on demand (e.g. before an eviction pass) as well as on the
// periodic schedule. A no-op when lot tracking is disabled.
func (pc *PersistentCache) syncLotUsage() error {
	if pc.lotMgr == nil {
		return nil
	}

	usage, err := pc.db.GetAllUsage()
	if err != nil {
		return errors.Wrap(err, "reading cache usage for lot sync")
	}

	// Reverse the persisted bucket mapping: bucket id -> lot name.
	pc.namespaceMapMu.RLock()
	idToName := make(map[NamespaceID]string, len(pc.namespaceMap))
	for name, id := range pc.namespaceMap {
		idToName[id] = name
	}
	pc.namespaceMapMu.RUnlock()

	perLot := aggregateUsageByLot(usage, idToName)

	// Write absolute self usage for every lot, so lots with no cached bytes are
	// reset to 0. Iterating the core's lots (rather than just the observed
	// buckets) is what lets a lot drop back to zero. Each update also recomputes
	// the affected ancestors' rollups.
	names, err := pc.lotMgr.ListAllLots()
	if err != nil {
		return errors.Wrap(err, "listing lots for usage sync")
	}
	for _, name := range names {
		bytes := perLot[name]
		if err := pc.lotMgr.UpdateLotUsage(core.UsageUpdate{LotName: name, SelfBytes: &bytes}, false, ""); err != nil {
			log.Warnf("lot usage sync: failed to update lot %q: %v", name, err)
		}
	}
	return nil
}

// priorityBuckets returns the accounting bucket ids to evict first within a
// storage directory, in priority order: lots past their deletion time, then
// past expiration, then over their dedicated+opportunistic quota, then over
// their dedicated quota. The result is restricted to lots that actually have
// usage in the given directory and is de-duplicated, preserving priority order.
// Implements lotEvictionPlanner.
func (pc *PersistentCache) priorityBuckets(storageID StorageID) []NamespaceID {
	if pc.lotMgr == nil {
		return nil
	}
	now := time.Now().UnixMilli()

	var lotNames []string
	appendLots := func(names []string, err error) {
		if err != nil {
			log.Warnf("lot eviction planning query failed: %v", err)
			return
		}
		lotNames = append(lotNames, names...)
	}
	// Recursive for the time-based passes so descendants of an expired/deleted
	// lot are included; hierarchical for the quota passes so the deepest
	// over-quota lots come first.
	appendLots(pc.lotMgr.LotsPastDel(now, true, false))
	appendLots(pc.lotMgr.LotsPastExp(now, true, false))
	appendLots(pc.lotMgr.LotsPastOpp(false, false, false, true))
	appendLots(pc.lotMgr.LotsPastDed(false, false, false, true))

	// Restrict to lots present in this storage directory.
	dirUsage, err := pc.db.GetDirUsage(storageID)
	if err != nil {
		log.Warnf("lot eviction planning: failed to read dir usage: %v", err)
		return nil
	}
	present := make(map[NamespaceID]bool, len(dirUsage))
	for id := range dirUsage {
		present[id] = true
	}

	pc.namespaceMapMu.RLock()
	defer pc.namespaceMapMu.RUnlock()
	seen := make(map[NamespaceID]bool)
	var out []NamespaceID
	for _, name := range lotNames {
		id, ok := pc.namespaceMap[name]
		if !ok || seen[id] || !present[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// defaultObjectCapTrimInterval is how often object-count caps are enforced when
// no interval is configured.
const defaultObjectCapTrimInterval = time.Minute

// trimObjectCaps enforces lots' max_num_objects caps as a rolling window,
// independent of disk pressure: for every lot with a finite object cap, it
// counts the objects in the lot's accounting bucket (across storage
// directories, including inline) and evicts the oldest excess so the lot is
// brought back to its cap. This is the mechanism behind the monitoring lot's
// bounded object count. A no-op when lot tracking is disabled.
//
// Object counts are read from the LRU index on demand (bounded per-lot prefix
// scans) rather than maintained as a hot-path counter; core's self_objects is
// not yet populated, so this enforcement is cache-side.
func (pc *PersistentCache) trimObjectCaps() error {
	if pc.lotMgr == nil {
		return nil
	}
	names, err := pc.lotMgr.ListAllLots()
	if err != nil {
		return errors.Wrap(err, "listing lots for object-cap trim")
	}
	rl := log.WithField("component", "lotObjTrim")

	// Buckets can hold inline objects (StorageID 0) as well as disk objects.
	storageIDs := append([]StorageID{StorageIDInline}, pc.eviction.dirIDs...)

	for _, name := range names {
		view, err := pc.lotMgr.GetLot(name)
		if err != nil {
			continue
		}
		objCap := view.MaxNumObjects
		if objCap < 0 { // unbounded
			continue
		}
		pc.namespaceMapMu.RLock()
		bucket, ok := pc.namespaceMap[name]
		pc.namespaceMapMu.RUnlock()
		if !ok { // no objects ever ingested for this lot
			continue
		}

		counts := make(map[StorageID]int64, len(storageIDs))
		var total int64
		for _, sid := range storageIDs {
			c, err := pc.db.CountLRUEntries(sid, bucket)
			if err != nil {
				rl.Warnf("object-cap trim: counting lot %q dir %d: %v", name, sid, err)
				continue
			}
			counts[sid] = c
			total += c
		}
		if total <= objCap {
			continue
		}

		excess := total - objCap
		rl.WithFields(log.Fields{"lot": name, "objects": total, "cap": objCap, "evict": excess}).Debug("trimming object-capped lot")
		for _, sid := range storageIDs {
			if excess <= 0 {
				break
			}
			if counts[sid] == 0 {
				continue
			}
			_, count, _, err := pc.eviction.evictFromNamespace(rl, sid, bucket, int(excess), 0)
			if err != nil {
				rl.Warnf("object-cap trim: evicting lot %q dir %d: %v", name, sid, err)
				continue
			}
			excess -= int64(count)
		}
	}
	return nil
}

// startObjectCapTrim runs trimObjectCaps on a fixed interval until ctx is
// cancelled. A no-op when lot tracking is disabled.
func (pc *PersistentCache) startObjectCapTrim(ctx context.Context, egrp *errgroup.Group, interval time.Duration) {
	if pc.lotMgr == nil {
		return
	}
	if interval <= 0 {
		interval = defaultObjectCapTrimInterval
	}
	egrp.Go(func() error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := pc.trimObjectCaps(); err != nil {
					log.Warnf("object-cap trim failed: %v", err)
				}
			}
		}
	})
}

// startLotUsageSync runs syncLotUsage on a fixed interval until ctx is
// cancelled. A no-op when lot tracking is disabled.
func (pc *PersistentCache) startLotUsageSync(ctx context.Context, egrp *errgroup.Group, interval time.Duration) {
	if pc.lotMgr == nil {
		return
	}
	if interval <= 0 {
		interval = defaultLotUsageSyncInterval
	}
	egrp.Go(func() error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := pc.syncLotUsage(); err != nil {
					log.Warnf("periodic lot usage sync failed: %v", err)
				}
			}
		}
	})
}
