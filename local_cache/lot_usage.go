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
	objCounts, err := pc.db.GetAllObjectCounts()
	if err != nil {
		return errors.Wrap(err, "reading cache object counts for lot sync")
	}

	// Reverse the persisted bucket mapping: bucket id -> lot name.
	pc.namespaceMapMu.RLock()
	idToName := make(map[NamespaceID]string, len(pc.namespaceMap))
	for name, id := range pc.namespaceMap {
		idToName[id] = name
	}
	pc.namespaceMapMu.RUnlock()

	perLotBytes := aggregateUsageByLot(usage, idToName)
	perLotObjects := aggregateUsageByLot(objCounts, idToName)

	// Write absolute self usage for every lot, so lots with no cached bytes are
	// reset to 0. Iterating the core's lots (rather than just the observed
	// buckets) is what lets a lot drop back to zero. Each update also recomputes
	// the affected ancestors' rollups.
	names, err := pc.lotMgr.ListAllLots()
	if err != nil {
		return errors.Wrap(err, "listing lots for usage sync")
	}
	for _, name := range names {
		bytes := perLotBytes[name]
		objects := perLotObjects[name]
		if err := pc.lotMgr.UpdateLotUsage(core.UsageUpdate{LotName: name, SelfBytes: &bytes, SelfObjects: &objects}, false, ""); err != nil {
			log.Warnf("lot usage sync: failed to update lot %q: %v", name, err)
		}
	}
	return nil
}

// priorityBuckets returns the accounting buckets to evict first within a storage
// directory, in priority order: lots past their deletion time, then past
// expiration, then over their dedicated+opportunistic quota, then over their
// dedicated quota. The result is restricted to lots that actually have usage in
// the given directory and is de-duplicated, preserving priority order.
// Implements lotEvictionPlanner.
func (pc *PersistentCache) priorityBuckets(storageID StorageID) []lotEvictionTarget {
	if pc.lotMgr == nil {
		return nil
	}
	now := time.Now().UnixMilli()

	// A lot selected because its lifetime is over may be drained completely; one
	// selected for being over a storage quota may only be drained back *to* that
	// quota. Losing that distinction means a lot 1 GB over a 5 TB reservation can
	// have terabytes taken from inside its guarantee -- which inverts the meaning
	// of a dedicated quota -- while unlotted data sits untouched.
	const unbounded int64 = -1
	type candidate struct {
		name    string
		overage int64 // bytes reclaimable lot-wide; unbounded to drain it entirely
	}
	var candidates []candidate
	appendLots := func(quotaOf func(core.LotView) int64) func([]string, error) {
		return func(names []string, err error) {
			if err != nil {
				log.Warnf("lot eviction planning query failed: %v", err)
				return
			}
			for _, name := range names {
				over := unbounded
				if quotaOf != nil {
					view, err := pc.lotMgr.GetLot(name)
					if err != nil {
						log.Warnf("lot eviction planning: reading lot %q: %v", name, err)
						continue
					}
					quota := quotaOf(*view)
					if quota < 0 { // unbounded quota: the lot cannot be over it
						continue
					}
					// Measure the overage against the lot's whole usage, not one
					// directory's share of it: a lot spread over several
					// directories is over quota as a whole, and each directory
					// contributes at most what it holds (capped below).
					over = view.Usage.SelfBytes - quota
					if over <= 0 {
						continue
					}
				}
				candidates = append(candidates, candidate{name: name, overage: over})
			}
		}
	}
	// Recursive for the time-based passes so descendants of an expired/deleted
	// lot are included; hierarchical for the quota passes so the deepest
	// over-quota lots come first.
	appendLots(nil)(pc.lotMgr.LotsPastDel(now, true, false))
	appendLots(nil)(pc.lotMgr.LotsPastExp(now, true, false))
	appendLots(func(v core.LotView) int64 {
		if v.DedicatedBytes < 0 || v.OpportunisticBytes < 0 {
			return unbounded
		}
		return v.DedicatedBytes + v.OpportunisticBytes
	})(pc.lotMgr.LotsPastOpp(false, false, false, true))
	appendLots(func(v core.LotView) int64 {
		return v.DedicatedBytes
	})(pc.lotMgr.LotsPastDed(false, false, false, true))

	// Restrict to lots present in this storage directory.
	dirUsage, err := pc.db.GetDirUsage(storageID)
	if err != nil {
		log.Warnf("lot eviction planning: failed to read dir usage: %v", err)
		return nil
	}

	pc.namespaceMapMu.RLock()
	defer pc.namespaceMapMu.RUnlock()
	seen := make(map[NamespaceID]bool)
	var out []lotEvictionTarget
	for _, c := range candidates {
		id, ok := pc.namespaceMap[c.name]
		if !ok || seen[id] {
			continue
		}
		usage, present := dirUsage[id]
		if !present {
			continue
		}
		seen[id] = true
		target := lotEvictionTarget{bucket: id, maxBytes: unbounded}
		if c.overage >= 0 {
			// This directory can give back at most what it holds of the lot; if
			// that is not enough, the other directories holding the lot take the
			// rest, and a later tick revisits it if it is still over.
			budget := c.overage
			if budget > usage {
				budget = usage
			}
			target.maxBytes = budget
		}
		out = append(out, target)
	}
	return out
}

// defaultObjectCapTrimInterval is how often object-count caps are enforced when
// no interval is configured.
const defaultObjectCapTrimInterval = time.Minute

// trimObjectCaps enforces lots' max_num_objects caps as a rolling window,
// independent of disk pressure: for every lot with a finite object cap, it
// reads the per-bucket object counts (reconciled by the periodic metadata scan,
// so this is O(buckets), not O(objects)), and evicts the oldest excess so the
// lot is brought back to its cap. This is the mechanism behind the monitoring
// lot's bounded object count. A no-op when lot tracking is disabled.
//
// Counts are as fresh as the last metadata scan (newly-ingested objects are
// picked up at the next scan), so the cap is approximate within that window;
// after evicting, the counter is decremented so a re-run before the next scan
// does not over-evict.
func (pc *PersistentCache) trimObjectCaps() error {
	if pc.lotMgr == nil {
		return nil
	}
	names, err := pc.lotMgr.ListAllLots()
	if err != nil {
		return errors.Wrap(err, "listing lots for object-cap trim")
	}
	counts, err := pc.db.GetAllObjectCounts()
	if err != nil {
		return errors.Wrap(err, "reading object counts for trim")
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
		// -1 is the unbounded sentinel. Treat any non-positive cap the same way:
		// a lot permitted to hold zero objects is not a meaningful configuration,
		// and honouring it literally would evict the lot's entire bucket on every
		// tick, independent of disk pressure.
		if objCap <= 0 {
			continue
		}
		pc.namespaceMapMu.RLock()
		bucket, ok := pc.namespaceMap[name]
		pc.namespaceMapMu.RUnlock()
		if !ok { // no objects ever ingested for this lot
			continue
		}

		var total int64
		for _, sid := range storageIDs {
			total += counts[StorageUsageKey{StorageID: sid, NamespaceID: bucket}]
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
			key := StorageUsageKey{StorageID: sid, NamespaceID: bucket}
			if counts[key] == 0 {
				continue
			}
			_, count, _, err := pc.eviction.evictFromNamespace(rl, sid, bucket, int(excess), 0)
			if err != nil {
				rl.Warnf("object-cap trim: evicting lot %q dir %d: %v", name, sid, err)
				continue
			}
			excess -= int64(count)
			// Keep the counter consistent so a re-run before the next metadata
			// scan does not over-evict.
			newCount := counts[key] - int64(count)
			if newCount < 0 {
				newCount = 0
			}
			counts[key] = newCount
			if err := pc.db.SetObjectCount(sid, bucket, newCount); err != nil {
				rl.Warnf("object-cap trim: updating count for lot %q dir %d: %v", name, sid, err)
			}
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
				// Refresh the lot index first so lots created since the last
				// tick (renewal successors, API creations) are resolvable
				// before we attribute usage. This is the periodic backstop;
				// in-process lot mutations may also rebuild it directly.
				if err := pc.RebuildLotIndex(); err != nil {
					log.Warnf("periodic lot index rebuild failed: %v", err)
				}
				if err := pc.syncLotUsage(); err != nil {
					log.Warnf("periodic lot usage sync failed: %v", err)
				}
			}
		}
	})
}
