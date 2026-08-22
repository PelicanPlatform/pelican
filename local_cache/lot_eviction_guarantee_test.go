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

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/lotman/core"
)

// TestEviction_StopsAtDedicatedQuota is the case the selectivity test is sized
// to avoid: a lot that is only slightly over its dedicated quota while the
// directory needs far more space than that overage.
//
// Tier 1 used to hand each priority bucket the *directory's* entire overhead as
// its byte budget, with no bound at the lot's own quota, so the first lot in
// priority order was drained until the directory reached its low watermark --
// taking data from inside a dedicated reservation, which is the one thing a
// dedicated quota is supposed to guarantee, while an unlotted bucket holding
// most of the cache went untouched. The budget must stop at the overage and let
// the lot-agnostic tier-2 fallback cover the remainder.
func TestEviction_StopsAtDedicatedQuota(t *testing.T) {
	m := newCoreTestManager(t)
	mustAdd := func(s core.LotSpec) {
		t.Helper()
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	unbounded := core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: unbounded})

	InitIssuerKeyForTests(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cdb, err := NewCacheDB(ctx, t.TempDir())
	require.NoError(t, err)
	defer cdb.Close()
	egrp, _ := errgroup.WithContext(ctx)
	storage, err := NewStorageManager(cdb, []string{t.TempDir()}, 0, egrp)
	require.NoError(t, err)
	defer storage.Close()

	const (
		reservedNS NamespaceID = 40
		bulkNS     NamespaceID = 41
		rootNS     NamespaceID = 42
		objSize    int64       = 100_000
	)
	fileBytes := CalculateFileSize(objSize)

	// `reserved` holds 10 objects against a dedicated quota worth 8, so exactly
	// 2 objects are reclaimable. `bulk` is unlotted-style: it maps to no lot at
	// all, so tier 1 never selects it and only the lot-agnostic fallback can.
	const reservedCount, bulkCount = 10, 10
	const reservedQuotaObjs = 8
	mustAdd(core.LotSpec{LotName: "reserved", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: reservedQuotaObjs * fileBytes, OpportunisticBytes: 0, MaxNumObjects: -1}})

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"reserved": reservedNS, "root": rootNS},
	}

	seed := func(ns NamespaceID, prefix string, n int) []InstanceHash {
		hashes := make([]InstanceHash, n)
		for i := 0; i < n; i++ {
			h := InstanceHash(fmt.Sprintf("%s-%03d", prefix, i))
			hashes[i] = h
			require.NoError(t, cdb.SetMetadata(h, &CacheMetadata{
				StorageID:     StorageIDFirstDisk,
				NamespaceID:   ns,
				ContentLength: objSize,
				ChunkSizeCode: ChunkingDisabled,
			}))
			require.NoError(t, cdb.UpdateLRU(h, 0))
			require.NoError(t, cdb.AddUsage(StorageIDFirstDisk, ns, fileBytes))
		}
		return hashes
	}
	reservedHashes := seed(reservedNS, "reserved", reservedCount)
	seed(bulkNS, "bulk", bulkCount)

	// 20 objects held, low watermark 8: the directory needs 12 objects' worth
	// freed, but `reserved` may only give up 2. The old code would have taken
	// all 12 from `reserved`, emptying it well inside its guarantee.
	const highObjs, lowObjs = 16, 8
	eviction := NewEvictionManager(cdb, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			StorageIDFirstDisk: {
				MaxSize:        uint64((reservedCount + bulkCount) * int(fileBytes)),
				HighWaterBytes: uint64(highObjs) * uint64(fileBytes),
				LowWaterBytes:  uint64(lowObjs) * uint64(fileBytes),
			},
		},
	})
	eviction.SetLotPlanner(pc)
	require.NoError(t, pc.syncLotUsage())

	targets := eviction.planner.priorityBuckets(StorageIDFirstDisk)
	require.Len(t, targets, 1, "only the over-quota lot is a priority target")
	require.Equal(t, reservedNS, targets[0].bucket)
	require.Equal(t, (reservedCount-reservedQuotaObjs)*fileBytes, targets[0].maxBytes,
		"the budget must be the lot's overage, not the directory's overhead")

	eviction.checkAndEvict()

	surviving := 0
	for _, h := range reservedHashes {
		if meta, _ := cdb.GetMetadata(h); meta != nil {
			surviving++
		}
	}
	require.GreaterOrEqual(t, surviving, reservedQuotaObjs,
		"a lot must never be drained below its dedicated quota: kept %d of %d objects, guarantee is %d",
		surviving, reservedCount, reservedQuotaObjs)

	// The directory still gets back to its low watermark -- the remainder comes
	// from the lot-agnostic fallback rather than from inside the reservation.
	require.LessOrEqual(t, eviction.getDirUsage(StorageIDFirstDisk), int64(lowObjs)*fileBytes,
		"eviction should still reach the low watermark via the tier-2 fallback")
}
