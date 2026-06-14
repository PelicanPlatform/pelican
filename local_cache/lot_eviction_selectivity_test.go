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

// TestEviction_TargetsOverQuotaLot_SparesProtected drives the full watermark
// eviction (EvictionManager.checkAndEvict with the lot planner installed) and
// proves selectivity: when the cache is over its high watermark, the lot-aware
// tier evicts from the over-quota lot's bucket and leaves a protected (well
// under-quota) lot's objects untouched.
//
// This is the deterministic complement to the federation eviction e2e, which
// only proves that eviction happens. Sizing is chosen so the over-quota lot
// alone covers the overhead down to the low watermark, so tier-1 (priority
// buckets) satisfies the eviction and the greediest-bucket fallback (tier-2),
// which is lot-agnostic, never runs.
func TestEviction_TargetsOverQuotaLot_SparesProtected(t *testing.T) {
	mpa := func(ded int64) core.MPA {
		return core.MPA{DedicatedBytes: ded, OpportunisticBytes: -1, MaxNumObjects: -1}
	}
	m := newCoreTestManager(t)
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	// root has an unbounded dedicated quota so it never registers as over-quota
	// (and so children's overage attributed upward never flags it).
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: mpa(-1)})
	// protected sits far below a very large dedicated quota.
	mustAdd(core.LotSpec{LotName: "protected", Owner: "fed", Parents: []string{"root"}, MPA: mpa(1 << 40)})
	// over has a tiny dedicated quota it will blow past once usage is synced.
	mustAdd(core.LotSpec{LotName: "over", Owner: "fed", Parents: []string{"root"}, MPA: mpa(1000)})

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
		protNS  NamespaceID = 30
		overNS  NamespaceID = 31
		rootNS  NamespaceID = 32
		objSize int64       = 100_000
	)
	fileBytes := CalculateFileSize(objSize) // on-disk size eviction accounts for

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"protected": protNS, "over": overNS, "root": rootNS},
	}

	// seed registers n metadata-only objects in a namespace bucket: each gets an
	// LRU entry (so EvictByLRU can find it) and its on-disk bytes charged to the
	// dir usage. No real file is written; eviction's file delete is best-effort.
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

	const protCount, overCount = 4, 12
	protHashes := seed(protNS, "prot", protCount)
	overHashes := seed(overNS, "over", overCount)

	// High watermark = 12 objects, low = 8. Total seeded = 16, so eviction must
	// free 8 objects' worth; the over-quota lot holds 12, enough on its own.
	const highObjs, lowObjs = 12, 8
	eviction := NewEvictionManager(cdb, storage, EvictionConfig{
		DirConfigs: map[StorageID]EvictionDirConfig{
			StorageIDFirstDisk: {
				MaxSize:        uint64((protCount + overCount) * int(fileBytes)),
				HighWaterBytes: uint64(highObjs) * uint64(fileBytes),
				LowWaterBytes:  uint64(lowObjs) * uint64(fileBytes),
			},
		},
	})
	eviction.SetLotPlanner(pc)

	require.Equal(t, int64(protCount+overCount)*fileBytes, eviction.getDirUsage(StorageIDFirstDisk),
		"all seeded objects should count toward dir usage")

	// The selection itself: only the over-quota lot's bucket is a priority target;
	// the protected (and root) buckets are excluded.
	require.NoError(t, pc.syncLotUsage())
	require.Equal(t, []NamespaceID{overNS}, pc.priorityBuckets(StorageIDFirstDisk),
		"only the over-quota lot should be selected for priority eviction")

	eviction.checkAndEvict()

	// The protected lot must be fully spared.
	for _, h := range protHashes {
		meta, err := cdb.GetMetadata(h)
		require.NoError(t, err)
		require.NotNil(t, meta, "protected object %s must not be evicted", h)
	}

	// The over-quota lot must have lost objects.
	survivingOver := 0
	for _, h := range overHashes {
		if meta, _ := cdb.GetMetadata(h); meta != nil {
			survivingOver++
		}
	}
	require.Less(t, survivingOver, overCount, "over-quota lot should have objects evicted")

	// And the dir is back at or below the low watermark.
	finalUsage := eviction.getDirUsage(StorageIDFirstDisk)
	require.LessOrEqual(t, finalUsage, int64(lowObjs)*fileBytes,
		"eviction should bring usage down to the low watermark")

	t.Logf("selective eviction: protected kept %d/%d, over-quota kept %d/%d, usage %d -> %d (low watermark %d)",
		protCount, protCount, survivingOver, overCount,
		int64(protCount+overCount)*fileBytes, finalUsage, int64(lowObjs)*fileBytes)
}
