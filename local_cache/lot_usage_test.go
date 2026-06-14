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

	"github.com/dgraph-io/badger/v4"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/lotman/core"
)

func TestObjectCountStore(t *testing.T) {
	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	if err := cdb.SetObjectCount(0, 7, 3); err != nil {
		t.Fatal(err)
	}
	if err := cdb.SetObjectCount(1, 7, 2); err != nil {
		t.Fatal(err)
	}
	if err := cdb.SetObjectCount(0, 8, 5); err != nil {
		t.Fatal(err)
	}

	if c, _ := cdb.GetObjectCount(0, 7); c != 3 {
		t.Errorf("(0,7) = %d, want 3", c)
	}
	if c, _ := cdb.GetObjectCount(0, 9); c != 0 {
		t.Errorf("absent (0,9) = %d, want 0", c)
	}
	all, err := cdb.GetAllObjectCounts()
	if err != nil {
		t.Fatal(err)
	}
	if all[StorageUsageKey{0, 7}] != 3 || all[StorageUsageKey{1, 7}] != 2 || all[StorageUsageKey{0, 8}] != 5 || len(all) != 3 {
		t.Errorf("GetAllObjectCounts = %v", all)
	}
	// Negative is clamped to 0.
	if err := cdb.SetObjectCount(0, 7, -4); err != nil {
		t.Fatal(err)
	}
	if c, _ := cdb.GetObjectCount(0, 7); c != 0 {
		t.Errorf("negative set should clamp to 0, got %d", c)
	}
}

func TestReconcileObjectCounts(t *testing.T) {
	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	// Pre-existing counts: (0,7)=10 (will change), (0,9)=4 (absent from scan -> zero).
	_ = cdb.SetObjectCount(0, 7, 10)
	_ = cdb.SetObjectCount(0, 9, 4)

	cc := &ConsistencyChecker{db: cdb}
	scan := map[StorageUsageKey]int64{
		{StorageID: 0, NamespaceID: 7}: 3, // corrected down
		{StorageID: 0, NamespaceID: 8}: 5, // new
	}
	if err := cc.reconcileObjectCounts(context.Background(), log.WithField("t", "test"), scan); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if c, _ := cdb.GetObjectCount(0, 7); c != 3 {
		t.Errorf("(0,7) = %d, want 3 (corrected)", c)
	}
	if c, _ := cdb.GetObjectCount(0, 8); c != 5 {
		t.Errorf("(0,8) = %d, want 5 (new)", c)
	}
	if c, _ := cdb.GetObjectCount(0, 9); c != 0 {
		t.Errorf("(0,9) = %d, want 0 (absent from scan)", c)
	}
}

func TestTrimObjectCaps(t *testing.T) {
	m := newCoreTestManager(t)
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1}})
	mustAdd(core.LotSpec{LotName: "mon", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: 0, OpportunisticBytes: -1, MaxNumObjects: 5}})

	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"mon": 7, "root": 8},
		eviction:     &EvictionManager{db: cdb},
	}

	// Under cap: trim is a no-op (eviction not invoked, so storage-less is fine).
	if err := cdb.SetObjectCount(0, 7, 2); err != nil {
		t.Fatal(err)
	}
	if err := pc.trimObjectCaps(); err != nil {
		t.Fatalf("trim under cap: %v", err)
	}
	if c, _ := cdb.GetObjectCount(0, 7); c != 2 {
		t.Errorf("under-cap count = %d, want 2 (untouched)", c)
	}

	// The over-cap eviction path (which calls StorageManager.EvictByLRU) is
	// exercised by the fed_test_utils integration tests; here we verify the
	// decision logic (excess computed against the reconciled counter and the
	// cap from the core).
	excess := computeObjectExcess(m, cdb, pc.namespaceMap, []StorageID{0})
	if excess["mon"] != 0 {
		t.Errorf("under cap should compute 0 excess, got %d", excess["mon"])
	}
	if err := cdb.SetObjectCount(0, 7, 9); err != nil { // 9 > cap 5 -> excess 4
		t.Fatal(err)
	}
	excess = computeObjectExcess(m, cdb, pc.namespaceMap, []StorageID{0})
	if excess["mon"] != 4 {
		t.Errorf("over cap (9 vs 5) should compute excess 4, got %d", excess["mon"])
	}
}

// TestTrimObjectCapsEvicts exercises the full over-cap trim path: a lot holding
// more objects than its max_num_objects cap has the oldest excess really evicted
// (through StorageManager.EvictByLRU), with the per-bucket counter brought back
// down to the cap. Inline objects (StorageID 0) keep the harness disk-free.
func TestTrimObjectCapsEvicts(t *testing.T) {
	m := newCoreTestManager(t)
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1}})
	mustAdd(core.LotSpec{LotName: "mon", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: 0, OpportunisticBytes: -1, MaxNumObjects: 5}})

	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	egrp, _ := errgroup.WithContext(context.Background())
	sm, err := NewStorageManager(cdb, []string{t.TempDir()}, 0, egrp)
	if err != nil {
		t.Fatalf("storage manager: %v", err)
	}

	const bucket NamespaceID = 7
	// Seed 9 real inline objects in the lot's bucket so the LRU index has
	// concrete entries to evict (9 > cap 5 -> excess 4).
	for i := 0; i < 9; i++ {
		hash := InstanceHash(fmt.Sprintf("obj-%02d", i))
		meta := &CacheMetadata{StorageID: StorageIDInline, NamespaceID: bucket, ContentLength: 100}
		if err := cdb.SetMetadata(hash, meta); err != nil {
			t.Fatalf("set metadata: %v", err)
		}
		if err := cdb.UpdateLRU(hash, 0); err != nil {
			t.Fatalf("update lru: %v", err)
		}
	}
	if err := cdb.SetObjectCount(StorageIDInline, bucket, 9); err != nil {
		t.Fatal(err)
	}

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"mon": bucket, "root": 8},
		eviction:     &EvictionManager{db: cdb, storage: sm},
	}

	if err := pc.trimObjectCaps(); err != nil {
		t.Fatalf("trim: %v", err)
	}

	// The counter is brought back down to the cap.
	if c, _ := cdb.GetObjectCount(StorageIDInline, bucket); c != 5 {
		t.Errorf("post-trim count = %d, want 5 (cap)", c)
	}
	// And the excess objects are really gone from the LRU index.
	if n := countLRUEntriesForTest(t, cdb, StorageIDInline, bucket); n != 5 {
		t.Errorf("remaining LRU entries = %d, want 5", n)
	}
}

// countLRUEntriesForTest counts LRU index entries for a (storage, bucket) pair.
func countLRUEntriesForTest(t *testing.T, cdb *CacheDB, sid StorageID, ns NamespaceID) int {
	t.Helper()
	prefix := []byte(fmt.Sprintf("%s%d:%d:", PrefixLRU, sid, ns))
	n := 0
	err := cdb.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count lru: %v", err)
	}
	return n
}

// computeObjectExcess mirrors trimObjectCaps's decision (count vs cap) without
// evicting, so it can be unit-tested without the storage-manager harness.
func computeObjectExcess(m *core.Manager, cdb *CacheDB, nsMap map[string]NamespaceID, storageIDs []StorageID) map[string]int64 {
	counts, _ := cdb.GetAllObjectCounts()
	names, _ := m.ListAllLots()
	out := map[string]int64{}
	for _, name := range names {
		view, err := m.GetLot(name)
		if err != nil || view.MaxNumObjects < 0 {
			continue
		}
		bucket, ok := nsMap[name]
		if !ok {
			continue
		}
		var total int64
		for _, sid := range storageIDs {
			total += counts[StorageUsageKey{StorageID: sid, NamespaceID: bucket}]
		}
		if total > view.MaxNumObjects {
			out[name] = total - view.MaxNumObjects
		}
	}
	return out
}

func TestAggregateUsageByLot(t *testing.T) {
	usage := map[StorageUsageKey]int64{
		{StorageID: 1, NamespaceID: 10}: 5000,
		{StorageID: 2, NamespaceID: 10}: 1000, // same lot, different storage dir
		{StorageID: 1, NamespaceID: 11}: 3000,
		{StorageID: 1, NamespaceID: 99}: 7000, // unknown bucket -> skipped
	}
	idToName := map[NamespaceID]string{10: "ns", 11: "sub"}

	got := aggregateUsageByLot(usage, idToName)
	if got["ns"] != 6000 {
		t.Errorf("ns = %d, want 6000 (summed across storage dirs)", got["ns"])
	}
	if got["sub"] != 3000 {
		t.Errorf("sub = %d, want 3000", got["sub"])
	}
	if len(got) != 2 {
		t.Errorf("expected 2 lots (unknown bucket skipped), got %v", got)
	}
}

func TestPriorityBuckets(t *testing.T) {
	m := newCoreTestManager(t)
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: 1_000_000, OpportunisticBytes: -1, MaxNumObjects: -1}})
	// expired: a finite window already in the past -> past expiration/deletion.
	mustAdd(core.LotSpec{LotName: "expired", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: 50_000, OpportunisticBytes: -1, MaxNumObjects: -1,
			CreationTime: 1, ExpirationTime: 100, DeletionTime: 200}})
	// over: non-expiring but over its dedicated quota (usage set below).
	mustAdd(core.LotSpec{LotName: "over", Owner: "fed", Parents: []string{"root"},
		MPA: core.MPA{DedicatedBytes: 1000, OpportunisticBytes: -1, MaxNumObjects: -1}})
	if err := m.UpdateLotUsage(core.UsageUpdate{LotName: "over", SelfBytes: ptrI64(5000)}, false, ""); err != nil {
		t.Fatal(err)
	}

	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"expired": 20, "over": 21, "root": 22},
	}

	// Dir 3 holds both priority lots; expect priority order [expired(20), over(21)].
	mustSeed(t, cdb, 3, 20, 1000)
	mustSeed(t, cdb, 3, 21, 2000)
	got := pc.priorityBuckets(3)
	if len(got) != 2 || got[0] != 20 || got[1] != 21 {
		t.Errorf("priorityBuckets(3) = %v, want [20 21] (expired before over)", got)
	}

	// Dir 1 holds only the over-quota lot; expired is filtered out (not present).
	mustSeed(t, cdb, 1, 21, 500)
	if got := pc.priorityBuckets(1); len(got) != 1 || got[0] != 21 {
		t.Errorf("priorityBuckets(1) = %v, want [21]", got)
	}

	// Dir 2 holds only the expired lot.
	mustSeed(t, cdb, 2, 20, 500)
	if got := pc.priorityBuckets(2); len(got) != 1 || got[0] != 20 {
		t.Errorf("priorityBuckets(2) = %v, want [20]", got)
	}

	// No planner without a manager.
	if (&PersistentCache{db: cdb}).priorityBuckets(3) != nil {
		t.Error("priorityBuckets should be nil with no lot manager")
	}
}

func ptrI64(v int64) *int64 { return &v }

func mustSeed(t *testing.T, cdb *CacheDB, sid StorageID, ns NamespaceID, delta int64) {
	t.Helper()
	if err := cdb.AddUsage(sid, ns, delta); err != nil {
		t.Fatalf("seed usage: %v", err)
	}
}

func TestSyncLotUsage(t *testing.T) {
	m := newCoreTestManager(t)
	mpa := func(ded int64) core.MPA {
		return core.MPA{DedicatedBytes: ded, OpportunisticBytes: -1, MaxNumObjects: -1}
	}
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	// root -> ns -> sub
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: mpa(1_000_000)})
	mustAdd(core.LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"}, MPA: mpa(500_000)})
	mustAdd(core.LotSpec{LotName: "sub", Owner: "fed", Parents: []string{"ns"}, MPA: mpa(100_000)})

	InitIssuerKeyForTests(t) // CacheDB encryption needs an issuer key
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open cache db: %v", err)
	}
	defer cdb.Close()

	pc := &PersistentCache{
		db:           cdb,
		lotMgr:       m,
		namespaceMap: map[string]NamespaceID{"ns": 10, "sub": 11, "root": 12},
	}

	// ns has 5000 bytes on disk 1 and 1000 on disk 2; sub has 3000 on disk 1.
	if err := cdb.AddUsage(1, 10, 5000); err != nil {
		t.Fatal(err)
	}
	if err := cdb.AddUsage(2, 10, 1000); err != nil {
		t.Fatal(err)
	}
	if err := cdb.AddUsage(1, 11, 3000); err != nil {
		t.Fatal(err)
	}

	if err := pc.syncLotUsage(); err != nil {
		t.Fatalf("sync: %v", err)
	}

	nsU, _ := m.GetLotUsage("ns")
	if nsU.SelfBytes != 6000 {
		t.Errorf("ns self = %d, want 6000", nsU.SelfBytes)
	}
	if nsU.ChildrenBytes != 3000 || nsU.TotalBytes != 9000 {
		t.Errorf("ns rollup = self %d children %d total %d, want children 3000 total 9000", nsU.SelfBytes, nsU.ChildrenBytes, nsU.TotalBytes)
	}
	subU, _ := m.GetLotUsage("sub")
	if subU.SelfBytes != 3000 {
		t.Errorf("sub self = %d, want 3000", subU.SelfBytes)
	}
	rootU, _ := m.GetLotUsage("root")
	if rootU.SelfBytes != 0 || rootU.ChildrenBytes != 9000 {
		t.Errorf("root = self %d children %d, want self 0 children 9000", rootU.SelfBytes, rootU.ChildrenBytes)
	}

	// Drain ns's usage; a second sync resets it to 0 (and updates rollups).
	if err := cdb.AddUsage(1, 10, -5000); err != nil {
		t.Fatal(err)
	}
	if err := cdb.AddUsage(2, 10, -1000); err != nil {
		t.Fatal(err)
	}
	if err := pc.syncLotUsage(); err != nil {
		t.Fatalf("sync 2: %v", err)
	}
	nsU, _ = m.GetLotUsage("ns")
	if nsU.SelfBytes != 0 {
		t.Errorf("after drain, ns self = %d, want 0", nsU.SelfBytes)
	}
	rootU, _ = m.GetLotUsage("root")
	if rootU.ChildrenBytes != 3000 {
		t.Errorf("after drain, root children = %d, want 3000 (sub only)", rootU.ChildrenBytes)
	}
}
