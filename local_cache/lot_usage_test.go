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
	"testing"

	"github.com/pelicanplatform/pelican/lotman/core"
)

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
