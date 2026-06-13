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

package core

import (
	"sort"
	"testing"
)

func contains(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestLotsPastExpAndDel(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	// Expires at 200, deletes at 300.
	if err := m.AddLot(LotSpec{LotName: "gen", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(10, -1, -1, 100, 200, 300)}, ""); err != nil {
		t.Fatal(err)
	}

	// Before expiration: not past exp.
	if lots, _ := m.LotsPastExp(150, false, false); contains(lots, "gen") {
		t.Errorf("gen should not be past-exp at t=150: %v", lots)
	}
	// After expiration but before deletion.
	if lots, _ := m.LotsPastExp(250, false, false); !contains(lots, "gen") {
		t.Errorf("gen should be past-exp at t=250: %v", lots)
	}
	if lots, _ := m.LotsPastDel(250, false, false); contains(lots, "gen") {
		t.Errorf("gen should not be past-del at t=250: %v", lots)
	}
	// After deletion.
	if lots, _ := m.LotsPastDel(350, false, false); !contains(lots, "gen") {
		t.Errorf("gen should be past-del at t=350: %v", lots)
	}
	// Non-expiring root never appears.
	if lots, _ := m.LotsPastExp(1_000_000, false, false); contains(lots, "root") {
		t.Errorf("non-expiring root should never be past-exp: %v", lots)
	}
}

func TestLotsPastDedQuota(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	if err := m.AddLot(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(50, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// ns uses 60 GB > its 50 dedicated.
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "ns", SelfGB: f64(60)}, false, ""); err != nil {
		t.Fatal(err)
	}
	past, err := m.LotsPastDed(false, false, false, false)
	if err != nil {
		t.Fatalf("past ded: %v", err)
	}
	if !contains(past, "ns") {
		t.Errorf("ns (60 > 50) should be past dedicated: %v", past)
	}
	// root: self 0, children_gb 60 (rollup). Non-recursive quota uses self only
	// (0 < 100) -> not past. Recursive quota uses self+children (60 < 100) ->
	// still not past.
	if contains(past, "root") {
		t.Errorf("root should not be past dedicated with non-recursive quota: %v", past)
	}
}

func TestLotsPastDedHierarchical(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	if err := m.AddLot(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(50, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// ns overshoots its dedicated by 70 (120 used, 50 quota). The overage (70)
	// attributed to root: root.self(0) + 70 = 70 < root.dedicated(100) -> root
	// not yet past. Bump ns to 180 (overage 130) -> root past (0 + 130 >= 100).
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "ns", SelfGB: f64(120)}, false, ""); err != nil {
		t.Fatal(err)
	}
	past, err := m.LotsPastDed(false, false, false, true)
	if err != nil {
		t.Fatalf("hierarchical past ded: %v", err)
	}
	if contains(past, "root") {
		t.Errorf("root should not be past with overage 70 (<100): %v", past)
	}
	if !contains(past, "ns") {
		t.Errorf("ns should be past its own dedicated: %v", past)
	}

	if err := m.UpdateLotUsage(UsageUpdate{LotName: "ns", SelfGB: f64(180)}, false, ""); err != nil {
		t.Fatal(err)
	}
	past, _ = m.LotsPastDed(false, false, false, true)
	if !contains(past, "root") {
		t.Errorf("root should be past with child overage 130 (>=100): %v", past)
	}
	// Deepest-first ordering: ns (deeper) before root.
	var ri, ni int = -1, -1
	for i, n := range past {
		if n == "root" {
			ri = i
		}
		if n == "ns" {
			ni = i
		}
	}
	if ni >= 0 && ri >= 0 && ni > ri {
		t.Errorf("expected ns (deeper) before root, got %v", past)
	}
}

func TestLotsPastObjAndUnboundedSkipped(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100) // max_num_objects is -1 (unbounded)
	if err := m.AddLot(LotSpec{LotName: "capped", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(50, -1, 5)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "capped", SelfObjects: i64(5)}, false, ""); err != nil {
		t.Fatal(err)
	}
	past, err := m.LotsPastObj(false, false, false, false)
	if err != nil {
		t.Fatalf("past obj: %v", err)
	}
	if !contains(past, "capped") {
		t.Errorf("capped (5 >= 5) should be past objects: %v", past)
	}
	// root has unbounded objects (-1) and must never appear.
	if contains(past, "root") {
		t.Errorf("unbounded-objects root should never be past objects: %v", past)
	}
}

func TestReclaimLot(t *testing.T) {
	m := seedThreeLevel(t) // root -> ns -> grand
	// Give grand usage so root's rollup counts it.
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(8)}, false, ""); err != nil {
		t.Fatal(err)
	}
	if r, _ := m.GetLotUsage("root"); r.ChildrenGB != 8 {
		t.Fatalf("precondition root children 8, got %v", r.ChildrenGB)
	}

	// Reclaim ns: cascades to grand.
	res, err := m.ReclaimLot("ns", 1000, "test", "")
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if res != ReclaimOK {
		t.Errorf("expected ReclaimOK, got %v", res)
	}
	// Reclaimed subtree drops out of root's rollup.
	if r, _ := m.GetLotUsage("root"); r.ChildrenGB != 0 {
		t.Errorf("root children should be 0 after reclaim, got %v", r.ChildrenGB)
	}

	// Re-reclaiming is a no-op signalled as already-reclaimed.
	res, err = m.ReclaimLot("ns", 1000, "again", "")
	if err != nil {
		t.Fatalf("re-reclaim: %v", err)
	}
	if res != ReclaimAlreadyReclaimed {
		t.Errorf("expected ReclaimAlreadyReclaimed, got %v", res)
	}

	// Default lot cannot be reclaimed.
	if _, err := m.ReclaimLot("default", 1000, "x", ""); err == nil {
		t.Error("expected error reclaiming default lot")
	}
}

func TestPastQuotaExcludesReclaimed(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	if err := m.AddLot(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(10, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "ns", SelfGB: f64(50)}, false, ""); err != nil {
		t.Fatal(err)
	}
	// Over quota and present by default.
	past, _ := m.LotsPastDed(false, false, false, false)
	if !contains(past, "ns") {
		t.Fatalf("ns should be past ded: %v", past)
	}
	// Reclaim it; now excluded unless includeReclaimed.
	if _, err := m.ReclaimLot("ns", 1, "test", ""); err != nil {
		t.Fatal(err)
	}
	past, _ = m.LotsPastDed(false, false, false, false)
	if contains(past, "ns") {
		t.Errorf("reclaimed ns should be filtered out: %v", past)
	}
	past, _ = m.LotsPastDed(false, false, true, false) // includeReclaimed
	if !contains(past, "ns") {
		t.Errorf("includeReclaimed should keep ns: %v", past)
	}
	_ = sort.StringSlice(past)
}
