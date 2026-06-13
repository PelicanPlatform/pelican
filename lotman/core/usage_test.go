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
	"errors"
	"testing"
)

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

// seedThreeLevel builds root -> ns -> grand, all owned by "fed", non-expiring,
// with recursive paths /atlas and /atlas/data.
func seedThreeLevel(t *testing.T) *Manager {
	t.Helper()
	m := newTestManager(t)
	mustAdd := func(spec LotSpec) {
		if err := m.AddLot(spec, ""); err != nil {
			t.Fatalf("add %s: %v", spec.LotName, err)
		}
	}
	mustAdd(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}}, MPA: nonExpiringMPA(100, -1, -1)})
	mustAdd(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/atlas", Recursive: true}}, MPA: nonExpiringMPA(50, -1, -1)})
	mustAdd(LotSpec{LotName: "grand", Owner: "fed", Parents: []string{"ns"},
		Paths: []PathSpec{{Path: "/atlas/data", Recursive: true}}, MPA: nonExpiringMPA(10, -1, -1)})
	return m
}

func TestUpdateLotUsageSelfAndRollup(t *testing.T) {
	m := seedThreeLevel(t)

	if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(5), SelfObjects: i64(7)}, false, ""); err != nil {
		t.Fatalf("update grand: %v", err)
	}
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "ns", SelfGB: f64(3), SelfObjects: i64(2)}, false, ""); err != nil {
		t.Fatalf("update ns: %v", err)
	}

	// grand: self only.
	g, _ := m.GetLotUsage("grand")
	if g.SelfGB != 5 || g.TotalGB != 5 || g.ChildrenGB != 0 || g.SelfObjects != 7 {
		t.Errorf("grand usage = %+v", g)
	}
	// ns: self 3 + children 5 (grand).
	ns, _ := m.GetLotUsage("ns")
	if ns.SelfGB != 3 || ns.ChildrenGB != 5 || ns.TotalGB != 8 || ns.ChildrenObjects != 7 {
		t.Errorf("ns usage = %+v", ns)
	}
	// root: self 0 + children = ns.self + grand.self = 8.
	root, _ := m.GetLotUsage("root")
	if root.ChildrenGB != 8 || root.TotalGB != 8 || root.ChildrenObjects != 9 {
		t.Errorf("root usage = %+v", root)
	}
}

func TestUpdateLotUsageDelta(t *testing.T) {
	m := seedThreeLevel(t)
	for i := 0; i < 3; i++ {
		if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(2)}, true, ""); err != nil {
			t.Fatalf("delta %d: %v", i, err)
		}
	}
	g, _ := m.GetLotUsage("grand")
	if g.SelfGB != 6 {
		t.Errorf("expected grand self_gb 6 after 3x +2, got %v", g.SelfGB)
	}
	// Negative-going delta is rejected and rolls back.
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(-10)}, true, ""); !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected ErrInvalidLot, got %v", err)
	}
	g, _ = m.GetLotUsage("grand")
	if g.SelfGB != 6 {
		t.Errorf("expected grand self_gb unchanged at 6, got %v", g.SelfGB)
	}
}

func TestAbsoluteUsageRejectsNegative(t *testing.T) {
	m := seedThreeLevel(t)
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(-1)}, false, ""); !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected ErrInvalidLot for negative absolute, got %v", err)
	}
}

func TestRollupExcludesReclaimed(t *testing.T) {
	m := seedThreeLevel(t)
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "grand", SelfGB: f64(5)}, false, ""); err != nil {
		t.Fatal(err)
	}
	root, _ := m.GetLotUsage("root")
	if root.ChildrenGB != 5 {
		t.Fatalf("precondition: root children = 5, got %v", root.ChildrenGB)
	}
	// Insert a reclamation row for grand and recompute: grand drops out of rollup.
	if err := m.db.Create(&LotReclamation{LotName: "grand", ReclaimedAt: 1, ReclaimedReason: "test"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := m.RecalculateChildrenUsage(); err != nil {
		t.Fatalf("recalc: %v", err)
	}
	root, _ = m.GetLotUsage("root")
	if root.ChildrenGB != 0 {
		t.Errorf("expected reclaimed grand excluded from rollup (children 0), got %v", root.ChildrenGB)
	}
}

func TestUpdateLotUsageByDir(t *testing.T) {
	m := seedThreeLevel(t)
	// /atlas/raw resolves to ns (recursive), /atlas/data/x resolves to grand.
	entries := []DirUsage{
		{Path: "/atlas/raw", SizeGB: 4, NumObjects: 2},
		{Path: "/atlas/data/x", SizeGB: 6, NumObjects: 3},
	}
	if err := m.UpdateLotUsageByDir(entries, false, 1000, ""); err != nil {
		t.Fatalf("by dir: %v", err)
	}
	ns, _ := m.GetLotUsage("ns")
	if ns.SelfGB != 4 {
		t.Errorf("ns self_gb = %v, want 4", ns.SelfGB)
	}
	grand, _ := m.GetLotUsage("grand")
	if grand.SelfGB != 6 {
		t.Errorf("grand self_gb = %v, want 6", grand.SelfGB)
	}
	// Rollup: ns total = 4 + 6 = 10.
	if ns.TotalGB != 10 {
		t.Errorf("ns total_gb = %v, want 10", ns.TotalGB)
	}
}
