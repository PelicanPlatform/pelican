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
	"sort"
	"testing"
)

// nonExpiringMPA returns an MPA with the given quotas and a non-expiring window.
func nonExpiringMPA(dedicated, opportunistic float64, maxObjects int64) MPA {
	return MPA{DedicatedGB: dedicated, OpportunisticGB: opportunistic, MaxNumObjects: maxObjects}
}

// seedRootAndChild builds: root (self-parent, owner "fed") -> childA (owner "fed",
// path /a recursive). Returns the manager.
func seedRootAndChild(t *testing.T) *Manager {
	t.Helper()
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{
		LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}},
		MPA:   nonExpiringMPA(100, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := m.AddLot(LotSpec{
		LotName: "childA", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/a", Recursive: true}},
		MPA:   nonExpiringMPA(50, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add childA: %v", err)
	}
	return m
}

func TestAddAndGetLot(t *testing.T) {
	m := seedRootAndChild(t)

	ok, err := m.LotExists("childA")
	if err != nil || !ok {
		t.Fatalf("expected childA to exist, ok=%v err=%v", ok, err)
	}

	view, err := m.GetLot("childA")
	if err != nil {
		t.Fatalf("get childA: %v", err)
	}
	if view.Owner != "fed" || view.DedicatedGB != 50 {
		t.Errorf("unexpected lot view: %+v", view.Lot)
	}
	if len(view.Parents) != 1 || view.Parents[0] != "root" {
		t.Errorf("expected parent [root], got %v", view.Parents)
	}
	if len(view.Paths) != 1 || view.Paths[0].Path != "/a" || !view.Paths[0].Recursive {
		t.Errorf("unexpected paths: %v", view.Paths)
	}

	isRoot, err := m.IsRoot("root")
	if err != nil || !isRoot {
		t.Errorf("expected root IsRoot=true, got %v err=%v", isRoot, err)
	}
	isRoot, err = m.IsRoot("childA")
	if err != nil || isRoot {
		t.Errorf("expected childA IsRoot=false, got %v err=%v", isRoot, err)
	}

	all, err := m.ListAllLots()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 lots, got %v", all)
	}
}

func TestGetLotNotFound(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.GetLot("nope"); !errors.Is(err, ErrLotNotFound) {
		t.Fatalf("expected ErrLotNotFound, got %v", err)
	}
}

func TestAddLotDuplicate(t *testing.T) {
	m := seedRootAndChild(t)
	err := m.AddLot(LotSpec{
		LotName: "childA", Owner: "fed", Parents: []string{"root"}, MPA: nonExpiringMPA(1, -1, -1),
	}, "")
	if !errors.Is(err, ErrLotExists) {
		t.Fatalf("expected ErrLotExists, got %v", err)
	}
}

func TestAddLotValidation(t *testing.T) {
	m := newTestManager(t)
	cases := map[string]LotSpec{
		"no parents":         {LotName: "x", Owner: "o", MPA: nonExpiringMPA(1, -1, -1)},
		"no owner":           {LotName: "x", Parents: []string{"x"}, MPA: nonExpiringMPA(1, -1, -1)},
		"bad dedicated":      {LotName: "x", Owner: "o", Parents: []string{"x"}, MPA: MPA{DedicatedGB: -1, OpportunisticGB: 5}},
		"partial-zero times": {LotName: "x", Owner: "o", Parents: []string{"x"}, MPA: MPA{DedicatedGB: 1, OpportunisticGB: -1, CreationTime: 10}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if err := m.AddLot(spec, ""); !errors.Is(err, ErrInvalidLot) {
				t.Fatalf("expected ErrInvalidLot, got %v", err)
			}
		})
	}
}

func TestAddLotParentMustExist(t *testing.T) {
	m := newTestManager(t)
	err := m.AddLot(LotSpec{
		LotName: "orphan", Owner: "o", Parents: []string{"ghost"}, MPA: nonExpiringMPA(1, -1, -1),
	}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected ErrInvalidLot for missing parent, got %v", err)
	}
}

func TestRecursiveTraversal(t *testing.T) {
	m := seedRootAndChild(t)
	if err := m.AddLot(LotSpec{
		LotName: "grand", Owner: "userA", Parents: []string{"childA"},
		Paths: []PathSpec{{Path: "/a/b", Recursive: true}},
		MPA:   nonExpiringMPA(10, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add grand: %v", err)
	}

	ancestors, err := m.GetParents("grand", true, false)
	if err != nil {
		t.Fatalf("ancestors: %v", err)
	}
	sort.Strings(ancestors)
	if len(ancestors) != 2 || ancestors[0] != "childA" || ancestors[1] != "root" {
		t.Errorf("expected ancestors [childA root], got %v", ancestors)
	}

	descendants, err := m.GetChildren("root", true, false)
	if err != nil {
		t.Fatalf("descendants: %v", err)
	}
	sort.Strings(descendants)
	if len(descendants) != 2 || descendants[0] != "childA" || descendants[1] != "grand" {
		t.Errorf("expected descendants [childA grand], got %v", descendants)
	}

	owners, err := m.GetOwners("grand", true)
	if err != nil {
		t.Fatalf("owners: %v", err)
	}
	// grand owner first, then ancestor owners (fed), de-duplicated.
	if len(owners) != 2 || owners[0] != "userA" || owners[1] != "fed" {
		t.Errorf("expected owners [userA fed], got %v", owners)
	}
}

func TestAuthorizationOnCreate(t *testing.T) {
	m := seedRootAndChild(t) // root and childA owned by "fed"

	// A caller who owns no parent cannot create a child.
	err := m.AddLot(LotSpec{
		LotName: "sneaky", Owner: "mallory", Parents: []string{"root"}, MPA: nonExpiringMPA(1, -1, -1),
	}, "mallory")
	if !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("expected ErrNotAuthorized, got %v", err)
	}

	// The owner of the parent can.
	if err := m.AddLot(LotSpec{
		LotName: "legit", Owner: "fed", Parents: []string{"root"}, MPA: nonExpiringMPA(1, -1, -1),
	}, "fed"); err != nil {
		t.Fatalf("expected authorized create to succeed, got %v", err)
	}
}

func TestAddToLotAndRemoveParents(t *testing.T) {
	m := seedRootAndChild(t)
	// Add a second root and attach childA to it.
	if err := m.AddLot(LotSpec{
		LotName: "root2", Owner: "fed", Parents: []string{"root2"}, MPA: nonExpiringMPA(100, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add root2: %v", err)
	}
	if err := m.AddToLot(LotAddition{
		LotName: "childA", Parents: []string{"root2"}, Paths: []PathSpec{{Path: "/a2"}},
	}, ""); err != nil {
		t.Fatalf("add to lot: %v", err)
	}
	parents, _ := m.GetParents("childA", false, false)
	sort.Strings(parents)
	if len(parents) != 2 || parents[0] != "root" || parents[1] != "root2" {
		t.Errorf("expected [root root2], got %v", parents)
	}

	// Removing both parents must fail (lot needs >=1).
	if err := m.RemoveParents(LotParentRemoval{LotName: "childA", Parents: []string{"root", "root2"}}, ""); !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected ErrInvalidLot removing all parents, got %v", err)
	}
	// childA should still have both parents (transaction rolled back).
	parents, _ = m.GetParents("childA", false, false)
	if len(parents) != 2 {
		t.Errorf("expected rollback to keep 2 parents, got %v", parents)
	}
	// Removing one is fine.
	if err := m.RemoveParents(LotParentRemoval{LotName: "childA", Parents: []string{"root2"}}, ""); err != nil {
		t.Fatalf("remove one parent: %v", err)
	}
	parents, _ = m.GetParents("childA", false, false)
	if len(parents) != 1 || parents[0] != "root" {
		t.Errorf("expected [root], got %v", parents)
	}
}

func TestUpdateLot(t *testing.T) {
	m := seedRootAndChild(t)
	newOwner := "newowner"
	newMPA := nonExpiringMPA(75, 10, 1000)
	if err := m.UpdateLot(LotUpdate{LotName: "childA", Owner: &newOwner, MPA: &newMPA}, ""); err != nil {
		t.Fatalf("update: %v", err)
	}
	view, _ := m.GetLot("childA")
	if view.Owner != "newowner" || view.DedicatedGB != 75 || view.OpportunisticGB != 10 || view.MaxNumObjects != 1000 {
		t.Errorf("update not applied: %+v", view.Lot)
	}
}

func TestRemoveLotReparentsChildren(t *testing.T) {
	m := seedRootAndChild(t)
	if err := m.AddLot(LotSpec{
		LotName: "grand", Owner: "fed", Parents: []string{"childA"}, MPA: nonExpiringMPA(10, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add grand: %v", err)
	}
	// Remove childA non-recursively: grand should be reparented to root.
	if err := m.RemoveLot("childA", RemoveOptions{}, ""); err != nil {
		t.Fatalf("remove childA: %v", err)
	}
	if ok, _ := m.LotExists("childA"); ok {
		t.Error("childA should be gone")
	}
	parents, _ := m.GetParents("grand", false, false)
	if len(parents) != 1 || parents[0] != "root" {
		t.Errorf("expected grand reparented to [root], got %v", parents)
	}
}

func TestRemoveLotRecursiveCascade(t *testing.T) {
	m := seedRootAndChild(t)
	if err := m.AddLot(LotSpec{
		LotName: "grand", Owner: "fed", Parents: []string{"childA"},
		Paths: []PathSpec{{Path: "/a/b"}}, MPA: nonExpiringMPA(10, -1, -1),
	}, ""); err != nil {
		t.Fatalf("add grand: %v", err)
	}
	if err := m.RemoveLotRecursive("childA", ""); err != nil {
		t.Fatalf("remove recursive: %v", err)
	}
	for _, name := range []string{"childA", "grand"} {
		if ok, _ := m.LotExists(name); ok {
			t.Errorf("%s should be deleted", name)
		}
	}
	// Cascade should have removed grand's path and usage rows.
	var pathCount int64
	m.db.Model(&LotPath{}).Where("lot_name = ?", "grand").Count(&pathCount)
	if pathCount != 0 {
		t.Errorf("expected grand paths cascade-deleted, got %d", pathCount)
	}
	var usageCount int64
	m.db.Model(&LotUsage{}).Where("lot_name = ?", "grand").Count(&usageCount)
	if usageCount != 0 {
		t.Errorf("expected grand usage cascade-deleted, got %d", usageCount)
	}
	// root remains.
	if ok, _ := m.LotExists("root"); !ok {
		t.Error("root should remain")
	}
}
