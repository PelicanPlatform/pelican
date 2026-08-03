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
	"time"
)

// unboundedMPA is a lot that constrains nothing, so these tests exercise
// hierarchy and authorization rules without tripping the capacity axioms.
func unboundedMPA() MPA {
	return MPA{DedicatedBytes: -1, OpportunisticBytes: -1, MaxNumObjects: -1}
}

// TestAuthorizeCreateRejectsMixedSelfParent covers the create-time ownership
// rule. A lot naming only itself as parent is a new root and is exempt, but
// naming yourself *alongside* someone else's lot must not extend that exemption
// to the other parents -- otherwise any caller can graft a lot (with a path
// claim, and with itself as owner) under a tree it does not own, and every
// later mutation then passes authorizeModify because it owns the new lot.
func TestAuthorizeCreateRejectsMixedSelfParent(t *testing.T) {
	m := newTestManager(t)

	mustAdd := func(s LotSpec, caller string) {
		t.Helper()
		if err := m.AddLot(s, caller); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()}, "")
	mustAdd(LotSpec{LotName: "childA", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()}, "")

	t.Run("self plus a lot the caller does not own", func(t *testing.T) {
		err := m.AddLot(LotSpec{
			LotName: "evil",
			Owner:   "mallory",
			Parents: []string{"evil", "root"},
			Paths:   []PathSpec{{Path: "/stolen", Recursive: true}},
			MPA:     unboundedMPA(),
		}, "mallory")
		if !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("expected ErrNotAuthorized, got %v", err)
		}
		if exists, _ := m.LotExists("evil"); exists {
			t.Error("unauthorized lot was created anyway")
		}
	})

	t.Run("self only is still allowed", func(t *testing.T) {
		if err := m.AddLot(LotSpec{
			LotName: "ownroot",
			Owner:   "mallory",
			Parents: []string{"ownroot"},
			MPA:     unboundedMPA(),
		}, "mallory"); err != nil {
			t.Fatalf("a caller must still be able to create its own root: %v", err)
		}
	})

	t.Run("the owner can still create beneath its own tree", func(t *testing.T) {
		if err := m.AddLot(LotSpec{
			LotName: "childB",
			Owner:   "fed",
			Parents: []string{"childA"},
			MPA:     unboundedMPA(),
		}, "fed"); err != nil {
			t.Fatalf("owner of an ancestor must be authorized: %v", err)
		}
	})
}

// TestAuthorizeModifyDeniesNonOwner covers the denial path of the modify rule,
// which had no coverage at all: every existing test asserted only that an
// authorized caller succeeds.
func TestAuthorizeModifyDeniesNonOwner(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()}, ""); err != nil {
		t.Fatalf("add root: %v", err)
	}
	if err := m.AddLot(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/ns", Recursive: true}}, MPA: unboundedMPA()}, ""); err != nil {
		t.Fatalf("add ns: %v", err)
	}

	newOwner := "mallory"
	cases := map[string]func() error{
		"UpdateLot": func() error { return m.UpdateLot(LotUpdate{LotName: "ns", Owner: &newOwner}, "mallory") },
		"AddToLot": func() error {
			return m.AddToLot(LotAddition{LotName: "ns", Paths: []PathSpec{{Path: "/ns2"}}}, "mallory")
		},
		"RemoveParents": func() error {
			return m.RemoveParents(LotParentRemoval{LotName: "ns", Parents: []string{"root"}}, "mallory")
		},
		"RemovePaths":    func() error { return m.RemovePaths(LotPathRemoval{LotName: "ns", Paths: []string{"/ns"}}, "mallory") },
		"RemoveLot":      func() error { return m.RemoveLot("ns", RemoveOptions{}, "mallory") },
		"UpdateLotUsage": func() error { return m.UpdateLotUsage(UsageUpdate{LotName: "ns"}, false, "mallory") },
		"ReclaimLot": func() error {
			_, err := m.ReclaimLot("ns", time.Now().UnixMilli(), "because", "mallory")
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, ErrNotAuthorized) {
				t.Errorf("%s by a non-owner: got %v, want ErrNotAuthorized", name, err)
			}
		})
	}
}

// TestAddToLotRejectsCycle pins the write-side cycle guard. Swapping a lot's
// parent is a normal operation (it is how the renewal path re-homes a lot), so
// nothing stops a caller from naming a descendant. A cycle in lot_parents makes
// the recursive depth query behind eviction ordering non-terminating, which
// wedges the purge path inside SQLite while holding a pooled connection.
func TestAddToLotRejectsCycle(t *testing.T) {
	m := newTestManager(t)
	for _, spec := range []LotSpec{
		{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()},
		{LotName: "a", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()},
		{LotName: "b", Owner: "fed", Parents: []string{"a"}, MPA: unboundedMPA()},
		{LotName: "c", Owner: "fed", Parents: []string{"b"}, MPA: unboundedMPA()},
	} {
		if err := m.AddLot(spec, ""); err != nil {
			t.Fatalf("add %s: %v", spec.LotName, err)
		}
	}

	t.Run("direct", func(t *testing.T) {
		if err := m.AddToLot(LotAddition{LotName: "a", Parents: []string{"b"}}, ""); !errors.Is(err, ErrInvalidLot) {
			t.Errorf("adding a child as a parent: got %v, want ErrInvalidLot", err)
		}
	})
	t.Run("transitive", func(t *testing.T) {
		if err := m.AddToLot(LotAddition{LotName: "a", Parents: []string{"c"}}, ""); !errors.Is(err, ErrInvalidLot) {
			t.Errorf("adding a grandchild as a parent: got %v, want ErrInvalidLot", err)
		}
	})
	t.Run("self edge is still allowed", func(t *testing.T) {
		if err := m.AddToLot(LotAddition{LotName: "a", Parents: []string{"a"}}, ""); err != nil {
			t.Errorf("a self edge is the root marker and must stay legal: %v", err)
		}
	})
	t.Run("a legitimate re-parent still works", func(t *testing.T) {
		if err := m.AddToLot(LotAddition{LotName: "c", Parents: []string{"root"}}, ""); err != nil {
			t.Errorf("adding an unrelated parent must be allowed: %v", err)
		}
	})

	// The eviction ordering query must still terminate and produce an order.
	done := make(chan []string, 1)
	go func() { done <- m.sortByDepthDescending([]string{"a", "b", "c"}) }()
	select {
	case got := <-done:
		if len(got) != 3 {
			t.Errorf("sortByDepthDescending returned %v, want 3 lots", got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("sortByDepthDescending did not terminate; the hierarchy contains a cycle")
	}
}

// childrenBytesOf reads a lot's rolled-up descendant byte total.
func childrenBytesOf(t *testing.T, m *Manager, name string) int64 {
	t.Helper()
	view, err := m.GetLot(name)
	if err != nil {
		t.Fatalf("get lot %s: %v", name, err)
	}
	return view.Usage.ChildrenBytes
}

// TestChildrenRollupSurvivesHierarchyMutations pins the children_* aggregates
// against every mutation that changes a lot's descendant set.
//
// Only usage updates used to recompute the chain, so hierarchy changes left the
// rollup stale. Ancestors self-healed opportunistically -- any later usage
// update on a surviving descendant fixed them -- but a parent left childless had
// nothing to trigger a recompute and stayed wrong indefinitely. These are the
// values the recursive-quota and hierarchical past-quota queries read, so the
// purge plugin ends up evicting live data on the strength of phantom bytes.
// Lots are removed on every renewal GC pass, so this accrues in normal
// operation.
func TestChildrenRollupSurvivesHierarchyMutations(t *testing.T) {
	setup := func(t *testing.T) *Manager {
		t.Helper()
		m := newTestManager(t)
		for _, spec := range []LotSpec{
			{LotName: "root", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()},
			{LotName: "ns", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()},
			{LotName: "grand", Owner: "fed", Parents: []string{"ns"}, MPA: unboundedMPA()},
			{LotName: "other", Owner: "fed", Parents: []string{"root"}, MPA: unboundedMPA()},
		} {
			if err := m.AddLot(spec, ""); err != nil {
				t.Fatalf("add %s: %v", spec.LotName, err)
			}
		}
		return m
	}
	setUsage := func(t *testing.T, m *Manager, name string, bytes int64) {
		t.Helper()
		if err := m.UpdateLotUsage(UsageUpdate{LotName: name, SelfBytes: &bytes}, false, ""); err != nil {
			t.Fatalf("set usage on %s: %v", name, err)
		}
	}

	t.Run("recursive removal", func(t *testing.T) {
		m := setup(t)
		setUsage(t, m, "grand", 8)
		if got := childrenBytesOf(t, m, "ns"); got != 8 {
			t.Fatalf("precondition: ns children_bytes = %d, want 8", got)
		}
		if err := m.RemoveLotRecursive("grand", ""); err != nil {
			t.Fatalf("remove: %v", err)
		}
		// `ns` is now childless, so nothing else will ever recompute it.
		if got := childrenBytesOf(t, m, "ns"); got != 0 {
			t.Errorf("ns children_bytes = %d after removing its only child, want 0", got)
		}
		if got := childrenBytesOf(t, m, "root"); got != 0 {
			t.Errorf("root children_bytes = %d after the subtree was removed, want 0", got)
		}
	})

	t.Run("non-recursive removal", func(t *testing.T) {
		m := setup(t)
		setUsage(t, m, "ns", 5)
		if got := childrenBytesOf(t, m, "root"); got != 5 {
			t.Fatalf("precondition: root children_bytes = %d, want 5", got)
		}
		// grand is reparented onto root; ns's own 5 bytes leave the tree.
		if err := m.RemoveLot("ns", RemoveOptions{}, ""); err != nil {
			t.Fatalf("remove: %v", err)
		}
		if got := childrenBytesOf(t, m, "root"); got != 0 {
			t.Errorf("root children_bytes = %d after removing ns, want 0", got)
		}
	})

	t.Run("adding a parent", func(t *testing.T) {
		m := setup(t)
		setUsage(t, m, "grand", 7)
		if got := childrenBytesOf(t, m, "other"); got != 0 {
			t.Fatalf("precondition: other children_bytes = %d, want 0", got)
		}
		if err := m.AddToLot(LotAddition{LotName: "grand", Parents: []string{"other"}}, ""); err != nil {
			t.Fatalf("add parent: %v", err)
		}
		if got := childrenBytesOf(t, m, "other"); got != 7 {
			t.Errorf("other children_bytes = %d after gaining a 7-byte child, want 7", got)
		}
	})

	t.Run("removing a parent", func(t *testing.T) {
		m := setup(t)
		setUsage(t, m, "grand", 7)
		if err := m.AddToLot(LotAddition{LotName: "grand", Parents: []string{"other"}}, ""); err != nil {
			t.Fatalf("add parent: %v", err)
		}
		if got := childrenBytesOf(t, m, "other"); got != 7 {
			t.Fatalf("precondition: other children_bytes = %d, want 7", got)
		}
		if err := m.RemoveParents(LotParentRemoval{LotName: "grand", Parents: []string{"other"}}, ""); err != nil {
			t.Fatalf("remove parent: %v", err)
		}
		if got := childrenBytesOf(t, m, "other"); got != 0 {
			t.Errorf("other children_bytes = %d after losing its only child, want 0", got)
		}
		// The remaining chain is untouched.
		if got := childrenBytesOf(t, m, "ns"); got != 7 {
			t.Errorf("ns children_bytes = %d, want 7 (still grand's parent)", got)
		}
	})
}
