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

// expiring returns an MPA with a finite [creation, expiration) window.
func expiring(dedicated, opportunistic, maxObjects, c, e, d int64) MPA {
	return MPA{DedicatedBytes: dedicated, OpportunisticBytes: opportunistic, MaxNumObjects: maxObjects,
		CreationTime: c, ExpirationTime: e, DeletionTime: d}
}

func addRoot(t *testing.T, m *Manager, name string, dedicated int64) {
	t.Helper()
	if err := m.AddLot(LotSpec{LotName: name, Owner: "fed", Parents: []string{name},
		MPA: nonExpiringMPA(dedicated, -1, -1)}, ""); err != nil {
		t.Fatalf("add root %s: %v", name, err)
	}
}

func TestAxiom1ChildExceedsParent(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	err := m.AddLot(LotSpec{LotName: "big", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(150, -1, -1)}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected axiom-1 rejection (150 > 100), got %v", err)
	}
	if ok, _ := m.LotExists("big"); ok {
		t.Error("rejected lot should not persist (transaction rollback)")
	}
}

func TestAxiom2ConcurrentChildrenExceedParent(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	// Two children with overlapping windows, each 60 GB: concurrent peak 120 > 100.
	if err := m.AddLot(LotSpec{LotName: "a", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(60, -1, -1, 100, 200, 300)}, ""); err != nil {
		t.Fatalf("add a: %v", err)
	}
	err := m.AddLot(LotSpec{LotName: "b", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(60, -1, -1, 150, 250, 350)}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected axiom-2 rejection (peak 120 > 100), got %v", err)
	}
}

func TestAxiom2NonOverlappingChildrenOK(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	// Two full-capacity children in disjoint windows: peak stays 100.
	if err := m.AddLot(LotSpec{LotName: "a", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(100, -1, -1, 100, 200, 400)}, ""); err != nil {
		t.Fatalf("add a: %v", err)
	}
	if err := m.AddLot(LotSpec{LotName: "b", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(100, -1, -1, 200, 300, 400)}, ""); err != nil {
		t.Fatalf("expected disjoint windows to be allowed, got %v", err)
	}
}

func TestAxiom3ChildWindowOutsideParent(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100)
	// Finite parent under the non-expiring root.
	if err := m.AddLot(LotSpec{LotName: "p", Owner: "fed", Parents: []string{"root"},
		MPA: expiring(50, -1, -1, 100, 200, 300)}, ""); err != nil {
		t.Fatalf("add p: %v", err)
	}
	// Child starts before the parent -> axiom 3 violation.
	err := m.AddLot(LotSpec{LotName: "c", Owner: "fed", Parents: []string{"p"},
		MPA: expiring(10, -1, -1, 50, 150, 250)}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected axiom-3 rejection (child starts before parent), got %v", err)
	}
	// Non-expiring child under a finite parent -> axiom 3 violation.
	err = m.AddLot(LotSpec{LotName: "d", Owner: "fed", Parents: []string{"p"},
		MPA: nonExpiringMPA(10, -1, -1)}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected axiom-3 rejection (non-expiring child under finite parent), got %v", err)
	}
}

func TestExplicitAttributionsAndCapacity(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "rootX", 100)
	addRoot(t, m, "rootY", 100)
	// Child reserves 80 GB split 60/20 across two parents.
	err := m.AddLot(LotSpec{LotName: "child", Owner: "fed", Parents: []string{"rootX", "rootY"},
		MPA: nonExpiringMPA(80, 0, 0),
		ParentAttributions: map[string]ParentAttribution{
			"rootX": {DedicatedBytes: i64(60)},
			"rootY": {DedicatedBytes: i64(20)},
		}}, "")
	if err != nil {
		t.Fatalf("explicit attribution add: %v", err)
	}

	capX, err := m.AvailableCapacity("rootX", 1, 1_000_000)
	if err != nil {
		t.Fatalf("capacity rootX: %v", err)
	}
	if capX.PeakDedicatedBytes != 60 || capX.AvailableDedicatedBytes == nil || *capX.AvailableDedicatedBytes != 40 {
		t.Errorf("rootX: peak=%v avail=%v, want peak 60 avail 40", capX.PeakDedicatedBytes, capX.AvailableDedicatedBytes)
	}
	capY, _ := m.AvailableCapacity("rootY", 1, 1_000_000)
	if capY.PeakDedicatedBytes != 20 || capY.AvailableDedicatedBytes == nil || *capY.AvailableDedicatedBytes != 80 {
		t.Errorf("rootY: peak=%v avail=%v, want peak 20 avail 80", capY.PeakDedicatedBytes, capY.AvailableDedicatedBytes)
	}
}

func TestExplicitAttributionsOverageRejected(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "rootX", 100)
	addRoot(t, m, "rootY", 100)
	// 50 + 50 = 100 attributed but child total is only 80 -> double-count.
	err := m.AddLot(LotSpec{LotName: "child", Owner: "fed", Parents: []string{"rootX", "rootY"},
		MPA: nonExpiringMPA(80, 0, 0),
		ParentAttributions: map[string]ParentAttribution{
			"rootX": {DedicatedBytes: i64(50)},
			"rootY": {DedicatedBytes: i64(50)},
		}}, "")
	if !errors.Is(err, ErrInvalidLot) {
		t.Fatalf("expected overage rejection, got %v", err)
	}
}

func TestAvailableCapacityUnboundedAxis(t *testing.T) {
	m := newTestManager(t)
	addRoot(t, m, "root", 100) // opportunistic is -1 (unbounded)
	cap, err := m.AvailableCapacity("root", 1, 1000)
	if err != nil {
		t.Fatalf("capacity: %v", err)
	}
	if cap.AvailableOpportunisticBytes != nil {
		t.Errorf("expected nil available opportunistic (unbounded), got %v", *cap.AvailableOpportunisticBytes)
	}
	if cap.AvailableDedicatedBytes == nil || *cap.AvailableDedicatedBytes != 100 {
		t.Errorf("expected available dedicated 100, got %v", cap.AvailableDedicatedBytes)
	}
}

func TestPolicyAttributesRestrictive(t *testing.T) {
	m := seedThreeLevel(t) // root 100 -> ns 50 -> grand 10
	res, err := m.PolicyAttributes(PolicyAttrsRequest{LotName: "grand", Recursive: true, Keys: []string{MpaKeyDedicatedBytes}})
	if err != nil {
		t.Fatalf("policy attrs: %v", err)
	}
	rv := res[MpaKeyDedicatedBytes]
	// In a valid hierarchy the deepest lot holds the smallest dedicated quota.
	if rv.Value != 10 || rv.LotName != "grand" {
		t.Errorf("restrictive dedicated = %+v, want {grand 10}", rv)
	}
	// Non-recursive returns the lot's own value.
	res, _ = m.PolicyAttributes(PolicyAttrsRequest{LotName: "ns", Recursive: false, Keys: []string{MpaKeyDedicatedBytes}})
	if res[MpaKeyDedicatedBytes].Value != 50 {
		t.Errorf("non-recursive ns dedicated = %v, want 50", res[MpaKeyDedicatedBytes].Value)
	}
}
