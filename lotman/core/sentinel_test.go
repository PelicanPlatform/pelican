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
	"testing"
)

func TestValidateMPASentinels(t *testing.T) {
	valid := []MPA{
		nonExpiringMPA(0, 0, 0),    // no storage
		nonExpiringMPA(0, 5, 0),    // purely opportunistic
		nonExpiringMPA(0, -1, -1),  // purely opportunistic, unbounded
		nonExpiringMPA(5, 0, 10),   // guaranteed, no burst
		nonExpiringMPA(5, 10, -1),  // guaranteed + finite burst
		nonExpiringMPA(5, -1, -1),  // guaranteed + unbounded burst
		nonExpiringMPA(-1, -1, -1), // fully unbounded
	}
	for i, mpa := range valid {
		if err := validateMPA(mpa); err != nil {
			t.Errorf("valid[%d] %+v unexpectedly rejected: %v", i, mpa, err)
		}
	}
	invalid := []MPA{
		nonExpiringMPA(-1, 0, -1),    // unbounded dedicated needs unbounded opp
		nonExpiringMPA(-1, 5, -1),    // same
		nonExpiringMPA(-0.5, -1, -1), // negative that is not the -1 sentinel
		nonExpiringMPA(5, -2, -1),    // opp below -1
		nonExpiringMPA(5, 5, -2),     // objects below -1
	}
	for i, mpa := range invalid {
		if err := validateMPA(mpa); err == nil {
			t.Errorf("invalid[%d] %+v unexpectedly accepted", i, mpa)
		}
	}
}

func TestValidateTimestampsParity(t *testing.T) {
	type tc struct {
		c, e, d int64
		ok      bool
	}
	cases := []tc{
		{0, 0, 0, true},     // non-expiring sentinel
		{10, 20, 30, true},  // ordered
		{10, 20, 20, true},  // deletion == expiration allowed
		{-5, 20, 30, true},  // non-zero negatives permitted (faithful to reference)
		{10, 10, 30, false}, // creation must be strictly < expiration
		{10, 0, 30, false},  // partial-zero
		{0, 20, 0, false},   // partial-zero
		{30, 20, 40, false}, // creation > expiration
		{10, 30, 20, false}, // deletion < expiration
	}
	for _, c := range cases {
		err := validateTimestamps(c.c, c.e, c.d)
		if c.ok && err != nil {
			t.Errorf("(%d,%d,%d) should be valid, got %v", c.c, c.e, c.d, err)
		}
		if !c.ok && err == nil {
			t.Errorf("(%d,%d,%d) should be invalid", c.c, c.e, c.d)
		}
	}
}

func TestUnboundedHierarchyAllowed(t *testing.T) {
	m := newTestManager(t)
	// Fully-unbounded root.
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(-1, -1, -1)}, ""); err != nil {
		t.Fatalf("unbounded root: %v", err)
	}
	// Fully-unbounded child under an unbounded parent is allowed.
	if err := m.AddLot(LotSpec{LotName: "ub", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(-1, -1, -1)}, ""); err != nil {
		t.Errorf("unbounded child under unbounded parent should be allowed: %v", err)
	}
	// Finite child under an unbounded parent is allowed (axes skipped).
	if err := m.AddLot(LotSpec{LotName: "fin", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(50, -1, -1)}, ""); err != nil {
		t.Errorf("finite child under unbounded parent should be allowed: %v", err)
	}
}

func TestUnboundedNeverPastQuota(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(-1, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateLotUsage(UsageUpdate{LotName: "root", SelfGB: f64(10000), SelfObjects: i64(10000)}, false, ""); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func() ([]string, error){
		"ded": func() ([]string, error) { return m.LotsPastDed(false, false, false, false) },
		"opp": func() ([]string, error) { return m.LotsPastOpp(false, false, false, false) },
		"obj": func() ([]string, error) { return m.LotsPastObj(false, false, false, false) },
	} {
		past, err := fn()
		if err != nil {
			t.Fatalf("%s query: %v", name, err)
		}
		if contains(past, "root") {
			t.Errorf("fully-unbounded root must never be past %s quota: %v", name, past)
		}
	}
}

func TestZeroDedicatedAlwaysPastDed(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(100, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Opportunistic-only lot (dedicated 0) -- the catch-all eviction shape.
	if err := m.AddLot(LotSpec{LotName: "opp", Owner: "fed", Parents: []string{"root"},
		MPA: nonExpiringMPA(0, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Even at zero usage, dedicated 0 means self_gb (0) >= 0 -> past dedicated.
	past, err := m.LotsPastDed(false, false, false, false)
	if err != nil {
		t.Fatalf("past ded: %v", err)
	}
	if !contains(past, "opp") {
		t.Errorf("zero-dedicated lot should always be past dedicated: %v", past)
	}
	if contains(past, "root") {
		t.Errorf("root (100, no usage) should not be past dedicated: %v", past)
	}
}

func TestReclaimedExcludedFromResolution(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}}, MPA: nonExpiringMPA(100, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.AddLot(LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/atlas", Recursive: true}}, MPA: nonExpiringMPA(50, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Before reclaim: resolves to ns.
	if lots, _ := m.LotsFromDir("/atlas/x", false, 1000); len(lots) != 1 || lots[0] != "ns" {
		t.Fatalf("expected ns before reclaim, got %v", lots)
	}
	if _, err := m.ReclaimLot("ns", 1, "test", ""); err != nil {
		t.Fatal(err)
	}
	// After reclaim: ns's accounting tie is severed -> falls to default.
	if lots, _ := m.LotsFromDir("/atlas/x", false, 1000); len(lots) != 1 || lots[0] != "default" {
		t.Errorf("expected default after reclaim, got %v", lots)
	}
}
