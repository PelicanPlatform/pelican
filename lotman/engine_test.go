//go:build linux && !ppc64le

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

package lotman

import (
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/lotman/core"
)

func fptr(v float64) *float64 { return &v }

// newAdapterTestDB opens a temp-file SQLite database for adapter tests that
// exercise the native engine without the federation/launcher machinery.
func newAdapterTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "lotman-adapter-test.sqlite")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open adapter test db: %v", err)
	}
	return db
}

func TestLotToSpecConversion(t *testing.T) {
	dedicated := 1.11
	opp := -1.0 // unbounded
	lot := &Lot{
		LotName: "atlas",
		Owner:   "https://fed.example",
		Parents: []string{"root"},
		Paths:   []LotPath{{Path: "/atlas", Recursive: true}},
		MPA: &MPA{
			DedicatedGB:     &dedicated,
			OpportunisticGB: &opp,
			MaxNumObjects:   &Int64FromFloat{Value: 42},
			CreationTime:    &Int64FromFloat{Value: 1000},
			ExpirationTime:  &Int64FromFloat{Value: 2000},
			DeletionTime:    &Int64FromFloat{Value: 3000},
		},
		ParentAttributions: map[string]ParentAttribution{
			"root": {DedicatedGB: fptr(1.11)},
		},
	}
	spec := lotToSpec(lot)

	if spec.LotName != "atlas" || spec.Owner != "https://fed.example" {
		t.Errorf("identity not mapped: %+v", spec)
	}
	if spec.MPA.DedicatedBytes != 1_110_000_000 {
		t.Errorf("dedicated 1.11 GB -> %d bytes, want 1.11e9", spec.MPA.DedicatedBytes)
	}
	if spec.MPA.OpportunisticBytes != core.Unbounded {
		t.Errorf("opportunistic -1 GB -> %d, want unbounded (-1)", spec.MPA.OpportunisticBytes)
	}
	if spec.MPA.MaxNumObjects != 42 || spec.MPA.CreationTime != 1000 || spec.MPA.DeletionTime != 3000 {
		t.Errorf("counts/times not mapped: %+v", spec.MPA)
	}
	if len(spec.Paths) != 1 || spec.Paths[0].Path != "/atlas" || !spec.Paths[0].Recursive {
		t.Errorf("paths not mapped: %+v", spec.Paths)
	}
	ra, ok := spec.ParentAttributions["root"]
	if !ok || ra.DedicatedBytes == nil || *ra.DedicatedBytes != 1_110_000_000 {
		t.Errorf("attribution not mapped: %+v", spec.ParentAttributions)
	}
}

func TestMpaToCoreDefaults(t *testing.T) {
	// A nil MPA maps to a zero-storage, unbounded-objects, non-expiring MPA.
	m := mpaToCore(nil)
	if m.DedicatedBytes != 0 || m.OpportunisticBytes != 0 || m.MaxNumObjects != core.Unbounded {
		t.Errorf("nil MPA defaults wrong: %+v", m)
	}
	if !core.IsNonExpiring(m.CreationTime, m.ExpirationTime, m.DeletionTime) {
		t.Errorf("nil MPA should be non-expiring: %+v", m)
	}
}

func TestSplitStorage(t *testing.T) {
	cases := []struct {
		used, ded, opp   int64
		wantDed, wantOpp int64
	}{
		{used: 30, ded: 100, opp: 50, wantDed: 30, wantOpp: 0},     // within dedicated
		{used: 120, ded: 100, opp: 50, wantDed: 100, wantOpp: 20},  // spills into opp
		{used: 200, ded: 100, opp: 50, wantDed: 100, wantOpp: 50},  // opp capped
		{used: 200, ded: 100, opp: -1, wantDed: 100, wantOpp: 100}, // unbounded opp
		{used: 200, ded: -1, opp: -1, wantDed: 200, wantOpp: 0},    // unbounded dedicated
	}
	for _, c := range cases {
		ded, opp := splitStorage(c.used, c.ded, c.opp)
		if ded != c.wantDed || opp != c.wantOpp {
			t.Errorf("splitStorage(%d,%d,%d) = (%d,%d), want (%d,%d)", c.used, c.ded, c.opp, ded, opp, c.wantDed, c.wantOpp)
		}
	}
}

func TestCapacityToAdapterUnbounded(t *testing.T) {
	avail := int64(40_000_000_000) // 40 GB
	c := &core.AvailableCapacity{
		AvailableDedicatedBytes:     &avail,
		AvailableOpportunisticBytes: nil, // unbounded
		PeakDedicatedBytes:          60_000_000_000,
		PeakMaxNumObjects:           7,
	}
	ac := capacityToAdapter(c)
	if ac.AvailableDedicatedGB != 40 {
		t.Errorf("available dedicated = %v, want 40", ac.AvailableDedicatedGB)
	}
	if ac.AvailableOpportunisticGB != 0 {
		t.Errorf("unbounded available opportunistic should map to 0, got %v", ac.AvailableOpportunisticGB)
	}
	if ac.PeakDedicatedGB != 60 || ac.PeakMaxNumObjects != 7 {
		t.Errorf("peaks not mapped: %+v", ac)
	}
}

func TestManagerHolder(t *testing.T) {
	setManager(nil)
	if getManager() != nil {
		t.Fatal("expected nil manager initially")
	}
	db := newAdapterTestDB(t)
	m, err := core.New(db, core.Options{StrictHierarchy: true, Logger: coreLogger{}})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	setManager(m)
	if getManager() != m {
		t.Fatal("manager not stored")
	}
	setManager(nil)
}
