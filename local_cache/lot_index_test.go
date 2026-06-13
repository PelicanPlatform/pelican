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
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/lotman/core"
)

func TestLotIndexResolve(t *testing.T) {
	li := newLotIndex()
	li.setEntries([]lotPathEntry{
		{lotName: "root", path: "/", recursive: false},
		{lotName: "ns", path: "/atlas", recursive: true},
		{lotName: "sub", path: "/atlas/data", recursive: false},
		{lotName: "L", path: "/foo", recursive: true},
		{lotName: "L", path: "/foo/private", recursive: true, exclude: true},
	})

	cases := map[string]string{
		"/atlas/data/file":    "ns",      // sub is non-recursive: exact-only
		"/atlas/data":         "sub",     // exact match
		"/atlas/x":            "ns",      // recursive
		"/foo/data/x":         "L",       // recursive
		"/foo/private/secret": "default", // carved out by exclusion
		"/cms/file":           "default", // root is non-recursive: exact-only
		"/":                   "root",    // exact match on "/"
	}
	for objectPath, want := range cases {
		if got := li.Resolve(objectPath); got != want {
			t.Errorf("Resolve(%q) = %q, want %q", objectPath, got, want)
		}
	}
}

func TestFederationQualifiedKey(t *testing.T) {
	cases := []struct {
		pelicanURL string
		defaultFed string
		want       string
	}{
		{"pelican://osg-htc.org/atlas/file", "primary.org", "/osg-htc.org/atlas/file"},
		{"pelican://other-fed.org/atlas/file", "primary.org", "/other-fed.org/atlas/file"},
		{"pelican://osg-htc.org:8443/cms/x", "primary.org", "/osg-htc.org:8443/cms/x"},
		{"/atlas/file", "primary.org", "/primary.org/atlas/file"}, // host-less -> default fed
	}
	for _, c := range cases {
		if got := federationQualifiedKey(c.pelicanURL, c.defaultFed); got != c.want {
			t.Errorf("federationQualifiedKey(%q, %q) = %q, want %q", c.pelicanURL, c.defaultFed, got, c.want)
		}
	}
}

func TestLotIDOf(t *testing.T) {
	// No lot index configured: lot tracking disabled -> LotID 0 regardless of bucket.
	pc := &PersistentCache{}
	if id := pc.lotIDOf(5); id != 0 {
		t.Errorf("nil lotIndex should yield LotID 0, got %d", id)
	}
	// With lot tracking on, the accounting bucket id is the lot id.
	pc.lotIndex = newLotIndex()
	if id := pc.lotIDOf(5); id != LotID(5) {
		t.Errorf("lotIDOf(5) = %d, want 5", id)
	}
}

func TestLotIndexFederationIsolation(t *testing.T) {
	li := newLotIndex()
	// Two federations each have an /atlas namespace; lots are federation-qualified.
	li.setEntries([]lotPathEntry{
		{lotName: "fedA-atlas", path: "/fedA.org/atlas", recursive: true},
		{lotName: "fedB-atlas", path: "/fedB.org/atlas", recursive: true},
	})

	keyA := federationQualifiedKey("pelican://fedA.org/atlas/data/x", "fedA.org")
	keyB := federationQualifiedKey("pelican://fedB.org/atlas/data/y", "fedA.org")

	if name := li.Resolve(keyA); name != "fedA-atlas" {
		t.Errorf("fedA object -> %q, want fedA-atlas", name)
	}
	if name := li.Resolve(keyB); name != "fedB-atlas" {
		t.Errorf("fedB object -> %q, want fedB-atlas (must NOT collapse into fedA)", name)
	}
}

// newCoreTestManager opens a temp-file SQLite core manager for integration tests.
func newCoreTestManager(t *testing.T) *core.Manager {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "lot.sqlite")
	db, err := gorm.Open(sqlite.Open(dbPath+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open core db: %v", err)
	}
	m, err := core.New(db, core.Options{StrictHierarchy: true})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	if err := m.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return m
}

func TestLotIndexFromManager(t *testing.T) {
	m := newCoreTestManager(t)
	mpa := func(ded int64) core.MPA {
		return core.MPA{DedicatedBytes: ded, OpportunisticBytes: -1, MaxNumObjects: -1}
	}
	mustAdd := func(s core.LotSpec) {
		if err := m.AddLot(s, ""); err != nil {
			t.Fatalf("add %s: %v", s.LotName, err)
		}
	}
	mustAdd(core.LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []core.PathSpec{{Path: "/", Recursive: false}}, MPA: mpa(100)})
	mustAdd(core.LotSpec{LotName: "ns", Owner: "fed", Parents: []string{"root"},
		Paths: []core.PathSpec{{Path: "/atlas", Recursive: true}}, MPA: mpa(50)})
	mustAdd(core.LotSpec{LotName: "sub", Owner: "fed", Parents: []string{"ns"},
		Paths: []core.PathSpec{{Path: "/atlas/data", Recursive: false}}, MPA: mpa(10)})

	li := newLotIndex()
	if err := li.rebuildFromManager(m); err != nil {
		t.Fatalf("rebuild: %v", err)
	}

	if name := li.Resolve("/atlas/raw/x"); name != "ns" {
		t.Errorf("/atlas/raw/x -> %q, want ns", name)
	}
	if name := li.Resolve("/atlas/data"); name != "sub" {
		t.Errorf("/atlas/data -> %q, want sub", name)
	}
	if name := li.Resolve("/cms/y"); name != "default" {
		t.Errorf("/cms/y -> %q, want default", name)
	}
}
