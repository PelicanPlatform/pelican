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

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":            "/",
		"/":           "/",
		"/foo/":       "/foo",
		"foo":         "/foo",
		"/foo//bar/":  "/foo/bar",
		"/foo/./bar":  "/foo/bar",
		"/foo/../bar": "/bar",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAncestorPrefixesInclusive(t *testing.T) {
	got := ancestorPrefixesInclusive("/a/b/c")
	want := []string{"/", "/a", "/a/b", "/a/b/c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if root := ancestorPrefixesInclusive("/"); len(root) != 1 || root[0] != "/" {
		t.Errorf("root prefixes = %v", root)
	}
}

// seedResolutionTree builds:
//
//	root (/, non-recursive)
//	 └── ns  (/atlas, recursive)
//	      └── sub (/atlas/data, non-recursive)
//
// all owned by "fed", non-expiring.
func seedResolutionTree(t *testing.T) *Manager {
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
	mustAdd(LotSpec{LotName: "sub", Owner: "fed", Parents: []string{"ns"},
		Paths: []PathSpec{{Path: "/atlas/data", Recursive: false}}, MPA: nonExpiringMPA(10, -1, -1)})
	return m
}

func resolve(t *testing.T, m *Manager, dir string) string {
	t.Helper()
	lots, err := m.LotsFromDir(dir, false, 1000)
	if err != nil {
		t.Fatalf("LotsFromDir(%q): %v", dir, err)
	}
	if len(lots) != 1 {
		t.Fatalf("LotsFromDir(%q) returned %v, want single lot", dir, lots)
	}
	return lots[0]
}

func TestLotsFromDirLongestPrefix(t *testing.T) {
	m := seedResolutionTree(t)

	// A non-recursive path matches ONLY its exact path (faithful to the C++
	// rule "p.recursive OR p.path = dir"). So children of /atlas/data do not
	// resolve to sub; they fall to the recursive ns lot.
	if got := resolve(t, m, "/atlas/data/file.root"); got != "ns" {
		t.Errorf("/atlas/data/file.root -> %q, want ns (sub is non-recursive, exact-only)", got)
	}
	if got := resolve(t, m, "/atlas/data/x/y.root"); got != "ns" {
		t.Errorf("/atlas/data/x/y.root -> %q, want ns", got)
	}
	// Elsewhere under /atlas -> ns (recursive).
	if got := resolve(t, m, "/atlas/raw/z.root"); got != "ns" {
		t.Errorf("/atlas/raw/z.root -> %q, want ns", got)
	}
	// Exact /atlas/data -> sub (the only thing a non-recursive path owns).
	if got := resolve(t, m, "/atlas/data"); got != "sub" {
		t.Errorf("/atlas/data -> %q, want sub", got)
	}
	// Outside any namespace -> default (root "/" is non-recursive, exact-only).
	if got := resolve(t, m, "/cms/file"); got != "default" {
		t.Errorf("/cms/file -> %q, want default", got)
	}
}

func TestLotsFromDirRecursiveParents(t *testing.T) {
	m := seedResolutionTree(t)
	// Query the exact non-recursive path so sub is the owner; recursive=true
	// then appends its ancestors.
	lots, err := m.LotsFromDir("/atlas/data", true, 1000)
	if err != nil {
		t.Fatalf("LotsFromDir recursive: %v", err)
	}
	// Owning lot first, then ancestors.
	if len(lots) == 0 || lots[0] != "sub" {
		t.Fatalf("expected owner sub first, got %v", lots)
	}
	rest := append([]string{}, lots[1:]...)
	sort.Strings(rest)
	if len(rest) != 2 || rest[0] != "ns" || rest[1] != "root" {
		t.Errorf("expected ancestors [ns root], got %v", rest)
	}
}

func TestLotsFromDirExcludeCarvesHole(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}}, MPA: nonExpiringMPA(100, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Lot owns /foo recursively but excludes /foo/private recursively.
	if err := m.AddLot(LotSpec{LotName: "L", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{
			{Path: "/foo", Recursive: true},
			{Path: "/foo/private", Recursive: true, Exclude: true},
		}, MPA: nonExpiringMPA(50, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	if got := resolve(t, m, "/foo/data/x"); got != "L" {
		t.Errorf("/foo/data/x -> %q, want L", got)
	}
	// Excluded subtree is carved out -> falls to default.
	if got := resolve(t, m, "/foo/private/secret"); got != "default" {
		t.Errorf("/foo/private/secret -> %q, want default (excluded)", got)
	}
}

func TestLotsFromDirActiveWindowAndReclaim(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}}, MPA: nonExpiringMPA(100, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Expiring lot active in [100, 200).
	if err := m.AddLot(LotSpec{LotName: "gen", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/atlas", Recursive: true}},
		MPA:   MPA{DedicatedBytes: 10, OpportunisticBytes: -1, MaxNumObjects: -1, CreationTime: 100, ExpirationTime: 200, DeletionTime: 300}}, ""); err != nil {
		t.Fatal(err)
	}

	// Inside the active window -> gen.
	if lots, _ := m.LotsFromDir("/atlas/x", false, 150); len(lots) != 1 || lots[0] != "gen" {
		t.Errorf("at t=150 -> %v, want [gen]", lots)
	}
	// Outside the active window -> default (non-attribution).
	if lots, _ := m.LotsFromDir("/atlas/x", false, 250); len(lots) != 1 || lots[0] != "default" {
		t.Errorf("at t=250 -> %v, want [default]", lots)
	}
	// Attribution fallback ignores the active window -> gen even at t=250.
	if lots, _ := m.lotsFromDir("/atlas/x", false, 250, true); len(lots) != 1 || lots[0] != "gen" {
		t.Errorf("attribution at t=250 -> %v, want [gen]", lots)
	}
}

func TestLotsForPathWindowUnion(t *testing.T) {
	m := newTestManager(t)
	if err := m.AddLot(LotSpec{LotName: "root", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/", Recursive: false}}, MPA: nonExpiringMPA(100, -1, -1)}, ""); err != nil {
		t.Fatal(err)
	}
	// Two back-to-back generations of /atlas: genA [100,200), genB [200,300).
	if err := m.AddLot(LotSpec{LotName: "genA", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/atlas", Recursive: true}},
		MPA:   MPA{DedicatedBytes: 10, OpportunisticBytes: -1, MaxNumObjects: -1, CreationTime: 100, ExpirationTime: 200, DeletionTime: 400}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.AddLot(LotSpec{LotName: "genB", Owner: "fed", Parents: []string{"root"},
		Paths: []PathSpec{{Path: "/atlas", Recursive: true}},
		MPA:   MPA{DedicatedBytes: 10, OpportunisticBytes: -1, MaxNumObjects: -1, CreationTime: 200, ExpirationTime: 300, DeletionTime: 400}}, ""); err != nil {
		t.Fatal(err)
	}

	// Window spanning both generations returns both.
	lots, err := m.LotsForPath("/atlas/x", false, 150, 250, false)
	if err != nil {
		t.Fatalf("LotsForPath: %v", err)
	}
	sort.Strings(lots)
	if len(lots) != 2 || lots[0] != "genA" || lots[1] != "genB" {
		t.Errorf("expected [genA genB], got %v", lots)
	}

	// Window with an uncovered tail also yields "default".
	lots, err = m.LotsForPath("/atlas/x", false, 150, 350, false)
	if err != nil {
		t.Fatalf("LotsForPath: %v", err)
	}
	hasDefault := false
	for _, l := range lots {
		if l == "default" {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("expected default in %v (gap after t=300)", lots)
	}
}
