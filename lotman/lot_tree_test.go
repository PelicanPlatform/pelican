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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

// makeAds is a tiny helper that turns a list of namespace paths into
// NamespaceAd values with a single shared issuer. Tree shape only
// depends on path containment, not on issuer identity, so the issuer
// is constant for these table tests.
func makeAds(paths ...string) []server_structs.NamespaceAd {
	issuerURL, _ := url.Parse("https://issuer.example/")
	out := make([]server_structs.NamespaceAd, 0, len(paths))
	for _, p := range paths {
		out = append(out, server_structs.NamespaceAd{
			Path: p,
			Issuer: []server_structs.TokenIssuer{
				{IssuerUrl: *issuerURL},
			},
		})
	}
	return out
}

// rootSeed builds the synthetic "root" lot used to seed buildLotTree in
// these unit tests. Quotas mirror what initLots installs in production:
// dedicated_GB derived from the cache disk total, opportunistic_GB and
// max_num_objects unbounded (-1 sentinel from lotman PR #46).
func rootSeed(dedGB float64) Lot {
	ded := dedGB
	opp := float64(-1)
	obj := Int64FromFloat{Value: -1}
	return Lot{
		LotName: "root",
		MPA: &MPA{
			DedicatedGB:     &ded,
			OpportunisticGB: &opp,
			MaxNumObjects:   &obj,
		},
	}
}

// childByPath looks up a tree node by its first declared namespace path.
// This is the canonical lookup for namespace lots since their LotName is
// a UUID. Returns nil if no node has nsPath in its paths[].
func childByPath(root *lotTreeNode, nsPath string) *lotTreeNode {
	return findLotNodeByPath(root, nsPath)
}

// parentNameMatches returns true when the supplied parent-name (recorded
// in node.lot.Parents[0]) refers to either the literal "root" lot, or to
// the lot returned by childByPath(root, expected). This indirection is
// required because non-root namespace lots now have UUID names.
func parentNameMatches(root *lotTreeNode, parentName, expected string) bool {
	if expected == "root" {
		return parentName == "root"
	}
	node := childByPath(root, expected)
	if node == nil {
		return false
	}
	return node.lot.LotName == parentName
}

func TestPathContains(t *testing.T) {
	cases := []struct {
		parent, child string
		want          bool
	}{
		{"/foo", "/foo/bar", true},
		{"/foo", "/foobar", false}, // segment-boundary check
		{"/foo", "/foo", false},    // strict ancestor
		{"/", "/anything", true},   // root contains everything
		{"/foo/bar", "/foo/bar/baz", true},
		{"/foo/bar", "/foo/bar2", false},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, pathContains(c.parent, c.child),
			"pathContains(%q,%q)", c.parent, c.child)
	}
}

func TestBuildLotTree_PathContainment(t *testing.T) {
	cases := []struct {
		name         string
		paths        []string
		expectParent map[string]string // childPath -> expected parent name
	}{
		{
			name:  "single namespace attaches to root",
			paths: []string{"/foo"},
			expectParent: map[string]string{
				"/foo": "root",
			},
		},
		{
			name:  "two siblings both attach to root",
			paths: []string{"/foo", "/bar"},
			expectParent: map[string]string{
				"/foo": "root",
				"/bar": "root",
			},
		},
		{
			name:  "nested child attaches to immediate namespace ancestor",
			paths: []string{"/foo", "/foo/bar"},
			expectParent: map[string]string{
				"/foo":     "root",
				"/foo/bar": "/foo",
			},
		},
		{
			name:  "three-deep nesting",
			paths: []string{"/a", "/a/b", "/a/b/c"},
			expectParent: map[string]string{
				"/a":     "root",
				"/a/b":   "/a",
				"/a/b/c": "/a/b",
			},
		},
		{
			name:  "siblings without shared namespace ancestor attach to root",
			paths: []string{"/a/b", "/a/c"},
			expectParent: map[string]string{
				"/a/b": "root",
				"/a/c": "root",
			},
		},
		{
			name:  "trailing slashes are normalised",
			paths: []string{"/foo/", "/foo/bar/"},
			expectParent: map[string]string{
				"/foo":     "root",
				"/foo/bar": "/foo",
			},
		},
		{
			name:  "monitoring namespaces are skipped",
			paths: []string{"/foo", "/pelican/monitoring/probe"},
			expectParent: map[string]string{
				"/foo": "root",
				// /pelican/monitoring/probe is intentionally absent.
			},
		},
		{
			name:  "/foo is not parent of /foobar",
			paths: []string{"/foo", "/foobar"},
			expectParent: map[string]string{
				"/foo":    "root",
				"/foobar": "root",
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tree := buildLotTree(rootSeed(100), makeAds(c.paths...), "https://fed.example/")
			require.NotNil(t, tree)
			for childPath, parentName := range c.expectParent {
				node := childByPath(tree, childPath)
				require.NotNilf(t, node, "expected node for path %q to exist", childPath)
				require.Lenf(t, node.lot.Parents, 1, "node %q should have exactly one parent", childPath)
				assert.Truef(t, parentNameMatches(tree, node.lot.Parents[0], parentName),
					"node %q parent mismatch: got %q, expected lot at path %q",
					childPath, node.lot.Parents[0], parentName)
			}
			// Negative: monitoring path should never appear in tree.
			for _, p := range c.paths {
				if p == "/pelican/monitoring/probe" {
					assert.Nil(t, childByPath(tree, "/pelican/monitoring/probe"))
				}
			}
		})
	}
}

func TestAllocateQuotas_TopLevel(t *testing.T) {
	// 6 GB root + 2 top-level children -> each child gets 3 GB.
	tree := buildLotTree(rootSeed(6), makeAds("/foo", "/bar"), "https://fed.example/")
	allocateQuotas(tree)

	foo := childByPath(tree, "/foo")
	bar := childByPath(tree, "/bar")
	require.NotNil(t, foo)
	require.NotNil(t, bar)
	assert.InDelta(t, 3.0, *foo.lot.MPA.DedicatedGB, 1e-9)
	assert.InDelta(t, 3.0, *bar.lot.MPA.DedicatedGB, 1e-9)

	// ParentAttribution to root for each child equals child's own value.
	require.Contains(t, foo.lot.ParentAttributions, "root")
	assert.InDelta(t, 3.0, *foo.lot.ParentAttributions["root"].DedicatedGB, 1e-9)
	require.Contains(t, bar.lot.ParentAttributions, "root")
	assert.InDelta(t, 3.0, *bar.lot.ParentAttributions["root"].DedicatedGB, 1e-9)

	// Sentinel axes propagate verbatim (root.opportunistic = -1 -> child = -1).
	assert.Equal(t, float64(-1), *foo.lot.MPA.OpportunisticGB)
	assert.Equal(t, int64(-1), foo.lot.MPA.MaxNumObjects.Value)
	assert.Equal(t, float64(-1), *foo.lot.ParentAttributions["root"].OpportunisticGB)
	assert.Equal(t, int64(-1), foo.lot.ParentAttributions["root"].MaxNumObjects.Value)
}

func TestAllocateQuotas_NPlusOneRule(t *testing.T) {
	// 3 GB at /foo with /foo/bar + /foo/baz -> /foo gets 3, each grandchild gets 1.
	// Construction: root (9 GB) + /foo only at top level -> /foo gets 9 GB.
	// Then add the two grandchildren and override /foo's quota to 3 to mirror
	// the spec example exactly.
	tree := buildLotTree(rootSeed(9),
		makeAds("/foo", "/foo/bar", "/foo/baz"), "https://fed.example/")
	allocateQuotas(tree)

	foo := childByPath(tree, "/foo")
	bar := childByPath(tree, "/foo/bar")
	baz := childByPath(tree, "/foo/baz")
	require.NotNil(t, foo)
	require.NotNil(t, bar)
	require.NotNil(t, baz)

	// Top-level: root has 9 GB, 1 child -> /foo gets 9 GB.
	assert.InDelta(t, 9.0, *foo.lot.MPA.DedicatedGB, 1e-9)

	// Deeper level: /foo has 9 GB, 2 children, divisor = N+1 = 3.
	// Each grandchild gets 9/3 = 3 GB; /foo retains 3 GB as its own reserve.
	assert.InDelta(t, 3.0, *bar.lot.MPA.DedicatedGB, 1e-9)
	assert.InDelta(t, 3.0, *baz.lot.MPA.DedicatedGB, 1e-9)

	// Sum of grandchildren's attribution to /foo = 6 < 9 (axiom 1 satisfied
	// with room to spare, which is the (N+1) rule's purpose).
	require.Contains(t, bar.lot.ParentAttributions, foo.lot.LotName)
	require.Contains(t, baz.lot.ParentAttributions, foo.lot.LotName)
	assert.InDelta(t, 3.0, *bar.lot.ParentAttributions[foo.lot.LotName].DedicatedGB, 1e-9)
	assert.InDelta(t, 3.0, *baz.lot.ParentAttributions[foo.lot.LotName].DedicatedGB, 1e-9)
}

func TestAllocateQuotas_AxiomOneSatisfied(t *testing.T) {
	// Verify across a more elaborate tree that for every parent, the sum of
	// its children's attributed dedicated_GB never exceeds the parent's own
	// dedicated_GB. This is the structural invariant strict_hierarchy
	// enforces in lotman.
	tree := buildLotTree(rootSeed(120),
		makeAds(
			"/a", "/b", "/c",
			"/a/x", "/a/y",
			"/a/x/i", "/a/x/j", "/a/x/k",
		),
		"https://fed.example/")
	allocateQuotas(tree)

	var walk func(*lotTreeNode)
	walk = func(n *lotTreeNode) {
		if n == nil || n.lot.MPA == nil {
			return
		}
		var sum float64
		for _, c := range n.children {
			require.NotNilf(t, c.lot.ParentAttributions, "child %q must have attributions", c.lot.LotName)
			att, ok := c.lot.ParentAttributions[n.lot.LotName]
			require.Truef(t, ok, "child %q must attribute to parent %q", c.lot.LotName, n.lot.LotName)
			require.NotNil(t, att.DedicatedGB)
			sum += *att.DedicatedGB
		}
		require.NotNil(t, n.lot.MPA.DedicatedGB)
		assert.LessOrEqualf(t, sum, *n.lot.MPA.DedicatedGB+1e-9,
			"axiom 1 violated at %q: sum of child attributions %f > parent %f",
			n.lot.LotName, sum, *n.lot.MPA.DedicatedGB)
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(tree)
}

func TestFlattenTreeForCreation_PreOrder(t *testing.T) {
	tree := buildLotTree(rootSeed(120),
		makeAds("/a", "/a/b", "/a/b/c", "/d"), "https://fed.example/")
	allocateQuotas(tree)
	flat := flattenTreeForCreation(tree)

	// Build a path -> position map (lot names are now UUIDs, so we key on
	// the namespace path stored in paths[0].Path). Root has no path entries
	// and keeps its literal name. Assert every parent precedes its children.
	pos := map[string]int{}
	for i, lot := range flat {
		key := lot.LotName
		if len(lot.Paths) > 0 {
			key = lot.Paths[0].Path
		}
		pos[key] = i
	}
	require.Contains(t, pos, "root")
	require.Contains(t, pos, "/a")
	require.Contains(t, pos, "/a/b")
	require.Contains(t, pos, "/a/b/c")
	require.Contains(t, pos, "/d")
	assert.Less(t, pos["root"], pos["/a"])
	assert.Less(t, pos["/a"], pos["/a/b"])
	assert.Less(t, pos["/a/b"], pos["/a/b/c"])
	assert.Less(t, pos["root"], pos["/d"])
}
