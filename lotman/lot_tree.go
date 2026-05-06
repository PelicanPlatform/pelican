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

// Nested-namespace lot tree construction and quota allocation. The
// data-plane in this file is intentionally pure: no lotman C calls are
// made here, so it can be unit-tested without dlopen'ing libLotMan.so.
//
// The pipeline is:
//
//	buildLotTree            — derive parent/child structure from nsAds by
//	                          path-prefix containment.
//	allocateQuotas          — walk the tree assigning per-axis MPAs and
//	                          parent_attributions following the recursive
//	                          (N+1) rule.
//	flattenTreeForCreation  — pre-order DFS into a []Lot, the order the
//	                          downstream lotman_add_lot calls require.
//
// # The (N+1) quota-allocation rule
//
// Each quota axis (dedicated_GB, opportunistic_GB, max_num_objects) is
// subdivided independently according to where in the tree a lot lives.
//
// Top-level lots (direct children of the synthetic root lot) split the
// root's budget equally among themselves, with no reserve left at root:
//
//	each top-level child = root_quota / N
//
// Example: root has 120 GB, three top-level namespaces → each gets 40 GB.
//
// At every deeper level the divisor increases by one — the parent keeps
// one share as its own unallocated reserve, and each of its N children
// receives one share:
//
//	each child = parent_quota / (N + 1)
//	parent reserve = parent_quota / (N + 1)   [one share retained]
//
// Example: /a has 40 GB and two children /a/x and /a/y.
//   Divisor = 2+1 = 3; each child gets 40/3 ≈ 13.3 GB; /a retains ≈ 13.3 GB.
//
// The reserve has two purposes:
//   1. It ensures the sum of all child attributions never exceeds the
//      parent's own quota (lotman's axiom 1 is satisfied with strict slack).
//   2. It gives an existing parent headroom to accept a future reservation
//      without forcing a global reallocation of the entire subtree.
//
// Sentinel values are never divided:
//   - -1 means "unbounded" (lotman PR #46); it propagates verbatim to all
//     descendants. Today, opportunistic_GB and max_num_objects are always
//     -1 because the root carries -1 on both axes.
//   - 0 means "zero capacity" (literal zero, not a sentinel for unbounded).
//     It also propagates verbatim.
//
// Each child's ParentAttributions[parentName] is set equal to the child's
// own computed value on every axis. This is the minimal attribution that
// satisfies lotman's axiom 1 (Σ child attributions ≤ parent quota), and
// it matches what the renewal scheduler (PR-5/PR-6) will re-derive from a
// fresh tree on each tick.

package lotman

import (
	"sort"
	"strings"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// lotTreeNode mirrors the planned parent/child structure of the cache's
// lot graph. A non-root node's lot already has Parents and (after
// allocateQuotas) ParentAttributions populated for its single tree
// parent.
type lotTreeNode struct {
	lot      Lot
	children []*lotTreeNode
}

// normaliseLotPath strips trailing slashes (other than for the bare "/"
// root path) so that path-prefix containment checks behave consistently
// regardless of whether the source ad uses /foo or /foo/.
func normaliseLotPath(p string) string {
	if p == "/" {
		return p
	}
	return strings.TrimRight(p, "/")
}

// pathContains reports whether `parent` is a strict ancestor of `child`
// in the namespace path tree. Paths are assumed normalised. The "/" path
// is the ancestor of every absolute path. Otherwise we require an exact
// segment boundary so that /foo is NOT considered an ancestor of /foobar.
func pathContains(parent, child string) bool {
	if parent == child {
		return false
	}
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return strings.HasPrefix(child, parent+"/")
}

// buildLotTree produces a tree rooted at `rootLot` whose descendants are
// derived from `nsAds` using path-prefix containment. Namespaces whose
// path is the prefix of another namespace's path become its parent;
// namespaces with no covering namespace ad attach directly to root.
//
// federationIssuer is used as the lot owner when an ad declares no
// issuer of its own. Monitoring-namespace ads are skipped.
//
// The default lot is NOT inserted into this tree: its zero-quota
// semantics would cause allocateQuotas to spread zero across the
// entire namespace fleet. It continues to exist as a self-parented
// sibling created by initLots.
func buildLotTree(rootLot Lot, nsAds []server_structs.NamespaceAdV2, federationIssuer string) *lotTreeNode {
	root := &lotTreeNode{lot: rootLot}

	// Collect candidate namespace nodes, normalised + de-duplicated.
	type nsNode struct {
		path   string
		issuer string
	}
	seen := map[string]nsNode{}
	for _, ad := range nsAds {
		if strings.HasPrefix(ad.Path, server_utils.MonitoringBaseNs) {
			continue
		}
		path := normaliseLotPath(ad.Path)
		if path == "" || path == "/" {
			// "/" would shadow the synthetic root lot; skip.
			continue
		}
		issuer := federationIssuer
		if len(ad.Issuer) > 0 {
			issuer = ad.Issuer[0].IssuerUrl.String()
		}
		// First write wins; subsequent ads for the same path are ignored.
		if _, exists := seen[path]; !exists {
			seen[path] = nsNode{path: path, issuer: issuer}
		}
	}

	// Sort ascending by path length so a parent is always visited before
	// any of its descendants, ensuring `attachUnder` finds the deepest
	// existing ancestor.
	ordered := make([]nsNode, 0, len(seen))
	for _, n := range seen {
		ordered = append(ordered, n)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].path) != len(ordered[j].path) {
			return len(ordered[i].path) < len(ordered[j].path)
		}
		return ordered[i].path < ordered[j].path
	})

	// Pointer index from path to inserted node to make the deepest-
	// ancestor search O(N*depth) rather than O(N^2) traversal.
	byPath := map[string]*lotTreeNode{}

	for _, ns := range ordered {
		// Find the deepest already-inserted node whose path is an
		// ancestor of ns.path. Default to root.
		var parent *lotTreeNode = root
		parentPathLen := 0
		for p, node := range byPath {
			if pathContains(p, ns.path) && len(p) > parentPathLen {
				parent = node
				parentPathLen = len(p)
			}
		}

		node := &lotTreeNode{
			lot: Lot{
				LotName: ns.path,
				Owner:   ns.issuer,
				Parents: []string{parent.lot.LotName},
				Paths: []LotPath{{
					Path:      ns.path,
					Recursive: true,
				}},
			},
		}
		parent.children = append(parent.children, node)
		byPath[ns.path] = node
	}

	return root
}

// splitFinite reports whether the per-axis value `v` is finite/positive
// and therefore subject to numeric subdivision. Sentinels (`-1`
// unbounded and `0` zero-capacity) are propagated verbatim to children.
func splitFinite(v float64) bool { return v > 0 }
func splitFiniteI(v int64) bool  { return v > 0 }

// allocateQuotas applies the recursive (N+1) rule on every axis:
//
//   - Root's direct children each receive root_axis / N (no reserve at
//     the top level — the entire pool is split among the top-level
//     namespaces).
//   - At every deeper level, each child receives parent_axis / (N+1),
//     leaving an equal share unallocated as the parent's reserve.
//
// Sentinel values (-1 unbounded, 0 zero-capacity) are not divided;
// children inherit them verbatim. ParentAttributions for each axis are
// set equal to the child's own value on that axis, which trivially
// satisfies axiom 1 (sum-of-attributions ≤ parent quota).
func allocateQuotas(root *lotTreeNode) {
	if root == nil || root.lot.MPA == nil {
		return
	}

	// Top-level children share root's pool by N (not N+1).
	if len(root.children) > 0 {
		distribute(root, len(root.children), root.lot.MPA, false)
		for _, c := range root.children {
			distributeRecursive(c)
		}
	}
}

// distributeRecursive applies the deeper-level (N+1) rule to a node and
// recurses into its children. Called only for non-root nodes whose own
// MPA has already been set by their parent.
func distributeRecursive(node *lotTreeNode) {
	if node == nil || node.lot.MPA == nil || len(node.children) == 0 {
		return
	}
	distribute(node, len(node.children)+1, node.lot.MPA, true)
	for _, c := range node.children {
		distributeRecursive(c)
	}
}

// distribute writes child MPAs and parent_attributions for one level of
// the tree. `divisor` is N at the top level and N+1 at deeper levels.
// `isDeeper` controls only diagnostic semantics today (kept to make the
// distinction explicit at call sites).
func distribute(parent *lotTreeNode, divisor int, parentMPA *MPA, isDeeper bool) {
	_ = isDeeper
	if divisor <= 0 || parentMPA == nil {
		return
	}
	dDed := splitAxisFloat(parentMPA.DedicatedGB, divisor)
	dOpp := splitAxisFloat(parentMPA.OpportunisticGB, divisor)
	dObj := splitAxisInt(parentMPA.MaxNumObjects, divisor)

	for _, child := range parent.children {
		ded := dDed
		opp := dOpp
		obj := dObj
		// Dereference to fresh storage so each child carries its own pointers
		// (the *float64 / *Int64FromFloat fields are stored by reference and
		// later mutation must not bleed across siblings).
		var dedPtr *float64
		if ded != nil {
			v := *ded
			dedPtr = &v
		}
		var oppPtr *float64
		if opp != nil {
			v := *opp
			oppPtr = &v
		}
		var objPtr *Int64FromFloat
		if obj != nil {
			v := *obj
			objPtr = &v
		}
		child.lot.MPA = &MPA{
			DedicatedGB:     dedPtr,
			OpportunisticGB: oppPtr,
			MaxNumObjects:   objPtr,
		}
		// Parent attribution mirrors the child's own per-axis value;
		// summed across siblings this is N*(parent/divisor) which is
		// either == parent (top level, divisor=N) or < parent (deeper,
		// divisor=N+1) — both satisfy axiom 1.
		var attDed *float64
		if dedPtr != nil {
			v := *dedPtr
			attDed = &v
		}
		var attOpp *float64
		if oppPtr != nil {
			v := *oppPtr
			attOpp = &v
		}
		var attObj *Int64FromFloat
		if objPtr != nil {
			v := *objPtr
			attObj = &v
		}
		child.lot.ParentAttributions = map[string]ParentAttribution{
			parent.lot.LotName: {
				DedicatedGB:     attDed,
				OpportunisticGB: attOpp,
				MaxNumObjects:   attObj,
			},
		}
	}
}

// splitAxisFloat returns the per-child value for a single float axis.
// Returns nil if the parent value is nil. Sentinels (-1, 0) propagate
// verbatim — never divided.
func splitAxisFloat(parentVal *float64, divisor int) *float64 {
	if parentVal == nil {
		return nil
	}
	if !splitFinite(*parentVal) {
		v := *parentVal
		return &v
	}
	v := *parentVal / float64(divisor)
	return &v
}

// splitAxisInt is the int64 analogue of splitAxisFloat. Sentinels (-1, 0)
// propagate verbatim. Integer division floors, so the leftover is left
// unattributed (acceptable since the purge plugin doesn't yet use
// max_num_objects strictly).
func splitAxisInt(parentVal *Int64FromFloat, divisor int) *Int64FromFloat {
	if parentVal == nil {
		return nil
	}
	if !splitFiniteI(parentVal.Value) {
		v := *parentVal
		return &v
	}
	return &Int64FromFloat{Value: parentVal.Value / int64(divisor)}
}

// flattenTreeForCreation returns the lots in pre-order DFS so each parent
// appears before any of its children — the order required by
// lotman_add_lot. The root lot itself IS included; callers that already
// hold a synthesised root lot in their lot map should de-duplicate by
// LotName.
func flattenTreeForCreation(root *lotTreeNode) []Lot {
	if root == nil {
		return nil
	}
	out := make([]Lot, 0)
	var walk func(n *lotTreeNode)
	walk = func(n *lotTreeNode) {
		out = append(out, n.lot)
		// Stable child ordering helps tests and reproducible logs.
		sort.Slice(n.children, func(i, j int) bool {
			return n.children[i].lot.LotName < n.children[j].lot.LotName
		})
		for _, c := range n.children {
			walk(c)
		}
	}
	walk(root)
	return out
}
