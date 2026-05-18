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

// Epoch-aware quota allocation.
//
// Reservations are immutable once created. To honour the system's
// "non-contracting" guarantee, the dedicated_GB stamped on a fresh lot
// must be feasible for the *whole* lifetime of that lot — not merely
// for the moment it is minted. If we stamped a quota based only on the
// path-population at minting time, a new sibling appearing later in the
// lot's lifetime would force an effective contraction (or a violation
// of axiom 1: sum-of-children's-dedicated ≤ parent's-dedicated).
//
// To handle this, the allocator partitions each parent's lifetime into
// "epochs": maximal half-open intervals during which the set of active
// children is constant. The boundaries are the union of every active
// child lot's creation_time and expiration_time within the parent's
// timeline (and the parent's own creation_time / expiration_time as
// outer bounds).
//
//	parent /a       [────────────────────────────────────)
//	child  /a/b          [──────────────)
//	child  /a/c                 [────────────────────)
//	             ┌────┬─────────┬───────┬────────────┬───┐
//	epochs       │ E0 │   E1    │  E2   │     E3     │E4 │   (within parent)
//	active       │    │  /a/b   │ /a/b  │   /a/c     │   │
//	             │    │         │ /a/c  │            │   │
//
// For each epoch, let
//
//	usedExisting_e   = Σ existing_sibling.dedicated_GB active in epoch e
//	residual_e       = parent_dedicated_e − usedExisting_e
//	nActiveNew_e     = number of OTHER planned-this-tick siblings
//	                   whose window covers epoch e
//
// A freshly-minted child's stamped dedicated_GB then equals
//
//	min over epochs the new lot spans of
//	    residual_e / divisor_e
//
// where
//
//	divisor_e = nActiveNew_e + 1                  (top level)
//	divisor_e = nActiveNew_e + 2                  (deeper levels)
//
// The "+1" counts the new lot itself; the extra "+1" at deeper levels
// reserves an equal share for the parent. Existing siblings appear in
// `usedExisting_e` only — never in `divisor_e` — because their bytes
// are already committed and counting them again would strand capacity
// (e.g. root=1000, existing /x at 400, three new top-level paths must
// each receive (1000−400)/3 = 200, NOT (1000−400)/4 = 150).
//
// Choosing the minimum across epochs guarantees axiom 1 holds in every
// epoch the lot lives in.
//
// At the top level the "parent" is the synthetic root lot, whose
// dedicated_GB is the cache's total storage capacity. The divisor rule
// above is the same `N` / `N+1` rule used by `lot_tree.go::distribute`,
// just expressed differently: distribute counts only children
// (`len(children)` at top, `len(children)+1` deeper), whereas the
// epoch allocator counts children plus the new lot itself
// (`nActiveNew+1` at top, `nActiveNew+2` deeper). Both agree on the
// final per-child share.

package lotman

import (
	"math"
	"sort"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

// allocateEpochAwareQuotas stamps dedicated_GB on every lot in
// `prop.newLots` using min-over-epochs feasibility.
//
// max_num_objects and opportunistic_GB are pre-stamped to the
// unbounded sentinel (-1) by renewExpiringLots itself: lotman's
// new_lot_schema requires both fields to be present on every
// CreateLot call, so we cannot leave them nil even though
// pelican+xrootd-lotman does not currently consume either axis. Using
// -1 (unbounded) keeps lots schema-valid without imposing a real cap;
// once the xrootd-lotman purge plugin learns to honour either field,
// the allocator can overwrite these defaults from the same
// min-over-epochs analysis used for dedicated_GB.
//
// `existing` is the set of lots already in the lotman DB at the start
// of this tick. `cfg.RootDedicatedGB` is the total capacity available
// to top-level paths.
//
// The function never reduces a lot's window — only its quotas. If no
// feasible non-zero quota exists for a lot in some epoch, that lot is
// stamped with dedicated_GB=0 (zero-capacity sentinel) and a warning is
// logged. A zero-capacity lot is a valid lotman record; it carries no
// dedicated promise but still defines a paths/owner/window for
// accounting and lets the timeline stay continuous, which lot_tree.go
// relies on for hierarchy invariants. The data attributed to such a
// lot is accounted to the default lot at purge time. Operators may
// alert on the warning above and re-tune quotas; the alternative —
// silently dropping the lot — would create a coverage gap that the
// next tick would just refill.
func allocateEpochAwareQuotas(prop *renewalProposal, existing []Lot, fedAds []server_structs.NamespaceAdV2, cfg renewalConfig) {
	if prop == nil || len(prop.newLots) == 0 {
		return
	}
	_ = fedAds // reserved for future per-namespace overrides; once the
	// director starts populating lot-policy fields on
	// server_structs.NamespaceAdV2, this allocator will read them here
	// to override defaults like the (N+1)/(N+2) divisor or per-NS
	// dedicated/opportunistic ratios.

	// Group new lots by namespace path; later we walk them parent-first
	// so a child sees its parent's already-stamped quotas.
	newByPath := map[string][]*Lot{}
	for i := range prop.newLots {
		l := &prop.newLots[i]
		if len(l.Paths) == 0 {
			continue
		}
		p := normaliseLotPath(l.Paths[0].Path)
		newByPath[p] = append(newByPath[p], l)
	}

	paths := make([]string, 0, len(newByPath))
	for p := range newByPath {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool {
		if len(paths[i]) != len(paths[j]) {
			return len(paths[i]) < len(paths[j])
		}
		return paths[i] < paths[j]
	})

	// `effective` indexes the post-tick view of every namespace path:
	// existing lots ∪ planned successors. Allocator queries about
	// "what does the parent look like at instant t?" go here.
	effective := buildEffectivePathIndex(existing, newByPath)

	for _, p := range paths {
		parentPath := parentNamespacePath(p, existing, newByPath)
		for _, lot := range newByPath[p] {
			ded := computeMinOverEpochsShare(lot, p, parentPath, existing, effective, cfg)
			if ded < 0 {
				// computeMinOverEpochsShare returns -1 when no feasible
				// share exists at all (e.g. parent has no coverage in
				// some epoch). Stamp zero so the lot exists but
				// promises nothing.
				log.Warnf("Lotman allocator: lot %s for %q has no feasible dedicated_GB; stamping 0",
					lot.LotName, p)
				ded = 0
			}
			v := ded
			lot.MPA.DedicatedGB = &v
			// Mirror the share onto parent_attributions so axiom 1 is
			// satisfied at admission. A self-only attribution is fine
			// for top-level lots; deeper lots get an explicit parent
			// attribution under the parent's UUID, but that UUID is
			// resolved in the apply step. For now, leave attributions
			// nil (lotman fills them in via recursive aggregation).
		}
	}
}

// computeMinOverEpochsShare returns the largest dedicated_GB the new
// `lot` can claim while remaining feasible in every epoch its window
// [creation_time, expiration_time) overlaps. Returns -1 when no
// feasible share exists at all (e.g. parent has zero coverage in some
// overlapped epoch).
func computeMinOverEpochsShare(
	lot *Lot,
	path, parentPath string,
	existing []Lot,
	effective map[string][]Lot,
	cfg renewalConfig,
) float64 {
	if lot.MPA == nil || lot.MPA.CreationTime == nil || lot.MPA.ExpirationTime == nil {
		return 0
	}
	lotStart := lot.MPA.CreationTime.Value
	lotEnd := lot.MPA.ExpirationTime.Value
	if lotEnd <= lotStart {
		return 0
	}

	// Index existing lots by lot-name so we can tell, for every entry
	// in `effective`, whether it came from the pre-tick snapshot
	// (already stamped, real bytes promised) or from this tick's
	// freshly-planned proposals (not yet stamped). Real-existing
	// lots' dedicated_GB is subtracted from `residual`; planned peers
	// only contribute to the divisor, so the round naturally divides
	// the parent's free capacity equally even though the for-loop
	// processes each lot one at a time.
	existingNames := map[string]struct{}{}
	for _, l := range existing {
		existingNames[l.LotName] = struct{}{}
	}

	// Determine parent's effective timeline (for capacity at each
	// epoch) and the sibling timelines (the OTHER children sharing
	// this parent who are active in each epoch).
	var (
		parentTimeline []Lot
		isTopLevel     = parentPath == ""
		siblingPaths   []string
	)
	if isTopLevel {
		// Top-level path's parent is the synthetic root lot, whose
		// capacity is constant for all time.
		siblingPaths = topLevelSiblings(path, effective)
	} else {
		parentTimeline = effective[parentPath]
		siblingPaths = childrenOfParent(parentPath, path, effective)
	}

	// Sibling epoch boundaries (creation_time / expiration_time of
	// other lots that share the same parent and overlap [lotStart,
	// lotEnd)). Plus parent's own boundaries.
	cuts := []int64{lotStart, lotEnd}
	for _, s := range siblingPaths {
		for _, sl := range effective[s] {
			if sl.MPA == nil || sl.MPA.CreationTime == nil || sl.MPA.ExpirationTime == nil {
				continue
			}
			c := sl.MPA.CreationTime.Value
			e := sl.MPA.ExpirationTime.Value
			if c < lotStart {
				c = lotStart
			}
			if e > lotEnd {
				e = lotEnd
			}
			if c < e {
				cuts = append(cuts, c, e)
			}
		}
	}
	if !isTopLevel {
		for _, pl := range parentTimeline {
			if pl.MPA == nil || pl.MPA.CreationTime == nil || pl.MPA.ExpirationTime == nil {
				continue
			}
			c := pl.MPA.CreationTime.Value
			e := pl.MPA.ExpirationTime.Value
			if c < lotStart {
				c = lotStart
			}
			if e > lotEnd {
				e = lotEnd
			}
			if c < e {
				cuts = append(cuts, c, e)
			}
		}
	}
	cuts = uniqueSortedInt64(cuts)

	// Iterate adjacent cut pairs; each pair is one epoch [a, b).
	minShare := math.Inf(+1)
	for i := 0; i+1 < len(cuts); i++ {
		a, b := cuts[i], cuts[i+1]
		if a < lotStart {
			a = lotStart
		}
		if b > lotEnd {
			b = lotEnd
		}
		if b <= a {
			continue
		}
		mid := a + (b-a)/2 // representative instant inside [a, b)

		// Parent capacity at mid.
		var parentCap float64
		if isTopLevel {
			parentCap = cfg.RootDedicatedGB
			if parentCap <= 0 {
				// Without a known root capacity we can't compute a
				// non-contracting share. Stamp 0; the operator sees
				// the warning at the call site.
				return 0
			}
		} else {
			seg := parentSegmentAt(parentTimeline, mid)
			if !seg.ok {
				// Parent has no coverage at this instant — should
				// have been excluded by the planner's clamp, but
				// be defensive.
				return -1
			}
			pc, ok := dedicatedAt(parentTimeline, mid)
			if !ok || pc <= 0 {
				return -1
			}
			parentCap = pc
		}

		// Sum of OTHER children's dedicated_GB at mid that come from
		// the existing snapshot (already-promised bytes), and a
		// separate count of how many distinct sibling paths have a
		// PLANNED-this-tick lot active at mid. Existing siblings are
		// excluded from the divisor: their bytes have already been
		// subtracted from `parentCap` via `usedExisting`, so counting
		// them again as a divisor slot would double-count them and
		// leave a chunk of capacity unbookable. (Example: root=1000,
		// existing /x at 400, three new /a /b /c — the residual 600
		// must be split among the 3 newcomers, giving 200 each. Adding
		// /x to the divisor would give 600/4=150 each and leave 150
		// stranded.)
		usedExisting := 0.0
		nActiveNew := 0
		for _, s := range siblingPaths {
			plannedActive := false
			for _, sl := range effective[s] {
				if sl.MPA == nil || sl.MPA.CreationTime == nil || sl.MPA.ExpirationTime == nil {
					continue
				}
				if sl.MPA.CreationTime.Value <= mid && mid < sl.MPA.ExpirationTime.Value {
					if _, isExisting := existingNames[sl.LotName]; isExisting {
						if sl.MPA.DedicatedGB != nil {
							usedExisting += *sl.MPA.DedicatedGB
						}
					} else {
						plannedActive = true
					}
				}
			}
			if plannedActive {
				nActiveNew++
			}
		}
		residual := parentCap - usedExisting
		if residual <= 0 {
			// No room left in this epoch.
			return -1
		}

		// Divisor: at the top level the new lot competes only against
		// other newcomers (no parent reserve), so divisor = N+1 (self).
		// At deeper levels the parent keeps an equal share as a
		// reserve, so divisor = N+2 — matching the rule already
		// enforced by lot_tree.go::distribute (parent.distribute uses
		// len(children) at top, len(children)+1 deeper).
		divisor := nActiveNew + 1 // include this lot itself
		if !isTopLevel {
			divisor++
		}
		if divisor <= 0 {
			continue
		}
		share := residual / float64(divisor)
		if share < minShare {
			minShare = share
		}
	}

	if math.IsInf(minShare, +1) {
		// No epochs were considered (e.g. zero-width lot). Treat as 0.
		return 0
	}
	if minShare < 0 {
		return 0
	}
	return minShare
}

// dedicatedAt returns the dedicated_GB of the lot in `timeline` covering
// `instantMs`, or (0, false) when no lot covers that instant. Lots
// without an explicit dedicated_GB are treated as `parent inheritance`
// for which we conservatively assume 0 contribution to `used`; that may
// under-count usage in mixed populations of stamped + nil-quota lots,
// but the planner stamps explicit values on every renewal so steady
// state has no nil entries.
func dedicatedAt(timeline []Lot, instantMs int64) (float64, bool) {
	for _, l := range timeline {
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		if l.MPA.CreationTime.Value <= instantMs && instantMs < l.MPA.ExpirationTime.Value {
			if l.MPA.DedicatedGB == nil {
				return 0, true
			}
			return *l.MPA.DedicatedGB, true
		}
	}
	return 0, false
}

// buildEffectivePathIndex returns a map[path] -> sorted timeline of
// lots, where each timeline is the union of existing lots whose
// paths[0].Path equals path and any planned successors for that path.
// Used by the allocator to query the post-tick world.
//
// Path-canonicalisation invariant: throughout the renewal scheduler
// (renewal.go, epoch.go), a lot is identified by `paths[0].Path`. This
// matches how Pelican mints lots — a single namespace ad produces a
// single-path lot — and is consistent with `lotsForNamespace` (which
// scans every entry in `paths` for backwards compatibility). Operators
// who hand-create multi-path lots may see those extra paths ignored by
// the allocator; the renewal scheduler currently does not mint
// multi-path lots itself.
func buildEffectivePathIndex(existing []Lot, planned map[string][]*Lot) map[string][]Lot {
	out := map[string][]Lot{}
	for _, l := range existing {
		if len(l.Paths) == 0 {
			continue
		}
		p := normaliseLotPath(l.Paths[0].Path)
		out[p] = append(out[p], l)
	}
	for p, lots := range planned {
		for _, l := range lots {
			if l == nil {
				continue
			}
			out[normaliseLotPath(p)] = append(out[normaliseLotPath(p)], *l)
		}
	}
	for _, lots := range out {
		sort.Slice(lots, func(i, j int) bool {
			ci := int64(0)
			cj := int64(0)
			if lots[i].MPA != nil && lots[i].MPA.CreationTime != nil {
				ci = lots[i].MPA.CreationTime.Value
			}
			if lots[j].MPA != nil && lots[j].MPA.CreationTime != nil {
				cj = lots[j].MPA.CreationTime.Value
			}
			return ci < cj
		})
		// sort.Slice mutates the slice header's underlying array in
		// place; the map entry already points at the sorted backing
		// storage, so no `out[p] = lots` reassignment is needed.
	}
	return out
}

// topLevelSiblings returns every path in `effective` that is at the top
// level (i.e. no other path in `effective` is its strict ancestor),
// excluding `self`. Used by the allocator to know who else is competing
// for root's pool.
func topLevelSiblings(self string, effective map[string][]Lot) []string {
	target := normaliseLotPath(self)
	out := make([]string, 0, len(effective))
	for p := range effective {
		c := normaliseLotPath(p)
		if c == "" || c == target {
			continue
		}
		// Skip synthetic root/default lot entries that may sneak in via
		// the existing snapshot but have no namespace path.
		if c == "/" {
			continue
		}
		isTop := true
		for q := range effective {
			d := normaliseLotPath(q)
			if d == c || d == "" {
				continue
			}
			// The synthetic "/" root lot is the parent pool, not a
			// real namespace ancestor. Treating it as an ancestor
			// here would mark every real path as non-top-level and
			// hide all sibling competition from the allocator.
			if d == "/" {
				continue
			}
			if pathContains(d, c) {
				isTop = false
				break
			}
		}
		if isTop {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// childrenOfParent returns every path in `effective` whose direct
// parent (longest-prefix ancestor present in `effective`) is `parent`,
// excluding `self`.
func childrenOfParent(parent, self string, effective map[string][]Lot) []string {
	parentN := normaliseLotPath(parent)
	selfN := normaliseLotPath(self)
	out := make([]string, 0, len(effective))
	for p := range effective {
		c := normaliseLotPath(p)
		if c == "" || c == selfN || c == parentN {
			continue
		}
		// `c` is a child of `parent` iff `parent` is c's
		// longest-prefix ancestor in `effective`.
		if !pathContains(parentN, c) {
			continue
		}
		// Verify nothing strictly between parent and c also lives in
		// effective (which would make that intermediate the real
		// parent, not `parent`).
		isDirect := true
		for q := range effective {
			d := normaliseLotPath(q)
			if d == c || d == parentN || d == "" {
				continue
			}
			if pathContains(parentN, d) && pathContains(d, c) && len(d) > len(parentN) {
				isDirect = false
				break
			}
		}
		if isDirect {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}

// uniqueSortedInt64 returns a stable, ascending, deduplicated copy of `xs`.
func uniqueSortedInt64(xs []int64) []int64 {
	if len(xs) == 0 {
		return xs
	}
	cp := make([]int64, len(xs))
	copy(cp, xs)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	w := 0
	for i := 0; i < len(cp); i++ {
		if w == 0 || cp[w-1] != cp[i] {
			cp[w] = cp[i]
			w++
		}
	}
	return cp[:w]
}

// rootDedicatedGB returns the total capacity available at the top of
// the lot tree. We look it up from the existing snapshot rather than
// recomputing disk capacity: lotman's "root" lot is created at startup
// with the right value (see computeRootDedicatedGB) and is non-expiring.
// Returns 0 when no root lot exists or its dedicated_GB is unset; the
// allocator then stamps zero quotas on top-level lots and warns.
func rootDedicatedGB(existing []Lot) float64 {
	for _, l := range existing {
		if l.LotName != "root" {
			continue
		}
		if l.MPA == nil || l.MPA.DedicatedGB == nil {
			return 0
		}
		return *l.MPA.DedicatedGB
	}
	return 0
}
