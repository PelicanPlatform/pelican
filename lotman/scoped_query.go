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

// Scoped lotman queries used by the renewal scheduler.
//
// The previous implementation enumerated every row in the lotman SQLite DB on
// every tick (listAllLotsFull); at thousands of lots this was wasteful and
// memory-hungry. This file replaces that O(total lot rows) walk with two
// targeted multi-step queries built on top of the lotman C API:
//
//	getActiveLotsForRenewal(adPaths, nowMs, horizonEndMs)
//	    Step 1: for each ad path, lotman_get_lots_for_path(p, recursive=true,
//	            nowMs, horizonEndMs, include_reclaimed=false) returns the
//	            full Lot objects that win the longest-prefix path-resolution
//	            contest at any instant in the planning window, plus each
//	            winner's ancestors (recursive=true). This is the "lots
//	            covering this namespace and its parents during planning"
//	            slice the renewal planner needs.
//	    Step 2: for every lot returned by step 1, recursively expand to
//	            descendants via lotman_get_children_names + lotman_get_lot_
//	            as_json. This pulls in stale sublots that no longer have
//	            advertised namespace ads but still consume parent capacity,
//	            which the epoch allocator's per-parent sibling sweep needs
//	            to see for axiom-1 (Σ children dedicated_GB ≤ parent
//	            dedicated_GB) compliance.
//	    Step 3: ensure the synthetic "root" lot is present so
//	            rootDedicatedGB() can find it for top-level capacity.
//
//	getGcCandidates(nowMs, retention)
//	    Single call: lotman_get_lots_past_del(query_time = nowMs - retention,
//	    recursive=false, include_reclaimed=true). Returns just the names
//	    eligible for GC; "root" and "default" are filtered defensively
//	    even though the C side already excludes sentinel lots.
//
// All three steps deliberately use existing lotman primitives rather than a
// dedicated "all lots under path" descendants API, keeping the lotman C
// surface small.

package lotman

import (
	"time"

	"github.com/pkg/errors"
)

// getActiveLotsForRenewal returns the union of every lot relevant to the
// renewal planner across the half-open planning window [nowMs, horizonEndMs).
// See file header for the multi-step strategy. Replaces listAllLotsFull()
// for runRenewalTick.
func getActiveLotsForRenewal(adPaths []string, nowMs, horizonEndMs int64) ([]Lot, error) {
	seen := map[string]struct{}{}
	out := make([]Lot, 0, 16)
	addLot := func(l Lot) {
		if _, ok := seen[l.LotName]; ok {
			return
		}
		seen[l.LotName] = struct{}{}
		out = append(out, l)
	}

	// Step 1: per-ad-path window-aware owners + ancestors.
	for _, p := range adPaths {
		lots, err := GetLotsForPath(p, true, nowMs, horizonEndMs, false)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to enumerate lots for namespace %s", p)
		}
		for _, l := range lots {
			addLot(l)
		}
	}

	// Step 2: recursively expand to descendants. The epoch allocator's
	// per-parent sibling sweep needs to see every active sublot to
	// compute axiom-1-respecting quotas, including stale sublots that
	// are no longer advertised by the director (those still consume
	// parent capacity until GC collects them). Iterate via index over a
	// growing slice so newly-added children are themselves expanded.
	for i := 0; i < len(out); i++ {
		head := out[i]
		// getSelf=false: we already have `head` in `seen`; we only want
		// its proper children.
		kids, err := GetChildrenNames(head.LotName, false, false)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to list children of lot %s", head.LotName)
		}
		for _, name := range kids {
			if _, ok := seen[name]; ok {
				continue
			}
			child, err := GetLot(name, false)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to fetch child lot %s", name)
			}
			if child == nil {
				continue
			}
			addLot(*child)
		}
	}

	// Step 3: ensure the synthetic "root" lot is in the result so
	// rootDedicatedGB() can find it. It is non-expiring and non-path-
	// owning, so steps 1-2 will not surface it on their own.
	if _, ok := seen["root"]; !ok {
		root, err := GetLot("root", false)
		if err == nil && root != nil {
			addLot(*root)
		}
	}

	return out, nil
}

// getGcCandidates returns the names of lots whose deletion_time was at least
// `retention` ago relative to nowMs, filtered to exclude the synthetic
// root/default lots (which are non-expiring and never garbage-collected).
// Replaces listAllLotsFull() + the slice-walking gcEligibleLots() inside
// runGcTick. The pure gcEligibleLots() function is preserved for unit tests
// that exercise the cutoff arithmetic against synthetic Lot slices.
func getGcCandidates(nowMs int64, retention time.Duration) ([]string, error) {
	if retention <= 0 {
		retention = 60 * 24 * time.Hour
	}
	cutoffMs := nowMs - retention.Milliseconds()
	// recursive=false: cleanup loops want each lot's own deletion_time,
	// not "deletion_time inherited from any parent". include_reclaimed=
	// true: a lot can be GC-eligible regardless of whether the purge
	// plugin already reclaimed it; deletion_time + retention is the
	// independent forensics-window bound.
	names, err := GetLotsPastDel(cutoffMs, false, true)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "root" || n == "default" {
			continue
		}
		out = append(out, n)
	}
	return out, nil
}
