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

// Renewal scheduler and lot garbage collector.
//
// # Renewal scheduler (renewExpiringLots)
//
// Lots have finite expiration times so a misbehaving (or simply forgotten)
// namespace cannot tie up cache space indefinitely. The scheduler runs on
// a fixed tick (Lotman.RenewalCheckInterval, default 1h) and ensures that
// every namespace currently advertised by the federation has at least one
// lot covering EVERY uncovered region inside the scheduling horizon
// [now, now+SchedulingHorizon).
//
// The scheduler ONLY mints new lots. It never updates an existing lot's
// reservation semantics (creation_time, expiration_time, deletion_time,
// dedicated_GB and other quota fields are treated as immutable once a
// lot is created). The xrootd-lotman purge plugin separately mutates
// usage accounting (current_usage, current_files, etc.) on every
// read/write — those mutations are orthogonal to the planner's
// reservation set. Renewal is exclusively the act of producing one or
// more successor lots whose paths[].Path matches the predecessor's,
// but whose UUID, creation_time, expiration_time, and deletion_time
// are fresh.
//
// ## Multi-fill within the horizon
//
// For each namespace path P, processed shortest-path-first so parents
// are planned before their children, the planner walks the post-tick
// timeline (existing ∪ already-planned successors) cursor-by-cursor and
// fills EVERY hole inside the horizon — not just the first one. Sample
// timeline before a tick:
//
//	now=T0   horizon=T0+H
//	   |        |
//	   v        v
//	[----)  [--)         [---)
//	     ^^^^   ^^^^^^^^^      ← gaps the planner must fill
//
// Each gap is filled by minting a successor whose window is
//
//	creation_time   = max(gapStart, predecessor.expiration_time)
//	expiration_time = min(creation_time + DefaultLotExpirationLifetime,
//	                      gapEnd,
//	                      effectiveParent.expiration_time)
//	deletion_time   = min(creation_time + DefaultLotDeletionLifetime,
//	                      effectiveParent.deletion_time)
//	                  capped overall at MaxLotLifetime
//
// Gaps narrower than Lotman.MinFillerWidth are left unfilled and a
// skipReason is emitted so operators can audit. The default value of
// Lotman.MinFillerWidth is 0, which means every gap is filled.
//
// ## Horizon refusal (and successor lifetime vs horizon)
//
// Successors whose computed creation_time falls beyond now+SchedulingHorizon
// are NOT minted on this tick; they will be planned on a future tick once
// "now" advances enough that they fall back inside the horizon. This keeps
// scheduling decisions tied to a meaningful look-ahead window and lets the
// system absorb federation-ad churn before committing to a new reservation.
//
// If the successor's creation_time is inside the horizon but its
// DefaultLotExpirationLifetime would push expiration_time past it, the
// lot IS created with the FULL default lifetime (not clipped to the
// horizon end). The horizon bounds when a lot is _started_, not when it
// ends — once the planner has committed to a successor, the rest of
// its window is determined by DefaultLotExpirationLifetime, the
// effective parent's expiration_time, and MaxLotLifetime.
//
// ## Race conditions with external reservations
//
// The planner takes a snapshot of `existing` lots at tick start. If an
// external API (anything other than this planner) creates a lot between
// the snapshot and our CreateLot calls, lotman's strict_hierarchy
// enforcement may reject our proposal. CreateLot errors are logged and
// skipped; the next tick's snapshot will see the new lot and the
// planner naturally converges. Today Pelican only mints lots from this
// scheduler, so this is mainly a defensive note for future external
// callers; a lotman-side advisory lock per path could be added if this
// becomes a real problem.
//
// ## Parent clamping (lotman "axiom 3": child time window ⊆ parent)
//
// Each successor's window is clipped to the effective parent segment
// active at the would-be creation_time, so lotman's third axiom
// always holds. In Pelican-internal terms: a child lot may not be
// active outside the lifetime of its parent.
//
//	child.creation_time   ≥ parent.creation_time
//	child.expiration_time ≤ parent.expiration_time
//	child.deletion_time   ≤ parent.deletion_time
//
// The effective parent is whichever lot will be active for the parent
// path AFTER this tick: a freshly-planned parent successor if the
// parent is also being renewed (which is why we process parents first),
// otherwise the parent's currently-latest existing lot.
//
// ## Epoch-aware quota stamping (allocateEpochAwareQuotas)
//
// After the planner has selected windows for every successor, the
// allocator stamps each successor's dedicated_GB. Because reservations
// are immutable, the stamped value must remain feasible for the
// successor's WHOLE lifetime — even if siblings appear or disappear
// later in that lifetime. The allocator therefore partitions the
// successor's window into "epochs" (maximal half-open intervals during
// which the active sibling set is constant) and stamps
//
//	dedicated_GB = min over epochs e of
//	    (parent_dedicated_in_e − Σ active_sibling.dedicated) / divisor_e
//
// where divisor_e is N+1 for top-level paths (sharing root's pool with
// no reserve) and N+2 for deeper paths (one extra share kept by the
// parent as reserve, matching lot_tree.go::distribute). Taking the
// minimum across epochs guarantees lotman's first axiom —
// Σ children.dedicated_GB ≤ parent.dedicated_GB — holds at every
// instant the successor will exist. (See lotman's documentation on
// hierarchical quota invariants for the formal statement.)
// See epoch.go for details.
//
// ## Lot names
//
// New lot names are fresh UUIDs; paths[].Path carries the human path P.
//
// # Lot garbage collector (LaunchLotGcRoutine)
//
// Lots whose deletion_time has been in the past for at least
// Lotman.LotRecordRetention (default 60 days) can be physically removed from
// the lotman database. This is the only code path in Pelican that ever
// calls lotman_remove_lot. A lot is assumed to have been reclaimed by
// the storage layer at or before its deletion_time, so deletion_time
// alone is the GC trigger:
//
//	GC if now − deletion_time ≥ LotRecordRetention
//
// The retention window gives operators a forensics window during which
// historical lot metadata is still inspectable. The GC routine runs at
// a fixed 24h cadence (not configurable).

package lotman

import (
	"context"
	"sort"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// renewalSawAdsOnce flips to true the first time runRenewalTick observes
// a non-empty ad set, and stays true for the lifetime of the process.
// runRenewalTick uses it to distinguish a cold-start "no ads yet" tick
// (DEBUG, expected during boot) from a "we had ads and now we don't"
// tick (WARN, indicates a director-side regression that will cause
// coverage to decay).
var renewalSawAdsOnce atomic.Bool

// skipReason explains why a particular renewal action was not taken.
// Returned in renewalProposal.skips so callers (and tests) can audit.
type skipReason struct {
	NamespacePath string
	Reason        string
}

// renewalProposal is the fully-precomputed action set the renewal
// scheduler will apply on a single tick. Splitting "decide" from "apply"
// keeps the scheduler unit-testable and lets the caller log/audit the
// plan before committing.
//
// The planner only ever proposes new lots. It never proposes mutations
// of existing lots — every reservation is immutable after creation, and
// the way to keep coverage going is to mint a fresh successor.
type renewalProposal struct {
	newLots []Lot
	skips   []skipReason
}

// renewalConfig captures the tunables threaded into the pure scheduler.
// Real callers fill this from param.* in LaunchRenewalRoutine; tests
// supply synthetic values directly.
//
// PeriodMs is the scheduler tick interval and is informational here:
// the planner uses it only to keep tests easy to write. The fill loop
// is bounded by HorizonMs (Lotman.SchedulingHorizon), not PeriodMs.
type renewalConfig struct {
	NowMs             int64
	PeriodMs          int64
	HorizonMs         int64
	MinFillerWidthMs  int64
	DefaultLifetimeMs int64
	DefaultDeletionMs int64
	MaxLifetimeMs     int64
	RootDedicatedGB   float64
	FederationIssuer  string
}

// renewExpiringLots is the pure planner used by LaunchRenewalRoutine.
// It receives the federation's current namespace ads and the full set of
// existing lots (typically obtained via getActiveLotsForRenewal) and produces a
// renewalProposal describing what should change. No FFI calls happen
// here, so the planner is unit-testable with synthetic Lot slices.
//
// # Multi-fill semantics
//
// Each tick fills *every* uncovered region of every advertised namespace
// inside [now, now+SchedulingHorizon) with back-to-back successor lots,
// trimmed to fit between adjacent existing lots so successor windows
// never overlap with each other or with pre-existing lots. A lot whose
// creation_time would fall beyond the horizon is deferred to a later
// tick (this is the user-facing meaning of Lotman.SchedulingHorizon).
//
// Holes shorter than Lotman.MinFillerWidth are recorded as Skips
// instead of being filled, to avoid producing a swarm of degenerate
// reservations from naturally-occurring sub-tick gaps. Bytes that
// arrive during a sub-threshold gap are accounted to the default lot.
//
// The planner is intentionally idempotent: re-running it against the
// outputs of a previous tick produces an empty proposal.
//
// # Axiom-3 invariant
//
// Lotman's strict_hierarchy mode requires
//
//	child.creation_time   ≥ parent.creation_time
//	child.expiration_time ≤ parent.expiration_time
//	child.deletion_time   ≤ parent.deletion_time
//
// (validated in lotman_internal.cpp::validate_axiom3). The planner
// satisfies this without ever mutating an existing lot:
//
//   - Namespaces are processed parent-before-child (shortest path first,
//     ties broken alphabetically). Each child's planned successor is
//     clamped to the parent segment that covers the successor's
//     creation_time, where "parent segment" means a single lot in the
//     parent's effective post-tick timeline (existing lots ∪ this
//     tick's planned parent successors).
//   - When no parent segment covers a candidate creation_time, the
//     planner records a Skip and advances past the offending hole.
//     The next tick will pick up the work once the parent has renewed.
//
// The planner does NOT extend existing lots. Every lot is immutable
// after creation; renewal is exclusively the job of minting fresh
// successors.
func renewExpiringLots(cfg renewalConfig, fedAds []server_structs.NamespaceAd, existing []Lot) renewalProposal {
	prop := renewalProposal{}

	if cfg.PeriodMs <= 0 || cfg.DefaultLifetimeMs <= 0 {
		prop.skips = append(prop.skips, skipReason{Reason: "period or default lifetime <= 0"})
		return prop
	}
	if cfg.MaxLifetimeMs > 0 && cfg.DefaultLifetimeMs > cfg.MaxLifetimeMs {
		// Defensive clamp: never propose a lifetime longer than the cap.
		// Done BEFORE the horizon check below so a misconfigured-up
		// DefaultLifetime cannot inflate the horizon past MaxLifetime.
		cfg.DefaultLifetimeMs = cfg.MaxLifetimeMs
	}
	if cfg.HorizonMs <= 0 {
		// Backwards-compatible fallback for callers that haven't
		// supplied a horizon: behave like the legacy single-fill
		// planner whose horizon was just one tick.
		cfg.HorizonMs = cfg.PeriodMs
	}
	if cfg.HorizonMs < cfg.DefaultLifetimeMs {
		// Defensive: a horizon shorter than the default lifetime is
		// pathological (every tick mints one lot whose end exceeds the
		// horizon). Round up so users who misconfigure still get sane
		// behaviour rather than thrashing.
		cfg.HorizonMs = cfg.DefaultLifetimeMs
	}
	if cfg.MinFillerWidthMs < 0 {
		cfg.MinFillerWidthMs = 0
	}

	horizonCreate := cfg.NowMs + cfg.HorizonMs

	// Distinct, non-monitoring namespace paths from the ads, sorted
	// parent-before-child (by length, ties alphabetical) so a parent's
	// planned successors are visible when its child is processed.
	nsPaths := dedupeNamespacePaths(fedAds)
	sort.Slice(nsPaths, func(i, j int) bool {
		if len(nsPaths[i]) != len(nsPaths[j]) {
			return len(nsPaths[i]) < len(nsPaths[j])
		}
		return nsPaths[i] < nsPaths[j]
	})

	// Per-path slice of newly-planned lots, in CreationTime order.
	// Used both to bound a path's own multi-fill loop (cursor advancement
	// past a just-planned successor) and to expose freshly-planned parent
	// successors when a child is processed.
	plannedByPath := map[string][]*Lot{}

	for _, p := range nsPaths {
		issuer := cfg.FederationIssuer
		if iss := issuerForPath(p, fedAds); iss != "" {
			issuer = iss
		}
		// The parent timeline a child must fit inside is the union of
		// the parent path's existing lots and any already-planned-this-
		// tick parent successors. Computed once per child for stability
		// across the multi-fill loop.
		parentPath := parentNamespacePath(p, existing, plannedByPath)
		parentTimeline := buildEffectiveTimeline(parentPath, existing, plannedByPath)
		// Existing-lots-only timeline for this path; planned successors
		// are tracked via cursor advancement, not by re-injection.
		ownTimeline := lotsForNamespace(p, existing)

		cursor := cfg.NowMs
		for cursor < horizonCreate {
			holeStart, holeEnd, ok := nextHole(ownTimeline, cursor)
			if !ok || holeStart >= horizonCreate {
				break
			}
			// Successors live strictly in [holeStart, holeEnd). Trim
			// holeEnd so we never bleed into the next existing lot's
			// window and produce same-path overlap.
			gapEnd := holeEnd

			create := holeStart
			if create < cfg.NowMs {
				create = cfg.NowMs
			}
			if create >= horizonCreate {
				// Far end of the path's coverage already extends past
				// horizon; nothing to do this tick.
				break
			}

			// Resolve which parent segment (if any) covers `create`.
			// `parentSeg.ok=false` means the parent has no coverage at
			// `create`, which forbids axiom-3 compliance: skip this
			// hole entirely and advance past it.
			parentSeg := parentSegmentAt(parentTimeline, create)
			if parentPath != "" && !parentSeg.ok {
				// The parent will have no live lot at `create`.
				// Advance past this hole; perhaps the next hole
				// (after the next existing same-path lot) is covered.
				prop.skips = append(prop.skips, skipReason{
					NamespacePath: p,
					Reason:        "no parent segment covers candidate creation_time; deferring",
				})
				cursor = gapEnd
				if cursor <= holeStart {
					cursor = holeStart + 1 // defensive against integer wrap
				}
				continue
			}
			if parentSeg.ok {
				if create < parentSeg.start {
					create = parentSeg.start
				}
				if create >= horizonCreate {
					break
				}
			}

			lifetime := cfg.DefaultLifetimeMs
			if cfg.MaxLifetimeMs > 0 && lifetime > cfg.MaxLifetimeMs {
				lifetime = cfg.MaxLifetimeMs
			}
			expire := create + lifetime
			if expire > gapEnd {
				expire = gapEnd
			}
			if parentSeg.ok && expire > parentSeg.end {
				expire = parentSeg.end
			}

			width := expire - create
			if width <= 0 {
				cursor = gapEnd
				if cursor <= holeStart {
					cursor = holeStart + 1
				}
				continue
			}
			if cfg.MinFillerWidthMs > 0 && width < cfg.MinFillerWidthMs {
				prop.skips = append(prop.skips, skipReason{
					NamespacePath: p,
					Reason:        "filler width below Lotman.MinFillerWidth; default lot will absorb the gap",
				})
				cursor = gapEnd
				if cursor <= holeStart {
					cursor = holeStart + 1
				}
				continue
			}

			// Deletion time defaults to create + DefaultDeletionMs but
			// must be ≥ expire and ≤ parent's deletion bound.
			del := create + cfg.DefaultDeletionMs
			if del < expire {
				del = expire
			}
			if parentSeg.ok && del > parentSeg.delEnd {
				del = parentSeg.delEnd
			}
			if del < expire {
				// Parent's deletion window is tighter than its own
				// expiration; fall back to expire (still satisfies
				// axiom 3 because parent.del ≥ parent.exp ≥ expire).
				del = expire
			}

			// Lotman's new_lot_schema requires opportunistic_GB and
			// max_num_objects to be present on every CreateLot call,
			// even though Pelican does not currently manage either
			// axis. Stamp the unbounded sentinel (-1) so the schema
			// is satisfied without imposing a real cap; if/when
			// Pelican grows policy for these axes the allocator can
			// overwrite these defaults before apply.
			unboundedOpp := float64(-1)
			newLot := Lot{
				LotName: uuid.NewString(),
				Owner:   issuer,
				// Parent UUID is filled in by the apply step.
				Paths: []LotPath{{Path: p, Recursive: true}},
				MPA: &MPA{
					CreationTime:    &Int64FromFloat{Value: create},
					ExpirationTime:  &Int64FromFloat{Value: expire},
					DeletionTime:    &Int64FromFloat{Value: del},
					OpportunisticGB: &unboundedOpp,
					MaxNumObjects:   &Int64FromFloat{Value: -1},
					// dedicated_GB is stamped by allocateEpochAwareQuotas
					// after every path's timing has been planned.
				},
			}
			prop.newLots = append(prop.newLots, newLot)
			ref := &prop.newLots[len(prop.newLots)-1]
			plannedByPath[p] = append(plannedByPath[p], ref)

			// Advance cursor past the just-planned successor. Continue
			// the loop so additional gaps inside [now, horizon) are
			// also filled (e.g. a future existing lot leaves another
			// hole before its own start).
			cursor = expire
			if cursor <= holeStart {
				cursor = holeStart + 1
			}
		}
	}

	return prop
}

// parentSegment is one entry in a path's effective post-tick timeline:
// a single lot that is or will be live for some closed-open window.
type parentSegment struct {
	ok     bool  // false → the parent has no coverage at the queried instant
	start  int64 // creation_time of the covering lot (Unix ms)
	end    int64 // expiration_time of the covering lot (Unix ms)
	delEnd int64 // deletion_time of the covering lot (Unix ms)
}

// buildEffectiveTimeline returns the parent path's full post-tick
// timeline (existing lots ∪ planned-this-tick successors), sorted by
// CreationTime ascending. Returns an empty slice when `path == ""`,
// which conventionally means "synthetic root, no parent clamp".
//
// Lots from `planned` are inserted as fresh shallow copies so the
// returned slice can be iterated without cross-contamination if a
// caller mutates entries (the planner does not, but the property is
// useful to preserve).
func buildEffectiveTimeline(path string, existing []Lot, planned map[string][]*Lot) []Lot {
	if path == "" {
		return nil
	}
	var out []Lot
	for _, l := range lotsForNamespace(path, existing) {
		out = append(out, l)
	}
	if planned != nil {
		for _, l := range planned[path] {
			if l == nil {
				continue
			}
			out = append(out, *l)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].MPA.CreationTime.Value < out[j].MPA.CreationTime.Value
	})
	return out
}

// parentSegmentAt returns the parent timeline segment that covers
// `instantMs` under the same half-open semantics as nextHole/nextGap:
// a lot covers t iff creation_time ≤ t < expiration_time.
//
// When `timeline` is empty the result has ok=false. Top-level paths use
// an empty timeline (their effective parent is the synthetic root lot,
// which is non-expiring and therefore imposes no clamp); the planner
// detects this case via parentNamespacePath returning "".
func parentSegmentAt(timeline []Lot, instantMs int64) parentSegment {
	for _, l := range timeline {
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		c := l.MPA.CreationTime.Value
		e := l.MPA.ExpirationTime.Value
		if c <= instantMs && instantMs < e {
			seg := parentSegment{ok: true, start: c, end: e, delEnd: e}
			if l.MPA.DeletionTime != nil {
				seg.delEnd = l.MPA.DeletionTime.Value
			}
			return seg
		}
	}
	return parentSegment{}
}

// parentNamespacePath returns the longest path that is a strict ancestor
// of `path` and is either being renewed this tick or has at least one
// existing lot. Returns "" when no such ancestor exists, in which case
// the synthetic root lot (non-expiring) is the effective parent and no
// clamp is applied.
func parentNamespacePath(path string, existing []Lot, planned map[string][]*Lot) string {
	target := normaliseLotPath(path)
	bestPath := ""
	bestLen := 0
	consider := func(candidate string) {
		c := normaliseLotPath(candidate)
		if c == target {
			return
		}
		// The synthetic root lot owns "/" (which normalises to "")
		// and is non-expiring; treat it as "no real parent" so the
		// planner falls into its top-level branch (empty timeline,
		// no axiom-3 clamp) instead of looking for a parent segment
		// that does not exist.
		if c == "" || c == "/" {
			return
		}
		if pathContains(c, target) && len(c) > bestLen {
			bestPath = c
			bestLen = len(c)
		}
	}
	for p := range planned {
		consider(p)
	}
	for _, l := range existing {
		for _, p := range l.Paths {
			consider(p.Path)
		}
	}
	return bestPath
}

// dedupeNamespacePaths returns the set of distinct, non-monitoring
// namespace paths advertised by the federation. Order is alphabetical
// for deterministic output.
func dedupeNamespacePaths(ads []server_structs.NamespaceAd) []string {
	seen := map[string]struct{}{}
	for _, a := range ads {
		p := normaliseLotPath(a.Path)
		if p == "" || p == "/" {
			continue
		}
		// Skip the monitoring sub-namespace; it's handled separately and
		// doesn't need lot coverage.
		if isMonitoringPath(p) {
			continue
		}
		seen[p] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// isMonitoringPath returns true for the cache's monitoring sub-namespace,
// which Pelican intentionally excludes from lot tracking.
func isMonitoringPath(p string) bool {
	mon := normaliseLotPath(server_utils.MonitoringBaseNs)
	np := normaliseLotPath(p)
	return np == mon || pathContains(mon, np)
}

// issuerForPath returns the first ad's issuer URL for the supplied
// namespace path, or "" when the path is not in `ads` (use the federation
// fallback) or the matching ad declares no issuer.
func issuerForPath(p string, ads []server_structs.NamespaceAd) string {
	target := normaliseLotPath(p)
	for _, a := range ads {
		if normaliseLotPath(a.Path) != target {
			continue
		}
		if len(a.Issuer) == 0 {
			return ""
		}
		return a.Issuer[0].IssuerUrl.String()
	}
	return ""
}

// ExpirationTimeIsSentinel reports whether the lot uses the "non-expiring"
// all-zero timestamp sentinel (lotman PR #44). Sentinel lots (root,
// default) must never be extended by the renewal scheduler.
func (l Lot) ExpirationTimeIsSentinel() bool {
	if l.MPA == nil {
		return true
	}
	if l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil || l.MPA.DeletionTime == nil {
		return false
	}
	return l.MPA.CreationTime.Value == 0 &&
		l.MPA.ExpirationTime.Value == 0 &&
		l.MPA.DeletionTime.Value == 0
}

// LaunchRenewalRoutine starts a background ticker that periodically calls
// renewExpiringLots and applies the resulting proposal to the lotman DB.
// It returns immediately; the goroutine exits when ctx is done.
//
// getNamespaceAds is supplied by the cache server so the routine reads
// the live ad set on every tick (rather than capturing a stale snapshot).
func LaunchRenewalRoutine(ctx context.Context, getNamespaceAds func() []server_structs.NamespaceAd) {
	interval := param.Lotman_RenewalCheckInterval.GetDuration()
	if interval <= 0 {
		interval = time.Hour
	}
	// SchedulingHorizon validation runs at config load
	// (config/config.go); the runtime planner additionally clamps
	// defensively per-tick so a stale config can't produce a coverage
	// gap.
	go func() {
		log.Infof("Starting Lotman renewal routine; interval=%s", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		// Run an immediate tick so freshly-launched caches converge faster.
		runRenewalTick(getNamespaceAds, interval)
		for {
			select {
			case <-ctx.Done():
				log.Info("Lotman renewal routine exiting (context cancelled)")
				return
			case <-ticker.C:
				runRenewalTick(getNamespaceAds, interval)
			}
		}
	}()
}

// resolveSuccessorParent picks the lot UUID under which a freshly-planned
// successor should be attached. The chosen parent must cover the
// successor's creation_time so axiom 3 holds at admission
// (parent.creation_time ≤ child.creation_time and
// child.expiration_time ≤ parent.expiration_time).
//
// Resolution order:
//  1. Walk ancestor paths (from any path that has a lot in either
//     `existing` or `planned`) longest-first.
//  2. For each candidate ancestor, prefer a planned-this-tick lot whose
//     window covers `successorCreate`. A planned parent always wins over
//     an existing one because `renewExpiringLots` clamps successor
//     windows to the planned-parent window when the existing parent is
//     itself expiring this tick.
//  3. Fall back to an existing lot whose window covers
//     `successorCreate`.
//  4. If no ancestor covers `successorCreate`, attach to "root". This is
//     the same branch first-ever lots take.
//
// Worked example. We are choosing a parent for a successor on
// `/a/b/c` whose creation_time is `*` below. The two candidate
// ancestors are `/a/b` and `/a`; only `/a/b` has a planned-this-tick
// successor, while `/a` has only an existing lot that covers `*`:
//
//	time →                     *
//	/a/b/c (successor)         [---)
//	/a/b   planned-this-tick   [-------)        ← chosen (rule 2)
//	/a/b   existing            [---)            (does not cover *)
//	/a     existing            [-------------)  (would match rule 3)
//	root   ──always covers──   [────────────)   (rule 4 fallback)
//
// Pure / data-only: no FFI calls, safe to unit-test.
func resolveSuccessorParent(path string, successorCreate int64, existing []Lot, planned map[string][]*Lot) string {
	target := normaliseLotPath(path)

	type ancestor struct {
		path string
		plen int
	}
	seen := map[string]bool{}
	var ancestors []ancestor
	consider := func(raw string) {
		n := normaliseLotPath(raw)
		if n == "" || n == target || seen[n] {
			return
		}
		if !pathContains(n, target) {
			return
		}
		seen[n] = true
		ancestors = append(ancestors, ancestor{n, len(n)})
	}
	for p := range planned {
		consider(p)
	}
	for _, l := range existing {
		for _, p := range l.Paths {
			consider(p.Path)
		}
	}
	sort.Slice(ancestors, func(i, j int) bool { return ancestors[i].plen > ancestors[j].plen })

	covers := func(l *Lot, t int64) bool {
		if l == nil || l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			return false
		}
		return l.MPA.CreationTime.Value <= t && t < l.MPA.ExpirationTime.Value
	}

	for _, a := range ancestors {
		// (2) Planned parent wins over an existing one.
		for _, l := range planned[a.path] {
			if covers(l, successorCreate) {
				return l.LotName
			}
		}
		// (3) Fall back to an existing covering lot.
		for _, l := range lotsForNamespace(a.path, existing) {
			lc := l
			if covers(&lc, successorCreate) {
				return l.LotName
			}
		}
	}
	return "root"
}

// runRenewalTick executes one cycle of the renewal scheduler. Errors are
// logged and swallowed so a transient failure does not crash the cache.
func runRenewalTick(getNamespaceAds func() []server_structs.NamespaceAd, period time.Duration) {
	ads := getNamespaceAds()
	if len(ads) == 0 {
		// Distinguish cold-start (cache just booted, director may not
		// have advertised yet) from a transient outage (we previously
		// saw ads and now don't). The latter is worth a WARN because
		// continued ad-loss while existing lots are valid means the
		// scheduler stops minting successors and coverage decays.
		if renewalSawAdsOnce.Load() {
			log.Warn("Lotman renewal: namespace ads disappeared after a previous tick had ads; skipping tick. Coverage will decay if this persists.")
		} else {
			log.Debug("Lotman renewal: no namespace ads yet (cold start); skipping tick")
		}
		return
	}
	renewalSawAdsOnce.Store(true)

	federationIssuer, err := getFederationIssuer()
	if err != nil || federationIssuer == "" {
		log.Warnf("Lotman renewal: cannot determine federation issuer; skipping tick: %v", err)
		return
	}

	nowMs := time.Now().UnixMilli()
	horizonMs := param.Lotman_SchedulingHorizon.GetDuration().Milliseconds()

	adPaths := dedupeNamespacePaths(ads)
	existing, err := getActiveLotsForRenewal(adPaths, nowMs, nowMs+horizonMs)
	if err != nil {
		log.Warnf("Lotman renewal: failed to enumerate lots: %v", err)
		return
	}

	cfg := renewalConfig{
		NowMs:             nowMs,
		PeriodMs:          period.Milliseconds(),
		HorizonMs:         horizonMs,
		MinFillerWidthMs:  param.Lotman_MinFillerWidth.GetDuration().Milliseconds(),
		DefaultLifetimeMs: param.Lotman_DefaultLotExpirationLifetime.GetDuration().Milliseconds(),
		DefaultDeletionMs: param.Lotman_DefaultLotDeletionLifetime.GetDuration().Milliseconds(),
		MaxLifetimeMs:     param.Lotman_MaxLotLifetime.GetDuration().Milliseconds(),
		RootDedicatedGB:   rootDedicatedGB(existing),
		FederationIssuer:  federationIssuer,
	}

	prop := renewExpiringLots(cfg, ads, existing)
	if len(prop.newLots) == 0 {
		log.Debug("Lotman renewal: nothing to do")
		return
	}

	// Stamp epoch-aware storage quotas on every newly-planned lot so
	// the immutable record reflects a non-contracting share that
	// remains feasible for the whole life of the lot, even as the
	// composition of active siblings changes across the lot's lifetime.
	allocateEpochAwareQuotas(&prop, existing, ads, cfg)

	// Apply proposal. Each step logs its own failures and the loop
	// continues so a single bad lot does not block the rest. Parent
	// resolution is delegated to assignSuccessorParents, which is pure
	// and independently unit-tested so the wiring (creation_time → the
	// resolver's `successorCreate` argument; planned-this-tick siblings
	// → its `planned` map) is exercised by tests rather than relying on
	// the call site being correct by inspection.
	assignSuccessorParents(prop.newLots, existing)

	for _, l := range prop.newLots {
		if err := CreateLot(&l, federationIssuer); err != nil {
			log.Warnf("Lotman renewal: failed to create lot for %q: %v", l.Paths[0].Path, err)
		} else {
			log.Infof("Lotman renewal: created successor lot %s for %q (parent=%s, expires %s)",
				l.LotName, l.Paths[0].Path, l.Parents[0],
				time.UnixMilli(l.MPA.ExpirationTime.Value).Format(time.RFC3339))
		}
	}
}

// assignSuccessorParents fills `Parents[0]` on every lot in `newLots`
// using resolveSuccessorParent. Pure / data-only so the wiring between
// runRenewalTick and the resolver can be exercised in unit tests
// (verifies createTime is sourced from MPA.CreationTime and that the
// planned-this-tick sibling map is built from `newLots` itself). Mutates
// `newLots` in place.
func assignSuccessorParents(newLots []Lot, existing []Lot) {
	planned := map[string][]*Lot{}
	for i := range newLots {
		l := &newLots[i]
		if len(l.Paths) == 0 {
			continue
		}
		p := normaliseLotPath(l.Paths[0].Path)
		planned[p] = append(planned[p], l)
	}
	for i := range newLots {
		l := &newLots[i]
		if len(l.Paths) == 0 {
			continue
		}
		createTime := int64(0)
		if l.MPA != nil && l.MPA.CreationTime != nil {
			createTime = l.MPA.CreationTime.Value
		}
		l.Parents = []string{resolveSuccessorParent(l.Paths[0].Path, createTime, existing, planned)}
	}
}

// LaunchLotGcRoutine starts a background ticker that periodically removes
// lots whose deletion_time + LotRecordRetention has passed. It returns
// immediately; the goroutine exits when ctx is done. The cadence is
// fixed at 24 hours.
func LaunchLotGcRoutine(ctx context.Context) {
	interval := param.Lotman_GarbageCollectionInterval.GetDuration()
	if interval <= 0 {
		log.Warningf("Lotman GC: invalid interval %s; falling back to 24h", interval)
		interval = 24 * time.Hour
	}
	go func() {
		log.Infof("Starting Lotman GC routine; interval=%s", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				log.Info("Lotman GC routine exiting (context cancelled)")
				return
			case <-ticker.C:
				runGcTick()
			}
		}
	}()
}

// gcEligibleLots returns the names of lots that runGcTick would remove
// if invoked at wall-clock `nowMs` with the supplied retention. Pure /
// data-only so it can be unit-tested without an FFI surface.
//
// Eligibility rules:
//   - Skip the synthetic root and default lots (immutable bookkeeping
//     entries that lotman creates at startup).
//   - Skip sentinel-time lots (creation/expiration/deletion all 0):
//     these are non-expiring by design.
//   - Skip lots whose deletion_time is unset or 0.
//   - Otherwise eligible iff `deletion_time + retention <= nowMs`,
//     equivalently `deletion_time <= nowMs - retention`.
func gcEligibleLots(existing []Lot, nowMs int64, retention time.Duration) []string {
	if retention <= 0 {
		retention = 60 * 24 * time.Hour
	}
	cutoffMs := nowMs - retention.Milliseconds()
	out := make([]string, 0)
	for _, l := range existing {
		if l.LotName == "root" || l.LotName == "default" {
			continue
		}
		if l.ExpirationTimeIsSentinel() {
			continue
		}
		if l.MPA == nil || l.MPA.DeletionTime == nil {
			continue
		}
		trigger := l.MPA.DeletionTime.Value
		if trigger == 0 {
			continue
		}
		if trigger > cutoffMs {
			continue
		}
		out = append(out, l.LotName)
	}
	return out
}

// RemoveLot bool-arg cheat sheet (matches the underlying lotman C API):
//
//	assignLTBRParentsToOrphans   reattach orphaned children to the
//	                              removed lot's parents (else: orphan).
//	assignLTBRParentsToNonOrphans same, for non-orphan children.
//	assignPolicyToChildren        copy the removed lot's policy down to
//	                              its children before removal.
//	overridePolicy                allow removal even when policy says no.
//
// The renewal scheduler's GC always wants the first two true (so a GC
// cascade does not orphan downstream lots) and the latter two false
// (we are not propagating policy and never want to override safety
// checks on a routine GC).
//
// On the option of collapsing this loop into a single recursive
// subtree delete: under strict_hierarchy lotman enforces
// child.deletion_time ≤ parent.deletion_time, so any past-deletion
// parent transitively implies all of its descendants are also past-
// deletion. That means lotman_remove_lots_recursive on each subtree
// root in `names` would, in principle, delete the same set without
// needing orphan reassignment. We deliberately keep the per-lot loop
// for three reasons:
//
//  1. Per-lot logging is operationally valuable — each removed lot
//     gets its own audit line, which simplifies forensics when a lot
//     disappears unexpectedly.
//  2. Detecting "subtree roots" inside `names` is itself extra logic
//     (group by parent_uuid, drop entries whose parent is also in the
//     set) that offsets most of the simplification, and it has to be
//     redone every tick.
//  3. assignLTBRParentsToOrphans=true keeps GC correct even if some
//     future external lot writer (or a transient invariant violation)
//     ever lands a non-past-deletion child under a past-deletion
//     parent. The recursive form would happily sweep that child away.
//     The defensive cost is a few extra FFI calls per tick on what is
//     already a daily cadence.
//
// If lotman ever exposes a "remove all lots whose deletion_time +
// retention ≤ now" primitive (lotman-side equivalent of getGcCandidates
// + RemoveLot fused into one C call), revisit this loop.
const (
	gcReassignOrphans    = true
	gcReassignNonOrphans = true
	gcAssignPolicy       = false
	gcOverridePolicy     = false
)

// runGcTick removes any lot whose deletion_time was at least LotRecordRetention
// ago. Failures are logged and swallowed.
//
// Concurrency note: this is the only Pelican code path that calls
// RemoveLot. Pelican does not currently expose any user-facing API
// (HTTP, CLI, or otherwise) that creates, updates, or deletes lots
// outside the renewal scheduler and this GC, so there is no in-process
// race to worry about today. If a future PR adds such an API — for
// example, an operator endpoint to mint or rescind reservations —
// concurrent writers may race against this tick (and against
// runRenewalTick) at the lotman C layer. lotman currently exposes no
// per-path advisory lock
func runGcTick() {
	federationIssuer, err := getFederationIssuer()
	if err != nil || federationIssuer == "" {
		log.Warnf("Lotman GC: cannot determine federation issuer; skipping tick: %v", err)
		return
	}
	retention := param.Lotman_LotRecordRetention.GetDuration()

	names, err := getGcCandidates(time.Now().UnixMilli(), retention)
	if err != nil {
		log.Warnf("Lotman GC: failed to enumerate GC candidates: %v", err)
		return
	}
	for _, name := range names {
		if err := RemoveLot(name, gcReassignOrphans, gcReassignNonOrphans, gcAssignPolicy, gcOverridePolicy, federationIssuer); err != nil {
			log.Warnf("Lotman GC: failed to remove lot %s: %v", name, err)
			continue
		}
		log.Infof("Lotman GC: removed lot %s", name)
	}
}

// validateLotLifetime returns an error if the supplied lot's
// expiration_time exceeds creation_time + Lotman.MaxLotLifetime. Used by
// CreateLot/UpdateLot at admission time so lots cannot be minted with
// arbitrary lifetimes.
func validateLotLifetime(l *Lot) error {
	if l == nil || l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
		return nil
	}
	if l.ExpirationTimeIsSentinel() {
		return nil
	}
	maxLifetime := param.Lotman_MaxLotLifetime.GetDuration().Milliseconds()
	if maxLifetime <= 0 {
		return nil
	}
	span := l.MPA.ExpirationTime.Value - l.MPA.CreationTime.Value
	if span > maxLifetime {
		return errors.Errorf(
			"lot %s expiration_time exceeds %s (%dms requested, max %dms)",
			l.LotName, param.Lotman_MaxLotLifetime.GetName(), span, maxLifetime)
	}
	return nil
}

// validateLotUpdateLifetime enforces Lotman.MaxLotLifetime on the
// post-update span of any update that touches creation_time or
// expiration_time. When only one of the two is supplied, the absent
// field is read from the live lot so the resulting span can be checked
// without allowing a sneak-extension. Updates that touch neither
// timestamp are allowed through unchanged.
func validateLotUpdateLifetime(upd *LotUpdate) error {
	if upd == nil || upd.MPA == nil {
		return nil
	}
	touchesCreate := upd.MPA.CreationTime != nil
	touchesExpire := upd.MPA.ExpirationTime != nil
	if !touchesCreate && !touchesExpire {
		return nil
	}
	create := int64(0)
	expire := int64(0)
	if touchesCreate {
		create = upd.MPA.CreationTime.Value
	}
	if touchesExpire {
		expire = upd.MPA.ExpirationTime.Value
	}
	if !touchesCreate || !touchesExpire {
		live, err := GetLot(upd.LotName, false)
		if err != nil {
			return errors.Wrapf(err, "cannot validate update lifetime for lot %s", upd.LotName)
		}
		if live == nil || live.MPA == nil {
			return nil
		}
		if !touchesCreate && live.MPA.CreationTime != nil {
			create = live.MPA.CreationTime.Value
		}
		if !touchesExpire && live.MPA.ExpirationTime != nil {
			expire = live.MPA.ExpirationTime.Value
		}
	}
	probe := &Lot{
		LotName: upd.LotName,
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: create},
			ExpirationTime: &Int64FromFloat{Value: expire},
		},
	}
	return validateLotLifetime(probe)
}
