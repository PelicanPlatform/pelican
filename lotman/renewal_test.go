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
***************************************************************/

package lotman

import (
	"net/url"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func adsForRenewal(paths ...string) []server_structs.NamespaceAd {
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

func defaultRenewalCfg(now int64) renewalConfig {
	// Legacy single-fill-style cfg used by the original tests:
	// Horizon == DefaultLifetime == Period so each path mints at most
	// one successor per tick, matching the pre-multi-fill semantics
	// those tests were written against. The planner will defensively
	// clamp Horizon up to DefaultLifetime; setting them equal keeps
	// behaviour predictable.
	return renewalConfig{
		NowMs:             now,
		PeriodMs:          int64(60 * 60 * 1000), // 1h
		HorizonMs:         int64(60 * 60 * 1000), // 1h
		DefaultLifetimeMs: int64(60 * 60 * 1000), // 1h
		DefaultDeletionMs: int64(60 * 60 * 1000),
		MaxLifetimeMs:     int64(168 * 60 * 60 * 1000), // 168h
		FederationIssuer:  "https://fed.example/",
	}
}

func TestRenewExpiringLots_NoExistingLots_MintsForEveryNamespace(t *testing.T) {
	now := int64(1_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a", "/b")

	prop := renewExpiringLots(cfg, ads, nil)
	require.Len(t, prop.newLots, 2)

	got := map[string]bool{}
	for _, l := range prop.newLots {
		require.NotEmpty(t, l.LotName, "new lots must have a UUID name")
		require.Len(t, l.Paths, 1)
		got[l.Paths[0].Path] = true
		assert.Equal(t, now, l.MPA.CreationTime.Value)
		assert.Equal(t, now+cfg.DefaultLifetimeMs, l.MPA.ExpirationTime.Value)
	}
	assert.True(t, got["/a"])
	assert.True(t, got["/b"])
}

func TestRenewExpiringLots_CoverageInsidePeriod_NoNewLot(t *testing.T) {
	now := int64(1_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a")

	// Existing lot covers [now-1h, now+24h) -> no gap inside [now, now+1h).
	existing := []Lot{makeLot("u1", "/a", now-int64(60*60*1000), now+int64(24*60*60*1000))}
	prop := renewExpiringLots(cfg, ads, existing)
	assert.Empty(t, prop.newLots)
}

func TestRenewExpiringLots_GapAtNow_MintsSuccessor(t *testing.T) {
	now := int64(10_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a")
	// Existing lot expired before now; coverage should restart at now.
	existing := []Lot{makeLot("u1", "/a", 0, now-1)}
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 1)
	assert.Equal(t, now, prop.newLots[0].MPA.CreationTime.Value)
}

func TestRenewExpiringLots_GapInsidePeriod_CreationAtPredecessorExpiration(t *testing.T) {
	now := int64(10_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a")
	predExp := now + int64(30*60*1000) // expires in 30 min, inside the 1h window.
	existing := []Lot{makeLot("u1", "/a", now-1000, predExp)}
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 1)
	// New lot must start at the predecessor's expiration to avoid overlap.
	assert.Equal(t, predExp, prop.newLots[0].MPA.CreationTime.Value)
}

func TestRenewExpiringLots_MonitoringPathSkipped(t *testing.T) {
	now := int64(1_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a", "/pelican/monitoring/probe")
	prop := renewExpiringLots(cfg, ads, nil)
	require.Len(t, prop.newLots, 1)
	assert.Equal(t, "/a", prop.newLots[0].Paths[0].Path)
}

func TestRenewExpiringLots_Idempotent(t *testing.T) {
	now := int64(1_000_000)
	cfg := defaultRenewalCfg(now)
	ads := adsForRenewal("/a")

	first := renewExpiringLots(cfg, ads, nil)
	require.Len(t, first.newLots, 1)

	// Second pass: feed the freshly-minted lot back as existing.
	second := renewExpiringLots(cfg, ads, first.newLots)
	assert.Empty(t, second.newLots)
}

func TestRenewExpiringLots_LifetimeClampedToMax(t *testing.T) {
	now := int64(1_000_000)
	cfg := defaultRenewalCfg(now)
	cfg.DefaultLifetimeMs = 2 * cfg.MaxLifetimeMs
	ads := adsForRenewal("/a")
	prop := renewExpiringLots(cfg, ads, nil)
	require.Len(t, prop.newLots, 1)
	span := prop.newLots[0].MPA.ExpirationTime.Value - prop.newLots[0].MPA.CreationTime.Value
	assert.Equal(t, cfg.MaxLifetimeMs, span)
}

func TestRenewExpiringLots_EmptyConfig_NoOp(t *testing.T) {
	cfg := renewalConfig{NowMs: 0, PeriodMs: 0, DefaultLifetimeMs: 0}
	prop := renewExpiringLots(cfg, adsForRenewal("/a"), nil)
	assert.Empty(t, prop.newLots)
	assert.NotEmpty(t, prop.skips)
}

// Axiom-3 clamping: a child successor whose default lifetime would exceed
// its parent's existing-lot expiration must be clamped to the parent's
// window so lotman accepts it. The child's lifetime is therefore shorter,
// and the next renewal tick will mint a new child once the parent has
// renewed.
func TestRenewExpiringLots_ChildClampedToExistingParentExpiration(t *testing.T) {
	now := int64(10_000_000)
	cfg := defaultRenewalCfg(now)
	// Use DefaultLifetime > parent's remaining 2h window so the child
	// successor's expiration must be clamped down. Horizon is set
	// equal to DefaultLifetime so the planner doesn't bump it up
	// defensively.
	cfg.DefaultLifetimeMs = int64(4 * 60 * 60 * 1000) // 4h
	cfg.HorizonMs = cfg.DefaultLifetimeMs
	ads := adsForRenewal("/a", "/a/b")

	// /a has an existing lot whose expiration is much earlier than
	// /a/b's default 4h window would extend to.
	parentExp := now + int64(2*60*60*1000) // /a expires in 2h
	parentLot := makeLot("u-parent", "/a", now-1000, parentExp)
	parentLot.MPA.DeletionTime = &Int64FromFloat{Value: parentExp}
	existing := []Lot{parentLot}
	prop := renewExpiringLots(cfg, ads, existing)

	// Find the FIRST /a/b successor — it must be clamped to the
	// existing parent's window.
	var child *Lot
	for i := range prop.newLots {
		if prop.newLots[i].Paths[0].Path == "/a/b" {
			child = &prop.newLots[i]
			break
		}
	}
	require.NotNil(t, child, "expected a successor for /a/b")
	assert.Equal(t, now, child.MPA.CreationTime.Value)
	assert.Equal(t, parentExp, child.MPA.ExpirationTime.Value,
		"child's expiration must be clamped to existing parent's expiration (axiom 3)")
	assert.LessOrEqual(t, child.MPA.DeletionTime.Value, parentExp,
		"child's deletion_time must also fit inside parent's deletion_time")
}

// When both parent and child are being renewed in the same tick, the
// child must be clamped against the FRESH successor's window (not the
// stale predecessor's). The parent is processed first by virtue of
// shortest-path-first ordering.
func TestRenewExpiringLots_ChildClampedToPlannedParentSuccessor(t *testing.T) {
	now := int64(10_000_000)
	cfg := defaultRenewalCfg(now)

	ads := adsForRenewal("/a", "/a/b")
	// Both lots already past their expiration, so both will renew this tick.
	existing := []Lot{
		makeLot("u-parent", "/a", now-int64(60*60*1000), now-1000),
		makeLot("u-child", "/a/b", now-int64(60*60*1000), now-1000),
	}
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 2)

	var parent, child Lot
	for _, l := range prop.newLots {
		if l.Paths[0].Path == "/a" {
			parent = l
		} else {
			child = l
		}
	}
	require.NotNil(t, parent.MPA)
	require.NotNil(t, child.MPA)
	// Both windows should be identical (same default lifetime, same
	// creation_time of `now`), satisfying axiom 3 with equality on the
	// expiration boundary.
	assert.Equal(t, parent.MPA.CreationTime.Value, child.MPA.CreationTime.Value)
	assert.Equal(t, parent.MPA.ExpirationTime.Value, child.MPA.ExpirationTime.Value)
	assert.LessOrEqual(t, child.MPA.ExpirationTime.Value, parent.MPA.ExpirationTime.Value)
}

// If the parent's effective window is already in the past (parent
// expired and its successor is not yet planned for some reason), the
// child cannot be minted with a positive window and must be skipped
// rather than violating axiom 3. The next tick will catch up after the
// parent has been renewed.
func TestRenewExpiringLots_SkippedWhenParentWindowGivesNoRoom(t *testing.T) {
	now := int64(10_000_000)
	cfg := defaultRenewalCfg(now)
	// Only /a/b is advertised — /a is an "implicit" parent path with a
	// historical lot but no current ad, so it won't be renewed.
	ads := adsForRenewal("/a/b")
	existing := []Lot{
		makeLot("u-parent-old", "/a", now-int64(2*60*60*1000), now-1000), // expired
	}
	prop := renewExpiringLots(cfg, ads, existing)
	assert.Empty(t, prop.newLots, "child cannot fit inside an already-expired parent window")
	require.NotEmpty(t, prop.skips)
	assert.Equal(t, "/a/b", prop.skips[0].NamespacePath)
}

// horizonRenewalCfg returns a renewalConfig with the new
// SchedulingHorizon / MinFillerWidth knobs set to plausible values so
// the multi-fill code path is exercised end-to-end without falling back
// to the legacy single-fill defaults.
func horizonRenewalCfg(now int64) renewalConfig {
	return renewalConfig{
		NowMs:             now,
		PeriodMs:          int64(60 * 60 * 1000),       // 1h
		HorizonMs:         int64(48 * 60 * 60 * 1000),  // 48h
		MinFillerWidthMs:  int64(15 * 60 * 1000),       // 15m
		DefaultLifetimeMs: int64(24 * 60 * 60 * 1000),  // 24h
		DefaultDeletionMs: int64(48 * 60 * 60 * 1000),  // 48h
		MaxLifetimeMs:     int64(168 * 60 * 60 * 1000), // 168h
		FederationIssuer:  "https://fed.example/",
	}
}

// Multi-fill: a path with three discrete holes inside the horizon must
// produce three successors on a single tick.
func TestRenewExpiringLots_MultiFillFillsEveryHoleInsideHorizon(t *testing.T) {
	const (
		hour = int64(60 * 60 * 1000)
	)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	ads := adsForRenewal("/a")

	// Existing lots create three internal holes inside [now, now+48h):
	//   [now, now+5h)            covered by L1
	//   [now+5h, now+10h)        HOLE
	//   [now+10h, now+12h)       covered by L2
	//   [now+12h, now+30h)       HOLE
	//   [now+30h, now+33h)       covered by L3
	//   [now+33h, now+48h)       HOLE (extends past end-of-horizon)
	existing := []Lot{
		makeLot("L1", "/a", now-hour, now+5*hour),
		makeLot("L2", "/a", now+10*hour, now+12*hour),
		makeLot("L3", "/a", now+30*hour, now+33*hour),
	}
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 3, "three internal holes must yield three successors")

	// Each successor must start at its hole's left edge and end no
	// later than the hole's right edge (no overlap with existing lots).
	for _, l := range prop.newLots {
		create := l.MPA.CreationTime.Value
		expire := l.MPA.ExpirationTime.Value
		assert.GreaterOrEqual(t, create, now)
		assert.Less(t, create, expire)
		// Successor must not overlap any of the existing lots.
		for _, e := range existing {
			ec := e.MPA.CreationTime.Value
			ee := e.MPA.ExpirationTime.Value
			overlap := create < ee && ec < expire
			assert.False(t, overlap,
				"new lot [%d,%d) overlaps existing [%d,%d)", create, expire, ec, ee)
		}
	}
}

// Gap trimming: a successor whose default lifetime would extend past
// the next existing lot must have its expiration_time clamped to the
// hole's right edge.
func TestRenewExpiringLots_GapTrimmingClampsExpirationToHoleEnd(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	// Narrow horizon to just the first hole so the post-existing-lot
	// hole [now+25h, ∞) is deferred to a future tick.
	cfg.HorizonMs = 2 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	ads := adsForRenewal("/a")

	// One small hole [now, now+2h), a 24h-default successor would
	// otherwise spill into the next existing lot starting at now+2h.
	existing := []Lot{
		makeLot("L-future", "/a", now+2*hour, now+25*hour),
	}
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 1)
	got := prop.newLots[0]
	assert.Equal(t, now, got.MPA.CreationTime.Value)
	assert.Equal(t, now+2*hour, got.MPA.ExpirationTime.Value,
		"expiration must be trimmed to hole_end to avoid same-path overlap")
}

// Horizon refusal: holes that begin past the horizon must NOT be filled
// on this tick. They will be picked up on a later tick once the
// horizon slides forward.
func TestRenewExpiringLots_HorizonRefusal_DefersHolesBeyondHorizon(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now) // 48h horizon

	ads := adsForRenewal("/a")
	// Fully cover the horizon with one big lot, then leave a hole far in the future.
	existing := []Lot{
		makeLot("L-now", "/a", now-hour, now+50*hour), // covers [now, now+48h]
	}
	prop := renewExpiringLots(cfg, ads, existing)
	assert.Empty(t, prop.newLots, "no holes inside horizon → no successors")
}

// Narrow-gap skip: a hole strictly narrower than MinFillerWidth must be
// recorded as a Skip rather than minted as a successor.
func TestRenewExpiringLots_NarrowGapSkipped(t *testing.T) {
	const (
		hour   = int64(60 * 60 * 1000)
		minute = int64(60 * 1000)
	)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now) // 15m MinFillerWidth
	// Narrow horizon so only the sub-MinFillerWidth gap is in scope;
	// the post-existing-lot hole [now+25h, ∞) lies past the horizon.
	cfg.HorizonMs = 1 * hour
	cfg.DefaultLifetimeMs = 1 * hour
	ads := adsForRenewal("/a")
	// 5-minute hole [now, now+5m) — narrower than MinFillerWidth=15m.
	existing := []Lot{
		makeLot("L-future", "/a", now+5*minute, now+25*hour),
	}
	prop := renewExpiringLots(cfg, ads, existing)
	assert.Empty(t, prop.newLots, "sub-MinFillerWidth gap must not be filled")
	require.NotEmpty(t, prop.skips)
	found := false
	for _, s := range prop.skips {
		if s.NamespacePath == "/a" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected a Skip for /a")
}

// Epoch-aware quota allocation: with N top-level paths and a known
// root capacity, every freshly-minted lot should be stamped with
// rootDedicatedGB / N (top-level uses no reserve, matching
// lot_tree.go::distribute).
func TestAllocateEpochAwareQuotas_TopLevelEqualShare(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour // exactly one fill per path
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 1000.0
	ads := adsForRenewal("/a", "/b", "/c") // three siblings under root

	prop := renewExpiringLots(cfg, ads, nil)
	require.Len(t, prop.newLots, 3)

	allocateEpochAwareQuotas(&prop, nil, ads, cfg)

	// Top-level divisor = N = 3, share = 1000/3 ≈ 333.33.
	want := 1000.0 / 3.0
	for _, l := range prop.newLots {
		require.NotNil(t, l.MPA.DedicatedGB, "lot %s missing dedicated_GB", l.LotName)
		assert.InDelta(t, want, *l.MPA.DedicatedGB, 0.01,
			"lot %s for %q got %.2f, want ~%.2f",
			l.LotName, l.Paths[0].Path, *l.MPA.DedicatedGB, want)
	}
}

// Epoch-aware quota allocation with no root capacity falls back to
// stamping zero (so the lot still exists but promises nothing).
func TestAllocateEpochAwareQuotas_NoRootCapacity_StampsZero(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 0 // unknown / unset
	ads := adsForRenewal("/a")

	prop := renewExpiringLots(cfg, ads, nil)
	require.Len(t, prop.newLots, 1)
	allocateEpochAwareQuotas(&prop, nil, ads, cfg)
	require.NotNil(t, prop.newLots[0].MPA.DedicatedGB)
	assert.Equal(t, 0.0, *prop.newLots[0].MPA.DedicatedGB)
}

// rootDedicatedGB pulls the dedicated_GB off the root lot in the
// existing snapshot. When no root lot is present, returns 0.
func TestRootDedicatedGB(t *testing.T) {
	v := 4096.0
	root := Lot{
		LotName: "root",
		MPA:     &MPA{DedicatedGB: &v},
	}
	other := makeLot("u1", "/x", 0, 1000)
	assert.Equal(t, 4096.0, rootDedicatedGB([]Lot{other, root}))
	assert.Equal(t, 0.0, rootDedicatedGB([]Lot{other}))
}

// makeLotWithDed is a test helper that builds a Lot with explicit
// CreationTime/ExpirationTime/DedicatedGB so the epoch allocator can
// see "already-promised bytes" from existing siblings.
func makeLotWithDed(name, path string, create, expire int64, ded float64) Lot {
	d := ded
	return Lot{
		LotName: name,
		Paths:   []LotPath{{Path: path, Recursive: true}},
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: create},
			ExpirationTime: &Int64FromFloat{Value: expire},
			DedicatedGB:    &d,
		},
	}
}

// Regression for the parent-attachment bug: when a parent and its
// child are both renewed in the same tick, the new child must attach to
// the NEW parent, not the now-expired old parent. The old behaviour
// inherited Parents[0] from the predecessor lot, which still pointed at
// the soon-to-be-reclaimed old parent UUID — failing axiom 3 at
// admission and orphaning the new child once the old parent was GC'd.
func TestResolveSuccessorParent_PrefersPlannedParentOverExpiredExisting(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)

	// Existing world: parent /a and child /a/b both expired in the past.
	parentOld := makeLot("uuid-parent-old", "/a", now-2*hour, now-hour)
	childOld := makeLot("uuid-child-old", "/a/b", now-2*hour, now-hour)
	childOld.Parents = []string{parentOld.LotName}
	existing := []Lot{parentOld, childOld}

	// Planned world: brand-new successors for both, both starting at
	// `now` and ending one default-lifetime later.
	parentNew := makeLot("uuid-parent-new", "/a", now, now+hour)
	childNew := makeLot("uuid-child-new", "/a/b", now, now+hour)
	planned := map[string][]*Lot{
		"/a":   {&parentNew},
		"/a/b": {&childNew},
	}

	got := resolveSuccessorParent("/a/b", now, existing, planned)
	assert.Equal(t, "uuid-parent-new", got,
		"child must attach to the freshly-planned parent, not the expired old parent")
}

// When only the child is being renewed but the existing parent still
// covers the child's creation_time, attach to the existing parent.
func TestResolveSuccessorParent_FallsBackToExistingCoveringParent(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)

	parent := makeLot("uuid-parent", "/a", now-hour, now+10*hour)
	existing := []Lot{parent}
	childNew := makeLot("uuid-child-new", "/a/b", now, now+hour)
	planned := map[string][]*Lot{"/a/b": {&childNew}}

	got := resolveSuccessorParent("/a/b", now, existing, planned)
	assert.Equal(t, "uuid-parent", got)
}

// First-ever lot for a top-level path with no covering ancestor falls
// back to "root".
func TestResolveSuccessorParent_RootFallback(t *testing.T) {
	got := resolveSuccessorParent("/a", 0, nil, nil)
	assert.Equal(t, "root", got)
}

// Picks the deepest covering ancestor when both /a and /a/b have
// covering lots and the new lot is /a/b/c.
func TestResolveSuccessorParent_PicksDeepestCoveringAncestor(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	a := makeLot("uuid-a", "/a", now-hour, now+10*hour)
	ab := makeLot("uuid-ab", "/a/b", now-hour, now+10*hour)
	existing := []Lot{a, ab}
	got := resolveSuccessorParent("/a/b/c", now, existing, nil)
	assert.Equal(t, "uuid-ab", got, "must pick the longest-prefix ancestor")
}

// Regression for the epoch-allocator double-counting bug: an existing
// sibling at the top level was being subtracted from `parentCap` AND
// added to the divisor, leaving capacity stranded. With root=1000 and
// an existing /x holding 400, three new /a /b /c must each receive
// (1000 − 400) / 3 = 200, not (1000 − 400) / 4 = 150.
func TestAllocateEpochAwareQuotas_MixedExistingAndPlannedSiblings(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 1000.0

	// Existing sibling /x already has 400 GB stamped, covering the
	// entire window of the new lots.
	existing := []Lot{makeLotWithDed("uuid-x", "/x", now-hour, now+48*hour, 400.0)}

	ads := adsForRenewal("/a", "/b", "/c", "/x")
	prop := renewExpiringLots(cfg, ads, existing)
	// /x is already covered by the existing lot inside the horizon, so
	// the planner mints only the three new top-level paths.
	require.Len(t, prop.newLots, 3, "planner should mint /a, /b, /c (not /x)")

	allocateEpochAwareQuotas(&prop, existing, ads, cfg)

	want := (1000.0 - 400.0) / 3.0 // = 200
	for _, l := range prop.newLots {
		require.NotNil(t, l.MPA.DedicatedGB)
		assert.InDelta(t, want, *l.MPA.DedicatedGB, 0.01,
			"lot %s for %q got %.2f, want %.2f (residual / nNew, not residual / (nNew+nExisting))",
			l.LotName, l.Paths[0].Path, *l.MPA.DedicatedGB, want)
	}
}

// Deeper-hierarchy divisor: when the parent /a has a stamped capacity
// and we plan two new children /a/b and /a/c, each must receive
// parent_capacity / (2 children + 1 parent reserve) = parent / 3 — the
// N+2 rule (2 newcomers + self counted via N+1 in the allocator's
// internal numbering, plus the parent reserve at deeper levels).
func TestAllocateEpochAwareQuotas_DeeperHierarchyDivisor(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 10000.0

	// Existing parent /a with 900 GB stamped covering the full horizon.
	parent := makeLotWithDed("uuid-a", "/a", now-hour, now+48*hour, 900.0)
	existing := []Lot{parent}

	ads := adsForRenewal("/a", "/a/b", "/a/c")
	prop := renewExpiringLots(cfg, ads, existing)
	// Only the two children are minted; /a is already covered.
	require.Len(t, prop.newLots, 2)

	allocateEpochAwareQuotas(&prop, existing, ads, cfg)

	// Parent has 900; two new children + 1 reserve share = 3-way split.
	want := 900.0 / 3.0
	for _, l := range prop.newLots {
		require.NotNil(t, l.MPA.DedicatedGB)
		assert.InDelta(t, want, *l.MPA.DedicatedGB, 0.01,
			"deeper-level lot %s for %q got %.2f, want %.2f (parent/3, leaving one reserve share)",
			l.LotName, l.Paths[0].Path, *l.MPA.DedicatedGB, want)
	}
}

// Multi-epoch: a new lot whose lifetime spans two epochs (sibling
// active in the first half, gone in the second) must be stamped with
// the SMALLER per-epoch share, so it is non-contracting in every
// epoch it lives through. With root=1200, a planned peer /b active for
// only the first half, the new lot /a sees:
//   - epoch 1 [now, now+12h): nActiveNew=1 (peer /b), divisor=2, share=600
//   - epoch 2 [now+12h, now+24h): nActiveNew=0, divisor=1, share=1200
//
// min-over-epochs = 600.
func TestAllocateEpochAwareQuotas_MultiEpoch_MinShareWins(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 1200.0

	// Pre-seed a planned-this-tick peer /b that is active only for the
	// first half of /a's window. We bypass the planner and inject the
	// peer directly into prop.newLots so we can control its window.
	prop := renewalProposal{}
	half := int64(12 * hour)
	create := now
	expireA := now + 24*hour
	expireB := now + half

	a := Lot{
		LotName: "uuid-a-new",
		Paths:   []LotPath{{Path: "/a", Recursive: true}},
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: create},
			ExpirationTime: &Int64FromFloat{Value: expireA},
		},
	}
	b := Lot{
		LotName: "uuid-b-new",
		Paths:   []LotPath{{Path: "/b", Recursive: true}},
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: create},
			ExpirationTime: &Int64FromFloat{Value: expireB},
		},
	}
	prop.newLots = []Lot{a, b}

	allocateEpochAwareQuotas(&prop, nil, nil, cfg)

	// Find /a; it should be stamped 600 (min over its 2 epochs), not
	// 1200 (the larger second-epoch share) and not 400 (which would
	// be the answer if the divisor incorrectly counted /b's window in
	// epoch 2 too).
	var aDed float64 = -1
	for _, l := range prop.newLots {
		if l.Paths[0].Path == "/a" {
			require.NotNil(t, l.MPA.DedicatedGB)
			aDed = *l.MPA.DedicatedGB
		}
	}
	assert.InDelta(t, 600.0, aDed, 0.01,
		"min-over-epochs share for /a should be 600 (root/2 in the epoch where /b is alive)")
}

// Regression for the planner-clamp+allocator interaction: when an
// existing sibling has zero stamped quota, it must NOT subtract from
// the residual capacity. Otherwise a misconfigured cache (or a lot
// whose quota was zeroed out by an earlier "no feasible share" path)
// would inflate `usedExisting` by zero (no harm) but the divisor
// behaviour is what changed: existing siblings shouldn't inflate the
// divisor either way. This locks that invariant in.
func TestAllocateEpochAwareQuotas_ExistingZeroQuotaSibling_DoesNotInflateDivisor(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)
	cfg := horizonRenewalCfg(now)
	cfg.HorizonMs = 24 * hour
	cfg.DefaultLifetimeMs = 24 * hour
	cfg.RootDedicatedGB = 900.0

	existing := []Lot{makeLotWithDed("uuid-z", "/z", now-hour, now+48*hour, 0.0)}
	ads := adsForRenewal("/a", "/b", "/c", "/z")
	prop := renewExpiringLots(cfg, ads, existing)
	require.Len(t, prop.newLots, 3) // /z is already covered

	allocateEpochAwareQuotas(&prop, existing, ads, cfg)

	want := 900.0 / 3.0 // existing /z contributes 0 bytes AND 0 to divisor
	for _, l := range prop.newLots {
		require.NotNil(t, l.MPA.DedicatedGB)
		assert.InDelta(t, want, *l.MPA.DedicatedGB, 0.01)
	}
}

// makeLotWithDeletion is like makeLot but also stamps a deletion_time
// so gcEligibleLots can reason about retention.
func makeLotWithDeletion(name, path string, create, expire, deletion int64) Lot {
	l := makeLot(name, path, create, expire)
	l.MPA.DeletionTime = &Int64FromFloat{Value: deletion}
	return l
}

// gcEligibleLots is a pure helper exercising every branch of runGcTick's
// eligibility decision: skip root/default, skip sentinel, skip
// missing/zero deletion_time, retention threshold (== eligible, > not
// eligible), and the retention<=0 fallback to 60 days.
func TestGcEligibleLots_BranchCoverage(t *testing.T) {
	const day = int64(24 * 60 * 60 * 1000)
	const ms = int64(time.Millisecond)
	_ = ms
	now := int64(1_000_000 * day) // arbitrary far-future wall clock

	// All have positive non-sentinel windows; only deletion_time varies.
	lots := []Lot{
		// root + default are unconditionally skipped.
		makeLotWithDeletion("root", "/", now-100*day, now-50*day, now-10*day),
		makeLotWithDeletion("default", "/x", now-100*day, now-50*day, now-10*day),

		// Sentinel lot (all-zero MPA timestamps) — never expires, never GC'd.
		{
			LotName: "sentinel",
			Paths:   []LotPath{{Path: "/sentinel"}},
			MPA: &MPA{
				CreationTime:   &Int64FromFloat{Value: 0},
				ExpirationTime: &Int64FromFloat{Value: 0},
				DeletionTime:   &Int64FromFloat{Value: 0},
			},
		},

		// No MPA / no DeletionTime / DeletionTime=0 → all skipped.
		{LotName: "no-mpa", Paths: []LotPath{{Path: "/a"}}},
		{LotName: "no-del", Paths: []LotPath{{Path: "/b"}}, MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: now - 5*day},
			ExpirationTime: &Int64FromFloat{Value: now - 1*day},
		}},
		makeLotWithDeletion("zero-del", "/c", now-5*day, now-day, 0),

		// retention=10d, now=now: cutoff = now - 10d.
		// trigger == cutoff is eligible (<=), trigger > cutoff is not.
		makeLotWithDeletion("eligible-on-cusp", "/d", now-100*day, now-50*day, now-10*day),
		makeLotWithDeletion("eligible-old", "/e", now-100*day, now-50*day, now-30*day),
		makeLotWithDeletion("not-yet", "/f", now-100*day, now-50*day, now-5*day),
		makeLotWithDeletion("future-del", "/g", now-100*day, now-50*day, now+5*day),
	}

	got := gcEligibleLots(lots, now, 10*24*time.Hour)
	assert.ElementsMatch(t, []string{"eligible-on-cusp", "eligible-old"}, got)

	// Empty input → empty output, never nil-deref.
	assert.Empty(t, gcEligibleLots(nil, now, 10*24*time.Hour))

	// retention<=0 falls back to the 60-day default. Same /e (deleted
	// 30d ago) is no longer eligible at the longer window.
	got = gcEligibleLots(lots, now, 0)
	assert.NotContains(t, got, "eligible-old")
	assert.NotContains(t, got, "eligible-on-cusp")
	// But a lot deleted 100d ago would be eligible under the 60d default.
	old := []Lot{makeLotWithDeletion("very-old", "/h", now-200*day, now-150*day, now-100*day)}
	assert.Equal(t, []string{"very-old"}, gcEligibleLots(old, now, 0))
}

// validateLotLifetime accepts:
//   - any lot with no MPA / missing timestamps (nothing to check)
//   - the all-zero sentinel
//   - lots whose span ≤ MaxLotLifetime
//   - any lot when MaxLotLifetime is unset (no admission cap)
//
// and rejects lots whose span exceeds MaxLotLifetime.
func TestValidateLotLifetime(t *testing.T) {
	const hour = int64(60 * 60 * 1000)

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	viper.Set("Lotman.MaxLotLifetime", "168h") // 7 days

	// Within bound (24h ≤ 168h): accept.
	in := makeLot("ok", "/a", 0, 24*hour)
	assert.NoError(t, validateLotLifetime(&in))

	// Exactly at the bound: accept (use <, not <=, in the validator).
	at := makeLot("at", "/a", 0, 168*hour)
	assert.NoError(t, validateLotLifetime(&at))

	// Over the bound: reject.
	over := makeLot("over", "/a", 0, 169*hour)
	err := validateLotLifetime(&over)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MaxLotLifetime")

	// Sentinel lot: accept regardless of MaxLotLifetime.
	sentinel := &Lot{
		LotName: "sentinel",
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: 0},
			ExpirationTime: &Int64FromFloat{Value: 0},
			DeletionTime:   &Int64FromFloat{Value: 0},
		},
	}
	assert.NoError(t, validateLotLifetime(sentinel))

	// nil / partial MPA: accept (nothing to check).
	assert.NoError(t, validateLotLifetime(nil))
	assert.NoError(t, validateLotLifetime(&Lot{LotName: "nil-mpa"}))
	assert.NoError(t, validateLotLifetime(&Lot{LotName: "no-create", MPA: &MPA{ExpirationTime: &Int64FromFloat{Value: 1}}}))

	// MaxLotLifetime unset → no cap, anything goes.
	server_utils.ResetTestState()
	viper.Set("Lotman.MaxLotLifetime", "0")
	huge := makeLot("huge", "/a", 0, 100000*hour)
	assert.NoError(t, validateLotLifetime(&huge))
}

// validateLotUpdateLifetime: when both creation_time and
// expiration_time are supplied in the update we never need to consult
// the live lot, so the validator runs entirely in-process. Cover the
// "updates neither timestamp" early-return, the "supplies both" branch,
// and the "MPA nil / update nil" guards. The mixed-supply branch
// (validator does an FFI GetLot) is exercised by integration tests
// that link against the lotman library.
func TestValidateLotUpdateLifetime_NoFFIBranches(t *testing.T) {
	const hour = int64(60 * 60 * 1000)

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	viper.Set("Lotman.MaxLotLifetime", "168h")

	// nil update / nil MPA: accept.
	assert.NoError(t, validateLotUpdateLifetime(nil))
	assert.NoError(t, validateLotUpdateLifetime(&LotUpdate{LotName: "x"}))

	// Update touches neither timestamp: accept (nothing to check).
	owner := "alice"
	assert.NoError(t, validateLotUpdateLifetime(&LotUpdate{
		LotName: "x",
		Owner:   &owner,
		MPA:     &MPA{},
	}))

	// Update supplies both timestamps within bound: accept.
	ok := &LotUpdate{
		LotName: "x",
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: 0},
			ExpirationTime: &Int64FromFloat{Value: 24 * hour},
		},
	}
	assert.NoError(t, validateLotUpdateLifetime(ok))

	// Update supplies both timestamps over bound: reject.
	over := &LotUpdate{
		LotName: "x",
		MPA: &MPA{
			CreationTime:   &Int64FromFloat{Value: 0},
			ExpirationTime: &Int64FromFloat{Value: 200 * hour},
		},
	}
	err := validateLotUpdateLifetime(over)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "MaxLotLifetime")
}

// assignSuccessorParents wires up `Parents[0]` from the (path,
// creation_time) pair of every planned lot, sourcing creation_time
// from MPA.CreationTime.Value and building the planned-this-tick
// sibling map from the input slice. This test guards against subtle
// wiring regressions (e.g. someone passing 0 as the create time, or
// forgetting to feed prop.newLots into the planned-parent index).
func TestAssignSuccessorParents_WiresParentAndCreateTime(t *testing.T) {
	const hour = int64(60 * 60 * 1000)
	now := int64(100 * hour)

	// Existing world: parent /a expired in past, with a single
	// historical child.
	parentOld := makeLot("uuid-parent-old", "/a", now-2*hour, now-hour)
	existing := []Lot{parentOld}

	// Planned world: a new /a (this tick) and a new /a/b. The child
	// must receive the NEW parent's UUID, not "root".
	newLots := []Lot{
		makeLot("uuid-parent-new", "/a", now, now+hour),
		makeLot("uuid-child-new", "/a/b", now, now+hour),
	}

	assignSuccessorParents(newLots, existing)

	// Find each lot back; assignSuccessorParents mutates in place.
	parentByPath := map[string]Lot{}
	for _, l := range newLots {
		parentByPath[l.Paths[0].Path] = l
	}
	a := parentByPath["/a"]
	ab := parentByPath["/a/b"]

	require.Len(t, a.Parents, 1)
	assert.Equal(t, "root", a.Parents[0],
		"top-level /a has no covering ancestor → root")

	require.Len(t, ab.Parents, 1)
	assert.Equal(t, "uuid-parent-new", ab.Parents[0],
		"child must attach to the planned-this-tick parent, not the expired old parent or root")
}

// assignSuccessorParents must tolerate lots without an MPA
// (creation_time defaulted to 0) without panicking, and must skip lots
// with no Paths.
func TestAssignSuccessorParents_HandlesDegenerateLots(t *testing.T) {
	newLots := []Lot{
		{LotName: "no-paths"},                               // no Paths → skip
		{LotName: "no-mpa", Paths: []LotPath{{Path: "/a"}}}, // no MPA → createTime=0
	}
	require.NotPanics(t, func() { assignSuccessorParents(newLots, nil) })
	// "no-paths" is skipped (still has nil Parents); "no-mpa" gets root.
	assert.Nil(t, newLots[0].Parents)
	require.Len(t, newLots[1].Parents, 1)
	assert.Equal(t, "root", newLots[1].Parents[0])
}

// isMonitoringPath: matches the monitoring root, anything strictly
// underneath it, and rejects sibling paths whose name shares a prefix
// (no /monitoringX false-positive).
func TestIsMonitoringPath(t *testing.T) {
	mon := server_utils.MonitoringBaseNs

	assert.True(t, isMonitoringPath(mon),
		"monitoring root is itself a monitoring path")
	assert.True(t, isMonitoringPath(mon+"/foo"),
		"strict descendant of monitoring root is a monitoring path")
	assert.True(t, isMonitoringPath(mon+"/foo/bar"))
	assert.False(t, isMonitoringPath("/random/ns"))
	// Sibling that shares a textual prefix but is NOT a path-segment
	// descendant: mon = "/pelican/monitoring", trickster =
	// "/pelican/monitoringX/oops" must NOT match.
	assert.False(t, isMonitoringPath(mon+"X"),
		"sibling whose name extends the monitoring base must not match")
	assert.False(t, isMonitoringPath(mon+"X/foo"))
}
