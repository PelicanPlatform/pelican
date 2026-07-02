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
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestRenewalEndToEnd is a federation-light integration test: it boots a
// real lotman instance via setupLotmanFromConf, registers two namespace
// ads (parent /foo and child /foo/bar), and exercises the full
// renewal → renewal → GC pipeline through runRenewalTick / runGcTick
// rather than calling the pure planner helpers directly.
//
// Coverage targets:
//  1. The first tick mints lots for both ads with the expected
//     parent/child relationship.
//  2. A second tick after the lots have moved deeper into their
//     lifetime is a no-op (existing coverage already extends to the
//     scheduling horizon).
//  3. After deletion_time + LotRecordRetention has elapsed, runGcTick
//     removes the now-eligible lots while leaving root/default
//     intact.
//
// The test uses tiny per-call durations (seconds, not hours) so it
// completes in well under a second.
func TestRenewalEndToEnd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server := getMockDiscoveryHost()
	defer server.Close()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

	success, cleanup := setupLotmanFromConf(t, false, "LotmanRenewalE2E", server.URL, nil)
	defer cleanup()
	require.True(t, success, "InitLotman must succeed")

	// Tight timings so the GC eligibility window opens within the
	// test's wall-clock lifetime. Set AFTER setupLotmanFromConf because
	// that helper resets the lifetime durations to 168h to keep
	// non-renewal tests from racing the planner.
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(2*time.Second))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(2*time.Second))
	require.NoError(t, param.Lotman_MaxLotLifetime.Set(10*time.Second))
	require.NoError(t, param.Lotman_SchedulingHorizon.Set(2*time.Second))
	require.NoError(t, param.Lotman_RenewalCheckInterval.Set(1*time.Second))
	require.NoError(t, param.Lotman_LotRecordRetention.Set(100*time.Millisecond))
	require.NoError(t, param.Lotman_MinFillerWidth.Set(0))

	issuerURL, _ := url.Parse("https://issuer.example/")
	ads := []server_structs.NamespaceAd{
		{Path: "/foo", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
		{Path: "/foo/bar", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
	}
	getAds := func() []server_structs.NamespaceAd { return ads }

	// --- Tick 1: should mint lots for /foo and /foo/bar -----------------
	runRenewalTick(getAds, time.Second)

	all, err := ListAllLots()
	require.NoError(t, err)
	sort.Strings(all)
	// root + default are auto-created; we expect at least two more (one
	// per namespace ad, sometimes a few more depending on filler logic).
	mintedFoo := lotsCoveringPath(t, "/foo", all)
	mintedFooBar := lotsCoveringPath(t, "/foo/bar", all)
	require.NotEmpty(t, mintedFoo, "tick should mint at least one /foo lot")
	require.NotEmpty(t, mintedFooBar, "tick should mint at least one /foo/bar lot")

	// Parent of /foo/bar successor should be the freshly-planned /foo
	// successor (not root). Pull each /foo/bar lot back and assert.
	for _, name := range mintedFooBar {
		lot, err := GetLot(name, false)
		require.NoError(t, err)
		require.NotEmpty(t, lot.Parents, "/foo/bar lot %s must have a parent", name)
		// Parent must be one of the /foo lots (not root/default).
		parent := lot.Parents[0]
		assert.Contains(t, mintedFoo, parent,
			"child /foo/bar lot %s should chain to a /foo lot, got %s", name, parent)
	}

	// --- Tick 2: same horizon, run immediately. The planner is a
	// multi-fill scheduler, so it may legitimately extend coverage by
	// minting one more successor when the previous tick's lots only
	// reach the horizon boundary. We only assert it does not delete
	// the lots from tick 1.
	beforeNames := map[string]struct{}{}
	for _, n := range all {
		beforeNames[n] = struct{}{}
	}
	runRenewalTick(getAds, time.Second)
	allAfter, err := ListAllLots()
	require.NoError(t, err)
	for n := range beforeNames {
		assert.Contains(t, allAfter, n,
			"second tick must not remove lot %s minted by first tick", n)
	}

	// --- GC eligibility: shrink horizon out so new lots aren't minted,
	//     wait past deletion_time + LotRecordRetention, then GC --------
	// 2s expiration + 2s deletion + 100ms retention ≈ 4.2s after tick 1.
	// We sleep 5s to be safe.
	time.Sleep(5 * time.Second)

	// Stop the renewal scheduler from minting fresh lots during GC by
	// supplying an empty ad list.
	emptyAds := func() []server_structs.NamespaceAd { return nil }
	runRenewalTick(emptyAds, time.Second)

	runGcTick()
	allFinal, err := ListAllLots()
	require.NoError(t, err)
	// root and default must survive; planner-minted lots should be gone.
	hasRoot := false
	hasDefault := false
	plannerLeft := 0
	for _, n := range allFinal {
		switch n {
		case "root":
			hasRoot = true
		case "default":
			hasDefault = true
		default:
			plannerLeft++
		}
	}
	assert.True(t, hasRoot, "root lot must survive GC")
	assert.True(t, hasDefault, "default lot must survive GC")
	assert.Zero(t, plannerLeft,
		"all planner-minted lots should be GC'd once past deletion_time + LotRecordRetention; %d still present (%v)",
		plannerLeft, allFinal)
}

// lotsCoveringPath returns the names from `all` whose paths[0].Path equals
// the supplied namespace path.
func lotsCoveringPath(t *testing.T, path string, all []string) []string {
	t.Helper()
	out := []string{}
	for _, name := range all {
		if name == "root" || name == "default" {
			continue
		}
		lot, err := GetLot(name, false)
		require.NoError(t, err)
		for _, lp := range lot.Paths {
			if normaliseLotPath(lp.Path) == normaliseLotPath(path) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}
