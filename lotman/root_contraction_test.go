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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestInitSurvivesRootContraction reproduces the failure mode
//
//	Unable to update lot root: error updating lot: ...
//	Contraction policy 'always' blocks reduction of 'dedicated_GB' on lot
//	'root'. Set admin_override to bypass.
//
// which fired when a cache administrator lowered Cache.FilesMaxSize
// (or HighWaterMark) between restarts. The root lot's dedicated_GB is
// derived from those settings, so the second InitLotman call must
// shrink root's MPA -- something lotman's contraction_policy=always
// would otherwise block.
//
// The fix uses admin_override for root/default updates and reclaims
// any descendants whose existing reservations no longer fit under the
// new budget. After contraction:
//   - InitLotman must succeed,
//   - the root lot's dedicated_GB must reflect the smaller post-restart
//     setting, and
//   - any descendant lot minted before the contraction must be marked
//     reclaimed (so it no longer counts against hierarchy enforcement).
func TestInitSurvivesRootContraction(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server := getMockDiscoveryHost()
	defer server.Close()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

	// First boot: large cache + one namespace ad so a descendant lot is
	// minted alongside root/default.
	issuerURL, _ := url.Parse("https://issuer.example/")
	ads := []server_structs.NamespaceAdV2{
		{Path: "/foo", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
	}

	require.NoError(t, param.Cache_FilesMaxSize.Set("100g"))
	success, cleanup := setupLotmanFromConf(t, false, "LotmanRootContractionFirst",
		server.URL, ads)
	defer cleanup()
	require.True(t, success, "initial InitLotman must succeed")

	// Sanity: root has the larger dedicated_GB and at least one
	// non-sentinel descendant exists.
	rootBefore, err := GetLot("root", false)
	require.NoError(t, err)
	require.NotNil(t, rootBefore.MPA.DedicatedGB)
	largeDedicated := *rootBefore.MPA.DedicatedGB
	require.Greater(t, largeDedicated, 1.0,
		"root.dedicated_GB before contraction should be the full configured size")

	descendantsBefore, err := GetChildrenNames("root", true, false)
	require.NoError(t, err)
	nonSentinelBefore := filterSentinels(descendantsBefore)
	require.NotEmpty(t, nonSentinelBefore,
		"first boot should mint at least one non-sentinel descendant of root")

	// Simulate an admin restart with a much smaller cache budget.
	// Reusing the same LotHome so the second InitLotman finds the
	// existing database -- this is the exact scenario the user hit.
	require.NoError(t, param.Cache_FilesMaxSize.Set("5m"))
	require.NoError(t, param.Cache_HighWaterMark.Set("5m"))
	require.NoError(t, param.Cache_LowWatermark.Set("4m"))

	// Second boot against the SAME LotHome (do not run setupLotmanFromConf
	// again -- that would generate a new tmp dir). Instead, drive
	// InitLotman directly with the existing on-disk DB.
	require.True(t, InitLotman(ads),
		"InitLotman must survive an admin-driven Cache.FilesMaxSize reduction")

	// Root's dedicated_GB must reflect the smaller setting.
	rootAfter, err := GetLot("root", false)
	require.NoError(t, err)
	require.NotNil(t, rootAfter.MPA.DedicatedGB)
	assert.Less(t, *rootAfter.MPA.DedicatedGB, largeDedicated,
		"root.dedicated_GB must contract after admin lowers Cache.FilesMaxSize")

	// Descendants minted under the old root budget must have been
	// reclaimed -- otherwise the renewal tick would still see them and
	// strict_hierarchy would forbid minting fresh successors against
	// the smaller root. GetLotsForPath with includeReclaimed=false
	// drops reclaimed lots, so once contraction completes the only
	// lot remaining for /foo's window should be the synthetic
	// "default".
	nowMs := time.Now().UnixMilli()
	covering, err := GetLotsForPath("/foo", true, nowMs, nowMs+1, false)
	require.NoError(t, err)
	for _, lot := range covering {
		assert.Contains(t, []string{"default", "root"}, lot.LotName,
			"non-sentinel descendant %s should have been reclaimed after root contraction", lot.LotName)
	}

	// Allow time for any reclamation effects to settle, then verify the
	// renewal tick can now plan against the contracted budget without
	// hitting a hierarchy violation.
	require.NoError(t, param.Lotman_RenewalCheckInterval.Set(1*time.Second))
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(2*time.Minute))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(2*time.Minute))
	require.NoError(t, param.Lotman_SchedulingHorizon.Set(30*time.Second))
	require.NoError(t, param.Lotman_MaxLotLifetime.Set(10*time.Minute))
	require.NoError(t, param.Lotman_MinFillerWidth.Set(0))

	runRenewalTick(func() []server_structs.NamespaceAdV2 { return ads }, time.Second)
}

func filterSentinels(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "root" || n == "default" {
			continue
		}
		out = append(out, n)
	}
	return out
}
