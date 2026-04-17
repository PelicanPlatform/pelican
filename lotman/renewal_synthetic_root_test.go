//go:build linux && !ppc64le

package lotman

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestInitPlusRenewalUnderFilesMaxSize reproduces the cache startup failure
// reported when Cache.FilesMaxSize clamps the root lot to a value smaller
// than what naive per-namespace allocation would consume across the
// init-lots + first-renewal-tick overlap window.
//
// Scenario (matches the user's pelican.yaml):
//   - HighWaterMark: 5g, FilesMaxSize: 3g → computeRootDedicatedGB → 3 GB
//   - Two top-level namespaces /my-prefix and /my-prefix2 → init mints
//     two lots at 3 / 2 = 1.5 GB each
//   - LaunchRenewalRoutine fires an immediate tick → mints successors
//   - Lotman's axiom-1 admission must hold: Σ active children's
//     dedicated_GB at every instant ≤ root.dedicated_GB = 3.0 GB
func TestInitPlusRenewalUnderFilesMaxSize(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(server_utils.ResetTestState)

	server := getMockDiscoveryHost()
	defer server.Close()

	// Set up server config like a real cache.
	require.NoError(t, param.ConfigBase.Set(t.TempDir()))
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))
	require.NoError(t, param.Logging_Level.Set("debug"))

	// Use a real directory so totalDiskSpaceB > 0 and the HWM/FilesMaxSize
	// clamping branches in computeRootDedicatedGB actually execute. The
	// in-container /tmp filesystem has plenty of capacity, so the disk
	// total is many GB and the small HWM/FilesMaxSize values bind.
	dataDir, err := os.MkdirTemp("", "cache-data-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dataDir) })
	require.NoError(t, param.Cache_DataLocations.Set([]string{dataDir}))

	// User's exact cache config.
	require.NoError(t, param.Cache_HighWaterMark.Set("5g"))
	require.NoError(t, param.Cache_LowWaterMark.Set("4g"))
	require.NoError(t, param.Cache_FilesMaxSize.Set("3g"))

	// Default lotman lifetimes/horizon (matches production).
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(24*time.Hour))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(48*time.Hour))
	require.NoError(t, param.Lotman_MaxLotLifetime.Set(168*time.Hour))
	require.NoError(t, param.Lotman_SchedulingHorizon.Set(48*time.Hour))
	require.NoError(t, param.Lotman_RenewalCheckInterval.Set(1*time.Hour))
	require.NoError(t, param.Lotman_LotHome.Set(t.TempDir()))

	_ = config.InitServer(context.Background(), server_structs.CacheType)

	issuerURL, _ := url.Parse("https://issuer.example/")
	ads := []server_structs.NamespaceAdV2{
		{Path: "/my-prefix", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
		{Path: "/my-prefix2", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
	}

	require.True(t, InitLotman(ads), "InitLotman must succeed with FilesMaxSize=3g + 2 namespaces")

	// Confirm root capacity and per-namespace allocations.
	rootLot, err := GetLot("root", false)
	require.NoError(t, err)
	require.NotNil(t, rootLot.MPA)
	require.NotNil(t, rootLot.MPA.DedicatedGB)
	t.Logf("root.dedicated_GB = %.3f", *rootLot.MPA.DedicatedGB)

	allAfterInit, err := ListAllLots()
	require.NoError(t, err)
	t.Logf("After init: %v", allAfterInit)
	for _, name := range allAfterInit {
		if name == "root" || name == "default" {
			continue
		}
		l, err := GetLot(name, false)
		require.NoError(t, err)
		var ded float64
		if l.MPA != nil && l.MPA.DedicatedGB != nil {
			ded = *l.MPA.DedicatedGB
		}
		t.Logf("  init lot %s paths=%v dedicated_GB=%.3f window=[%v, %v)",
			name, l.Paths, ded,
			l.MPA.CreationTime.Value, l.MPA.ExpirationTime.Value)
	}

	// Run the immediate renewal tick that LaunchRenewalRoutine fires at
	// startup. This is where the production cache reports
	// "Hierarchy violation: peak concurrent dedicated_GB across children
	// of parent lot 'root' is 6.0, which exceeds 3.0".
	getAds := func() []server_structs.NamespaceAdV2 { return ads }
	runRenewalTick(getAds, time.Hour)

	allAfterTick, err := ListAllLots()
	require.NoError(t, err)
	t.Logf("After renewal tick: %v", allAfterTick)

	rootCap := *rootLot.MPA.DedicatedGB

	// Walk every active lot at every distinct creation/expiration boundary
	// and verify axiom 1: Σ dedicated_GB of active children of root
	// ≤ root.dedicated_GB. This is the property lotman enforces at
	// admission; reproducing it here as a sweep ensures the test fails
	// the same way lotman fails inside CreateLot.
	type evt struct {
		name string
		ded  float64
		c, e int64
	}
	var lots []evt
	cuts := map[int64]struct{}{}
	for _, name := range allAfterTick {
		if name == "root" || name == "default" {
			continue
		}
		l, err := GetLot(name, false)
		require.NoError(t, err)
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		var ded float64
		if l.MPA.DedicatedGB != nil {
			ded = *l.MPA.DedicatedGB
		}
		if len(l.Parents) > 0 && l.Parents[0] != "root" {
			continue
		}
		lots = append(lots, evt{name, ded, l.MPA.CreationTime.Value, l.MPA.ExpirationTime.Value})
		cuts[l.MPA.CreationTime.Value] = struct{}{}
		cuts[l.MPA.ExpirationTime.Value] = struct{}{}
		t.Logf("  child-of-root lot %s ded=%.3f window=[%v, %v)",
			name, ded, l.MPA.CreationTime.Value, l.MPA.ExpirationTime.Value)
	}

	for cut := range cuts {
		sum := 0.0
		for _, l := range lots {
			if l.c <= cut && cut < l.e {
				sum += l.ded
			}
		}
		assert.LessOrEqualf(t, sum, rootCap+1e-9,
			"axiom 1 violated at instant %v: Σ active children dedicated_GB = %.3f exceeds root %.3f",
			cut, sum, rootCap)
	}

	// The original bug stamped each /my-prefix successor with the FULL
	// root capacity (3.0 GB) because topLevelSiblings treated the
	// synthetic "/" root entry as an ancestor and so excluded every real
	// namespace from the sibling set, making divisor=1. As a result,
	// lotman rejected ALL /my-prefix2 successors at CreateLot with a
	// "peak concurrent dedicated_GB exceeds parent" hierarchy violation.
	// Assert that both namespaces ended up with at least one successor
	// (init lot + ≥ 1 renewal lot).
	type pathSpan struct {
		create, expire int64
	}
	spansByPath := map[string][]pathSpan{}
	for _, name := range allAfterTick {
		if name == "root" || name == "default" {
			continue
		}
		l, err := GetLot(name, false)
		require.NoError(t, err)
		if l.MPA == nil || l.MPA.CreationTime == nil || l.MPA.ExpirationTime == nil {
			continue
		}
		if len(l.Parents) > 0 && l.Parents[0] != "root" {
			continue
		}
		for _, p := range l.Paths {
			np := p.Path
			if len(np) > 1 && np[len(np)-1] == '/' {
				np = np[:len(np)-1]
			}
			spansByPath[np] = append(spansByPath[np], pathSpan{l.MPA.CreationTime.Value, l.MPA.ExpirationTime.Value})
		}
	}
	for _, want := range []string{"/my-prefix", "/my-prefix2"} {
		assert.GreaterOrEqualf(t, len(spansByPath[want]), 2,
			"namespace %q should have init lot + ≥1 renewal successor; got %d lots. "+
				"Lotman rejected this namespace's renewals as hierarchy violations, which is "+
				"how the user's cache fails to start.", want, len(spansByPath[want]))
	}

	// Restart simulation: invoking InitLotman a second time against the
	// same on-disk DB must NOT mint duplicate init lots for namespaces
	// whose paths are still covered by lots from the prior run. Before
	// the filterAdsAlreadyScheduled guard, this second call failed with:
	//   "Hierarchy violation: peak concurrent dedicated_GB across
	//    children of parent lot 'root' is 4.500000, which exceeds
	//    the parent's dedicated_GB allocation of 3.000000."
	// because the new UUID lot's [now, now+24h) window overlapped the
	// pre-existing UUID lot's still-active [now, now+24h) window.
	require.True(t, InitLotman(ads), "second InitLotman call (restart) must succeed when DB already covers the ad paths")

	allAfterRestart, err := ListAllLots()
	require.NoError(t, err)

	// Count distinct top-level child lots per namespace before vs after
	// the restart call. The restart must add zero new init lots; the
	// only growth allowed is renewal successors (which are minted by
	// runRenewalTick, not by InitLotman).
	gotByPath := map[string]int{}
	for _, name := range allAfterRestart {
		if name == "root" || name == "default" {
			continue
		}
		l, err := GetLot(name, false)
		require.NoError(t, err)
		if l == nil || len(l.Parents) == 0 || l.Parents[0] != "root" {
			continue
		}
		for _, p := range l.Paths {
			np := p.Path
			if len(np) > 1 && np[len(np)-1] == '/' {
				np = np[:len(np)-1]
			}
			gotByPath[np]++
		}
	}
	for _, want := range []string{"/my-prefix", "/my-prefix2"} {
		assert.Equalf(t, len(spansByPath[want]), gotByPath[want],
			"restart minted duplicate lots for %q: had %d before, %d after",
			want, len(spansByPath[want]), gotByPath[want])
	}
}
