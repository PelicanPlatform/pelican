//go:build linux && !ppc64le && lotman

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestConcurrentReadAndWriteFFI is a regression test for the GC failures
// that surfaced as
//
//	error querying lots-past-del: Failure on call to
//	  update_db_children_usage() ... list_all_lots failed:
//	  bad parameter or other API misuse
//
// or, less often, "out of memory" -- both classic symptoms of two
// goroutines hitting the shared SQLite handle inside libLotMan without
// serialisation.
//
// The root cause was that lotman's "Get*Past*" / "GetLotsForPath" /
// "GetLot" C entry points call update_db_children_usage() under the
// hood, which rewrites every lot's cached usage rows. That makes them
// effective writers, not pure readers, so they MUST be serialised
// against the renewal goroutine's CreateLot/UpdateLot/RemoveLot calls.
//
// This test hammers the FFI with concurrent reader/writer goroutines
// for ~2 seconds. Before the lock fix this reliably trips at least one
// SQLite error within the first few hundred iterations; with the fix
// it must complete cleanly.
func TestConcurrentReadAndWriteFFI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server := getMockDiscoveryHost()
	defer server.Close()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(server.URL))

	success, cleanup := setupLotmanFromConf(t, false, "LotmanConcurrentFFI", server.URL, nil)
	defer cleanup()
	require.True(t, success, "InitLotman must succeed")

	// Generous lifetimes so renewal ticks always have work to do but
	// nothing GC's mid-test.
	require.NoError(t, param.Lotman_DefaultLotExpirationLifetime.Set(2*time.Hour))
	require.NoError(t, param.Lotman_DefaultLotDeletionLifetime.Set(2*time.Hour))
	require.NoError(t, param.Lotman_MaxLotLifetime.Set(48*time.Hour))
	require.NoError(t, param.Lotman_SchedulingHorizon.Set(2*time.Hour))
	require.NoError(t, param.Lotman_LotRecordRetention.Set(72*time.Hour))
	require.NoError(t, param.Lotman_MinFillerWidth.Set(0))

	issuerURL, _ := url.Parse("https://issuer.example/")
	ads := []server_structs.NamespaceAdV2{
		{Path: "/foo", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
		{Path: "/foo/bar", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
		{Path: "/baz", Issuer: []server_structs.TokenIssuer{{IssuerUrl: *issuerURL}}},
	}
	getAds := func() []server_structs.NamespaceAdV2 { return ads }

	// Seed the DB with one tick so reads have something to look at.
	runRenewalTick(getAds, time.Second)

	var (
		wg      sync.WaitGroup
		stop    atomic.Bool
		errMu   sync.Mutex
		errList []error
	)

	record := func(err error) {
		errMu.Lock()
		errList = append(errList, err)
		errMu.Unlock()
	}

	// Reader goroutines: hammer the unlocked read-side wrappers that
	// used to race. Each of these ultimately invokes
	// update_db_children_usage() inside lotman C.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if _, err := GetLotsPastDel(time.Now().UnixMilli(), false, true); err != nil {
					record(err)
					return
				}
				if _, err := GetLotsPastExp(time.Now().UnixMilli(), false, true); err != nil {
					record(err)
					return
				}
				if _, err := GetLotsForPath("/foo/bar", true,
					time.Now().UnixMilli(),
					time.Now().Add(time.Hour).UnixMilli(), false); err != nil {
					record(err)
					return
				}
				if _, err := ListAllLots(); err != nil {
					record(err)
					return
				}
			}
		}()
	}

	// Writer goroutine: drives the renewal tick, which calls
	// CreateLot/UpdateLot under callerMutex.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			runRenewalTick(getAds, time.Second)
		}
	}()

	// GC goroutine: same pattern as the production tick.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			runGcTick()
		}
	}()

	time.Sleep(2 * time.Second)
	stop.Store(true)
	wg.Wait()

	if len(errList) > 0 {
		// Surface the first error so the failure message is actionable.
		t.Fatalf("FFI race produced %d errors; first: %v", len(errList), errList[0])
	}
}
