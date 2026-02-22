/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestLaunchTTLCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	mockPelicanOriginServerAd := server_structs.ServerAd{
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8444",
		},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockPelicanOriginServerAd.Initialize("test-origin-server")

	mockNamespaceAd := server_structs.NamespaceAdV2{
		Caps:   server_structs.Capabilities{PublicReads: false},
		Path:   "/foo/bar/",
		Issuer: []server_structs.TokenIssuer{{IssuerUrl: url.URL{}}},
		Generation: []server_structs.TokenGen{{
			MaxScopeDepth: 1,
			Strategy:      "",
			VaultServer:   "",
		},
		},
	}

	t.Run("evicted-origin-can-cancel-health-test", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		LaunchTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		errgrp, errgrpCtx := errgroup.WithContext(shutdownCtx)
		ctx, cancelFunc := context.WithDeadline(errgrpCtx, time.Now().Add(time.Second*5))

		func() {
			serverAds.DeleteAll()
			resetHealthTests()

			serverAds.Set(mockPelicanOriginServerAd.URL.String(), &server_structs.Advertisement{
				ServerAd:     mockPelicanOriginServerAd,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
			}, ttlcache.DefaultTTL)
			healthTestUtilsMutex.Lock()
			defer healthTestUtilsMutex.Unlock()
			healthTestUtils[mockPelicanOriginServerAd.URL.String()] = &healthTestUtil{
				Cancel:        cancelFunc,
				ErrGrp:        errgrp,
				ErrGrpContext: errgrpCtx,
			}

			require.True(t, serverAds.Has(mockPelicanOriginServerAd.URL.String()), "serverAds failed to register the originAd")
		}()

		cancelChan := make(chan int)
		go func() {
			<-ctx.Done()
			if ctx.Err() == context.Canceled {
				cancelChan <- 1
			}
		}()

		func() {
			serverAds.Delete(mockPelicanOriginServerAd.URL.String()) // This should call onEviction handler and close the context

			require.False(t, serverAds.Has(mockPelicanOriginServerAd.URL.String()), "serverAds didn't delete originAd")
		}()

		// OnEviction is handled on a different goroutine than the cache management
		// So we want to wait for a bit so that OnEviction can have time to be
		// executed
		select {
		case <-cancelChan:
			require.True(t, true)
		case <-time.After(3 * time.Second):
			require.False(t, true)
		}
	})
}

func TestServerAdsCacheEviction(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	mockServerAd := server_structs.ServerAd{Type: server_structs.OriginType.String(), URL: url.URL{Host: "mock.server.org"}}
	mockServerAd.Initialize("foo")

	t.Run("evict-after-expire-time", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		LaunchTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		deletedChan := make(chan int)
		cancelChan := make(chan int)

		func() {
			serverAds.DeleteAll()

			serverAds.Set(mockServerAd.URL.String(), &server_structs.Advertisement{
				ServerAd:     mockServerAd,
				NamespaceAds: []server_structs.NamespaceAdV2{},
			}, time.Second*2)
			require.True(t, serverAds.Has(mockServerAd.URL.String()), "Failed to register server Ad")
		}()

		// Keep checking if the cache item is present until absent or cancelled
		go func() {
			for {
				select {
				case <-cancelChan:
					return
				default:
					if !serverAds.Has(mockServerAd.URL.String()) {
						deletedChan <- 1
						return
					}
				}
			}
		}()

		// Wait for 3s to check if the expired cache item is evicted
		select {
		case <-deletedChan:
			require.True(t, true)
		case <-time.After(3 * time.Second):
			cancelChan <- 1
			require.False(t, true, "Cache didn't evict expired item")
		}
	})
}

func TestRecordAd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		// Drain any background goroutines spawned by health/stat utilities to avoid leaks across tests.
		shutdownHealthTests()
		shutdownStatUtils()
	})

	resetHealthTests()
	shutdownStatUtils()

	serverAds.DeleteAll()
	go serverAds.Start()
	t.Cleanup(func() {
		serverAds.DeleteAll()
		serverAds.Stop()
	})

	topologyServerUrl := url.URL{Scheme: "http", Host: "origin.chtc.wisc.edu"} // Topology server URL is always in http
	pelicanServerUrl := url.URL{Scheme: "https", Host: "origin.chtc.wisc.edu"} // Pelican server URL is always in https

	mockTopology := &server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			URL:          topologyServerUrl,
			FromTopology: true,
		},
		NamespaceAds: []server_structs.NamespaceAdV2{},
	}
	mockPelican := &server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			URL:          pelicanServerUrl,
			FromTopology: false,
		},
		NamespaceAds: []server_structs.NamespaceAdV2{},
	}

	t.Run("topology-server-added-if-no-duplicate", func(t *testing.T) {
		defer serverAds.DeleteAll()
		recordAd(context.Background(), mockTopology.ServerAd, &mockTopology.NamespaceAds)
		assert.Len(t, serverAds.Items(), 1)
		assert.True(t, serverAds.Has(topologyServerUrl.String()))
	})

	t.Run("pelican-server-added-if-no-duplicate", func(t *testing.T) {
		defer serverAds.DeleteAll()
		recordAd(context.Background(), mockPelican.ServerAd, &mockPelican.NamespaceAds)
		assert.Len(t, serverAds.Items(), 1)
		assert.True(t, serverAds.Has(pelicanServerUrl.String()))
	})

	t.Run("pelican-server-overwrites-topology", func(t *testing.T) {
		defer serverAds.DeleteAll()
		recordAd(context.Background(), mockTopology.ServerAd, &mockTopology.NamespaceAds)
		recordAd(context.Background(), mockPelican.ServerAd, &mockPelican.NamespaceAds)

		assert.Len(t, serverAds.Items(), 1)
		assert.True(t, serverAds.Has(pelicanServerUrl.String()))
		getAd := serverAds.Get(pelicanServerUrl.String())
		assert.NotNil(t, getAd)
		assert.False(t, getAd.Value().FromTopology) // it's updated
	})

	t.Run("topology-server-is-ignored-with-dup-pelican-server", func(t *testing.T) {
		defer serverAds.DeleteAll()
		recordAd(context.Background(), mockPelican.ServerAd, &mockPelican.NamespaceAds)
		recordAd(context.Background(), mockTopology.ServerAd, &mockTopology.NamespaceAds)

		assert.Len(t, serverAds.Items(), 1)
		assert.True(t, serverAds.Has(pelicanServerUrl.String()))
		getAd := serverAds.Get(pelicanServerUrl.String())
		assert.NotNil(t, getAd)
		assert.False(t, getAd.Value().FromTopology) // topology ad is ignored
	})

	t.Run("recorded-sad-should-match-health-test-utils-one", func(t *testing.T) {
		t.Cleanup(func() {
			server_utils.ResetTestState()
			resetHealthTests()
			shutdownStatUtils()
			serverAds.DeleteAll()
			geoNetOverrides = nil
			geoOverridesOnce = sync.Once{}
		})
		server_utils.ResetTestState()
		func() {
			geoNetOverrides = nil
			geoOverridesOnce = sync.Once{}
			resetHealthTests()
			shutdownStatUtils()
			serverAds.DeleteAll()
		}()

		require.NoError(t, param.Set("GeoIPOverrides", []map[string]interface{}{{"IP": "192.168.100.100", "Coordinate": map[string]float64{"lat": 43.567, "long": -65.322}}}))
		mockUrl := url.URL{Scheme: "https", Host: "192.168.100.100"}
		serverAd := server_structs.ServerAd{URL: mockUrl, WebURL: mockUrl, FromTopology: false}
		serverAd.Initialize("TEST_ORIGIN")
		updatedAd := recordAd(context.Background(), serverAd, &mockPelican.NamespaceAds)
		assert.NotEmpty(t, updatedAd.Longitude)
		assert.NotEmpty(t, updatedAd.Latitude)
		_, ok := healthTestUtils[mockUrl.String()]
		assert.True(t, ok)
	})
}

func TestGetRawStatusWeight(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name           string
		status         metrics.HealthStatusEnum
		expectedWeight float64
	}{
		{
			name:           "StatusOK",
			status:         metrics.StatusOK,
			expectedWeight: 1.0,
		},
		{
			name:           "StatusWarning",
			status:         metrics.StatusWarning,
			expectedWeight: 0.5,
		},
		{
			name:           "StatusDegraded",
			status:         metrics.StatusDegraded,
			expectedWeight: 0.01,
		},
		{
			// Although StatusShuttingDown completely filters the ad,
			// (rendering any weight irrelevant), test for completeness
			name:           "StatusShuttingDown",
			status:         metrics.StatusShuttingDown,
			expectedWeight: 0.01,
		},
		{
			name:           "StatusCritical",
			status:         metrics.StatusCritical,
			expectedWeight: 0.01,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weight := getRawStatusWeight(tc.status)
			assert.Equal(t, tc.expectedWeight, weight, "Expected weight for %s should be %f, got %f", tc.status.String(), tc.expectedWeight, weight)
		})
	}
}

func TestPopulateEWMAStatusWeightSequence(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Note: Expected weights calculated using this online calculator:
	// https://calculatorsforhome.com/ewma-estimator/
	// For mixed-delta tests, calculations must be done pair-wise because
	// alphas must be adjusted in between each (which the calculator does not do).
	testCases := []struct {
		name            string
		adSequence      []server_structs.ServerAd // sequence of ads to test
		deltaTs         []time.Duration           // the time delta between these two ads
		expectedWeights []float64
	}{
		{
			name: "ok-status-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusOK.String()},
				{Status: metrics.StatusOK.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				0.59063,
				0.66484,
			},
		},
		{
			name: "critical-status-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusCritical.String()},
				{Status: metrics.StatusCritical.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				0.41118,
				0.33846,
			},
		},
		{
			name: "degraded-status-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusDegraded.String()},
				{Status: metrics.StatusDegraded.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				// Same as critical status because of same xt
				0.41118,
				0.33846,
			},
		},
		{
			name: "unknown-status-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusUnknown.String()},
				{Status: metrics.StatusUnknown.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				// Same as OK status because of same xt
				0.59063,
				0.66484,
			},
		},
		{
			name: "oscillating-status-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusOK.String()},
				{Status: metrics.StatusDegraded.String()},
				{Status: metrics.StatusOK.String()},
				{Status: metrics.StatusDegraded.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				0.59063,
				0.48538,
				0.57867,
				0.47559,
			},
		},
		{
			name: "mixed-deltaTs-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusOK.String()},
				{Status: metrics.StatusOK.String()},
				{Status: metrics.StatusOK.String()},
			},
			deltaTs: []time.Duration{
				// Required alphas (generated using Wolfram Alpha and equation for
				// EWMA alpha) if you want to hand-calculate the expected weights:
				// - 0.181269
				// - 0.329680
				// - 0.451188
				time.Minute * 1,
				time.Minute * 2,
				time.Minute * 3,
			},
			expectedWeights: []float64{
				0.59063,
				0.72559,
				0.84940,
			},
		},
		{
			name: "old-ads-no-ewma-fields-case",
			adSequence: []server_structs.ServerAd{
				// Old ads will not set the relevant EWMA fields
				{},
				{},
				{},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
				time.Minute * 1,
			},
			expectedWeights: []float64{
				// Should default to steady 1s
				1.0,
				1.0,
			},
		},
		{
			// Out of bounds weights should be detected and result
			// in setting the weight to 1.0
			name: "oob-starting-ad-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: -0.5}, // Out of bounds starting weight
				{Status: metrics.StatusOK.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * 1,
			},
			expectedWeights: []float64{
				1.0,
			},
		},
		{
			name: "negative-deltaT-case",
			adSequence: []server_structs.ServerAd{
				{StatusWeight: 0.5},
				{Status: metrics.StatusCritical.String()},
			},
			deltaTs: []time.Duration{
				time.Minute * -1,
			},
			expectedWeights: []float64{
				0.5, // the previous weight will be imputed because alpha --> 0
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for i := 0; i < len(tc.adSequence)-1; i++ {
				// Overwrite any fields needed to calculate the desired deltaT
				tc.adSequence[i].StatusWeightLastUpdate = time.Now().Add(-tc.deltaTs[i]).Unix()
				populateEWMAStatusWeight(&tc.adSequence[i+1], &tc.adSequence[i])

				// Check status weight calculation. Epsilon accounts for time lag, and mult by i+1 accounts
				// for that lag accumulating over iterations
				assert.InEpsilon(t, tc.expectedWeights[i], tc.adSequence[i+1].StatusWeight, float64(i+1)*0.0035,
					"status weight is %d at index %d", tc.adSequence[i+1].StatusWeight, i+1)
			}
		})
	}
}

func TestApplyDowntimeFilters(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	now := time.Now().UTC().UnixMilli()

	activeDowntime := server_structs.Downtime{
		ServerName: "active-new",
		StartTime:  now - 1_000,
		EndTime:    now + 1_000,
	}
	tempAllowedDowntime := server_structs.Downtime{
		ServerName: "temp-allowed",
		StartTime:  now - 500,
		EndTime:    now + 500,
	}
	futureDowntime := server_structs.Downtime{
		ServerName: "future-only",
		StartTime:  now + 5_000,
		EndTime:    now + 6_000,
	}
	indefDowntime := server_structs.Downtime{
		ServerName: "indef",
		StartTime:  now - 2_000,
		EndTime:    server_structs.IndefiniteEndTime,
	}
	permFilteredDowntime := server_structs.Downtime{
		ServerName: "perm-filtered",
		StartTime:  now - 1_000,
		EndTime:    now + 1_000,
	}

	offlineOnly := server_structs.Downtime{
		ServerName: "offline-only",
		StartTime:  now - 10_000,
		EndTime:    now - 5_000,
	}

	allDowntimes := []server_structs.Downtime{
		activeDowntime,
		tempAllowedDowntime,
		futureDowntime,
		indefDowntime,
		permFilteredDowntime,
		offlineOnly,
	}

	currentFilters := map[string]filterType{
		"perm-filtered":       permFiltered,
		"temp-filter-cleanup": tempFiltered,
		"temp-allowed":        tempAllowed,
	}
	currentFederation := map[string][]server_structs.Downtime{
		"legacy": {
			{ServerName: "legacy"},
		},
	}

	newFilters, newFederation := applyDowntimeFilters(allDowntimes, currentFilters, currentFederation)

	require.NotNil(t, newFilters)
	require.NotNil(t, newFederation)

	// Ensure the original maps are untouched.
	assert.Contains(t, currentFilters, "temp-filter-cleanup")
	assert.Contains(t, currentFederation, "legacy")

	// tempFiltered entries should be removed from the new state.
	_, exists := newFilters["temp-filter-cleanup"]
	assert.False(t, exists)

	// Existing filters that are not tempAllowed should stay as-is.
	assert.Equal(t, permFiltered, newFilters["perm-filtered"])
	// tempAllowed filters should be overwritten if there is an active downtime.
	assert.Equal(t, tempFiltered, newFilters["temp-allowed"])

	// Active downtimes should mark the server as tempFiltered.
	assert.Equal(t, tempFiltered, newFilters["active-new"])
	assert.Equal(t, tempFiltered, newFilters["indef"])

	// Future downtimes should not mark servers as filtered yet.
	_, exists = newFilters["future-only"]
	assert.False(t, exists)

	// Federation downtimes include every server from the provided list, including offline ones.
	assert.Len(t, newFederation["active-new"], 1)
	assert.Len(t, newFederation["offline-only"], 1)
	assert.NotContains(t, newFederation, "legacy")
}

func TestGetCachedDowntimesDedup(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	serverName := "TEST_CACHE"
	now := time.Now().UnixMilli()
	dup := server_structs.Downtime{
		UUID:        "dup-id",
		ServerName:  serverName,
		ServerID:    "server-id",
		Source:      "cache",
		StartTime:   now - 1_000,
		EndTime:     now + 1_000,
		Description: "cache downtime",
	}
	registry := server_structs.Downtime{
		UUID:        "registry-id",
		ServerName:  serverName,
		Source:      "registry",
		StartTime:   now + 10_000,
		EndTime:     server_structs.IndefiniteEndTime,
		Description: "registry downtime",
	}

	filteredServersMutex.Lock()
	serverDowntimes = map[string][]server_structs.Downtime{
		serverName: {dup},
	}
	federationDowntimes = map[string][]server_structs.Downtime{
		serverName: {dup, registry},
	}
	filteredServersMutex.Unlock()

	downtimes, err := getCachedDowntimes(serverName)
	require.NoError(t, err)
	require.Len(t, downtimes, 2)

	assert.ElementsMatch(t, []string{"dup-id", "registry-id"}, []string{downtimes[0].UUID, downtimes[1].UUID})
}
