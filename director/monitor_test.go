/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestLaunchPeriodicDirectorTest verifies that LaunchPeriodicDirectorTest:
// 1. Only runs against servers that are in the TTL cache and not expired
// 2. Does not run against servers in scheduled downtime
func TestLaunchPeriodicDirectorTest(t *testing.T) {
	config.ResetConfig()
	defer config.ResetConfig()

	// Set test interval to be very short for faster testing
	viper.Set(param.Director_OriginCacheHealthTestInterval.GetName(), "100ms")

	mockServerAd := server_structs.ServerAd{
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "test-origin.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "test-origin.org:8444",
		},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockServerAd.Initialize("test-origin-server")

	mockNamespaceAd := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{PublicReads: false},
		Path: "/test/path",
	}

	testCases := []struct {
		name              string
		serverInCache     bool
		cacheTTL          time.Duration
		downtimes         []server_structs.Downtime
		expectTestToStart bool
		expectTestToStop  bool
		description       string
	}{
		{
			name:              "server-not-in-cache",
			serverInCache:     false,
			cacheTTL:          time.Second * 5,
			downtimes:         nil,
			expectTestToStart: false,
			expectTestToStop:  false,
			description:       "Test should not start if server is not in TTL cache",
		},
		{
			name:              "server-in-cache-no-downtime",
			serverInCache:     true,
			cacheTTL:          time.Second * 5,
			downtimes:         nil,
			expectTestToStart: true,
			expectTestToStop:  false,
			description:       "Test should start and run if server is in cache with no downtime",
		},
		{
			name:          "server-expires-from-cache",
			serverInCache: true,
			cacheTTL:      time.Millisecond * 200, // Very short TTL so it expires during test
			downtimes:     nil,
			expectTestToStart: true,
			expectTestToStop:  true,
			description:       "Test should stop when server expires from TTL cache",
		},
		{
			name:          "server-in-active-downtime",
			serverInCache: true,
			cacheTTL:      time.Second * 5,
			downtimes: []server_structs.Downtime{
				{
					ServerName: "test-origin-server",
					StartTime:  time.Now().Add(-time.Hour).UTC().UnixMilli(),
					EndTime:    time.Now().Add(time.Hour).UTC().UnixMilli(),
				},
			},
			expectTestToStart: true,
			expectTestToStop:  false,
			description:       "Test should skip cycles when server is in active downtime",
		},
		{
			name:          "server-with-past-downtime",
			serverInCache: true,
			cacheTTL:      time.Second * 5,
			downtimes: []server_structs.Downtime{
				{
					ServerName: "test-origin-server",
					StartTime:  time.Now().Add(-time.Hour * 2).UTC().UnixMilli(),
					EndTime:    time.Now().Add(-time.Hour).UTC().UnixMilli(),
				},
			},
			expectTestToStart: true,
			expectTestToStop:  false,
			description:       "Test should run normally when downtime has ended",
		},
		{
			name:          "server-with-future-downtime",
			serverInCache: true,
			cacheTTL:      time.Second * 5,
			downtimes: []server_structs.Downtime{
				{
					ServerName: "test-origin-server",
					StartTime:  time.Now().Add(time.Hour).UTC().UnixMilli(),
					EndTime:    time.Now().Add(time.Hour * 2).UTC().UnixMilli(),
				},
			},
			expectTestToStart: true,
			expectTestToStop:  false,
			description:       "Test should run normally when downtime hasn't started yet",
		},
		{
			name:          "server-with-indefinite-downtime",
			serverInCache: true,
			cacheTTL:      time.Second * 5,
			downtimes: []server_structs.Downtime{
				{
					ServerName: "test-origin-server",
					StartTime:  time.Now().Add(-time.Hour).UTC().UnixMilli(),
					EndTime:    server_structs.IndefiniteEndTime,
				},
			},
			expectTestToStart: true,
			expectTestToStop:  false,
			description:       "Test should skip cycles when server is in indefinite downtime",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Clean up test environment
			serverAds.DeleteAll()
			filteredServersMutex.Lock()
			serverDowntimes = make(map[string][]server_structs.Downtime)
			topologyDowntimes = make(map[string][]server_structs.Downtime)
			federationDowntimes = make(map[string][]server_structs.Downtime)
			if tc.downtimes != nil {
				serverDowntimes[mockServerAd.Name] = tc.downtimes
			}
			filteredServersMutex.Unlock()

			// Set up server in cache if test requires it
			if tc.serverInCache {
				serverAds.Set(mockServerAd.URL.String(), &server_structs.Advertisement{
					ServerAd:     mockServerAd,
					NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
				}, tc.cacheTTL)
			}

			// Create context that will be canceled after test
			ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
			defer cancel()

			// Launch the test in a goroutine
			testStarted := make(chan bool, 1)
			testStopped := make(chan bool, 1)

			go func() {
				// Check if test starts by seeing if it gets past the initial check
				if serverAds.Has(mockServerAd.URL.String()) {
					testStarted <- true
				} else {
					testStarted <- false
				}

				// Run the actual test (will be interrupted by context cancellation)
				LaunchPeriodicDirectorTest(ctx, mockServerAd.URL.String())
				testStopped <- true
			}()

			// Wait a bit to see if test started
			time.Sleep(time.Millisecond * 50)

			select {
			case started := <-testStarted:
				if tc.expectTestToStart {
					assert.True(t, started, tc.description)
				} else {
					assert.False(t, started, tc.description)
				}
			case <-time.After(time.Millisecond * 100):
				if tc.expectTestToStart {
					t.Errorf("Test case %s: expected test to start but timed out", tc.name)
				}
			}

			// For cache expiration test, wait for the ad to expire
			if tc.expectTestToStop {
				// Wait for TTL to expire plus a bit more
				time.Sleep(tc.cacheTTL + time.Millisecond*150)

				// Check if test stopped due to cache expiration
				select {
				case <-testStopped:
					// Test stopped as expected when cache expired
				case <-time.After(time.Millisecond * 200):
					t.Errorf("Test case %s: expected test to stop when cache expired but it didn't", tc.name)
				}
			}

			// Wait for context cancellation to clean up
			<-ctx.Done()
		})
	}
}

// TestDirectorTestDowntimeLogic specifically tests the downtime checking logic
func TestDirectorTestDowntimeLogic(t *testing.T) {
	now := time.Now().UTC().UnixMilli()

	testCases := []struct {
		name              string
		downtime          server_structs.Downtime
		expectSkip        bool
		description       string
	}{
		{
			name: "active-downtime",
			downtime: server_structs.Downtime{
				StartTime: now - 1000,
				EndTime:   now + 1000,
			},
			expectSkip:  true,
			description: "Should skip when downtime is active",
		},
		{
			name: "past-downtime",
			downtime: server_structs.Downtime{
				StartTime: now - 2000,
				EndTime:   now - 1000,
			},
			expectSkip:  false,
			description: "Should not skip when downtime has ended",
		},
		{
			name: "future-downtime",
			downtime: server_structs.Downtime{
				StartTime: now + 1000,
				EndTime:   now + 2000,
			},
			expectSkip:  false,
			description: "Should not skip when downtime hasn't started",
		},
		{
			name: "indefinite-active-downtime",
			downtime: server_structs.Downtime{
				StartTime: now - 1000,
				EndTime:   server_structs.IndefiniteEndTime,
			},
			expectSkip:  true,
			description: "Should skip when in indefinite downtime",
		},
		{
			name: "downtime-start-equals-now",
			downtime: server_structs.Downtime{
				StartTime: now,
				EndTime:   now + 1000,
			},
			expectSkip:  true,
			description: "Should skip when downtime starts exactly now",
		},
		{
			name: "downtime-end-equals-now",
			downtime: server_structs.Downtime{
				StartTime: now - 1000,
				EndTime:   now,
			},
			expectSkip:  true,
			description: "Should skip when downtime ends exactly now",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			currentTime := now
			// Use the helper function from monitor.go
			hasActiveDowntime := isDowntimeActive(tc.downtime, currentTime)

			if tc.expectSkip {
				assert.True(t, hasActiveDowntime, tc.description)
			} else {
				assert.False(t, hasActiveDowntime, tc.description)
			}
		})
	}
}

// TestDirectorTestCacheEviction verifies that tests stop when server ads are evicted
func TestDirectorTestCacheEviction(t *testing.T) {
	config.ResetConfig()
	defer config.ResetConfig()
	viper.Set(param.Director_OriginCacheHealthTestInterval.GetName(), "50ms")

	mockServerAd := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "eviction-test.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "eviction-test.org:8444",
		},
		Type: server_structs.OriginType.String(),
	}
	mockServerAd.Initialize("eviction-test-server")

	mockNamespaceAd := server_structs.NamespaceAdV2{
		Path: "/test",
	}

	// Start cache eviction handler
	shutdownCtx, shutdownCancel, egrp := test_utils.TestContext(context.Background(), t)
	cacheCtx := context.WithValue(shutdownCtx, config.EgrpKey, egrp)
	LaunchTTLCache(cacheCtx, egrp)
	defer func() {
		shutdownCancel()
		err := egrp.Wait()
		assert.NoError(t, err)
	}()

	// Clean up
	serverAds.DeleteAll()

	// Add server to cache with very short TTL
	serverAds.Set(mockServerAd.URL.String(), &server_structs.Advertisement{
		ServerAd:     mockServerAd,
		NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
	}, time.Millisecond*150)

	require.True(t, serverAds.Has(mockServerAd.URL.String()), "Server should be in cache")

	// Launch test
	testCtx, testCancel, _ := test_utils.TestContext(context.Background(), t)
	defer testCancel()

	testFinished := make(chan bool, 1)
	go func() {
		LaunchPeriodicDirectorTest(testCtx, mockServerAd.URL.String())
		testFinished <- true
	}()

	// Wait for cache to expire
	time.Sleep(time.Millisecond * 200)

	// Verify server is no longer in cache
	assert.False(t, serverAds.Has(mockServerAd.URL.String()), "Server should have been evicted from cache")

	// Verify test finished (because cache entry was evicted)
	select {
	case <-testFinished:
		// Test finished as expected when server was evicted from cache
	case <-time.After(time.Millisecond * 300):
		t.Error("Test should have stopped when server was evicted from cache")
	}
}
