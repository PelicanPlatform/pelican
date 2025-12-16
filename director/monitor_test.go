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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

const (
	// Test timing constants for better readability and maintainability
	testHealthCheckInterval = 100 * time.Millisecond
	testShortTTL            = 200 * time.Millisecond
	testStartupWait         = 50 * time.Millisecond
	testTickerWait          = 150 * time.Millisecond
	testTimeoutBuffer       = 200 * time.Millisecond
)

// setupTestDowntimes is a helper to configure downtime maps and filteredServers for testing
func setupTestDowntimes(serverName string, downtimes []server_structs.Downtime) {
	filteredServersMutex.Lock()
	defer filteredServersMutex.Unlock()

	// Clear all downtime maps
	serverDowntimes = make(map[string][]server_structs.Downtime)
	topologyDowntimes = make(map[string][]server_structs.Downtime)
	federationDowntimes = make(map[string][]server_structs.Downtime)
	filteredServers = make(map[string]filterType)

	if downtimes != nil {
		serverDowntimes[serverName] = downtimes

		// Check if any downtime is currently active and update filteredServers accordingly
		currentTime := time.Now().UTC().UnixMilli()
		for _, downtime := range downtimes {
			if isDowntimeActive(downtime, currentTime) {
				filteredServers[serverName] = tempFiltered
				break
			}
		}
	}
}

// TestLaunchPeriodicDirectorTest verifies that LaunchPeriodicDirectorTest:
// 1. Only runs against servers that are in the TTL cache and not expired
// 2. Does not run against servers in scheduled downtime
func TestLaunchPeriodicDirectorTest(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)

	// Set test interval to be very short for faster testing
	viper.Set(param.Director_OriginCacheHealthTestInterval.GetName(), testHealthCheckInterval.String())

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

	// Test cases covering different cache and downtime scenarios
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
			name:              "server-expires-from-cache",
			serverInCache:     true,
			cacheTTL:          testShortTTL, // Very short TTL so it expires during test
			downtimes:         nil,
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
			setupTestDowntimes(mockServerAd.Name, tc.downtimes)

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
			testStopped := make(chan bool, 1)

			go func() {
				// Run the actual test (will be interrupted by context cancellation)
				LaunchPeriodicDirectorTest(ctx, mockServerAd.URL.String())
				testStopped <- true
			}()

			// Wait a bit to see if test started or immediately returned
			time.Sleep(testStartupWait)

			// Check if the test started or immediately returned
			select {
			case <-testStopped:
				// Test returned immediately (e.g., server not in cache)
				if tc.expectTestToStart {
					t.Errorf("Test case %s: expected test to start but it returned immediately. Description: %s", tc.name, tc.description)
				}
			default:
				// Test is still running
				if !tc.expectTestToStart {
					t.Errorf("Test case %s: expected test not to start but it's still running. Description: %s", tc.name, tc.description)
				}
			}

			// For cache expiration test, manually remove the entry to simulate expiration
			if tc.expectTestToStop {
				// Wait for TTL to expire
				time.Sleep(tc.cacheTTL)

				// Manually delete the entry to simulate cache expiration
				serverAds.Delete(mockServerAd.URL.String())

				// Wait for one more ticker cycle plus buffer to ensure LaunchPeriodicDirectorTest exits
				time.Sleep(testTickerWait)

				// Check if test stopped due to cache expiration
				select {
				case <-testStopped:
					// Test stopped as expected when cache expired
				case <-time.After(testTimeoutBuffer):
					t.Errorf("Test case %s: expected test to stop when cache expired but it didn't. Description: %s", tc.name, tc.description)
					cancel() // Force cancel to avoid hanging
				}
			}
		})
	}
}

// TestDirectorTestDowntimeLogic specifically tests the downtime checking logic
func TestDirectorTestDowntimeLogic(t *testing.T) {
	now := time.Now().UTC().UnixMilli()

	testCases := []struct {
		name        string
		downtime    server_structs.Downtime
		expectSkip  bool
		description string
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
	t.Cleanup(config.ResetConfig)
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
	t.Cleanup(func() {
		shutdownCancel()
		err := egrp.Wait()
		assert.NoError(t, err)
	})

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

	// Wait for cache to expire (150ms TTL + buffer)
	time.Sleep(testShortTTL)

	// Verify server is no longer in cache
	assert.False(t, serverAds.Has(mockServerAd.URL.String()), "Server should have been evicted from cache")

	// Wait for the next ticker cycle (50ms interval + buffer) to ensure LaunchPeriodicDirectorTest checks cache and exits
	time.Sleep(100 * time.Millisecond)

	// Verify test finished (because cache entry was evicted)
	select {
	case <-testFinished:
		// Test finished as expected when server was evicted from cache
	case <-time.After(testTimeoutBuffer):
		t.Error("Test should have stopped when server was evicted from cache")
		testCancel() // Force cancel to avoid hanging
	}
}
