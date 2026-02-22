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
	_ "embed"
	"math"
	"math/rand"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Geo Override Yaml mockup
//
//go:embed resources/geoip_overrides.yaml
var yamlMockup string

func TestCheckOverrides(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	// Reset override state at start, in case a prior test in this
	// package triggered geoOverridesOnce via checkOverrides.
	geoNetOverrides = nil
	geoOverridesOnce = sync.Once{}

	t.Cleanup(func() {
		server_utils.ResetTestState()
		geoNetOverrides = nil
		geoOverridesOnce = sync.Once{}
	})

	// Set up the override cache for the test
	old := clientIpGeoOverrideCache
	t.Cleanup(func() {
		clientIpGeoOverrideCache.DeleteAll()
		clientIpGeoOverrideCache.Stop()
		clientIpGeoOverrideCache = old
	})
	clientIpGeoOverrideCache = ttlcache.New(
		ttlcache.WithCapacity[netip.Addr, server_structs.Coordinate](10),
	)
	go clientIpGeoOverrideCache.Start()

	testCases := []struct {
		name        string
		inputIP     string
		expectMatch bool
		expectCoord server_structs.Coordinate
	}{
		{
			name:        "test-no-ipv4-match",
			inputIP:     "192.168.0.2",
			expectMatch: false,
			expectCoord: server_structs.Coordinate{},
		},
		{
			name:        "test-no-ipv6-match",
			inputIP:     "ABCD::0123",
			expectMatch: false,
			expectCoord: server_structs.Coordinate{},
		},
		{
			name:        "test-ipv4-match",
			inputIP:     "192.168.0.1",
			expectMatch: true,
			expectCoord: server_structs.Coordinate{
				Lat:    123.4,
				Long:   987.6,
				Source: server_structs.CoordinateSourceOverride,
			},
		},
		{
			name:        "test-ipv4-CIDR-match",
			inputIP:     "10.0.0.136",
			expectMatch: true,
			expectCoord: server_structs.Coordinate{
				Lat:    43.073904,
				Long:   -89.384859,
				Source: server_structs.CoordinateSourceOverride,
			},
		},
		{
			name:        "test-ipv6-match",
			inputIP:     "FC00::0001",
			expectMatch: true,
			expectCoord: server_structs.Coordinate{
				Lat:    123.4,
				Long:   987.6,
				Source: server_structs.CoordinateSourceOverride,
			},
		},
		{
			name:        "test-ipv6-CIDR-match",
			inputIP:     "FD00::FA1B",
			expectMatch: true,
			expectCoord: server_structs.Coordinate{
				Lat:    43.073904,
				Long:   -89.384859,
				Source: server_structs.CoordinateSourceOverride,
			},
		},
	}

	viper.SetConfigType("yaml")
	err := viper.ReadConfig(strings.NewReader(yamlMockup))
	if err != nil {
		t.Fatalf("Error reading config: %v", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.inputIP)
			assert.NoError(t, err, "failed to parse IP address")
			if tc.expectMatch {
				// Make sure the IP is not in the cache beforehand
				cached := clientIpGeoOverrideCache.Get(addr)
				assert.Nil(t, cached, "IP should not be in cache before test")
			}
			coordinate, exists := checkOverrides(addr)
			assert.Equal(t, tc.expectMatch, exists, "unexpected match result")
			if tc.expectMatch {
				tc.expectCoord.Source = server_structs.CoordinateSourceOverride
				tc.expectCoord.AccuracyRadius = 0
				assert.EqualValues(t, tc.expectCoord, coordinate, "coordinates do not match expected values")
				// Make sure the IP is now in the cache
				cached := clientIpGeoOverrideCache.Get(addr)
				if assert.NotNil(t, cached, "IP should be in cache after test") {
					assert.EqualValues(t, tc.expectCoord, cached.Value(), "cached coordinates do not match expected values")
				}
			}
		})
	}
}

func TestAngularDistanceOnSphere(t *testing.T) {
	degToRad := func(d float64) float64 {
		return d * 3.141592653589793 / 180.0
	}

	testCases := []struct {
		name     string
		coord1   server_structs.Coordinate
		coord2   server_structs.Coordinate
		expected float64
	}{
		{
			name:     "null lat/long",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			expected: 0.0,
		},
		{
			name:     "same point",
			coord1:   server_structs.Coordinate{Lat: 43.0753, Long: -89.4114},
			coord2:   server_structs.Coordinate{Lat: 43.0753, Long: -89.4114},
			expected: 0.0,
		},
		{
			name:     "rotate longitude 90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 0.0, Long: 90.0},
			expected: degToRad(90.0),
		},
		{
			name:     "rotate longitude -90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 0.0, Long: -90.0},
			expected: degToRad(90.0),
		},
		{
			name:     "rotate latitude 90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 90.0, Long: 0.0},
			expected: degToRad(90.0),
		},
		{
			name:     "rotate latitude -90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: -90.0, Long: 0.0},
			expected: degToRad(90.0),
		},
		{
			name:     "rotate latitude and longitude 90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 90.0, Long: 90.0},
			expected: degToRad(90.0),
		},
		{
			name:     "rotate latitude 90 degrees and longitude -90 degrees",
			coord1:   server_structs.Coordinate{Lat: 0.0, Long: 0.0},
			coord2:   server_structs.Coordinate{Lat: 90.0, Long: -90.0},
			expected: degToRad(90.0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := angularDistanceOnSphere(tc.coord1.Lat, tc.coord1.Long, tc.coord2.Lat, tc.coord2.Long)
			assert.InDelta(t, tc.expected, result, 0.0001)
		})
	}
}

func TestThresholdedExponentialHalvingMultiplier(t *testing.T) {
	testCases := []struct {
		name          string
		val           float64
		threshold     float64
		halvingFactor float64
		expected      float64
	}{
		{
			name:          "value below threshold",
			val:           5.0,
			threshold:     10.0,
			halvingFactor: 20.0,
			expected:      1.0,
		},
		{
			name:          "value at threshold",
			val:           10.0,
			threshold:     10.0,
			halvingFactor: 20.0,
			expected:      1.0,
		},
		{
			name:          "value one halving factor above threshold",
			val:           30.0,
			threshold:     10.0,
			halvingFactor: 20.0,
			expected:      0.5,
		},
		{
			name:          "value two halving factors above threshold",
			val:           50.0,
			threshold:     10.0,
			halvingFactor: 20.0,
			expected:      0.25,
		},
		{
			name:          "negative threshold",
			val:           5.0,
			threshold:     -10.0,
			halvingFactor: 20.0,
			expected:      1.0,
		},
		{
			name:          "zero halving factor",
			val:           30.0,
			threshold:     10.0,
			halvingFactor: 0.0,
			expected:      1.0,
		},
		{
			name:          "negative halving factor",
			val:           30.0,
			threshold:     10.0,
			halvingFactor: -20.0,
			expected:      1.0,
		},
		{
			name:          "negative value",
			val:           -5.0,
			threshold:     10.0,
			halvingFactor: 20.0,
			expected:      1.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := thresholdedExponentialHalvingMultiplier(tc.val, tc.threshold, tc.halvingFactor)
			assert.InDelta(t, tc.expected, result, 0.0001)
		})
	}
}

func TestTruncateAds(t *testing.T) {
	ad1 := server_structs.ServerAd{}
	ad1.Initialize("ad1")
	ad2 := server_structs.ServerAd{}
	ad2.Initialize("ad2")
	ad3 := server_structs.ServerAd{}
	ad3.Initialize("ad3")

	testCases := []struct {
		name     string
		ads      []server_structs.ServerAd
		maxAds   int
		expected []server_structs.ServerAd
	}{
		{
			name:     "fewer ads than max",
			ads:      []server_structs.ServerAd{ad1, ad2},
			maxAds:   5,
			expected: []server_structs.ServerAd{ad1, ad2},
		},
		{
			name:     "equal number of ads and max",
			ads:      []server_structs.ServerAd{ad1, ad2, ad3},
			maxAds:   3,
			expected: []server_structs.ServerAd{ad1, ad2, ad3},
		},
		{
			name:     "more ads than max",
			ads:      []server_structs.ServerAd{ad1, ad2, ad3},
			maxAds:   2,
			expected: []server_structs.ServerAd{ad1, ad2},
		},
		{
			name:     "max ads is zero",
			ads:      []server_structs.ServerAd{ad1, ad2, ad3},
			maxAds:   0,
			expected: []server_structs.ServerAd{ad1, ad2, ad3},
		},
		{
			name:     "max ads is negative",
			ads:      []server_structs.ServerAd{ad1, ad2, ad3},
			maxAds:   -1,
			expected: []server_structs.ServerAd{ad1, ad2, ad3},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncateAds(tc.ads, tc.maxAds)
			assert.EqualValues(t, tc.expected, result)
		})
	}
}

func TestGetMedian(t *testing.T) {
	testCases := []struct {
		name     string
		values   []float64
		expected float64
	}{
		{
			name:     "odd number of values",
			values:   []float64{1.0, 3.0, 2.0},
			expected: 2.0,
		},
		{
			name:     "even number of values",
			values:   []float64{1.0, 4.0, 2.0, 3.0},
			expected: 2.5,
		},
		{
			name:     "single value",
			values:   []float64{42.0},
			expected: 42.0,
		},
		{
			name:     "empty slice",
			values:   []float64{},
			expected: 0.0,
		},
		{
			name:     "negative values",
			values:   []float64{-1.0, -3.0, -2.0},
			expected: -2.0,
		},
		{
			// The function calling `getMedian` should never receive negative
			// weights because we only pass it positive, valid weights. Regardless,
			// we test that the function computes the median correctly anyway.
			name:     "mixed values",
			values:   []float64{-1.0, 1.0, 0.0},
			expected: 0.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := getMedian(tc.values)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestComputeWeights(t *testing.T) {
	ad1 := server_structs.ServerAd{}
	ad1.Initialize("ad1")
	ad2 := server_structs.ServerAd{}
	ad2.Initialize("ad2")
	ad3 := server_structs.ServerAd{}
	ad3.Initialize("ad3")

	testCases := []struct {
		name            string
		ads             []server_structs.ServerAd
		weightFn        func(int, server_structs.ServerAd) (float64, bool)
		expectedWeights SwapMaps
	}{
		{
			name: "all valid weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			weightFn: func(idx int, ad server_structs.ServerAd) (float64, bool) {
				return float64(idx + 1), true
			},
			expectedWeights: SwapMaps{
				{Weight: 1.0, Index: 0},
				{Weight: 2.0, Index: 1},
				{Weight: 3.0, Index: 2},
			},
		},
		{
			name: "invalid weight with even number of valid weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			weightFn: func(idx int, ad server_structs.ServerAd) (float64, bool) {
				if idx == 0 {
					return 0.0, false
				}
				return float64(idx + 1), true
			},
			expectedWeights: SwapMaps{
				{Weight: 2.5, Index: 0}, // median of 2.0 and 3.0
				{Weight: 2.0, Index: 1},
				{Weight: 3.0, Index: 2},
			},
		},
		{
			name: "invalid weight with odd number of valid weights",
			ads:  []server_structs.ServerAd{ad1, ad2},
			weightFn: func(idx int, ad server_structs.ServerAd) (float64, bool) {
				if idx == 0 {
					return 0.0, false
				}
				return float64(idx + 1), true
			},
			expectedWeights: SwapMaps{
				{Weight: 2.0, Index: 0},
				{Weight: 2.0, Index: 1}, // Should use this value
			},
		},
		{
			name: "all invalid weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			weightFn: func(idx int, ad server_structs.ServerAd) (float64, bool) {
				return 0.0, false
			},
			expectedWeights: SwapMaps{
				{Weight: 1.0, Index: 0}, // fallback to 1.0
				{Weight: 1.0, Index: 1},
				{Weight: 1.0, Index: 2},
			},
		},
		{
			name: "no ads",
			ads:  []server_structs.ServerAd{},
			weightFn: func(idx int, ad server_structs.ServerAd) (float64, bool) {
				return float64(idx + 1), true
			},
			expectedWeights: SwapMaps{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := computeWeights(tc.ads, tc.weightFn)
			assert.Equal(t, len(tc.expectedWeights), len(result))
			assert.Equal(t, tc.expectedWeights, result)
		})
	}
}

func TestAssignRandBoundedCoord(t *testing.T) {
	// Because of the test's randomness, do it a few times to increase the likelihood of catching errors
	for range 10 {
		// Generate a random bounding box between -200, 200
		lat1 := rand.Float64()*400 - 200
		long1 := rand.Float64()*400 - 200
		lat2 := rand.Float64()*400 - 200
		long2 := rand.Float64()*400 - 200

		// Assign mins and maxes
		minLat, maxLat := math.Min(lat1, lat2), math.Max(lat1, lat2)
		minLong, maxLong := math.Min(long1, long2), math.Max(long1, long2)

		// Assign a random coordinate within the bounding box
		lat, long := assignRandBoundedCoord(minLat, maxLat, minLong, maxLong)
		assert.True(t, lat >= minLat && lat <= maxLat)
		assert.True(t, long >= minLong && long <= maxLong)
	}
}

func TestGetProjectLabel(t *testing.T) {
	testCases := []struct {
		name     string
		project  string
		expected string
	}{
		{
			name:     "normal project",
			project:  "myproject",
			expected: "myproject",
		},
		{
			name:     "empty project",
			project:  "",
			expected: "unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), ProjectContextKey{}, tc.project)
			result := getProjectLabel(ctx)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Helpers for TestGet*Coordinate tests
// Also used in sort_algorithms_test.go to aid in testing
// sort algorithms
var (
	ipInMaxMindSmallRadius = netip.MustParseAddr("192.168.1.1")
	ipInMaxMindLargeRadius = netip.MustParseAddr("192.168.1.2")
	ipNotInMaxMind         = netip.MustParseAddr("192.168.1.3")
	ipFromOverride         = netip.MustParseAddr("192.168.1.4")

	smallRadiusHostname  = "smallradius"
	largeRadiusHostname  = "largeradius"
	notInMaxMindHostname = "notinmaxmind"
	fromOverrideHostname = "fromoverride"
)

// Override the getIPFromHostname function so we don't need to do actual DNS lookups
func setupGetIPStub(t *testing.T) {
	old := getIPFromHostname
	t.Cleanup(func() { getIPFromHostname = old })
	getIPFromHostname = func(hostname string) (netip.Addr, error) {
		switch hostname {
		case smallRadiusHostname:
			return ipInMaxMindSmallRadius, nil
		case largeRadiusHostname:
			return ipInMaxMindLargeRadius, nil
		case notInMaxMindHostname:
			return ipNotInMaxMind, nil
		case fromOverrideHostname:
			return ipFromOverride, nil
		default:
			t.Errorf("unexpected hostname lookup: %s", hostname)
			return netip.Addr{}, nil
		}
	}
}

// Override the getMaxMindCoordinate function so we don't need to figure out
// how to get a maxmind database into the test environment
func setupGetMaxMindStub(t *testing.T) {
	old := getMaxMindCoordinate
	t.Cleanup(func() { getMaxMindCoordinate = old })
	getMaxMindCoordinate = func(addr netip.Addr) (coord server_structs.Coordinate, err error) {
		coord.Source = server_structs.CoordinateSourceMaxMind
		switch addr {
		case ipInMaxMindSmallRadius:
			coord.AccuracyRadius = 5.0
			coord.Lat = 43.07296
			coord.Long = -89.40831
			return
		case ipInMaxMindLargeRadius:
			err = maxmindError{Kind: MaxMindLargeAccuracyError, Message: "large accuracy radius"}
			return
		case ipNotInMaxMind:
			err = maxmindError{Kind: MaxMindNullLatLonError, Message: "not found in maxmind db"}
			return
		default:
			return coord, nil
		}
	}
}

// Setup the override cache directly instead of configuring/passing a yaml
// file
func setupOverrideCache(t *testing.T) {
	old := clientIpGeoOverrideCache
	t.Cleanup(func() {
		clientIpGeoOverrideCache.DeleteAll()
		clientIpGeoOverrideCache.Stop()
		clientIpGeoOverrideCache = old
	})
	clientIpGeoOverrideCache = ttlcache.New(
		ttlcache.WithCapacity[netip.Addr, server_structs.Coordinate](10),
	)
	go clientIpGeoOverrideCache.Start()
	clientIpGeoOverrideCache.Set(ipFromOverride, server_structs.Coordinate{
		Lat:            43.07296, // Discovery Building
		Long:           -89.40831,
		AccuracyRadius: 1.0,
		Source:         server_structs.CoordinateSourceOverride,
	}, 0)
}

// Setup the random assignment cache for testing
func setUpRandAssignmentCache(t *testing.T) {
	old := clientIpRandAssignmentCache
	t.Cleanup(func() {
		clientIpRandAssignmentCache.DeleteAll()
		clientIpRandAssignmentCache.Stop()
		clientIpRandAssignmentCache = old
	})
	ttlcache.New(ttlcache.WithTTL[netip.Addr, server_structs.Coordinate](0),
		ttlcache.WithDisableTouchOnHit[netip.Addr, server_structs.Coordinate](),
		ttlcache.WithCapacity[netip.Addr, server_structs.Coordinate](10),
	)
	go clientIpRandAssignmentCache.Start()
}

func mustUrl(hostname string) url.URL {
	u, _ := url.Parse("https://" + hostname)
	return *u
}

// Note: This does not test the underlying maxmind or override parsing functions,
// which have been overridden for the purposes of this test. It only tests that
// GetServerCoordinate gets coordinates from the expected source.
func TestGetServerCoordinate(t *testing.T) {
	setupGetIPStub(t)
	setupGetMaxMindStub(t)
	setupOverrideCache(t)

	sAdInMaxMindSmallRadius := server_structs.ServerAd{URL: mustUrl(smallRadiusHostname)}
	sAdInMaxMindSmallRadius.Initialize("inmaxmindsmallradius")
	sAdInMaxMindLargeRadius := server_structs.ServerAd{URL: mustUrl(largeRadiusHostname)}
	sAdInMaxMindLargeRadius.Initialize("inmaxmindlargeradius")
	sAdNotInMaxMind := server_structs.ServerAd{URL: mustUrl(notInMaxMindHostname)}
	sAdNotInMaxMind.Initialize("notinmaxmind")
	sAdFromOverride := server_structs.ServerAd{URL: mustUrl(fromOverrideHostname)}
	sAdFromOverride.Initialize("fromoverride")
	testCases := []struct {
		name          string
		sAd           server_structs.ServerAd
		expectedCoord server_structs.Coordinate
		expectError   bool
	}{
		{
			name: "valid maxmind coordinate",
			sAd:  sAdInMaxMindSmallRadius,
			expectedCoord: server_structs.Coordinate{
				Lat:            43.07296,
				Long:           -89.40831,
				AccuracyRadius: 5.0,
				Source:         server_structs.CoordinateSourceMaxMind,
			},
			expectError: false,
		},
		{
			name: "valid coordinate from override",
			sAd:  sAdFromOverride,
			expectedCoord: server_structs.Coordinate{
				Lat:            43.07296,
				Long:           -89.40831,
				AccuracyRadius: 1.0,
				Source:         server_structs.CoordinateSourceOverride,
			},
			expectError: false,
		},
		{
			name:        "from maxmind large accuracy radius",
			sAd:         sAdInMaxMindLargeRadius,
			expectError: true,
		},
		{
			name:        "not in maxmind",
			sAd:         sAdNotInMaxMind,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			coord, err := getServerCoordinate(tc.sAd)
			if tc.expectError {
				assert.Error(t, err)
				// No point making assertions about the coords here because we've
				// overridden some internal functions used by getServerCoordinate
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedCoord.Lat, coord.Lat)
				assert.Equal(t, tc.expectedCoord.Long, coord.Long)
				assert.Equal(t, tc.expectedCoord.AccuracyRadius, coord.AccuracyRadius)
				assert.Equal(t, tc.expectedCoord.Source, coord.Source)
			}
		})
	}
}

func TestGetClientCoordinate(t *testing.T) {
	setupGetIPStub(t)
	setupGetMaxMindStub(t)
	setupOverrideCache(t)
	setUpRandAssignmentCache(t)

	testCases := []struct {
		name          string
		addr          netip.Addr
		expectedCoord server_structs.Coordinate
	}{
		{
			name: "valid maxmind coordinate",
			addr: ipInMaxMindSmallRadius,
			expectedCoord: server_structs.Coordinate{
				Lat:            43.07296,
				Long:           -89.40831,
				AccuracyRadius: 5.0,
				Source:         server_structs.CoordinateSourceMaxMind,
			},
		},
		{
			name: "valid coordinate from override",
			addr: ipFromOverride,
			expectedCoord: server_structs.Coordinate{
				Lat:            43.07296,
				Long:           -89.40831,
				AccuracyRadius: 1.0,
				Source:         server_structs.CoordinateSourceOverride,
			},
		},
		{
			name: "from maxmind large accuracy radius, should get random assignment",
			addr: ipInMaxMindLargeRadius,
			expectedCoord: server_structs.Coordinate{
				Source: server_structs.CoordinateSourceRandom,
			},
		},
		{
			name: "not in maxmind, should get random assignment",
			addr: ipNotInMaxMind,
			expectedCoord: server_structs.Coordinate{
				Source: server_structs.CoordinateSourceRandom,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			coord := getClientCoordinate(ctx, tc.addr)
			assert.Equal(t, tc.expectedCoord.Source, coord.Source)
			if tc.expectedCoord.Source != server_structs.CoordinateSourceRandom {
				// For non-random sources, check full equality
				assert.Equal(t, tc.expectedCoord.Lat, coord.Lat)
				assert.Equal(t, tc.expectedCoord.Long, coord.Long)
				assert.Equal(t, tc.expectedCoord.AccuracyRadius, coord.AccuracyRadius)
			} else {
				// For random source, check that lat/long are in valid ranges
				assert.True(t, coord.Lat >= usLatMin && coord.Lat <= usLatMax)
				assert.True(t, coord.Long >= usLongMin && coord.Long <= usLongMax)
			}
		})
	}
}
