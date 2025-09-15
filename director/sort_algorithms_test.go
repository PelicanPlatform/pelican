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
	"math"
	"net/netip"
	"net/url"
	"slices"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

func TestFilterZeroAndNegWeights(t *testing.T) {
	testCases := []struct {
		name            string
		input           SwapMaps
		expectedLen     int
		expectedErrIdxs []int
	}{
		{
			name: "all positive weights",
			input: SwapMaps{
				{Index: 0, Weight: 1.0},
				{Index: 1, Weight: 2.0},
				{Index: 2, Weight: 3.0},
			},
			expectedLen: 3,
		},
		{
			name: "some zero weights",
			input: SwapMaps{
				{Index: 0, Weight: 0.0},
				{Index: 1, Weight: 2.0},
				{Index: 2, Weight: 0.0},
			},
			expectedLen: 1,
			// No error indices because no zero weights
		},
		{
			name: "some negative weights",
			input: SwapMaps{
				{Index: 0, Weight: -1.0},
				{Index: 1, Weight: 2.0},
				{Index: 2, Weight: -3.0},
			},
			expectedLen:     1,
			expectedErrIdxs: []int{0, 2},
		},
		{
			name: "mixed zero and negative weights",
			input: SwapMaps{
				{Index: 0, Weight: -1.0},
				{Index: 1, Weight: 0.0},
				{Index: 2, Weight: 3.0},
				{Index: 3, Weight: -0.5},
				{Index: 4, Weight: 0.0},
			},
			expectedLen:     1,
			expectedErrIdxs: []int{0, 3},
		},
		{
			name: "all zero and negative weights",
			input: SwapMaps{
				{Index: 0, Weight: 0.0},
				{Index: 1, Weight: -2.0},
				{Index: 2, Weight: 0.0},
			},
			expectedLen:     0,
			expectedErrIdxs: []int{1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			negIdxs := tc.input.FilterZeroAndNegWeights()
			assert.Equal(t, tc.expectedLen, len(tc.input), "filtered length does not match expected")
			assert.EqualValues(t, tc.expectedErrIdxs, negIdxs, "negative weight indices do not match expected")
		})
	}
}

func TestSwapMapsSortDescending(t *testing.T) {
	// Test that SortDescending correctly sorts SwapMaps in descending order by weight,
	// and filters out any entries with zero or negative weights. The return for the method
	// should indicate which indices had negative weights.
	testCases := []struct {
		name           string
		input          SwapMaps
		expected       SwapMaps
		expectedErrIdx []int
	}{
		{
			name: "already sorted descending",
			input: SwapMaps{
				{Index: 0, Weight: 5.0},
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: 1.0},
			},
			expected: SwapMaps{
				{Index: 0, Weight: 5.0},
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: 1.0},
			},
		},
		{
			name: "unsorted",
			input: SwapMaps{
				{Index: 0, Weight: 1.0},
				{Index: 1, Weight: 5.0},
				{Index: 2, Weight: 3.0},
			},
			expected: SwapMaps{
				{Index: 1, Weight: 5.0},
				{Index: 2, Weight: 3.0},
				{Index: 0, Weight: 1.0},
			},
		},
		{
			name: "with negative weights",
			input: SwapMaps{
				{Index: 0, Weight: -1.0},
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: -5.0},
			},
			expected: SwapMaps{
				{Index: 1, Weight: 3.0},
			},
			expectedErrIdx: []int{0, 2},
		},
		{
			name: "with 0 weights",
			input: SwapMaps{
				{Index: 0, Weight: 0},
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: 5.0},
			},
			expected: SwapMaps{
				{Index: 2, Weight: 5.0},
				{Index: 1, Weight: 3.0},
			},
		},
		{
			name: "with equal weights",
			input: SwapMaps{
				{Index: 0, Weight: 2.0},
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: 3.0},
			},
			expected: SwapMaps{
				{Index: 1, Weight: 3.0},
				{Index: 2, Weight: 3.0},
				{Index: 0, Weight: 2.0},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weightError := tc.input.smSortDescending()
			assert.EqualValues(t, tc.expected, tc.input, "sorted result does not match expected")
			if len(tc.expectedErrIdx) == 0 {
				assert.Nil(t, weightError, "expected no weight error, but got one")
			} else {
				assert.NotNil(t, weightError, "expected weight error, but got nil")
				assert.ElementsMatch(t, tc.expectedErrIdx, weightError.NegIdxs, "weight error indices do not match expected")
			}
		})
	}
}

func TestSwapMapsSortStochastic(t *testing.T) {
	// This test's strategy is to run the stochastic sort ~1000 times for each input,
	// and to assert correctness based on the statistical distribution of results.
	// For each index in the input, we record how often it appears at each position
	// in the output. We then check that:
	// 1) Only indices with positive weights appear in the output (zero and negative
	//    weights should be filtered out).
	// 2) Each index appears most often (mode) at the position expected based on its weight
	//    relative to the others.
	//    For example, if index A has the highest weight, it should appear most often
	//    at position 0; if index B has the second highest weight, it should appear
	//    most often at position 1; and so on.
	testCases := []struct {
		name           string
		input          SwapMaps
		expectedIdxMap map[int]int // expected "mode" position for each index
		expectedErrIdx []int       // Indices that should produce weight errors
	}{
		{
			name: "all positive weights",
			input: SwapMaps{
				{Weight: 50, Index: 0},
				{Weight: 100, Index: 1},
				{Weight: 25, Index: 2},
			},
			expectedIdxMap: map[int]int{
				1: 0, // Index 1 should most often end up first
				0: 1,
				2: 2,
			},
		},
		{
			name: "mixed positive, zero, negative",
			input: SwapMaps{
				{Weight: 0, Index: 0},
				{Weight: 50, Index: 1},
				{Weight: -2, Index: 2},
				{Weight: 10, Index: 3},
			},
			expectedIdxMap: map[int]int{
				1: 0, // Index 1 should most often be first
				3: 1, // Index 3 should most often be second
				// 0 and 2 should be filtered out
			},
			expectedErrIdx: []int{2},
		},
		{
			name: "all zero and negative weights",
			input: SwapMaps{
				{Weight: 0, Index: 0},
				{Weight: -1, Index: 1},
				{Weight: 0, Index: 2},
			},
			expectedIdxMap: map[int]int{}, // none should remain
			expectedErrIdx: []int{1},
		},
		{
			name: "one positive, rest zero/negative",
			input: SwapMaps{
				{Weight: 0, Index: 0},
				{Weight: 15, Index: 1},
				{Weight: -5, Index: 2},
			},
			expectedIdxMap: map[int]int{
				1: 0, // Only index 1 should remain, always at position 0
			},
			expectedErrIdx: []int{2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Store which indices appear with what frequency at each position after sorting
			counts := make(map[int]map[int]int)

			// Run the stochastic sort many times to gather statistics
			for range 5000 {
				cp := make(SwapMaps, len(tc.input))
				copy(cp, tc.input)
				weightError := cp.smSortStochastic()
				if weightError != nil {
					if len(tc.expectedErrIdx) == 0 {
						t.Errorf("unexpected weight error: %+v", weightError)
					} else {
						if !assert.ElementsMatch(t, tc.expectedErrIdx, weightError.NegIdxs, "weight error indices do not match expected") {
							t.Logf("got weight error: %+v", weightError)
						}
					}
				} else {
					if len(tc.expectedErrIdx) != 0 {
						t.Errorf("expected weight error for indices %v, but got none", tc.expectedErrIdx)
					}
				}

				// Record positions of each index in this sorted result
				for pos, sm := range cp {
					if counts[sm.Index] == nil {
						counts[sm.Index] = make(map[int]int)
					}
					counts[sm.Index][pos]++
				}
			}

			// Check that only expected indices remain
			for idx := range counts {
				if _, ok := tc.expectedIdxMap[idx]; !ok {
					t.Errorf("unexpected index %d found after sort (should have been filtered out)", idx)
				}
			}
			for idx := range tc.expectedIdxMap {
				if _, ok := counts[idx]; !ok {
					t.Errorf("expected index %d to remain after sort, but it was missing", idx)
				}
			}

			// Check mode position for each expected index
			for idx, freqMap := range counts {
				modePos, maxCount := -1, -1
				for pos, cnt := range freqMap {
					if cnt > maxCount {
						modePos, maxCount = pos, cnt
					}
				}
				expected, ok := tc.expectedIdxMap[idx]
				if !ok {
					continue // already checked above
				}
				if modePos != expected {
					t.Errorf("index %d: expected mode position %d, got %d (distribution=%v)", idx, expected, modePos, freqMap)
				}
			}
		})
	}
}

func TestGetSortedAds(t *testing.T) {
	// Here we only test expected order of ads for descending sort to avoid dealing
	// with probability distributions in stochastic sort.
	// The SortDescending and SortStochastic methods are tested separately, so all
	// that remains to be covered is that a sorted SwapMaps correctly reorders
	// the ads slice, and that weight errors are logged as expected.

	ad1 := server_structs.ServerAd{URL: url.URL{Scheme: "http", Host: "ad1"}}
	ad1.Initialize("ad1")
	ad2 := server_structs.ServerAd{URL: url.URL{Scheme: "http", Host: "ad2"}}
	ad2.Initialize("ad2")
	ad3 := server_structs.ServerAd{URL: url.URL{Scheme: "http", Host: "ad3"}}
	ad3.Initialize("ad3")

	testCases := []struct {
		name              string
		ads               []server_structs.ServerAd
		swapMaps          SwapMaps
		sortType          smSortType
		expectedOrder     []string // expected order of ad URLs after sorting
		expectLoggedError bool
	}{
		{
			name: "descending sort without errors",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: 10.0},
				{Index: 1, Weight: 20.0},
				{Index: 2, Weight: 15.0},
			},
			sortType:      smSortDescending,
			expectedOrder: []string{"ad2", "ad3", "ad1"},
		},
		{
			name: "descending sort with negative weights triggers error log",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: -5.0},
				{Index: 1, Weight: 20.0},
				{Index: 2, Weight: 5.0},
			},
			sortType:          smSortDescending,
			expectedOrder:     []string{"ad2", "ad3"},
			expectLoggedError: true,
		},
		{
			name: "descending sort with 0 weight does not trigger error log",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: 0.0},
				{Index: 1, Weight: 20.0},
				{Index: 2, Weight: 5.0},
			},
			sortType:          smSortDescending,
			expectedOrder:     []string{"ad2", "ad3"},
			expectLoggedError: false,
		},

		// For adaptive sort, we won't assert a specific order, but we'll
		// still check that error conditions generate logs as expected
		{
			name: "adaptive sort with positive weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: 10.0},
				{Index: 1, Weight: 50.0},
				{Index: 2, Weight: 15.0},
			},
			sortType:          smSortStochastic,
			expectLoggedError: false,
		},
		{
			name: "adaptive sort with mixed weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: 10.0},
				{Index: 1, Weight: -5.0},
				{Index: 2, Weight: 15.0},
			},
			sortType:          smSortStochastic,
			expectLoggedError: true,
		},
		{
			name: "adaptive sort with zero weights",
			ads:  []server_structs.ServerAd{ad1, ad2, ad3},
			swapMaps: SwapMaps{
				{Index: 0, Weight: 0.0},
				{Index: 1, Weight: 5.0},
				{Index: 2, Weight: 15.0},
			},
			sortType:          smSortStochastic,
			expectLoggedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up logrus test logger and hook
			// Initialize the logger and add a test hook
			hook := test.NewGlobal()
			logrus.SetLevel(logrus.WarnLevel)

			sortedAds := tc.swapMaps.GetSortedAds(tc.ads, tc.sortType)

			// Check the order of sorted ads
			if len(tc.expectedOrder) > 0 && len(sortedAds) != len(tc.expectedOrder) {
				t.Fatalf("expected %d ads after sorting, got %d", len(tc.expectedOrder), len(sortedAds))
			}
			for i, expectedName := range tc.expectedOrder {
				if sortedAds[i].Name != expectedName {
					t.Errorf("at position %d: expected ad named %s, got %s", i, expectedName, sortedAds[i].Name)
				}
			}

			// Check for error log if expected
			errorEntries := hook.Entries
			if tc.expectLoggedError {
				found := false
				for _, entry := range errorEntries {
					if entry.Level == logrus.ErrorLevel {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected error log, but none was found")
				}
			} else {
				for _, entry := range errorEntries {
					if entry.Level == logrus.ErrorLevel {
						t.Errorf("unexpected error log: %s", entry.Message)
					}
				}
			}
		})
	}
}

func TestDistanceWeightFn(t *testing.T) {
	testCases := []struct {
		name          string
		clientCoord   server_structs.Coordinate
		serverCoord   server_structs.Coordinate
		weightValid   bool
		expectedValue float64
	}{
		{
			name:          "same coordinates",
			clientCoord:   server_structs.Coordinate{Lat: 40.0, Long: -75.0},
			serverCoord:   server_structs.Coordinate{Lat: 40.0, Long: -75.0},
			weightValid:   true,
			expectedValue: 1.0,
		},
		{
			name:          "different coordinates",
			clientCoord:   server_structs.Coordinate{Lat: 40.0, Long: -75.0},
			serverCoord:   server_structs.Coordinate{Lat: 41.0, Long: -76.0},
			weightValid:   true,
			expectedValue: 0.740, // Approximate expected value (calculated distance w/ external tool and plugged into formula)
		},
		{
			name:        "invalid client coord",
			clientCoord: server_structs.Coordinate{Lat: 0, Long: 0},
			serverCoord: server_structs.Coordinate{Lat: 41.0, Long: -76.0},
			weightValid: false,
		},
		{
			name:        "invalid server coord",
			clientCoord: server_structs.Coordinate{Lat: 40.0, Long: -75.0},
			serverCoord: server_structs.Coordinate{Lat: 0, Long: 0},
			weightValid: false,
		},
		// No actual test for negative inner weight because it's currently impossible
		// and meant only as a guard against future code changes.
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weight, valid := distanceWeightFn(tc.clientCoord.Lat, tc.clientCoord.Long, tc.serverCoord.Lat, tc.serverCoord.Long)
			if tc.weightValid {
				assert.True(t, valid, "expected weight to be valid")
				assert.InDelta(t, tc.expectedValue, weight, 0.001, "weight value does not match expected")
			} else {
				assert.False(t, valid, "expected weight to be invalid")
			}
		})
	}
}

func TestIOLoadWeightFn(t *testing.T) {
	testCases := []struct {
		name          string
		load          float64
		weightValid   bool
		expectedValue float64
	}{
		{
			name:          "zero load",
			load:          0.0,
			weightValid:   true,
			expectedValue: 1.0,
		},
		{
			name:          "below threshold",
			load:          9.0,
			weightValid:   true,
			expectedValue: 1.0,
		},
		{
			name:          "at threshold",
			load:          10.0,
			weightValid:   true,
			expectedValue: 1.0,
		},
		{
			name:          "one halving factor above threshold",
			load:          14.0,
			weightValid:   true,
			expectedValue: 0.5,
		},
		{
			name:          "extremely high load causes underflow",
			load:          float64(1e12),
			weightValid:   true,
			expectedValue: 0.0,
		},
		{
			name:        "negative load is invalid",
			load:        -5.0,
			weightValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weight, valid := ioLoadWeightFn(tc.load)
			if tc.weightValid {
				assert.True(t, valid, "expected weight to be valid")
				assert.Equal(t, tc.expectedValue, weight, "weight value does not match expected")
			} else {
				assert.False(t, valid, "expected weight to be invalid")
			}
		})
	}
}

func TestStatusWeightFn(t *testing.T) {
	testCases := []struct {
		name            string
		statusWeightRaw float64
		weightValid     bool
		expectedValue   float64
	}{
		{
			name:            "raw status weight in valid range",
			statusWeightRaw: 0.5,
			weightValid:     true,
			expectedValue:   0.5,
		},
		{
			name:            "raw status weight beyond lower range",
			statusWeightRaw: 0.0,
			weightValid:     false,
		},
		{
			name:            "raw status weight beyond upper range",
			statusWeightRaw: 1.5,
			weightValid:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weight, valid := statusWeightFn(tc.statusWeightRaw)
			if tc.weightValid {
				assert.True(t, valid, "expected weight to be valid")
				// The status weight function is the identity function within the valid range
				assert.Equal(t, tc.statusWeightRaw, weight, "weight value does not match expected")
			} else {
				assert.False(t, valid, "expected weight to be invalid")
			}

		})
	}
}

func TestAvailabilityWeightFn(t *testing.T) {
	sAd := server_structs.ServerAd{}
	sAd.Initialize("ad1")

	testCases := []struct {
		name           string
		availMap       map[string]bool
		sAd            server_structs.ServerAd
		weightValid    bool
		expectedWeight float64
	}{
		{
			name:           "object available at server",
			availMap:       map[string]bool{sAd.Name: true},
			sAd:            sAd,
			weightValid:    true,
			expectedWeight: 2.0,
		},
		{
			name:           "object not available at server",
			availMap:       map[string]bool{sAd.Name: false},
			sAd:            sAd,
			weightValid:    true,
			expectedWeight: 0.5,
		},
		{
			name:        "server not in availability map",
			availMap:    map[string]bool{},
			sAd:         sAd,
			weightValid: false,
		},
		{
			name:           "nil availability map",
			availMap:       nil,
			sAd:            sAd,
			weightValid:    true,
			expectedWeight: 1.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			weight, valid := availabilityWeightFn(tc.sAd, tc.availMap, 2)
			if tc.weightValid {
				assert.True(t, valid, "expected weight to be valid")
				assert.Equal(t, tc.expectedWeight, weight, "weight value does not match expected")
			} else {
				assert.False(t, valid, "expected weight to be invalid")
			}
		})
	}
}

// Helper for setting up server ads in distance/adaptive sort tests
func getAdBase(name string, lat, long float64) server_structs.ServerAd {
	ad := server_structs.ServerAd{Latitude: lat, Longitude: long, Coordinate: server_structs.Coordinate{Lat: lat, Long: long}, URL: url.URL{Host: name}}
	ad.Initialize(name)
	return ad
}

func TestDistanceSortAlg(t *testing.T) {
	// Note that this test is relatively paired back and doesn't
	// exhaustively test cases like invalid client IPs. This is because
	// the internal functions that handle these edge cases are tested
	// rigorously and separately. For example, getClientCoordinate()
	// is guaranteed to return _some_ client coordinate so a test here
	// for an invalid IP still only tests basic distance sorting logic.

	setupOverrideCache(t) // will map 192.168.1.4 --> Discovery building's lat/long

	testCases := []struct {
		name          string
		sCtx          SortContext
		sAds          []server_structs.ServerAd
		expectedOrder []string
		expectedRInfo map[string]server_structs.ServerRedirectInfo
	}{
		{
			name: "basic distance sort",
			sCtx: SortContext{
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
			},
			sAds: []server_structs.ServerAd{
				// These coordinates are approximate and chosen to yield a clear order
				// based on distance from the Discovery building in Madison, WI
				getAdBase("LA", 34.0522, -118.2437),
				getAdBase("Chicago", 41.8781, -87.6298),
				getAdBase("NYC", 40.7128, -74.0060),
				getAdBase("unknown1", 0.0, 0.0), // invalid coordinates
				getAdBase("unknown2", 0.0, 0.0),
			},
			expectedOrder: []string{"Chicago", "NYC", "unknown1", "unknown2", "LA"},
			expectedRInfo: map[string]server_structs.ServerRedirectInfo{
				"LA": {
					Coordinate:      server_structs.Coordinate{Lat: 34.0522, Long: -118.2437},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.0030855674215090165},
				},
				"NYC": {
					Coordinate:      server_structs.Coordinate{Lat: 40.7128, Long: -74.0060},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.06083031669691837},
				},
				"unknown1": {
					Coordinate:      server_structs.Coordinate{Lat: 0, Long: 0},                          // Will still have invalid coord
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.06083031669691837}, // Will get imputed distance weight from NYC
				},
			},
		},
		{
			name: "all unknown coordinates preserves original order",
			sCtx: SortContext{
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
			},
			sAds: []server_structs.ServerAd{
				getAdBase("unknown1", 0.0, 0.0),
				getAdBase("unknown2", 0.0, 0.0),
				getAdBase("unknown3", 0.0, 0.0),
			},
			expectedOrder: []string{"unknown1", "unknown2", "unknown3"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sortAlg := &DistanceSort{}
			sortedAds, err := sortAlg.Sort(tc.sAds, tc.sCtx)

			// Distance sort should not return an error
			assert.NoError(t, err, "unexpected error from DistanceSort alg")
			assert.Equal(t, len(sortedAds), len(tc.expectedOrder), "number of sorted ads does not match expected")

			// Check order of sorted ads
			for i, expectedName := range tc.expectedOrder {
				assert.Equal(t, expectedName, sortedAds[i].Name, "ad at position %d does not match expected", i)
			}

			// Validate redirect info if expected
			if tc.expectedRInfo != nil {
				for _, ad := range sortedAds {
					expectedRInfo, ok := tc.expectedRInfo[ad.Name]
					if !ok {
						// Skip ads if the test doesn't provide an expected value for this
						// This lets of us only check a subset of redirect info as needed
						continue
					}
					serverInfo := *tc.sCtx.RedirectInfo.ServersInfo[ad.URL.String()]

					// Compare coordinates
					assert.Equal(t, expectedRInfo.Coordinate.Lat, serverInfo.Coordinate.Lat, "lat mismatch for ad '%s'", ad.Name)
					assert.Equal(t, expectedRInfo.Coordinate.Long, serverInfo.Coordinate.Long, "long mismatch for ad '%s'", ad.Name)
					assert.Equal(t, expectedRInfo.Coordinate.AccuracyRadius, serverInfo.Coordinate.AccuracyRadius, "accuracy radius mismatch for ad '%s'", ad.Name)
					assert.Equal(t, expectedRInfo.Coordinate.Source, serverInfo.Coordinate.Source, "coordinate source mismatch for ad '%s'", ad.Name)
					assert.Equal(t, expectedRInfo.Coordinate.FromTTLCache, serverInfo.Coordinate.FromTTLCache, "fromTTLCache mismatch for ad '%s'", ad.Name)

					// Compare redirect weights (in delta because of floating point math)
					assert.InDelta(t, expectedRInfo.RedirectWeights.DistanceWeight, serverInfo.RedirectWeights.DistanceWeight, 1e-8, "distance weight mismatch for ad '%s'", ad.Name)
					assert.InDelta(t, expectedRInfo.RedirectWeights.IOLoadWeight, serverInfo.RedirectWeights.IOLoadWeight, 1e-8, "io load weight mismatch for ad '%s'", ad.Name)
					assert.InDelta(t, expectedRInfo.RedirectWeights.StatusWeight, serverInfo.RedirectWeights.StatusWeight, 1e-8, "status weight mismatch for ad '%s'", ad.Name)
					assert.InDelta(t, expectedRInfo.RedirectWeights.AvailabilityWeight, serverInfo.RedirectWeights.AvailabilityWeight, 1e-8, "availability weight mismatch for ad '%s'", ad.Name)
				}
			}
		})
	}
}

func TestAdaptiveSortAlg(t *testing.T) {
	// There are two primary test types here:
	// - A set of tests that test adaptive sorting along individual weight axes.
	//   These work by setting all but one weight to a constant value, and
	//   varying the remaining weight to produce a clear expected order.
	// - A "snapshot" test that comes from a real-world snapshot of server state
	//   from a Madison client in July 2025. Before refactoring the Director's sorting
	//   logic/algorithms (which happened shortly after this snapshot was taken),
	//   the adaptive sort algorithm produced an ordering we decided was wrong because
	//   it mishandled unknown load values and sorted European caches to the top of the
	//   list for a US client. The snapshot test makes sure these issues remain fixed.
	//
	// Both the tests use multiple runs of the stochastic sort in an attempt to catch
	// improbable-but-possible misorderings. The assumption for the per-axis tests is
	// that ordering each server along the varied axis should produce a clear mode position
	// after the stochastic sort. That is, if s1 has the highest weight and s2 has second
	// highest, s1 should appear most often at position 0 and s2 should appear most often
	// at position 1.
	setupOverrideCache(t) // will map 192.168.1.4 --> Discovery building's lat/long

	var getAd = func(name string, lat, long float64, ioLoad float64, sWeight float64) server_structs.ServerAd {
		ad := getAdBase(name, lat, long)
		ad.IOLoad = ioLoad
		ad.StatusWeight = sWeight
		return ad
	}

	testCases := []struct {
		name             string
		sCtx             SortContext
		sAds             []server_structs.ServerAd
		expectedModeIdxs map[string][]int // If ad name maps to multiple valid mode positions, list them all here
		expectedRInfo    map[string]server_structs.ServerRedirectInfo
	}{
		{
			name: "sort along distance weight axis",
			sCtx: SortContext{
				Ctx:          context.Background(),
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
			},
			sAds: []server_structs.ServerAd{
				// These coordinates are approximate and chosen to yield a clear order
				// based on distance from the Discovery building in Madison, WI
				getAd("LA", 34.0522, -118.2437, 0.0, 0.5),
				getAd("Chicago", 41.8781, -87.6298, 0.0, 0.5),
				getAd("NYC", 40.7128, -74.0060, 0.0, 0.5),
				getAd("unknown1", 0.0, 0.0, 0.0, 0.5), // unknowns should be in middle
				getAd("unknown2", 0.0, 0.0, 0.0, 0.5),
			},
			expectedModeIdxs: map[string][]int{
				"Chicago":  {0},
				"NYC":      {1, 2, 3}, // NYC's distance will become the imputed median, so it will flipflop with unknowns
				"unknown1": {1, 2, 3},
				"unknown2": {1, 2, 3},
				"LA":       {4},
			},
			expectedRInfo: map[string]server_structs.ServerRedirectInfo{
				"LA": {
					Coordinate:      server_structs.Coordinate{Lat: 34.0522, Long: -118.2437},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.0030855674215090165, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
				"NYC": {
					Coordinate:      server_structs.Coordinate{Lat: 40.7128, Long: -74.0060},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.06083031669691837, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
				"unknown1": {
					Coordinate:      server_structs.Coordinate{Lat: 0, Long: 0}, // Will still have invalid coord, but distance weight will be imputed from NYC weight
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 0.06083031669691837, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
			},
		},
		{
			name: "sort along io load weight axis",
			sCtx: SortContext{
				Ctx:          context.Background(),
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
			},
			sAds: []server_structs.ServerAd{
				getAd("zero load", 43.07296, -89.40831, 0.0, 0.5),                                                              // should produce ioLoad weight of 1.0
				getAd("load below threshold", 43.07296, -89.40831, loadHalvingThreshold*0.5, 0.5),                              // also 1.0
				getAd("load slightly above threshold", 43.07296, -89.40831, loadHalvingThreshold+(3.0*loadHalvingFactor), 0.5), // Load weight of 1/8
				getAd("load greatly above threshold", 43.07296, -89.40831, loadHalvingThreshold+(5.0*loadHalvingFactor), 0.5),  // Load weight of 1/32
				getAd("load causes underflow", 43.07296, -89.40831, 1e12, 0.5),                                                 // should produce ioLoad weight of 0.0, causing filtering
				getAd("unknown1", 43.07296, -89.40831, -1.0, 0.5),                                                              // unknowns should produce median load weight of 1/8
				getAd("unknown2", 43.07296, -89.40831, -1.0, 0.5),
			},
			expectedModeIdxs: map[string][]int{
				"zero load":                     {0, 1}, // will filpflop with load below threshold
				"load below threshold":          {0, 1},
				"unknown1":                      {2, 3, 4}, // although the underflow load gets filtered, it's still used in median calc
				"unknown2":                      {2, 3, 4},
				"load slightly above threshold": {2, 3, 4},
				"load greatly above threshold":  {5},
				"load causes underflow":         {}, // should be filtered out
			},
			expectedRInfo: map[string]server_structs.ServerRedirectInfo{
				"zero load": {
					Coordinate:      server_structs.Coordinate{Lat: 43.07296, Long: -89.40831},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 1.0, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
				"load causes underflow": {
					Coordinate:      server_structs.Coordinate{Lat: 43.07296, Long: -89.40831},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 1.0, IOLoadWeight: 0.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
				"load below threshold": {
					Coordinate:      server_structs.Coordinate{Lat: 43.07296, Long: -89.40831},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 1.0, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
			},
		},
		{
			name: "sort along status weight axis",
			sCtx: SortContext{
				Ctx:          context.Background(),
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
			},
			sAds: []server_structs.ServerAd{
				getAd("one status weight", 43.07296, -89.40831, 0.0, 1.0),
				getAd("very small status weight", 43.07296, -89.40831, 0.0, math.SmallestNonzeroFloat64), // smallest value EWMA calc will set
				getAd("medium weight", 43.07296, -89.40831, 0.0, 0.5),
				getAd("unknown status weight", 43.07296, -89.40831, 0.0, 0.0), // constitutes error, impute median
				getAd("negative status weight", 43.07296, -89.40831, 0.0, -1), // shouldn't happen, but would be treated as unknown
			},
			expectedModeIdxs: map[string][]int{
				"one status weight":        {0},
				"medium weight":            {1, 2, 3},
				"unknown status weight":    {1, 2, 3},
				"negative status weight":   {1, 2, 3},
				"very small status weight": {4},
			},
			expectedRInfo: map[string]server_structs.ServerRedirectInfo{
				// Already checked RInfo in other cases, only one per test from here on out.
				"medium weight": {
					Coordinate:      server_structs.Coordinate{Lat: 43.07296, Long: -89.40831},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 1.0, IOLoadWeight: 1.0, StatusWeight: 0.5, AvailabilityWeight: 1.0},
				},
			},
		},
		{
			name: "sort along avail weight axis with availability map",
			sCtx: SortContext{
				Ctx:          context.Background(),
				ClientAddr:   netip.MustParseAddr("192.168.1.4"),
				RedirectInfo: &server_structs.RedirectInfo{},
				AvailabilityMap: map[string]bool{
					"s1": true,  // avail weight 2.0
					"s2": false, // avail weight 0.5
					"s3": true,
					"s4": false,
				},
			},
			sAds: []server_structs.ServerAd{
				getAd("s1", 43.07296, -89.40831, 0.0, 1.0),
				getAd("s2", 43.07296, -89.40831, 0.0, 1.0),
				getAd("s3", 43.07296, -89.40831, 0.0, 1.0),
				getAd("s4", 43.07296, -89.40831, 0.0, 1.0),
				getAd("unknown", 43.07296, -89.40831, 0.0, 1.0), // should get median avail weight of 1.25
			},
			expectedModeIdxs: map[string][]int{
				"s1":      {0, 1},
				"s3":      {0, 1},
				"unknown": {2},
				"s2":      {3, 4},
				"s4":      {3, 4},
			},
			expectedRInfo: map[string]server_structs.ServerRedirectInfo{
				// Already checked RInfo in other cases, only one per test from here on out.
				"unknown": {
					Coordinate:      server_structs.Coordinate{Lat: 43.07296, Long: -89.40831},
					RedirectWeights: server_structs.RedirectWeights{DistanceWeight: 1.0, IOLoadWeight: 1.0, StatusWeight: 1.0, AvailabilityWeight: 1.25},
				},
			},
		},
		// No explicit test for nil availability map because it results
		// in uniform random sorting along that axis, and this case was
		// implicitly tested by previous adaptive sort tests!
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			counts := make(map[string]map[int]int)
			for range 5000 {
				sortAlg := &AdaptiveSort{}
				sortedAds, err := sortAlg.Sort(tc.sAds, tc.sCtx)
				assert.NoError(t, err, "unexpected error from AdaptiveSort alg")

				// Record positions of each ad in this sorted result
				for pos, ad := range sortedAds {
					if counts[ad.Name] == nil {
						counts[ad.Name] = make(map[int]int)
					}
					counts[ad.Name][pos]++
				}

				// Validate redirect info if expected
				if tc.expectedRInfo != nil {
					for _, ad := range sortedAds {
						expectedRInfo, ok := tc.expectedRInfo[ad.Name]
						if !ok {
							// Skip ads if the test doesn't provide an expected value for this
							// This lets of us only check a subset of redirect info as needed
							continue
						}
						serverInfo := *tc.sCtx.RedirectInfo.ServersInfo[ad.URL.String()]

						// Use require here because if RInfo values are incorrect, sorts later in the test will likely be invalid
						require.Equal(t, expectedRInfo.Coordinate.Lat, serverInfo.Coordinate.Lat, "lat mismatch for ad '%s'", ad.Name)
						require.Equal(t, expectedRInfo.Coordinate.Long, serverInfo.Coordinate.Long, "long mismatch for ad '%s'", ad.Name)
						require.Equal(t, expectedRInfo.Coordinate.AccuracyRadius, serverInfo.Coordinate.AccuracyRadius, "accuracy radius mismatch for ad '%s'", ad.Name)
						require.Equal(t, expectedRInfo.Coordinate.Source, serverInfo.Coordinate.Source, "coordinate source mismatch for ad '%s'", ad.Name)
						require.Equal(t, expectedRInfo.Coordinate.FromTTLCache, serverInfo.Coordinate.FromTTLCache, "fromTTLCache mismatch for ad '%s'", ad.Name)

						// Compare redirect weights (in delta because of floating point math)
						require.InDelta(t, expectedRInfo.RedirectWeights.DistanceWeight, serverInfo.RedirectWeights.DistanceWeight, 1e-8, "distance weight mismatch for ad '%s'", ad.Name)
						require.InDelta(t, expectedRInfo.RedirectWeights.IOLoadWeight, serverInfo.RedirectWeights.IOLoadWeight, 1e-8, "io load weight mismatch for ad '%s'", ad.Name)
						require.InDelta(t, expectedRInfo.RedirectWeights.StatusWeight, serverInfo.RedirectWeights.StatusWeight, 1e-8, "status weight mismatch for ad '%s'", ad.Name)
						require.InDelta(t, expectedRInfo.RedirectWeights.AvailabilityWeight, serverInfo.RedirectWeights.AvailabilityWeight, 1e-8, "availability weight mismatch for ad '%s'", ad.Name)
					}
				}
			}

			// Check that computed modes match expected modes
			for adName, freqMap := range counts {
				modePos, maxCount := -1, -1
				for pos, cnt := range freqMap {
					if cnt > maxCount {
						modePos, maxCount = pos, cnt
					}
				}
				expectedPositions, ok := tc.expectedModeIdxs[adName]
				if !ok {
					t.Errorf("unexpected ad %s found after sort (should have been filtered out)", adName)
					continue
				}
				if !slices.Contains(expectedPositions, modePos) {
					t.Errorf("ad %s: expected mode position in %v, got %d (distribution=%v)", adName, expectedPositions, modePos, freqMap)
				}
			}
		})
	}

	t.Run("full snapshot test with real ads", func(t *testing.T) {
		// This test uses a real snapshot of information from the OSDF in ~July 2025
		// that came from the Director's "redirectInfo" for a client request in Madison, WI.
		// Status and availability weights were not present, so those are set to constant values
		// for this test (we can always get a new snapshot in the future and update if desired).
		// The assertions for this test are meant to:
		// 1) Ensure no non-USA-based servers appear in the output results (they should all be
		//    filtered by the first pass of distance weights)
		// 2) Ensure we get the expected number of server ads (sourceWorkingSetSize)
		//
		// Beyond that, we don't assert a specific order because doing so in this multi-dimensional
		// stochastic sort makes it seem like we mere mortals actually know the "correct" order.
		sCtx := SortContext{
			Ctx:          context.Background(),
			ClientAddr:   netip.MustParseAddr("192.168.1.4"),
			RedirectInfo: &server_structs.RedirectInfo{},
		}
		snapshotAds := []server_structs.ServerAd{
			getAd("https://amst-fiona.nationalresearchplatform.org:8443", 52.3759, 4.8975, 90.79649122807017, 1.0),
			getAd("https://amst-osdf-xcache01.es.net:8443", 52.3759, 4.8975, 0, 1.0),
			getAd("https://buzzard-pelican-ext.pace.gatech.edu:8443", 33.7697, -84.3754, 83.17163799425266, 1.0),
			getAd("https://ccpelicanli01.in2p3.fr:8443", 48.8582, 2.3387, 73.0979891298627, 1.0),
			getAd("https://cf-ac-uk-cache.nationalresearchplatform.org:8443", 51.4801, -3.1855, 71.8774451840182, 1.0),
			getAd("https://dtn-pas.bois.nrp.internet2.edu:8443", 43.6349, -116.2023, 108.14186865780573, 1.0),
			getAd("https://dtn-pas.denv.nrp.internet2.edu:8443", 39.7391, -104.9866, 142.77894736842103, 1.0),
			getAd("https://dtn-pas.hous.nrp.internet2.edu:8443", 29.7539, -95.359, 64.05263157894736, 1.0),
			getAd("https://dtn-pas.jack.nrp.internet2.edu:8443", 30.3337, -81.6542, 200.95859985473635, 1.0),
			getAd("https://dtn-pas.kans.nrp.internet2.edu:8443", 39.1024, -94.5986, 218.10953722644638, 1.0),
			getAd("https://fdp-d3d-cache.nationalresearchplatform.org:8443", 32.8919, -117.2035, 70.01428075186227, 1.0),
			getAd("https://kagra-dsr-b1.icrr.u-tokyo.ac.jp:8443", 35.8566, 139.9185, 41.01481481481482, 1.0),
			getAd("https://mghpcc-cache.nationalresearchplatform.org:8443", 42.2043, -72.6162, 235.43591381022392, 1.0),
			getAd("https://ncar-cache.nationalresearchplatform.org:8443", 39.9834, -105.143, 59.42105263157894, 1.0),
			getAd("https://osdf-cache.sprace.org.br:8443", -23.5475, -46.6361, 0, 1.0),
			getAd("https://osdf1.amst.nrp.internet2.edu:8443", 53.2048, 5.8055, 55.6446378133717, 1.0),
			getAd("https://osdf1.chic.nrp.internet2.edu:8443", 41.8882, -87.6164, 130.5337913466363, 1.0),
			getAd("https://osdf1.newy32aoa.nrp.internet2.edu:8443", 40.78, -73.97, 100.3017543859649, 1.0),
			getAd("https://osdfcache.ligo.caltech.edu:8443", 34.1424, -118.1257, 51.09824561403508, 1.0),
			getAd("https://osg-cache.ms4.surfsara.nl:8443", 52.3824, 4.8995, 63.831354977701835, 1.0),
			getAd("https://osg-houston-stashcache.nrp.internet2.edu:8443", 29.8137, -95.3111, 43.9578947368421, 1.0),
			getAd("https://osg-sunnyvale-stashcache.nrp.internet2.edu:8443", 37.4043, -122.0748, 101.86315789473683, 1.0),
			getAd("https://sdsc-cache.nationalresearchplatform.org:8443", 32.7173, -117.157, 64.6699485264964, 1.0),
			getAd("https://singapore.nationalresearchplatform.org:8443", 1.3024, 103.7857, 36.266666666666666, 1.0),
			getAd("https://ucsd-t2-cache.nationalresearchplatform.org:8443", 32.7173, -117.157, 181.9830946775252, 1.0),
			getAd("https://unl-cache.nationalresearchplatform.org:8443", 40.8035, -96.651, 523.5684210526315, 1.0),
		}

		urlsSet := map[string]struct{}{}
		sortAlg := &AdaptiveSort{}
		// Run the test multiple times to catch low-probability servers
		// that shouldn't end up in the results
		for range 5000 {
			sortedAds, err := sortAlg.Sort(snapshotAds, sCtx)
			assert.NoError(t, err, "unexpected error from AdaptiveSort alg")
			assert.Equal(t, sourceWorkingSetSize, len(sortedAds), "number of sorted ads does not match expected")
			for _, ad := range sortedAds {
				urlsSet[ad.Name] = struct{}{}
			}
		}

		// A set of caches we'd NEVER want the Madison client to be sent to
		// because they're outside the US and thus too far away to even consider.
		// These should be filtered by the adaptive sort's first pass over
		// distance weights as long as len(snapshotAds) - len(these ads) > sourceWorkingSetSize.
		shouldNeverBeReturned := []string{
			"https://amst-fiona.nationalresearchplatform.org:8443",
			"https://amst-osdf-xcache01.es.net:8443",
			"https://ccpelicanli01.in2p3.fr:8443",
			"https://cf-ac-uk-cache.nationalresearchplatform.org:8443",
			"https://kagra-dsr-b1.icrr.u-tokyo.ac.jp:8443",
			"https://osdf1.amst.nrp.internet2.edu:8443",
			"https://osdf-cache.sprace.org.br:8443",
			"https://osg-cache.ms4.surfsara.nl:8443",
			"https://singapore.nationalresearchplatform.org:8443",
		}

		for _, badUrl := range shouldNeverBeReturned {
			if _, found := urlsSet[badUrl]; found {
				t.Errorf("server %s should not have been returned by adaptive sort", badUrl)
			}
		}
	})
}

func TestSortServerAdsByTopo(t *testing.T) {
	mock1 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock1.ServerAd.Initialize("alpha")
	mock2 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock2.ServerAd.Initialize("bravo")
	mock3 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: true,
		},
	}
	mock3.ServerAd.Initialize("charlie")
	mock4 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock4.ServerAd.Initialize("alpha")
	mock5 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock5.ServerAd.Initialize("bravo")
	mock6 := server_structs.Advertisement{
		ServerAd: server_structs.ServerAd{
			FromTopology: false,
		},
	}
	mock6.ServerAd.Initialize("charlie")

	inputList := []*server_structs.Advertisement{&mock6, &mock1, &mock2, &mock4, &mock5, &mock3}
	expectedList := []*server_structs.Advertisement{&mock4, &mock5, &mock6, &mock1, &mock2, &mock3}

	sortServerAdsByTopo(inputList)

	assert.EqualValues(t, expectedList, inputList)
}

func TestSortServerAdsByAvailability(t *testing.T) {
	firstUrl := url.URL{Host: "first.org", Scheme: "https"}
	secondUrl := url.URL{Host: "second.org", Scheme: "https"}
	thirdUrl := url.URL{Host: "third.org", Scheme: "https"}
	fourthUrl := url.URL{Host: "fourth.org", Scheme: "https"}

	firstServer := server_structs.ServerAd{URL: firstUrl}
	secondServer := server_structs.ServerAd{URL: secondUrl}
	thirdServer := server_structs.ServerAd{URL: thirdUrl}
	fourthServer := server_structs.ServerAd{URL: fourthUrl}

	randomOrder := []server_structs.ServerAd{thirdServer, firstServer, fourthServer, secondServer}
	expected := []server_structs.ServerAd{firstServer, secondServer, thirdServer, fourthServer}
	avaiMap := map[string]bool{}
	avaiMap[firstUrl.String()] = true
	avaiMap[secondUrl.String()] = true
	avaiMap[thirdUrl.String()] = false
	avaiMap[fourthUrl.String()] = false

	sortServerAdsByAvailability(randomOrder, avaiMap)
	assert.EqualValues(t, expected, randomOrder)
}
