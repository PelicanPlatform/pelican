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
