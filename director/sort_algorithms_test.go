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
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDistanceWeight(t *testing.T) {
	// Some basic values to test and ensure it returns miles, not radian
	d, isRand := distanceWeight(43.0753, -89.4114, 43.0753, -89.4114, true)
	assert.False(t, isRand)
	assert.Equal(t, 0.0, d)

	d, isRand = distanceWeight(42.0753, -89.4114, 43.0753, -89.4114, true)
	assert.False(t, isRand)
	assert.Equal(t, 69.0, math.Round(d))

	d, isRand = distanceWeight(43.0753, -90.4114, 43.0753, -89.4114, true)
	assert.False(t, isRand)
	assert.Equal(t, 50.0, math.Round(d))

	// Test passing null lat long
	_, isRand = distanceWeight(0, 0, 0, 0, true)
	assert.True(t, isRand)

	_, isRand = distanceWeight(42.0753, -89.4114, 0, 0, true)
	assert.True(t, isRand)

	_, isRand = distanceWeight(0, 0, 43.0753, -89.4114, true)
	assert.True(t, isRand)

	// Make sure a 0 in both is not mistaken for null
	_, isRand = distanceWeight(43.0753, 0, 0, -89.4114, true)
	assert.False(t, isRand)
}

func TestGatedHalvingMultiplier(t *testing.T) {
	// return 1.0 if the havlvingFactor is zero
	assert.Equal(t, 1.0, gatedHalvingMultiplier(1.0, 10.0, 0.0))
	// return 1.0 if the threshold is zero
	assert.Equal(t, 1.0, gatedHalvingMultiplier(10.0, 0.0, 0.0))

	// return 1.0 if load < threshold
	assert.Equal(t, 1.0, gatedHalvingMultiplier(1.0, 10.0, 4.0))
	assert.Equal(t, 1.0, gatedHalvingMultiplier(10.0, 10.0, 4.0))

	// return 1.0 if threshold <= load < threshold + havlvingFactor
	assert.Equal(t, 1.0, gatedHalvingMultiplier(10.1, 10.0, 4.0))
	assert.Equal(t, 1.0, gatedHalvingMultiplier(13.9, 10.0, 4.0))

	// return half if load >= threshold + havlvingFactor
	assert.Equal(t, 0.5, gatedHalvingMultiplier(14, 10.0, 4.0))

	// return 1/4 if load >= threshold + 2* havlvingFactor
	assert.Equal(t, 0.25, gatedHalvingMultiplier(18, 10.0, 4.0))
}

// Given a set of ranges, test that the correct index is removed
// and the remaining ranges are shifted to the left.
func TestRemoveAndRerange(t *testing.T) {
	tests := []struct {
		name           string
		wSum           float64
		ranges         map[int][]float64
		index          int
		expectedWSum   float64
		expectedRanges map[int][]float64
	}{
		{
			name: "Remove middle range",
			wSum: 10.0,
			ranges: map[int][]float64{
				0: {0.0, 2.0},
				1: {2.0, 5.0},
				2: {5.0, 10.0},
			},
			index:        1,
			expectedWSum: 7.0,
			expectedRanges: map[int][]float64{
				0: {0.0, 2.0},
				2: {2.0, 7.0},
			},
		},
		{
			name: "Remove first range",
			wSum: 10.0,
			ranges: map[int][]float64{
				0: {0.0, 2.0},
				1: {2.0, 5.0},
				2: {5.0, 10.0},
			},
			index:        0,
			expectedWSum: 8.0,
			expectedRanges: map[int][]float64{
				1: {0.0, 3.0},
				2: {3.0, 8.0},
			},
		},
		{
			name: "Remove last range",
			wSum: 10.0,
			ranges: map[int][]float64{
				0: {0.0, 2.0},
				1: {2.0, 5.0},
				2: {5.0, 10.0},
			},
			index:        2,
			expectedWSum: 5.0,
			expectedRanges: map[int][]float64{
				0: {0.0, 2.0},
				1: {2.0, 5.0},
			},
		},
		{
			name: "Remove only range",
			wSum: 2.0,
			ranges: map[int][]float64{
				0: {0.0, 2.0},
			},
			index:          0,
			expectedWSum:   0.0,
			expectedRanges: map[int][]float64{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			removeAndRerange(&tt.wSum, tt.ranges, tt.index)
			assert.Equal(t, tt.expectedWSum, tt.wSum)
			assert.Equal(t, tt.expectedRanges, tt.ranges)
		})
	}
}

// Given a list of swap maps, test that the correct ranges are generated
// This test assumes that negative values are normalized to positive values
// using the scheme described in the function.
func TestGenerateRanges(t *testing.T) {
	tests := []struct {
		name           string
		sm             SwapMaps
		expectedWSum   float64
		expectedRanges map[int][]float64
	}{
		{
			name: "Positive weights",
			sm: SwapMaps{
				0: {Index: 0, Weight: 2.0},
				1: {Index: 1, Weight: 3.0},
				2: {Index: 2, Weight: 5.0},
			},
			expectedWSum: 10.0,
			expectedRanges: map[int][]float64{
				0: {0.0, 2.0},
				1: {2.0, 5.0},
				2: {5.0, 10.0},
			},
		},
		{
			// When all weights are negative, we normalize using 1.0 as the numerator
			name: "Negative weights",
			sm: SwapMaps{
				0: {Index: 0, Weight: -2.0}, // converts to -1 / (-2 - 1) = 0.3333
				1: {Index: 1, Weight: -3.0}, // converts to -1 / (-3 - 1) = 0.25
				2: {Index: 2, Weight: -5.0}, // converts to -1 / (-5 - 1) = 0.1667
			},
			expectedWSum: 0.75,
			expectedRanges: map[int][]float64{
				0: {0.0, 0.3333},
				1: {0.3333, 0.5833},
				2: {0.5833, 0.75},
			},
		},
		{
			name: "Mixed weights",
			sm: SwapMaps{
				0: {Index: 0, Weight: -2.0}, // converts to -3 / (-2 - 1) = 1
				1: {Index: 1, Weight: 3.0},
				2: {Index: 2, Weight: -5.0}, // converts to -3 / (-5 - 1) = 0.5
			},
			expectedWSum: 4.5,
			expectedRanges: map[int][]float64{
				0: {0.0, 1.0},
				1: {1.0, 4.0},
				2: {4.0, 4.5},
			},
		},
		{
			name: "Single weight",
			sm: SwapMaps{
				0: {Index: 0, Weight: 2.0},
			},
			expectedWSum: 2.0,
			expectedRanges: map[int][]float64{
				0: {0.0, 2.0},
			},
		},
		{
			name: "Zero weight",
			sm: SwapMaps{
				0: {Index: 0, Weight: 0.0},
			},
			expectedWSum: 0.0,
			expectedRanges: map[int][]float64{
				0: {0.0, 0.0},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wSum, ranges := generateRanges(tt.sm)
			assert.InDelta(t, tt.expectedWSum, wSum, 0.0001) // InDelta to get around float precision
			for key, val := range ranges {
				assert.InDeltaSlice(t, tt.expectedRanges[key], val, 0.0001)
			}
		})
	}
}

func TestStochasticSort(t *testing.T) {
	mockSwapMaps := SwapMaps{
		{Weight: 0.2, Index: 2},
		{Weight: 0.1, Index: 1},
		{Weight: 0.4, Index: 6},
		{Weight: 0.05, Index: 3},
		{Weight: 10.5, Index: 4},
		{Weight: 8, Index: 5},
		{Weight: 2.1, Index: 0},
		{Weight: -0.9, Index: 7},
	}
	t.Run("non-positive-maxOut-returns-all", func(t *testing.T) {
		c := stochasticSort(mockSwapMaps, 0)
		assert.Len(t, c, len(mockSwapMaps))

		c = stochasticSort(mockSwapMaps, -1)
		assert.Len(t, c, len(mockSwapMaps))

		c = stochasticSort(mockSwapMaps, -10)
		assert.Len(t, c, len(mockSwapMaps))
	})

	t.Run("maxOut-greater-than-length-returns-len-of-sm", func(t *testing.T) {
		c := stochasticSort(mockSwapMaps, len(mockSwapMaps)+1)
		assert.Len(t, c, len(mockSwapMaps))
	})

	t.Run("maxOut-returns-correctly", func(t *testing.T) {
		c := stochasticSort(mockSwapMaps, 3)
		assert.Len(t, c, 3)
	})
}
