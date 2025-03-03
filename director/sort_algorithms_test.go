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
		c:= stochasticSort(mockSwapMaps, len(mockSwapMaps)+1)
		assert.Len(t, c, len(mockSwapMaps))
	})

	t.Run("maxOut-returns-correctly", func(t *testing.T) {
		c := stochasticSort(mockSwapMaps, 3)
		assert.Len(t, c, 3)
	})
}
