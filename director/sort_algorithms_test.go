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
	assert.Equal(t, 0.0, distanceWeight(43.0753, -89.4114, 43.0753, -89.4114, true))
	assert.Equal(t, 69.0, math.Round(distanceWeight(42.0753, -89.4114, 43.0753, -89.4114, true)))
	assert.Equal(t, 50.0, math.Round(distanceWeight(43.0753, -90.4114, 43.0753, -89.4114, true)))
}

func TestGatedHavlingMultiplier(t *testing.T) {
	// return 1.0 if the havlvingFactor is zero
	assert.Equal(t, 1.0, gatedHavlingMultiplier(1.0, 10.0, 0.0))
	// return 1.0 if the threshold is zero
	assert.Equal(t, 1.0, gatedHavlingMultiplier(10.0, 0.0, 0.0))

	// return 1.0 if load < threshold
	assert.Equal(t, 1.0, gatedHavlingMultiplier(1.0, 10.0, 4.0))
	assert.Equal(t, 1.0, gatedHavlingMultiplier(10.0, 10.0, 4.0))

	// return 1.0 if threshold <= load < threshold + havlvingFactor
	assert.Equal(t, 1.0, gatedHavlingMultiplier(10.1, 10.0, 4.0))
	assert.Equal(t, 1.0, gatedHavlingMultiplier(13.9, 10.0, 4.0))

	// return half if load >= threshold + havlvingFactor
	assert.Equal(t, 0.5, gatedHavlingMultiplier(14, 10.0, 4.0))

	// return 1/4 if load >= threshold + 2* havlvingFactor
	assert.Equal(t, 0.25, gatedHavlingMultiplier(18, 10.0, 4.0))
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
	}
	t.Run("0-maxOut-returns-all", func(t *testing.T) {
		c, r := stochasticSort(mockSwapMaps, 0)
		assert.Len(t, c, len(mockSwapMaps))
		assert.Len(t, r, len(mockSwapMaps))
	})

	t.Run("maxOut-greater-than-length-returns-nothing", func(t *testing.T) {
		c, r := stochasticSort(mockSwapMaps, len(mockSwapMaps)+1)
		assert.Len(t, c, 0)
		assert.Len(t, r, 0)
	})

	t.Run("maxOut-returns-correctly", func(t *testing.T) {
		c, r := stochasticSort(mockSwapMaps, 3)
		assert.Len(t, c, 3)
		assert.Len(t, r, 3)
	})

	t.Run("random-num-matches-range", func(t *testing.T) {
		c, r := stochasticSort(mockSwapMaps, 0)
		ranges := [][]float64{} // items in ranges should corresponds to items in sm
		for idx, val := range mockSwapMaps {
			if idx == 0 {
				ranges = append(ranges, []float64{0.0, val.Weight})
			} else {
				prev := ranges[idx-1][1]
				ranges = append(ranges, []float64{prev, prev + val.Weight})
			}
		}

		for ridx, ran := range r {
			foundWeight := -1.0
			foundMMIdx := -1
			for midx, mm := range mockSwapMaps {
				if c[ridx] == mm.Index {
					foundWeight = mm.Weight
					foundMMIdx = midx
				}
			}
			assert.NotEqual(t, foundWeight, -1.0)
			assert.NotEqual(t, foundMMIdx, -1)

			assert.True(t, ran >= ranges[foundMMIdx][0] && ran < ranges[foundMMIdx][1])
		}
	})
}
