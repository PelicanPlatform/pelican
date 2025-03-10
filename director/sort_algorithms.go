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
	"math/rand"
)

const earthRadiusToMilesFactor = 3960

// Mathematical function, not implementation, came from
// http://www.johndcook.com/python_longitude_latitude.html
// Returned values are not actual distances, but is relative to earth's radius
func distanceOnSphere(lat1 float64, long1 float64, lat2 float64, long2 float64) float64 {

	if (lat1 == lat2) && (long1 == long2) {
		return 0.0
	}

	// Convert latitude and longitude to
	// spherical coordinates in radians.
	degrees_to_radians := math.Pi / 180.0

	// phi = 90 - latitude
	phi1 := (90.0 - lat1) * degrees_to_radians
	phi2 := (90.0 - lat2) * degrees_to_radians

	// theta = longitude
	theta1 := long1 * degrees_to_radians
	theta2 := long2 * degrees_to_radians

	// Compute spherical distance from spherical coordinates.

	// For two locations in spherical coordinates
	// (1, theta, phi) and (1, theta, phi)
	// cosine( arc length ) =
	//    sin phi sin phi' cos(theta-theta') + cos phi cos phi'
	// distance = rho * arc length

	cos := (math.Sin(phi1)*math.Sin(phi2)*math.Cos(theta1-theta2) +
		math.Cos(phi1)*math.Cos(phi2))
	arc := math.Acos(cos)

	return arc
}

// Create a weight between [0,1] that indicates a priority. The returned weight is directly correlated
// with priority (higher weight is higher priority is lower distance)
//
// Is realD set to true, then return the distance between the two coordinates in miles
func distanceWeight(lat1 float64, long1 float64, lat2 float64, long2 float64, realD bool) (weight float64, isRand bool) {
	// If either coordinate is sitting at null island, return a random weight
	isRand = false
	if (lat1 == 0.0 && long1 == 0.0) || (lat2 == 0.0 && long2 == 0.0) {
		isRand = true
		weight = rand.Float64() // technically this returns [0,1)
	} else if realD {
		weight = distanceOnSphere(lat1, long1, lat2, long2) * earthRadiusToMilesFactor
	} else {
		weight = 1 - (distanceOnSphere(lat1, long1, lat2, long2) / math.Pi)
	}
	return
}

// Given the input value, return a weight [0, 1.0] based on the gated havling of the base weight 1.0.
//   - If the input value is between 0.0 and the threshold, return 1.0.
//   - If the input value is above the threshold, the weight decreases by half for every halvingFactor units of the input value
func gatedHalvingMultiplier(val float64, threshold float64, halvingFactor float64) float64 {
	if halvingFactor == 0 || threshold == 0 {
		return 1.0
	}
	if val >= 0.0 && val <= threshold {
		return 1.0
	} else {
		// multiplier decreases by half for every havlvingFactor units of the value for value above the threshold
		base := math.Max(1, (math.Floor((val-threshold)/halvingFactor))*2)
		multiplier := 1.0 / base
		return multiplier
	}
}

// Given a map of ranges and an index, remove the range at the index and shift the rest of the ranges
// to the left. Assumes incoming ranges are all positive values.
func removeAndRerange(wSum *float64, ranges map[int][]float64, index int) {
	shiftVal := ranges[index][1] - ranges[index][0]
	*wSum -= shiftVal
	delete(ranges, index)
	for i := range ranges {
		if i > index {
			ranges[i][0] -= shiftVal
			ranges[i][1] -= shiftVal
		}
	}
}

// Given a SwapMaps struct, generate the ranges for each weight and the total weight sum.
func generateRanges(sm SwapMaps) (wSum float64, ranges map[int][]float64) {
	wSum = 0.0
	ranges = make(map[int][]float64, len(sm))
	// Some incoming weights may be negative, indicating they should be sorted at the end of the list.
	// However, this adaptive sort algorithm assumes positive weights because of the way it stochastically
	// grabs values from ranges. To handle this, we'll normalize the negative weights by making positive and
	// dividing by the smallest non-negative weight from the swap maps. This guarantees negative weights always
	// have a smaller range than positive weights, and more heavily negative weights have smaller ranges than
	// less negative weights.
	var minWeight float64 = math.Inf(1)
	foundNonNegative := false
	for _, val := range sm {
		if val.Weight >= 0 && val.Weight < minWeight {
			minWeight = val.Weight
			foundNonNegative = true
		}
	}
	if !foundNonNegative {
		// Handle the case where all weights are negative
		minWeight = 1.0
	}

	// Calculate the ranges for each weight, and the total weight sum
	for idx, val := range sm {
		// Guarantee that any negative weights are turned into a positive range,
		// where the more negative weights correspond to smaller ranges.
		if val.Weight < 0 {
			val.Weight = -1 * minWeight / (val.Weight - 1) // subtract by one to guarantee abs(denominator) > 1
		}
		if idx == 0 {
			ranges[idx] = []float64{0.0, val.Weight}
		} else {
			prev := ranges[idx-1][1]
			ranges[idx] = []float64{prev, prev + val.Weight}
		}
		wSum += val.Weight
	}

	return
}

// Given a SwapMaps struct, stochasticlly sort the weights based on the following procedure:
//
//  1. Create ranges [0, weight_1), [weight_1, weight_1 + weight_2), ... for each weight.
//
//  2. Select a random number in the range [0, sum(weights)).
//
//  3. If the number falls within the range corresponding to the weight, it is sorted to the top.
//
//  4. Remove the range corresponding to the selected weight and re-calculate the ranges.
//
//  5. Repeat step 2-4 to select a the rest weights
//
// Returns the sorted list of SwapMap.Index
// You may specify the maxOut argument to limit the output.
func stochasticSort(sm SwapMaps, maxOut int) (candidates []int) {
	if maxOut <= 0 || maxOut > len(sm) {
		maxOut = len(sm)
	}

	wSum, ranges := generateRanges(sm)

	for len(candidates) < maxOut {
		ranNum := rand.Float64() * wSum
		for idx, r := range ranges {
			if ranNum >= r[0] && ranNum < r[1] {
				removeAndRerange(&wSum, ranges, idx)

				// Here, we append Index of the SwapMaps[idx] as that's the
				// true index to sort
				candidates = append(candidates, sm[idx].Index)
				break
			}
		}
	}
	return
}
