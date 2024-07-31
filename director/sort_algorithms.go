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
func distanceWeight(lat1 float64, long1 float64, lat2 float64, long2 float64, realD bool) float64 {
	if realD {
		return distanceOnSphere(lat1, long1, lat2, long2) * earthRadiusToMilesFactor
	} else {
		return 1 - (distanceOnSphere(lat1, long1, lat2, long2) / math.Pi)
	}
}

// Given the input value, return a weight [0, 1.0] based on the gated havling of the base weight 1.0.
//   - If the input value is between 0.0 and the threshold, return 1.0.
//   - If the input value is above the threshold, the weight decreases by half for every halvingFactor units of the input value
func gatedHavlingMultiplier(val float64, threshold float64, halvingFactor float64) float64 {
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

// Given a SwapMaps struct, stochasticlly sort the weights based on the folliwng procedure:
//
//  1. Create ranges [0, weight_1), [weight_1, weight_1 + weight_2), ... for each weight.
//
//  2. Select a random number in the range [0, sum(weights)).
//
//  3. If the number falls within the range corresponding to the weight, it is sorted to the top.
//
//  4. Repeat step 2-3 to select a the rest weights
//
// Returnss the sorted list of SwapMap.Index and the generated random weights for reference.
// You may specify the maxOut argument to limit the output.
func stochasticSort(sm SwapMaps, maxOut int) (candidates []int, randWeights []float64) {
	if maxOut == 0 {
		maxOut = len(sm)
	} else if maxOut > len(sm) {
		return
	}

	wSum := 0.0
	ranges := [][]float64{} // items in ranges should corresponds to items in sm
	visited := make([]bool, len(sm))
	for idx, val := range sm {
		if idx == 0 {
			ranges = append(ranges, []float64{0.0, val.Weight})
		} else {
			prev := ranges[idx-1][1]
			ranges = append(ranges, []float64{prev, prev + val.Weight})
		}
		wSum += val.Weight
		visited[idx] = false
	}

	for len(candidates) < maxOut {
		ranNum := rand.Float64() * wSum
		for idx, r := range ranges {
			if ranNum >= r[0] && ranNum < r[1] && !visited[idx] {
				// Here, we append Index of the SwapMaps[idx] as that's the
				// true index to sort
				candidates = append(candidates, sm[idx].Index)
				randWeights = append(randWeights, ranNum)
				visited[idx] = true
				break
			}
		}
	}
	return
}
