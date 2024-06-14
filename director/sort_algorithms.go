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

	"github.com/pelicanplatform/pelican/server_structs"
)

// Mathematical function, not implementation, came from
// http://www.johndcook.com/python_longitude_latitude.html
// Returned values are not actual distances, but normalized between [0,1]
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

	// Finally, standardize the distance to be between [0,1]
	return arc / math.Pi
}

// Create a weight between [0,1] that indicates a priority. The returned weight is directly correlated
// with priority (higher weight is higher priority is lower distance)
func distanceWeight(coord Coordinate, ad server_structs.ServerAd) float64 {
	return 1 - distanceOnSphere(coord.Lat, coord.Long, ad.Latitude, ad.Longitude)
}

// Create a weight between [0,1] that indicates a priority. The returned weight is directly correlated
// with priority (higher weight is higher priority)
func distanceAndLoadWeight(coord Coordinate, sAd server_structs.ServerAd) float64 {
	distance := distanceOnSphere(coord.Lat, coord.Long, sAd.Latitude, sAd.Longitude)

	// For now, load is always 0.5. Eventually we'll pull this value from the server ad. Furthermore,
	// assume a server's load has more impact on its performance than its distance does. As long as load is
	// hard coded, this function should act exactly like distanceWeight.
	// TODO: Come up with a better function once we have an actual load value and know how it works
	load := 0.5

	a1 := 1.0 / 3.0
	a2 := 2.0 / 3.0

	return 1 - a1*distance - a2*load
}
