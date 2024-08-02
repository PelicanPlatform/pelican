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
	"cmp"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

type (
	SwapMap struct {
		Weight float64
		Index  int
	}

	SwapMaps []SwapMap
)

type (
	Coordinate struct {
		Lat  float64 `mapstructure:"lat"`
		Long float64 `mapstructure:"long"`
	}

	GeoIPOverride struct {
		IP         string     `mapstructure:"IP"`
		Coordinate Coordinate `mapstructure:"Coordinate"`
	}
)

var (
	invalidOverrideLogOnce = map[string]bool{}
	geoIPOverrides         []GeoIPOverride
)

// Constants for the director sorting algorithm
const (
	souceServerAdsLimit      = 6    // Number of servers under consideration
	distanceHalvingThreshold = 10   // Threshold where the distance havling factor kicks in, in miles
	distanceHalvingFactor    = 200  // Halving distance for the GeoIP weight, in miles
	objAvailabilityFactor    = 2    // Multiplier for knowing whether an object is present
	loadHalvingThreshold     = 10.0 // Threshold where the load havling factor kicks in
	loadHalvingFactor        = 4.0  // Halving interval for load
	candidateLimit           = 3    // Number of servers return
)

func (me SwapMaps) Len() int {
	return len(me)
}

func (me SwapMaps) Less(left, right int) bool {
	return me[left].Weight < me[right].Weight
}

func (me SwapMaps) Swap(left, right int) {
	me[left], me[right] = me[right], me[left]
}

// Check for any pre-configured IP-to-lat/long overrides. If the passed address
// matches an override IP (either directly or via CIDR masking), then we use the
// configured lat/long from the override instead of relying on MaxMind.
// NOTE: We don't return an error because if checkOverrides encounters an issue,
// we still have GeoIP to fall back on.
func checkOverrides(addr net.IP) (coordinate *Coordinate) {
	// Unmarshal the values, but only the first time we run through this block
	if geoIPOverrides == nil {
		err := param.GeoIPOverrides.Unmarshal(&geoIPOverrides)
		if err != nil {
			log.Warningf("Error while unmarshaling GeoIP Overrides: %v", err)
		}
	}

	for _, geoIPOverride := range geoIPOverrides {
		// Check for regular IP addresses before CIDR
		overrideIP := net.ParseIP(geoIPOverride.IP)
		if overrideIP == nil {
			// The IP is malformed
			if !invalidOverrideLogOnce[geoIPOverride.IP] && !strings.Contains(geoIPOverride.IP, "/") {
				// Don't return here, because we have more to check.
				// Do provide a notice to the user, however.
				log.Warningf("Failed to parse configured GeoIPOverride address (%s). Unable to use for GeoIP resolution!", geoIPOverride.IP)
				invalidOverrideLogOnce[geoIPOverride.IP] = true
			}
		}
		if overrideIP.Equal(addr) {
			return &geoIPOverride.Coordinate
		}

		// Alternatively, we can match by CIDR blocks
		if strings.Contains(geoIPOverride.IP, "/") {
			_, ipNet, err := net.ParseCIDR(geoIPOverride.IP)
			if err != nil {
				if !invalidOverrideLogOnce[geoIPOverride.IP] {
					// Same reason as above for not returning.
					log.Warningf("Failed to parse configured GeoIPOverride CIDR address (%s): %v. Unable to use for GeoIP resolution!", geoIPOverride.IP, err)
					invalidOverrideLogOnce[geoIPOverride.IP] = true
				}
				continue
			}
			if ipNet.Contains(addr) {
				return &geoIPOverride.Coordinate
			}
		}
	}

	return nil
}

func getLatLong(addr netip.Addr) (lat float64, long float64, err error) {
	ip := net.IP(addr.AsSlice())
	override := checkOverrides(ip)
	if override != nil {
		log.Infof("Overriding Geolocation of detected IP (%s) to lat:long %f:%f based on configured overrides", ip.String(), (override.Lat), override.Long)
		return override.Lat, override.Long, nil
	}

	reader := maxMindReader.Load()
	if reader == nil {
		err = errors.New("No GeoIP database is available")
		return
	}
	record, err := reader.City(ip)
	if err != nil {
		return
	}
	lat = record.Location.Latitude
	long = record.Location.Longitude

	if lat == 0 && long == 0 {
		log.Infof("GeoIP Resolution of the address %s resulted in the nul lat/long.", ip.String())
	}
	return
}

func getClientLatLong(addr netip.Addr) (coord Coordinate, ok bool) {
	var err error
	coord.Lat, coord.Long, err = getLatLong(addr)
	ok = (err == nil && !(coord.Lat == 0 && coord.Long == 0))
	if err != nil {
		log.Warningf("failed to resolve lat/long for address %s: %v", addr, err)
	}
	return
}

// The all-in-one method to sort serverAds based on Dirtector.CacheSortMethod configuration parameter
//   - distance: sort serverAds by the distance between the geolocation of the servers and the client
//   - distanceAndLoad: sort serverAds by the distance with gated halving factor (see details in the adaptive method)
//     and the server IO load
//   - random: sort serverAds randomly
//   - adaptive:  sort serverAds based on rules discussed here: https://github.com/PelicanPlatform/pelican/discussions/1198
//
// Note that if the client has invalid IP address or MaxMind is unable to get the coordinates out of
// the client IP, any distance-related steps are skipped. If the sort method is "distance", then
// the serverAds are randomly sorted.
func sortServerAds(clientAddr netip.Addr, ads []server_structs.ServerAd, availabilityMap map[string]bool) ([]server_structs.ServerAd, error) {
	// Each entry in weights will map a priority to an index in the original ads slice.
	// A larger weight is a higher priority.
	weights := make(SwapMaps, len(ads))
	sortMethod := param.Director_CacheSortMethod.GetString()

	clientCoord := Coordinate{}
	clientCoordOk := false

	if clientAddr.IsValid() {
		clientCoord, clientCoordOk = getClientLatLong(clientAddr)
	} else {
		log.Warningf("Unable to sort servers based on client-server distance. Invalid client IP address: %s", clientAddr.String())
	}

	// For each ad, we apply the configured sort method to determine a priority weight.
	for idx, ad := range ads {
		switch sortMethod {
		case "distance":
			// If we can't get the client coordinates, then simply use random sort
			if !clientCoordOk {
				weights[idx] = SwapMap{rand.Float64(), idx}
				continue
			}
			if ad.Latitude == 0 && ad.Longitude == 0 {
				// If server lat and long are 0, the server geolocation is unknown
				// Below we sort weights in descending order, so we assign negative value here,
				// causing them to always be at the end of the sorted list.
				weights[idx] = SwapMap{0 - rand.Float64(), idx}
			} else {
				weights[idx] = SwapMap{distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, false),
					idx}
			}
		case "distanceAndLoad":
			weight := 1.0
			// Distance weight
			if clientCoordOk {
				distance := distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, true)
				dWeighted := gatedHalvingMultiplier(distance, distanceHalvingThreshold, distanceHalvingFactor)
				weight *= dWeighted
			}

			// Load weight
			lWeighted := gatedHalvingMultiplier(ad.IOLoad, loadHalvingThreshold, loadHalvingFactor)
			weight *= lWeighted

			weights[idx] = SwapMap{weight, idx}
		case "adaptive":
			weight := 1.0
			// Distance weight
			if clientCoordOk {
				distance := distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, true)
				dWeighted := gatedHalvingMultiplier(distance, distanceHalvingThreshold, distanceHalvingFactor)
				weight *= dWeighted
			}
			// Availability weight
			if availabilityMap == nil {
				weight *= 1.0
			} else if hasObj, ok := availabilityMap[ad.URL.String()]; ok && hasObj {
				weight *= 2.0
			} else if !ok {
				weight *= 1.0
			} else { // ok but does not have the object
				weight *= 0.5
			}

			// Load weight
			lWeighted := gatedHalvingMultiplier(ad.IOLoad, loadHalvingThreshold, loadHalvingFactor)
			weight *= lWeighted

			weights[idx] = SwapMap{weight, idx}
		case "random":
			weights[idx] = SwapMap{rand.Float64(), idx}
		default:
			return nil, errors.Errorf("Invalid sort method '%s' set in Director.CacheSortMethod. Valid methods are 'distance',"+
				"'distanceAndLoad', 'adaptive', and 'random.'", param.Director_CacheSortMethod.GetString())
		}
	}

	if sortMethod == "adaptive" {
		candidates, _ := stochasticSort(weights, candidateLimit)
		resultAds := []server_structs.ServerAd{}
		for _, cidx := range candidates[:candidateLimit] {
			resultAds = append(resultAds, ads[cidx])
		}
		return resultAds, nil
	} else {
		// Larger weight = higher priority, so we reverse the sort (which would otherwise default to ascending)
		sort.Sort(sort.Reverse(weights))
		resultAds := make([]server_structs.ServerAd, len(ads))
		for idx, weight := range weights {
			resultAds[idx] = ads[weight.Index]
		}
		return resultAds, nil
	}
}

// Sort a list of ServerAds with the following rule:
//   - if a ServerAds has FromTopology = true, then it will be moved to the end of the list
//   - if two ServerAds has the SAME FromTopology value (both true or false), then break tie them by name
//
// TODO: remove the return statement as slices.SortStableFunc sorts the slice in-place
func sortServerAdsByTopo(ads []*server_structs.Advertisement) []*server_structs.Advertisement {
	slices.SortStableFunc(ads, func(a, b *server_structs.Advertisement) int {
		if a.FromTopology && !b.FromTopology {
			return 1
		} else if !a.FromTopology && b.FromTopology {
			return -1
		} else {
			return cmp.Compare(a.Name, b.Name)
		}
	})
	return ads
}

// Stable-sort the given serveAds in-place given the avaiMap, where the key of the map is serverAd.Url.String()
// and the value is a bool suggesting if the server has the object requested.
//
// Smaller index in the sorted array means higher priority
func sortServerAdsByAvailability(ads []server_structs.ServerAd, avaiMap map[string]bool) {
	slices.SortStableFunc(ads, func(a, b server_structs.ServerAd) int {
		if !avaiMap[a.URL.String()] && avaiMap[b.URL.String()] {
			return 1
		} else if avaiMap[a.URL.String()] && !avaiMap[b.URL.String()] {
			return -1
		} else {
			// Preserve original ordering
			return 0
		}
	})
}
