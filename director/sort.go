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
	"context"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
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

	// Stores a mapping of client IPs that have been randomly assigned a coordinate
	clientIpCache = ttlcache.New(ttlcache.WithTTL[netip.Addr, Coordinate](20 * time.Minute))
)

// Constants for the director sorting algorithm
const (
	souceServerAdsLimit      = 6    // Number of servers under consideration
	distanceHalvingThreshold = 10   // Threshold where the distance havling factor kicks in, in miles
	distanceHalvingFactor    = 200  // Halving distance for the GeoIP weight, in miles
	objAvailabilityFactor    = 2    // Multiplier for knowing whether an object is present
	loadHalvingThreshold     = 10.0 // Threshold where the load havling factor kicks in
	loadHalvingFactor        = 4.0  // Halving interval for load

	// A rough lat/long bounding box for the contiguous US. We might eventually make this box
	// a configurable value, but for now it's hardcoded
	usLatMin  = 30.0
	usLatMax  = 50.0
	usLongMin = -125.0
	usLongMax = -65.0
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

func getLatLong(ctx context.Context, addr netip.Addr) (lat float64, long float64, err error) {
	ip := net.IP(addr.AsSlice())
	override := checkOverrides(ip)
	if override != nil {
		log.Infof("Overriding Geolocation of detected IP (%s) to lat:long %f:%f based on configured overrides", ip.String(), (override.Lat), override.Long)
		return override.Lat, override.Long, nil
	}

	labels := prometheus.Labels{
		"network": "",
		"source":  "",
		"proj":    "",
	}

	network, ok := utils.ApplyIPMask(addr.String())
	if !ok {
		log.Warningf("Failed to apply IP mask to address %s", ip.String())
	} else {
		labels["network"] = network
	}

	project, ok := ctx.Value(ProjectContextKey{}).(string)
	if !ok || project == "" {
		log.Warningf("Failed to get project from context")
		labels["proj"] = "unknown"
		labels["network"] = "unknown"
		labels["source"] = "server"
	} else {
		labels["proj"] = project
	}

	reader := maxMindReader.Load()
	if reader == nil {
		err = errors.New("No GeoIP database is available")
		labels["source"] = "server"
		metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
		return
	}
	record, err := reader.City(ip)
	if err != nil {
		labels["source"] = "server"
		metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
		return
	}
	lat = record.Location.Latitude
	long = record.Location.Longitude

	// If the lat/long results in null _before_ we've had a chance to potentially set it to null, log a warning.
	// There's likely a problem with the GeoIP database or the IP address. Usually this just means the IP address
	// comes from a private range.
	if lat == 0 && long == 0 {
		log.Warningf("GeoIP Resolution of the address %s resulted in the null lat/long. This will result in random server sorting.", ip.String())
		labels["source"] = "client"
		metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
	}

	// MaxMind provides an accuracy radius in kilometers. When it actually has no clue how to resolve a valid, public
	// IP, it sets the radius to 1000. If we get a radius of 900 or more (probably even much less than this...), we
	// should be very suspicious of the data, and mark it as appearing at the null lat/long (and provide a warning in
	// the Director), which also triggers random weighting in our sort algorithms.
	if record.Location.AccuracyRadius >= 900 {
		log.Warningf("GeoIP resolution of the address %s resulted in a suspiciously large accuracy radius of %d km. "+
			"This will be treated as GeoIP resolution failure and result in random server sorting. Setting lat/long to null.", ip.String(), record.Location.AccuracyRadius)
		lat = 0
		long = 0
		labels["source"] = "client"
		metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
	}

	return
}

// Given a bounding box, assign a random coordinate within that box.
func assignRandBoundedCoord(minLat, maxLat, minLong, maxLong float64) (lat, long float64) {
	lat = rand.Float64()*(maxLat-minLat) + minLat
	long = rand.Float64()*(maxLong-minLong) + minLong
	return
}

// Given a client address, attempt to get the lat/long of the client. If the address is invalid or
// the lat/long is not resolvable, assign a random location in the contiguous US.
func getClientLatLong(ctx context.Context, addr netip.Addr) (coord Coordinate) {
	var err error
	if !addr.IsValid() {
		log.Warningf("Unable to sort servers based on client-server distance. Invalid client IP address: %s", addr.String())
		coord.Lat, coord.Long = assignRandBoundedCoord(usLatMin, usLatMax, usLongMin, usLongMax)
		cached, exists := clientIpCache.GetOrSet(addr, coord)
		if exists {
			log.Warningf("Retrieving pre-assigned lat/long for unresolved client IP %s: %f, %f.This assignment will be cached for 20 minutes unless the client IP is used again in that period.", addr.String(), coord.Lat, coord.Long)
		} else {
			log.Warningf("Assigning random location in the contiguous US to lat/long %f, %f. This assignment will be cached for 20 minutes unless the client IP is used again in that period.", coord.Lat, coord.Long)
		}
		coord = cached.Value()
		return
	}

	coord.Lat, coord.Long, err = getLatLong(ctx, addr)
	coord.Lat, coord.Long, err = getLatLong(ctx, addr)
	if err != nil || (coord.Lat == 0 && coord.Long == 0) {
		if err != nil {
			log.Warningf("Error while getting the client IP address: %v", err)
		}
		coord.Lat, coord.Long = assignRandBoundedCoord(usLatMin, usLatMax, usLongMin, usLongMax)
		cached, exists := clientIpCache.GetOrSet(addr, coord)
		if exists {
			log.Warningf("Retrieving pre-assigned lat/long for client IP %s: %f, %f. This assignment will be cached for 20 minutes unless the client IP is used again in that period.", addr.String(), coord.Lat, coord.Long)
		} else {
			log.Warningf("Client IP %s has been re-assigned a random location in the contiguous US to lat/long %f, %f. This assignment will be cached for 20 minutes unless the client IP is used again in that period.", addr.String(), coord.Lat, coord.Long)
		}
		coord = cached.Value()
	}
	return
}

// Any time we end up with a random distance, we flip the weights negative. When this happens,
// we want a multiplier that should double a servers rank to multiply the weight by 0.5, not 2.0
func invertWeightIfNeeded(isRand bool, weight float64) float64 {
	if isRand {
		return 1 / weight
	}
	return weight
}

// The all-in-one method to sort serverAds based on the Director.CacheSortMethod configuration parameter
//   - distance: sort serverAds by the distance between the geolocation of the servers and the client
//   - distanceAndLoad: sort serverAds by the distance with gated halving factor (see details in the adaptive method)
//     and the server IO load
//   - random: sort serverAds randomly
//   - adaptive:  sort serverAds based on rules discussed here: https://github.com/PelicanPlatform/pelican/discussions/1198
//
// Note that if the client has invalid IP address or MaxMind is unable to get the coordinates out of
// the client IP, any distance-related steps are skipped. If the sort method is "distance", then
// the serverAds are randomly sorted.
func sortServerAds(ctx context.Context, clientAddr netip.Addr, ads []server_structs.ServerAd, availabilityMap map[string]bool) ([]server_structs.ServerAd, error) {
	// Each entry in weights will map a priority to an index in the original ads slice.
	// A larger weight is a higher priority.
	weights := make(SwapMaps, len(ads))
	sortMethod := param.Director_CacheSortMethod.GetString()
	// This will handle the case where the client address is invalid or the lat/long is not resolvable.
	clientCoord := getClientLatLong(ctx, clientAddr)

	// For each ad, we apply the configured sort method to determine a priority weight.
	for idx, ad := range ads {
		switch server_structs.SortType(sortMethod) {
		case server_structs.DistanceType:
			// If either client or ad coordinates are null, the underlying distanceWeight function will return a random weight
			weight, isRand := distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, false)
			if isRand {
				// Guarantee randomly-weighted servers are sorted to the bottom
				weights[idx] = SwapMap{0 - weight, idx}
			} else {
				weights[idx] = SwapMap{weight, idx}
			}
		case server_structs.DistanceAndLoadType:
			weight := 1.0
			// Distance weight
			distance, isRand := distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, true)
			if isRand {
				// In distanceAndLoad/adaptive modes, pin random distance weights to the range [-0.475, -0.525)] in an attempt
				// to make sure the weights from availability/load overpower the random distance weights while
				// still having a stochastic element. We do this instead of ignoring the distance weight entirely, because
				// it's possible load information and or availability information is not available for all servers.
				weight = 0 - (0.475+rand.Float64())*(0.05)
			} else {
				dWeighted := gatedHalvingMultiplier(distance, distanceHalvingThreshold, distanceHalvingFactor)
				weight *= dWeighted
			}

			// Load weight
			lWeighted := gatedHalvingMultiplier(ad.IOLoad, loadHalvingThreshold, loadHalvingFactor)
			weight *= invertWeightIfNeeded(isRand, lWeighted)
			weights[idx] = SwapMap{weight, idx}
		case server_structs.AdaptiveType:
			weight := 1.0
			// Distance weight
			distance, isRand := distanceWeight(clientCoord.Lat, clientCoord.Long, ad.Latitude, ad.Longitude, true)
			if isRand {
				weight = 0 - (0.475+rand.Float64())*(0.05)
			} else {
				dWeighted := gatedHalvingMultiplier(distance, distanceHalvingThreshold, distanceHalvingFactor)
				weight *= dWeighted
			}

			// Availability weight
			if availabilityMap == nil {
				weight *= 1.0
			} else if hasObj, ok := availabilityMap[ad.URL.String()]; ok && hasObj {
				weight *= invertWeightIfNeeded(isRand, 2.0)
			} else if !ok {
				weight *= 1.0
			} else { // ok but does not have the object
				weight *= invertWeightIfNeeded(isRand, 0.5)
			}

			// Load weight
			lWeighted := gatedHalvingMultiplier(ad.IOLoad, loadHalvingThreshold, loadHalvingFactor)
			weight *= invertWeightIfNeeded(isRand, lWeighted)

			weights[idx] = SwapMap{weight, idx}
		case server_structs.RandomType:
			weights[idx] = SwapMap{rand.Float64(), idx}
		default:
			// Never say never, but this should never get hit because we validate the value on startup.
			return nil, errors.Errorf("Invalid sort method '%s' set in Director.CacheSortMethod.", param.Director_CacheSortMethod.GetString())
		}
	}

	if sortMethod == string(server_structs.AdaptiveType) {
		candidates, _ := stochasticSort(weights, serverResLimit)
		resultAds := []server_structs.ServerAd{}
		for _, cidx := range candidates[:serverResLimit] {
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
