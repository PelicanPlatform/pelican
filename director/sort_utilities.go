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
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	// A GeoIPOverride maps a specific IP to a configured lat/long coordinate.
	GeoIPOverride struct {
		IP         string                    `mapstructure:"IP"`
		Coordinate server_structs.Coordinate `mapstructure:"Coordinate"`
	}

	// A GeoNetOverride maps a CIDR block to a configured lat/long coordinate.
	GeoNetOverride struct {
		IPNet      netip.Prefix
		Coordinate server_structs.Coordinate
	}
)

var (
	// Stores the unmarshalled GeoIP override config in a form that's efficient to test
	geoNetOverrides []GeoNetOverride

	// Stores a mapping of client IPs that have been randomly assigned a coordinate
	clientIpRandAssignmentCache = ttlcache.New(ttlcache.WithTTL[netip.Addr, server_structs.Coordinate](20*time.Minute),
		ttlcache.WithDisableTouchOnHit[netip.Addr, server_structs.Coordinate](),
		ttlcache.WithCapacity[netip.Addr, server_structs.Coordinate](10_000),
	)

	// Stores a mapping of client IPs that have previously matched some GeoIP override
	// Note that this cache does not have an actual TTL/Expiration because GeoIP overrides
	// come from static yaml config and exist for the duration of the instance -- if an
	// IP matches an override, we expect it to match the override every time until the config
	// is updated and the service is rebooted.
	// This cache should only be accessed by `checkOverrides` to guarantee overrides have already been unmarshalled
	clientIpGeoOverrideCache = ttlcache.New(
		ttlcache.WithCapacity[netip.Addr, server_structs.Coordinate](50_000), // limit was chosen somewhat arbitrarily, but seems reasonable
	)
)

const (
	earthRadiusToMilesFactor = 3960

	// A rough lat/long bounding box for the contiguous US. We might eventually make this box
	// a configurable value, but for now it's hardcoded
	usLatMin  = 30.0
	usLatMax  = 50.0
	usLongMin = -125.0
	usLongMax = -65.0
)

// Unmarshal any configured GeoIP overrides.
// Malformed IPs and CIDRs are logged but not returned as errors.
func unmarshalOverrides() error {
	var geoIPOverrides []GeoIPOverride

	// Ensure that we're starting with an empty slice.
	geoNetOverrides = nil

	if err := param.GeoIPOverrides.Unmarshal(&geoIPOverrides); err != nil {
		return err
	}

	for _, override := range geoIPOverrides {
		var addr netip.Addr
		var prefix netip.Prefix
		var err error

		// Try CIDR first.
		if pfx, perr := netip.ParsePrefix(override.IP); perr == nil {
			prefix = pfx
		} else if a, aerr := netip.ParseAddr(override.IP); aerr == nil {
			addr = a
			// Turn it into a /32 (IPv4) or /128 (IPv6) prefix (i.e. a one-host CIDR block)
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		} else {
			err = fmt.Errorf("failed to parse as CIDR (%v) or IP (%v)", perr, aerr)
		}

		if err != nil {
			log.Warningf("Failed to parse configured GeoIPOverride address (%s): %v. Unable to use for GeoIP resolution!", override.IP, err)
			continue
		}

		coordinate := server_structs.Coordinate{
			Lat:            override.Coordinate.Lat,
			Long:           override.Coordinate.Long,
			AccuracyRadius: 0, // Maybe this should be the maximum possible accuracy radius instead of using 0 to mean "unknown"?
			Source:         server_structs.CoordinateSourceOverride,
			FromTTLCache:   false,
		}
		geoNetOverrides = append(geoNetOverrides, GeoNetOverride{
			IPNet:      prefix,
			Coordinate: coordinate,
		})
	}
	return nil
}

// Check for any pre-configured IP-to-lat/long overrides. If the passed address
// matches an override IP (either directly or via CIDR masking), then we use the
// configured lat/long from the override instead of relying on MaxMind.
// NOTE: We don't return an error because if checkOverrides encounters an issue,
// we still have GeoIP to fall back on.
func checkOverrides(addr netip.Addr) (coord server_structs.Coordinate, exists bool) {
	if cached := clientIpGeoOverrideCache.Get(addr); cached != nil {
		coord = cached.Value()
		return coord, true
	}

	// Unmarshal the GeoIP override config if we haven't already done so.
	if geoNetOverrides == nil {
		if err := unmarshalOverrides(); err != nil {
			log.Warningf("Unable to unmarshal GeoIP overrides: %v", err)
			return
		}
	}
	for _, override := range geoNetOverrides {
		if override.IPNet.Contains(addr) {
			// Insert entry into cache with -1 to indicate no expiration
			// If the cache is already full, it should use LRU GC
			clientIpGeoOverrideCache.Set(addr, override.Coordinate, -1)
			// Moreover, while we're technically sticking this in a cache, we don't
			// set set FromTTLCache to true because this is a configured override that
			// has no expiration. We're only using the ttl cache for efficient lookup.
			return override.Coordinate, true
		}
	}

	return
}

// Mathematical function, not implementation, came from
// http://www.johndcook.com/python_longitude_latitude.html
// Returned values are not actual distances, but is relative to earth's radius
func angularDistanceOnSphere(lat1 float64, long1 float64, lat2 float64, long2 float64) float64 {

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

// Apply a thresholded exponential halving multiplier to a value:
// 1; 0 <= val <= threshold
// 2 ^ (-(val-threshold)/halvingFactor); val > threshold
// If any invalid parameters are provided (negative threshold/halving factor, etc), 1.0 is returned.
func thresholdedExponentialHalvingMultiplier(val float64, threshold float64, halvingFactor float64) float64 {
	if halvingFactor <= 0 {
		return 1.0
	}

	if threshold < 0 {
		return 1.0
	}

	// this also handles nevative values, since they will always be <= threshold
	if val <= threshold {
		return 1.0
	}

	return math.Pow(2.0, -1.0*((val-threshold)/halvingFactor))
}

// Given a slice of ads, truncate it to the specified limit. A limit of 0 or less means no truncation.
func truncateAds(ads []server_structs.ServerAd, limit int) []server_structs.ServerAd {
	if limit <= 0 {
		return ads
	}

	if len(ads) > limit {
		return ads[:limit]
	}
	return ads
}

// Given a slice of float64 values, return the median (half above, half below).
func getMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := slices.Clone(values)
	slices.Sort(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	} else {
		return sorted[mid]
	}
}

// Compute weights for a list of server ads using the provided weight function.
// Whenever a weight is not computable, the median of the computable weights is imputed for the server.
// If no weights are computable, 1.0 is used as the median so as not to impute a value of 0.0, which would
// effectively remove the server from consideration.
//
// Each input weightFn returns a weight and a bool indicating whether the weight is valid, letting us define
// both how a weight is computed and what constitutes validity differently for different weight types
func computeWeights(ads []server_structs.ServerAd, weightFn func(int, server_structs.ServerAd) (float64, bool)) SwapMaps {
	valid := []float64{} // holds onto assignable weights
	nullIdxs := []int{}  // for tracking which indices need median imputation
	weights := make(SwapMaps, len(ads))

	for idx, ad := range ads {
		if w, ok := weightFn(idx, ad); ok {
			valid = append(valid, w)
			weights[idx] = SwapMap{Weight: w, Index: idx}
		} else {
			nullIdxs = append(nullIdxs, idx)
		}
	}

	// Impute median for nulls
	// If there are no valid weights, we use 1.0 as the median so as not to remove the remaining
	// ads from consideration
	if len(nullIdxs) > 0 { // guard to avoid doing the median sort/calculation if not needed
		median := getMedian(valid)
		if len(valid) == 0 {
			median = 1.0
		}
		for _, idx := range nullIdxs {
			weights[idx] = SwapMap{Weight: median, Index: idx}
		}
	}
	return weights
}

// Given a bounding box, assign a random coordinate within that box.
func assignRandBoundedCoord(minLat, maxLat, minLong, maxLong float64) (lat, long float64) {
	lat = rand.Float64()*(maxLat-minLat) + minLat
	long = rand.Float64()*(maxLong-minLong) + minLong
	return
}

// Given a hostname, perform a DNS lookup to find the associated IP address.
// While this is only used by getServerCoordinate at time of writing, it's split
// into a separate function to facilitate unit testing (where it's useful to override this)
var getIPFromHostname = func(hostname string) (netip.Addr, error) {
	ip, err := net.LookupIP(hostname)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ip) == 0 {
		return netip.Addr{}, fmt.Errorf("unable to find an IP address for hostname '%s'", hostname)
	}
	addr, ok := netip.AddrFromSlice(ip[0])
	if !ok {
		return netip.Addr{}, fmt.Errorf("unable to convert IP address '%s' associated with hostname '%s' to netip.Addr", ip[0].String(), hostname)
	}
	return addr, nil
}

// Client redirects use the gin request's user agent to specify a project.
// The project gets tied to the request context so it can be passed around as needed.
func getProjectLabel(ctx context.Context) (project string) {
	project, ok := ctx.Value(ProjectContextKey{}).(string)
	if !ok || project == "" {
		project = "unknown"
	}

	return
}

// Given a server ad, retrieve the associated geolocation coordinate,
// including provenance metadata (coordinate source, accuracy radius, etc.)
//
// The URL from the server ad is first used for a DNS lookup to get the IP address,
// which is then used for GeoIP resolution.
// Coordinates are determined in order of precedence:
// 1. Configured GeoIP Overrides
// 2. MaxMind Lookups
func getServerCoordinate(sAd server_structs.ServerAd) (coord server_structs.Coordinate, err error) {
	// Get the IP from the server ad's hostname
	hostname := sAd.URL.Hostname()
	addr, err := getIPFromHostname(hostname)
	if err != nil {
		return coord, fmt.Errorf("failed to get IP address for server ad '%s' with hostname '%s': %v", sAd.Name, hostname, err)
	}

	// Check for overrides
	if overrideCoord, exists := checkOverrides(addr); exists {
		// All coordinate provenance fields should have been handled on GeoOverride unmarshal or cache insertion
		coord = overrideCoord
		log.Tracef("Overriding Geolocation of detected client IP (%s) (lat:long %f:%f) based on configured overrides",
			addr.String(), coord.Lat, coord.Long)
		return
	}

	// Now try MaxMind
	coord, err = getMaxMindCoordinate(addr)
	if err != nil {
		network, ok := utils.ApplyIPMask(addr.String())
		if !ok {
			log.Warningf("Failed to apply IP mask to address %s", addr.String())
			network = "unknown"
		}

		labels := prometheus.Labels{
			"network":     network,
			"server_name": sAd.Name,
		}
		metrics.PelicanDirectorMaxMindServerErrorsTotal.With(labels).Inc()
	}

	return
}

// Given a client IP address, retrieve the associated geolocation coordinate
// including provenance metadata (coordinate source, accuracy radius, etc.)
// This method does not return an error because it will always return a coordinate,
// so any GeoIP/MaxMind errors generated during the lookup process are handled internally.
//
// Coordinates are determined in order of precedence:
// 1. Configured GeoIP Overrides
// 2. MaxMind Lookups
// 3. Random, Geo-Bounded Assignments (when (1), (2) are not available)
func getClientCoordinate(ctx context.Context, addr netip.Addr) (coord server_structs.Coordinate) {
	// Check for overrides
	if overrideCoord, exists := checkOverrides(addr); exists {
		// All coordinate provenance fields should have been handled on GeoOverride unmarshal or cache insertion
		coord = overrideCoord
		log.Tracef("Overriding Geolocation of detected client IP (%s) (lat:long %f:%f) based on configured overrides",
			addr.String(), coord.Lat, coord.Long)
		return
	}

	handleClientGeoIPFailure := func(addr netip.Addr) {
		network, ok := utils.ApplyIPMask(addr.String())
		if !ok {
			log.Warningf("Failed to apply IP mask to address %s", addr.String())
			network = "unknown"
		}
		proj := getProjectLabel(ctx)
		labels := prometheus.Labels{
			"network": network,
			"project": proj,
		}
		metrics.PelicanDirectorMaxMindClientErrorsTotal.With(labels).Inc()
	}

	// Check the random assignment cache
	if cached := clientIpRandAssignmentCache.Get(addr); cached != nil {
		// Even though this is a cached random assignment, we still want to increment the
		// Prometheus metric for GeoIP failures because this would presumably cause another
		// failure were it not cached.
		handleClientGeoIPFailure(addr)

		// Similarly, provenance fields should have been handled on cache insertion
		coord = cached.Value()
		log.Tracef("Grabbing coordinate of detected client IP (%s) from random assignment cache (lat:long %f:%f). This assignment will be cached for %v",
			addr.String(), coord.Lat, coord.Long, time.Until(cached.ExpiresAt()))
		return
	}

	// Now try MaxMind
	mmCoord, err := getMaxMindCoordinate(addr)
	if err == nil {
		coord = mmCoord
		return
	}

	// Getting here means we tried and failed to find a coordinate via all other
	// sources of truth and we're using a fallback random assignment.
	// Increment the Prometheus metric that tracks GeoIP errors for client IPs
	handleClientGeoIPFailure(addr)

	log.Tracef("Assigning random location in the contiguous US to lat/long %f, %f to unresolvable client IP %s. This assignment will be cached for 20 minutes.", coord.Lat, coord.Long, addr.String())
	coord.Lat, coord.Long = assignRandBoundedCoord(usLatMin, usLatMax, usLongMin, usLongMax)
	coord.AccuracyRadius = 0
	coord.Source = server_structs.CoordinateSourceRandom
	// Set the coord's TTL cache field to true so cached value is accurate, but reset it on return
	// because this value wasn't cached when we generated it.
	coord.FromTTLCache = true
	clientIpRandAssignmentCache.Set(addr, coord, 20*time.Minute)

	coord.FromTTLCache = false
	return
}
