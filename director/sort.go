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
	"cmp"
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	SwapMap struct {
		Weight float64
		Index  int
	}

	SwapMaps []SwapMap

	Coordinate struct {
		Lat  float64 `mapstructure:"lat"`
		Long float64 `mapstructure:"long"`
	}

	GeoIPOverride struct {
		IP         string     `mapstructure:"IP"`
		Coordinate Coordinate `mapstructure:"Coordinate"`
	}

	GeoNetOverride struct {
		IPNet      net.IPNet
		Coordinate Coordinate
	}

	geoIPError struct {
		labels   prometheus.Labels
		errorMsg string
	}

	// A function type for filtering ads -- given a request and an ad, it should
	// determine whether the server ad is capable of fulfilling the predicate, and
	// thus should be included in the list of ads to be returned.
	// A collection of these are used during Director matchmaking to produce the list of
	// caches/origins that can fulfill the request.
	AdPredicate func(ctx *gin.Context, ad copyAd) bool
)

func (e geoIPError) Error() string {
	return e.errorMsg
}

var (
	// Stores the unmarshalled GeoIP override config in a form that's efficient to test
	geoNetOverrides []GeoNetOverride

	// Stores a mapping of client IPs that have been randomly assigned a coordinate
	clientIpCache = ttlcache.New(ttlcache.WithTTL[netip.Addr, Coordinate](20*time.Minute),
		ttlcache.WithDisableTouchOnHit[netip.Addr, Coordinate](),
	)
)

// Constants for the director sorting algorithm
const (
	sourceServerAdsLimit     = 6    // Number of servers under consideration
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
		var ipNet *net.IPNet

		if _, parsedNet, err := net.ParseCIDR(override.IP); err == nil {
			ipNet = parsedNet
		} else if ip := net.ParseIP(override.IP); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ipNet = &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
			} else if ip16 := ip.To16(); ip16 != nil {
				ipNet = &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)}
			}
		}

		if ipNet == nil {
			// Log the error, and continue looking for good configuration.
			log.Warningf("Failed to parse configured GeoIPOverride address (%s). Unable to use for GeoIP resolution!", override.IP)
			continue
		}
		geoNetOverrides = append(geoNetOverrides, GeoNetOverride{IPNet: *ipNet, Coordinate: override.Coordinate})
	}
	return nil
}

// Check for any pre-configured IP-to-lat/long overrides. If the passed address
// matches an override IP (either directly or via CIDR masking), then we use the
// configured lat/long from the override instead of relying on MaxMind.
// NOTE: We don't return an error because if checkOverrides encounters an issue,
// we still have GeoIP to fall back on.
func checkOverrides(addr net.IP) (coordinate *Coordinate) {
	// Unmarshal the GeoIP override config if we haven't already done so.
	if geoNetOverrides == nil {
		err := unmarshalOverrides()
		if err != nil {
			log.Warningf("Error while unmarshalling GeoIP overrides: %v", err)
			return nil
		}
	}
	for _, override := range geoNetOverrides {
		if override.IPNet.Contains(addr) {
			return &override.Coordinate
		}
	}
	return nil
}

func setProjectLabel(ctx context.Context, labels *prometheus.Labels) {
	project, ok := ctx.Value(ProjectContextKey{}).(string)
	if !ok || project == "" {
		(*labels)["proj"] = "unknown"
	} else {
		(*labels)["proj"] = project
	}
}

func getLatLong(addr netip.Addr) (lat float64, long float64, radius uint16, err error) {
	ip := net.IP(addr.AsSlice())
	override := checkOverrides(ip)
	if override != nil {
		log.Infof("Overriding Geolocation of detected IP (%s) to lat:long %f:%f based on configured overrides", ip.String(), (override.Lat), override.Long)
		return override.Lat, override.Long, 0, nil
	}

	labels := prometheus.Labels{
		"network": "",
		"source":  "",
		"proj":    "", // this will be set in the setProjectLabel function
	}

	network, ok := utils.ApplyIPMask(addr.String())
	if !ok {
		log.Warningf("Failed to apply IP mask to address %s", ip.String())
		labels["network"] = "unknown"
	} else {
		labels["network"] = network
	}

	reader := maxMindReader.Load()
	if reader == nil {
		labels["source"] = "server"
		err = geoIPError{labels: labels, errorMsg: "No GeoIP database is available"}
		return
	}
	record, err := reader.City(ip)
	if err != nil {
		labels["source"] = "server"
		err = geoIPError{labels: labels, errorMsg: err.Error()}
		return
	}
	lat = record.Location.Latitude
	long = record.Location.Longitude
	radius = record.Location.AccuracyRadius
	// If the lat/long results in null _before_ we've had a chance to potentially set it to null, log a warning.
	// There's likely a problem with the GeoIP database or the IP address. Usually this just means the IP address
	// comes from a private range.
	if lat == 0 && long == 0 {
		errMsg := fmt.Sprintf("GeoIP Resolution of the address %s resulted in the null lat/long. This will result in random server sorting.", ip.String())
		log.Warning(errMsg)
		labels["source"] = "client"
		err = geoIPError{labels: labels, errorMsg: errMsg}
	}

	// MaxMind provides an accuracy radius in kilometers. When it actually has no clue how to resolve a valid, public
	// IP, it sets the radius to 1000. If we get a radius of 900 or more (probably even much less than this...), we
	// should be very suspicious of the data, and mark it as appearing at the null lat/long (and provide a warning in
	// the Director), which also triggers random weighting in our sort algorithms.
	if radius >= 900 {
		errMsg := fmt.Sprintf("GeoIP resolution of the address %s resulted in a suspiciously large accuracy radius of %d km. "+
			"This will be treated as GeoIP resolution failure and result in random server sorting. Setting lat/long to null.", ip.String(), radius)
		log.Warning(errMsg)
		lat = 0
		long = 0
		labels["source"] = "client"
		err = geoIPError{labels: labels, errorMsg: errMsg}
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
func getClientLatLong(addr netip.Addr, redirectInfo *server_structs.RedirectInfo) (coord Coordinate, err error) {
	if !addr.IsValid() {
		log.Warningf("Unable to sort servers based on client-server distance. Invalid client IP address: %s", addr.String())
		coord.Lat, coord.Long = assignRandBoundedCoord(usLatMin, usLatMax, usLongMin, usLongMax)
		cached, exists := clientIpCache.GetOrSet(addr, coord)
		if exists {
			log.Warningf("Using randomly-assigned lat/long for unresolved client IP %s: %f, %f.  This assignment will be cached for %v.", addr.String(), cached.Value().Lat, cached.Value().Long, time.Until(cached.ExpiresAt()))
		} else {
			log.Warningf("Assigning random location in the contiguous US to lat/long %f, %f. This assignment will be cached for 20 minutes.", coord.Lat, coord.Long)
		}
		coord = cached.Value()
		redirectInfo.ClientInfo.Lat = coord.Lat
		redirectInfo.ClientInfo.Lon = coord.Long
		redirectInfo.ClientInfo.FromTTLCache = exists
		redirectInfo.ClientInfo.Resolved = false
		redirectInfo.ClientInfo.GeoIpRadiusKm = 0 // 0 indicates no radius, i.e. an error
		return
	}

	coord.Lat, coord.Long, redirectInfo.ClientInfo.GeoIpRadiusKm, err = getLatLong(addr)
	if err != nil || (coord.Lat == 0 && coord.Long == 0) {
		if err != nil {
			log.Warningf("Error while getting the client IP address: %v", err)
		}
		coord.Lat, coord.Long = assignRandBoundedCoord(usLatMin, usLatMax, usLongMin, usLongMax)
		cached, exists := clientIpCache.GetOrSet(addr, coord)
		if exists {
			log.Warningf("Using randomly-assigned lat/long for client IP %s: %f, %f. This assignment will be cached for %v.", addr.String(), cached.Value().Lat, cached.Value().Long, time.Until(cached.ExpiresAt()))
		} else {
			log.Warningf("Client IP %s has been re-assigned a random location in the contiguous US to lat/long %f, %f. This assignment will be cached for 20 minutes.", addr.String(), coord.Lat, coord.Long)
		}
		coord = cached.Value()
		redirectInfo.ClientInfo.Lat = coord.Lat
		redirectInfo.ClientInfo.Lon = coord.Long
		redirectInfo.ClientInfo.FromTTLCache = exists
		redirectInfo.ClientInfo.Resolved = false
		redirectInfo.ClientInfo.GeoIpRadiusKm = 0 // 0 indicates no radius, i.e. an error
		return
	}

	redirectInfo.ClientInfo.FromTTLCache = false
	redirectInfo.ClientInfo.Resolved = true
	redirectInfo.ClientInfo.Lat = coord.Lat
	redirectInfo.ClientInfo.Lon = coord.Long

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
func sortServerAds(ctx context.Context, clientAddr netip.Addr, ads []server_structs.ServerAd, availabilityMap map[string]bool, redirectInfo *server_structs.RedirectInfo) ([]server_structs.ServerAd, error) {
	// Each entry in weights will map a priority to an index in the original ads slice.
	// A larger weight is a higher priority.
	weights := make(SwapMaps, len(ads))
	sortMethod := param.Director_CacheSortMethod.GetString()
	redirectInfo.DirectorSortMethod = sortMethod
	// This will handle the case where the client address is invalid or the lat/long is not resolvable.
	clientCoord, err := getClientLatLong(clientAddr, redirectInfo)
	if err != nil {
		// If it is a geoIP error, then we get the labels and increment the error counter
		// Otherwise we log the error and continue
		if geoIPError, ok := err.(geoIPError); ok {
			labels := geoIPError.labels
			setProjectLabel(ctx, &labels)
			// TODO: Remove this metric (the line directly below)
			// The renamed metric was added in v7.16
			metrics.PelicanDirectorGeoIPErrors.With(labels).Inc()
			metrics.PelicanDirectorGeoIPErrorsTotal.With(labels).Inc()
		}
		log.Warningf("Error while getting the client IP address: %v", err)
	}

	// For each ad, we apply the configured sort method to determine a priority weight.
	for idx, ad := range ads {
		redirectInfo.ServersInfo[ad.URL.String()] = &server_structs.ServerRedirectInfo{
			Lat:        ad.Latitude,
			Lon:        ad.Longitude,
			LoadWeight: ad.IOLoad,
			HasObject:  "unknown",
		}

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
				redirectInfo.ServersInfo[ad.URL.String()].HasObject = "true"
			} else if !ok {
				weight *= 1.0
			} else { // ok but does not have the object
				weight *= invertWeightIfNeeded(isRand, 0.5)
				redirectInfo.ServersInfo[ad.URL.String()].HasObject = "false"
			}

			// Load weight
			lWeighted := gatedHalvingMultiplier(ad.IOLoad, loadHalvingThreshold, loadHalvingFactor)
			weight *= invertWeightIfNeeded(isRand, lWeighted)

			weights[idx] = SwapMap{weight, idx}
		case server_structs.RandomType:
			weights[idx] = SwapMap{rand.Float64(), idx}
		default:
			// Never say never, but this should never get hit because we validate the value on startup.
			// The only real way to get here is through writing unit tests.
			return nil, errors.Errorf("Invalid sort method '%s' set in Director.CacheSortMethod.", param.Director_CacheSortMethod.GetString())
		}
	}

	if sortMethod == string(server_structs.AdaptiveType) {
		candidates := stochasticSort(weights, serverResLimit)
		resultAds := []server_structs.ServerAd{}
		for _, cidx := range candidates[:min(len(candidates), serverResLimit)] {
			resultAds = append(resultAds, ads[cidx])
		}

		// When Justin was refactoring the Director's matchmaking code for https://github.com/PelicanPlatform/pelican/issues/2041
		// he noticed that sortServerAdsByAvailability was called for all adaptive sorts directly in redirectToCache after
		// we got back the slice of sorted ads from `sortServerAds`. It didn't make sense to call two sort functions at that level
		// when `sortServerAds` is already supposed to be a one-stop shop, so he moved `sortServerAdsByAvailability` into this function.
		// However, he then began to wonder why we do all this weighting stuff based on availability only to immediately toss the results
		// and sort by availability... Figuring out what's going on here should be a followup.
		// TODO: Revisit this
		sortServerAdsByAvailability(resultAds, availabilityMap)

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

// Given a request path and a slice of namespace ads, pick the namespace ad whose
// path is the longest logical prefix of the request path. For example, for path
// `/foo/bar/baz` and namespace ads `/foo` & `/foo/bar`, the function should return
// the namespace ad for `/foo/bar`.
func getLongestNSMatch(reqPath string, namespaceAds []server_structs.NamespaceAdV2) *server_structs.NamespaceAdV2 {
	// Normalize incoming path if needed --> adding the trailing / makes
	// basic prefix matching safer
	if !strings.HasSuffix(reqPath, "/") {
		reqPath += "/"
	}

	var bestFedPrefix string
	var bestNamespace *server_structs.NamespaceAdV2
	for _, ns := range namespaceAds {
		// Create a copy of ns to avoid reusing the loop variable
		currentNS := ns

		// Additionally normalize stored namespace paths
		nsPath := currentNS.Path
		if !strings.HasSuffix(currentNS.Path, "/") {
			nsPath += "/"
		}

		if !strings.HasPrefix(reqPath, nsPath) {
			// This namespace doesn't match the request path, skip it
			continue
		}

		if bestFedPrefix == "" {
			bestFedPrefix = nsPath
			bestNamespace = &currentNS
			continue
		}

		if len(nsPath) > len(bestFedPrefix) {
			bestFedPrefix = nsPath
			bestNamespace = &currentNS
			continue
		}
	}

	return bestNamespace
}

// Given a request path, find all the ads that express willingness to work with
// a prefix that best matches (i.e. is the longest prefix of) the path. We return
// a copy ad at this point instead of a pointer to the ad in the TTL cache because
// we want to be able to modify the ad without modifying the original ad in the cache.
func getAdsForPath(reqPath string) (oAds []copyAd, cAds []copyAd) {
	// Clean the path, but make sure we re-add the trailing / --> this makes it easier to compare
	// paths like /foo and /foobar with basic prefix matching because without the trailing /, these
	// two would match.
	reqPath = path.Clean(reqPath) + "/"
	ads := make([]*server_structs.Advertisement, 0, len(serverAds.Items()))

	for _, serverAd := range serverAds.Items() {
		ads = append(ads, serverAd.Value())
	}

	// Move topo sorted ads to the end of our slice
	topoSortedAds := sortServerAdsByTopo(ads)

	var bestFedPrefix string
	for _, ad := range topoSortedAds {
		// Skip over any ads that are filtered out or marked in downtime
		if filtered, fType := checkFilter(ad.Name); filtered {
			log.Tracef("Skipping '%s' server '%s' as it's in the filtered server list with type %s", ad.Type, ad.Name, fType)
			continue
		}

		var nsAd *server_structs.NamespaceAdV2
		if nsAd = getLongestNSMatch(reqPath, ad.NamespaceAds); nsAd == nil {
			// This server doesn't support the requested namespace, skip it
			continue
		}

		// Normalize the namespace path for comparison
		nsPath := nsAd.Path
		if !strings.HasSuffix(nsPath, "/") {
			nsPath += "/"
		}

		// If we haven't yet encountered a best prefix, set the current one as best
		if bestFedPrefix == "" {
			bestFedPrefix = nsPath
		}

		// if the current ad's path matches but is shorter than the best path, skip
		if len(nsPath) < len(bestFedPrefix) {
			continue
		}

		// If the current nsAd's path has the same best prefix as the longest known,
		// append the ad
		if len(nsPath) == len(bestFedPrefix) {
			if ad.Type == server_structs.OriginType.String() {
				// Replace topology origins with Pelican origins if needed
				if len(oAds) == 0 || (oAds[len(oAds)-1].ServerAd.FromTopology && !ad.ServerAd.FromTopology) {
					nsCopy := *nsAd
					// We want returned namespace paths to forgo any trailing / that might come from
					// topology. To trim the prefix without modifying the original ad, we copy it
					nsCopy.Path = strings.TrimSuffix(nsCopy.Path, "/")
					oAds = []copyAd{{ServerAd: ad.ServerAd, NamespaceAd: nsCopy}}
				} else if !ad.ServerAd.FromTopology || oAds[len(oAds)-1].ServerAd.FromTopology == ad.ServerAd.FromTopology {
					nsCopy := *nsAd
					nsCopy.Path = strings.TrimSuffix(nsCopy.Path, "/")
					oAds = append(oAds, copyAd{ServerAd: ad.ServerAd, NamespaceAd: nsCopy})
				}
			} else if ad.Type == server_structs.CacheType.String() {
				nsCopy := *nsAd
				nsCopy.Path = strings.TrimSuffix(nsCopy.Path, "/")
				cAds = append(cAds, copyAd{ServerAd: ad.ServerAd, NamespaceAd: nsCopy})
			}
			continue
		}

		// Otherwise we've found a better match. Overwrite slices we're tracking and
		// set the new best prefix
		bestFedPrefix = nsPath
		nsCopy := *nsAd
		nsCopy.Path = strings.TrimSuffix(nsCopy.Path, "/")
		if ad.Type == server_structs.OriginType.String() {
			oAds = []copyAd{{ServerAd: ad.ServerAd, NamespaceAd: nsCopy}}
			cAds = []copyAd{}
		} else if ad.Type == server_structs.CacheType.String() {
			oAds = []copyAd{}
			cAds = []copyAd{{ServerAd: ad.ServerAd, NamespaceAd: nsCopy}}
		}
	}

	return oAds, cAds
}

// allPass returns true if the ad satisfies all predicates.
func allPredicatesPass(ctx *gin.Context, ad copyAd, preds ...AdPredicate) bool {
	for _, pred := range preds {
		if !pred(ctx, ad) {
			return false
		}
	}
	return true
}

// ORIGIN FILTERING PREDICATES

// Filter out origins that don't support the incoming request verb. For example,
// if the client is trying to do a PUT, only send them to origins that are willing
// to support writes on the namespace's behalf.
func originSupportsVerb(verb string) AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		switch verb {
		case http.MethodGet, http.MethodHead:
			return (ad.ServerAd.Caps.Reads && ad.NamespaceAd.Caps.Reads) ||
				(ad.ServerAd.Caps.PublicReads && ad.NamespaceAd.Caps.PublicReads)
		case http.MethodPut:
			return ad.ServerAd.Caps.Writes && ad.NamespaceAd.Caps.Writes
		case http.MethodDelete:
			return ad.ServerAd.Caps.Writes && ad.NamespaceAd.Caps.Writes
		case "PROPFIND":
			return ad.ServerAd.Caps.Listings && ad.NamespaceAd.Caps.Listings
		default:
			return false
		}
	}
}

// Filter out origins that don't support the incoming request query. For example,
// if the client is trying to do a direct read, only send them to origins that enable
// that capability.
func originSupportsQuery() AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		q := ctx.Request.URL.Query()
		if q.Has(pelican_url.QueryDirectRead) && !(ad.ServerAd.Caps.DirectReads && ad.NamespaceAd.Caps.DirectReads) {
			return false
		}
		if q.Has(pelican_url.QueryRecursive) && !(ad.ServerAd.Caps.Listings && ad.NamespaceAd.Caps.Listings) {
			return false
		}
		return true
	}
}

// Compute the union of required features between all of the origins. We're not able
// to do individual origin-cache feature compatibility checks for client redirects,
// because we don't know which origin a cache may be given at this level.
func computeFeaturesUnion(origins []copyAd) map[string]features.Feature {
	featureSet := make(map[string]features.Feature)
	for _, ad := range origins {
		for _, featureStr := range ad.ServerAd.RequiredFeatures {
			feature, err := features.GetFeature(featureStr)
			if err != nil {
				log.Warningf("Unable to get feature '%s' for server '%s': %v", featureStr, ad.ServerAd.Name, err)
				continue
			}
			featureSet[feature.GetName()] = feature
		}
	}
	return featureSet
}

// Given a gin request, a slice of ads and a set of filter predicates, return only
// the ads that pass all the predicates.
func filterOrigins(ctx *gin.Context, ads []copyAd, predicates ...AdPredicate) []copyAd {
	filtered := make([]copyAd, 0, len(ads))
	for _, ad := range ads {
		if allPredicatesPass(ctx, ad, predicates...) {
			filtered = append(filtered, ad)
		}
	}
	return filtered
}

// CACHE FILTERING PREDICATES

// Given the union set of required features for all origins that may fulfill the request,
// determine which caches support the required features.
func cacheSupportsFeature(requiredFeatures map[string]features.Feature) AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		if len(requiredFeatures) == 0 {
			return true
		}
		for _, feature := range requiredFeatures {
			val := features.ServerSupportsFeature(feature, ad.ServerAd)
			// if features.ServerSupportsFeature(feature, ad.ServerAd) == utils.Tern_True {
			if val == utils.Tern_True {
				return true
			}
		}
		return false
	}
}

// Given the union set of required features for all origins that may fulfill the request,
// determine which caches _might_ support the required features. This is used to highlight
// the fact that some information may be missing for us to concretely determine whether
// the cache can fulfill the request. Such caches are ultimately put at the end of the
// sorted slice because we don't know if they'll work.
func cacheMightSupportFeature(requiredFeatures map[string]features.Feature) AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		if len(requiredFeatures) == 0 {
			return false
		}
		for _, feature := range requiredFeatures {
			if features.ServerSupportsFeature(feature, ad.ServerAd) == utils.Tern_Unknown {
				return true
			}
		}
		return false
	}
}

// If the request is for a publicly-readable object, prevent redirection to the public
// HTTP endpoint from topology-only caches.
func cacheNotFromTopoIfPubReads() AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		return !(ad.NamespaceAd.Caps.PublicReads && ad.ServerAd.FromTopology)
	}
}

// classifyAds is a generic helper to classify ads into groups in a single pass.
// It first applies the common predicate (for example, topology) to every ad.
// Then, for each ad that passes the common check, it tests a list of group predicates.
// If the ad passes all predicates for a given group, it is added to that group.
// Here, we use it to split caches into "supported" and "unknown" groups.
func filterCaches(
	ctx *gin.Context,
	ads []copyAd,
	commonPred AdPredicate,
	supportedPreds []AdPredicate,
	unknownPreds []AdPredicate,
) (supported, unknown []copyAd) {
	for _, ad := range ads {
		// Apply common predicate.
		if !commonPred(ctx, ad) {
			continue
		}
		// Check supported group.
		if allPredicatesPass(ctx, ad, supportedPreds...) {
			supported = append(supported, ad)
		} else if allPredicatesPass(ctx, ad, unknownPreds...) {
			// Otherwise check unknown group.
			unknown = append(unknown, ad)
		}
	}
	return
}

// Find and return a sorted list of all the origins/caches that may
// be able to fulfill the request.
func getSortedAds(ctx *gin.Context) (sortedOrigins, sortedCaches []copyAd, err error) {
	// Start off by getting all ads that support the given request path. In this case, an "ad" is a struct
	// containing the server ad and the namespace ad for the request path. We track both to treat matchmaking
	// as a function over the coupling of server+namespace.
	reqPath := getObjectPathFromRequest(ctx)
	reqParams := getRequestParameters(ctx.Request)
	reqVerb := ctx.Request.Method
	originAds, cacheAds := getAdsForPath(reqPath)

	// If there are no matching origin ads, then we also assume no caches should be serving the object as shutting
	// down the origin(s) is the same as unplugging from the federation.
	if len(originAds) == 0 {
		// If the director restarted recently, tell the client to try again soon by sending a 429
		if inStartupSequence() {
			return nil, nil, directorStartupErr{reqPath}
		} else {
			return nil, nil, noOriginsForNsErr{reqPath}
		}
	}

	// Of the origins supporting the path, filter out those that don't support some other
	// aspect of this request, e.g. trying to PUT to an origin/namespace that only supports
	// GETs.
	originPredicates := []AdPredicate{
		originSupportsVerb(reqVerb),
		originSupportsQuery(),
	}
	sortedOrigins = filterOrigins(ctx, originAds, originPredicates...)
	if len(sortedOrigins) == 0 {
		// Since caches are supposed to act on behalf of origins, the fact that there are no
		// origins capable of supporting the request means we can fail early.
		return nil, nil, noOriginsForReqErr{verb: mapHTTPVerbToPelVerb(reqVerb), queries: mapQueriesToCaps(ctx)}
	}

	// Some of the Origins we're keeping track of up to this point may require specific features
	// that restrict which caches they can communicate with, e.g. CacheAuthz. Because we have no way
	// of knowing which Origin a specific cache miss might be sent to, we restrict potential caches to
	// only those that support the union of all required features for all Origins.
	requiredFeatures := computeFeaturesUnion(sortedOrigins)

	// Now use predicate filtering against caches. This is more nuanced than origins,
	// and the predicates are broken into three groups:
	// 1. Common predicate: every cache no matter what must pass this.
	// 2. Supported predicates: if the cache passes the common predicate, we can mark whether we know it supports a feature
	// 3. Unknown predicates: if the cache passes the common predicate but we don't know if it supports a feature, we can
	//    mark it as unknown.
	commonPredicate := cacheNotFromTopoIfPubReads()
	supportedPredicates := []AdPredicate{cacheSupportsFeature(requiredFeatures)}
	unknownPredicates := []AdPredicate{cacheMightSupportFeature(requiredFeatures)}
	sortedCaches, unknownCaches := filterCaches(ctx, cacheAds, commonPredicate, supportedPredicates, unknownPredicates)

	// Avoid sorting any slices we don't need to
	shouldSortOrigins := isOriginRequest(ctx)
	shouldSortCaches := isCacheRequest(ctx)
	if reqParams.Has(pelican_url.QueryDirectRead) {
		shouldSortOrigins = true
		shouldSortCaches = false
	}

	// From here on, some functions only need to observe actual server ads, not pairings of server ads
	// and namespace ads. Split those out
	cServAds := make([]server_structs.ServerAd, 0, len(sortedCaches))
	oServAds := make([]server_structs.ServerAd, 0, len(sortedOrigins))
	for _, c := range sortedCaches {
		cServAds = append(cServAds, c.ServerAd)
	}
	for _, o := range sortedOrigins {
		oServAds = append(oServAds, o.ServerAd)
	}

	if requiresCacheChaining(ctx, oServAds) {
		shouldSortCaches = true
	}

	// Generate availability maps for origins and caches by performing stat queries
	originAvailabilityMap, cacheAvailabilityMap, err := generateAvailabilityMaps(ctx, oServAds, cServAds, sortedOrigins[0].NamespaceAd)
	if err != nil {
		if _, ok := err.(objectNotFoundErr); ok {
			return nil, nil, err
		}

		return nil, nil, errors.Wrap(err, "failed to generate stat availability maps")
	}

	// Finally, sort everything as needed
	pCtx := context.WithValue(context.Background(), ProjectContextKey{},
		utils.ExtractProjectFromUserAgent(ctx.Request.Header.Values("User-Agent")))
	var wg sync.WaitGroup
	var lastError error
	redirectInfo := server_structs.NewRedirectInfoFromIP(utils.ClientIPAddr(ctx).String())
	if shouldSortOrigins {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sortedServerAds, err := sortServerAds(pCtx, utils.ClientIPAddr(ctx), oServAds, originAvailabilityMap, redirectInfo)
			if err != nil {
				lastError = errors.Wrap(err, "failed to sort origins")
				return
			}

			// Map server ads to copyAds for sorting
			copyAdMap := make(map[string]copyAd, len(sortedOrigins))
			for _, o := range sortedOrigins {
				copyAdMap[o.ServerAd.URL.String()] = o
			}

			// Reconstruct sortedOrigins as []copyAd
			sortedOrigins = make([]copyAd, 0, len(sortedServerAds))
			for _, sortedAd := range sortedServerAds {
				if copyAd, exists := copyAdMap[sortedAd.URL.String()]; exists {
					sortedOrigins = append(sortedOrigins, copyAd)
				}
			}
		}()
	}

	if shouldSortCaches {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sortedServerAds, err := sortServerAds(pCtx, utils.ClientIPAddr(ctx), cServAds, cacheAvailabilityMap, redirectInfo)
			if err != nil {
				lastError = errors.Wrap(err, "failed to sort caches")
				return
			}

			// Map server ads to copyAds for sorting
			copyAdMap := make(map[string]copyAd, len(sortedCaches))
			for _, c := range sortedCaches {
				copyAdMap[c.ServerAd.URL.String()] = c
			}

			// Reconstruct sortedCaches as []copyAd
			sortedCaches = make([]copyAd, 0, len(sortedServerAds))
			for _, sortedAd := range sortedServerAds {
				if copyAd, exists := copyAdMap[sortedAd.URL.String()]; exists {
					sortedCaches = append(sortedCaches, copyAd)
				}
			}
		}()
	}
	wg.Wait()
	if lastError != nil {
		return nil, nil, lastError
	}

	// Provide redirect debugging info if asked to. This gets set in the context and should be retrieved
	// by redirectTo{Cache/Origin}
	if ctx.GetHeader("X-Pelican-Debug") == "true" {
		ctx.Set("redirectInfo", redirectInfo)
	}

	// Append unknown caches to the end of the sorted caches list since we don't know whether they'll
	// function or not.
	sortedCaches = append(sortedCaches, unknownCaches...)

	return sortedOrigins, sortedCaches, nil
}
