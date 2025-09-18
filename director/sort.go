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
	"net/http"
	"net/netip"
	"path"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	// Holds all the stuff, minus a few globals, needed to perform a given sort
	// alg that aren't a part of the server ads themselves.
	SortContext struct {
		Ctx             context.Context
		ClientAddr      netip.Addr
		AvailabilityMap map[string]bool
		RedirectInfo    *server_structs.RedirectInfo
	}

	// A function type for filtering ads -- given a request and an ad, it should
	// determine whether the server ad is capable of fulfilling the predicate, and
	// thus should be included in the list of ads to be returned.
	// A collection of these are used during Director matchmaking to produce the list of
	// caches/origins that can fulfill the request.
	AdPredicate func(ctx *gin.Context, ad copyAd) bool
)

// Constants for director sorting algorithms
const (
	sourceWorkingSetSize = 15 // Number of servers we consider after first GeoIP sort in adaptive method
	sourceServerAdsLimit = 6  // Number of servers sent to the client after all sorting operations complete
)

// The all-in-one method to sort serverAds based on the Director.CacheSortMethod configuration parameter
//   - distance: sort serverAds by the distance between the geolocation of the servers and the client
//   - distanceAndLoad: sort serverAds by the distance with gated halving factor (see details in the adaptive method)
//     and the server IO load
//   - random: sort serverAds randomly
//   - adaptive:  sort serverAds based on rules discussed in these places:
//   - https://github.com/PelicanPlatform/pelican/discussions/1198
//   - https://docs.google.com/document/d/e/2PACX-1vQg9biPzp3RbC5qVuJFvgMZHgIM-nw92JzjHkGl-h7djeNNXa68ckv2rAqtXEDYe8QvXL3oX0Fr0-bp/pub
//
// Note that if the client IP isn't overridden and MaxMind cannot resolve accurate coordinates for it, the client's
// coordinate is randomly assigned within the contiguous US and cached for re-use. This means that distance-based sorts
// will be effectively random the first time, but subsequent requests within a short time period will still likely
// generate cache hits.
func sortServerAds(ctx context.Context, clientAddr netip.Addr, ads []server_structs.ServerAd, availabilityMap map[string]bool, redirectInfo *server_structs.RedirectInfo) ([]server_structs.ServerAd, error) {
	sortMethod := server_structs.SortType(param.Director_CacheSortMethod.GetString())
	redirectInfo.DirectorSortMethod = sortMethod.String()
	redirectInfo.ClientInfo.IpAddr = clientAddr.String()

	sortContext := SortContext{
		Ctx:             ctx,
		ClientAddr:      clientAddr,
		AvailabilityMap: availabilityMap,
		RedirectInfo:    redirectInfo,
	}
	var sortAlg SortAlgorithm
	switch sortMethod {
	case server_structs.DistanceType:
		sortAlg = &DistanceSort{}
	case server_structs.DistanceAndLoadType: // currently a place holder for distance (per our parameters.yaml docs)
		sortAlg = &DistanceSort{}
	case server_structs.AdaptiveType:
		sortAlg = &AdaptiveSort{}
	case server_structs.RandomType:
		sortAlg = &RandomSort{}
	default:
		// Never say never, but this should never get hit because we validate the value on Director startup.
		// The only real way to get here is through writing bad unit tests.
		return nil, errors.Errorf("invalid sort method '%s' set in %s", param.Director_CacheSortMethod.GetString(), param.Director_CacheSortMethod.GetName())
	}

	sortedAds, err := sortAlg.Sort(ads, sortContext)
	if err != nil {
		// Use fallbacks that are less likely to produce errors (Distance, then Random)
		var fallbackMethod server_structs.SortType
		if sortMethod != server_structs.DistanceType && sortMethod != server_structs.RandomType {
			fallbackMethod = server_structs.DistanceType
			sortAlg = &DistanceSort{}
		} else if sortMethod != server_structs.RandomType {
			fallbackMethod = server_structs.RandomType
			sortAlg = &RandomSort{}
		} else {
			return nil, errors.Wrapf(err, "failed to sort server ads using %s", sortMethod.String())
		}

		sortedAds, err = sortAlg.Sort(ads, sortContext)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to sort server ads using both %s and fallback %s algorithms", sortMethod.String(), fallbackMethod.String())
		}
	}

	return truncateAds(sortedAds, sourceServerAdsLimit), nil
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
	sortServerAdsByTopo(ads)

	var bestFedPrefix string
	for _, ad := range ads {
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
			if features.ServerSupportsFeature(feature, ad.ServerAd) == utils.Tern_True {
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

// If the cache is in an error state, we shouldn't send traffic to it.
func cacheNotInErrorState() AdPredicate {
	return func(ctx *gin.Context, ad copyAd) bool {
		return metrics.ParseHealthStatus(ad.ServerAd.Status) > metrics.StatusCritical
	}
}

// classifyAds is a generic helper to classify ads into groups in a single pass.
// It first applies the common predicates (for example, topology, err state) to every ad.
// Then, for each ad that passes the common check, it tests a list of group predicates.
// If the ad passes all predicates for a given group, it is added to that group.
// Here, we use it to split caches into "supported" and "unknown" groups.
func filterCaches(
	ctx *gin.Context,
	ads []copyAd,
	commonPreds []AdPredicate,
	supportedPreds []AdPredicate,
	unknownPreds []AdPredicate,
) (supported, unknown []copyAd) {
	for _, ad := range ads {
		// Apply common predicates.
		if !allPredicatesPass(ctx, ad, commonPreds...) {
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
func getSortedAds(ctx *gin.Context, requestId uuid.UUID) (sortedOrigins, sortedCaches []copyAd, err error) {
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
	log.Tracef("Request %s for path %s requires features %v", requestId, reqPath, requiredFeatures)

	// Now use predicate filtering against caches. This is more nuanced than origins,
	// and the predicates are broken into three groups:
	// 1. Common predicatse: every cache no matter what must pass this to be considered.
	// 2. Supported predicates: if the cache passes the common predicate, we can mark whether we know it supports a feature.
	// 3. Unknown predicates: if the cache passes the common predicate but we don't know if it supports a feature, we can
	//    mark it as unknown.
	commonPredicates := []AdPredicate{cacheNotFromTopoIfPubReads()}
	if param.Director_FilterCachesInErrorState.GetBool() {
		commonPredicates = append(commonPredicates, cacheNotInErrorState())
	}
	supportedPredicates := []AdPredicate{cacheSupportsFeature(requiredFeatures)}
	unknownPredicates := []AdPredicate{cacheMightSupportFeature(requiredFeatures)}
	sortedCaches, unknownCaches := filterCaches(ctx, cacheAds, commonPredicates, supportedPredicates, unknownPredicates)

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
		log.Tracef("The Director determine cache chaining was needed for request %s for path %s", requestId.String(), reqPath)
		shouldSortCaches = true
	}

	// Generate availability maps for origins and caches by performing stat queries
	originAvailabilityMap, cacheAvailabilityMap, err := generateAvailabilityMaps(ctx, oServAds, cServAds, sortedOrigins[0].NamespaceAd, requestId)
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
		log.Tracef("Sorting origins for request %s for path %s", requestId.String(), reqPath)
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
		log.Tracef("Sorting caches for request %s for path %s", requestId.String(), reqPath)
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
