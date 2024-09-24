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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (
	// status of director-based health tests to origins and caches
	HealthTestStatus string

	// Prometheus HTTP discovery endpoint struct, used by director
	// to dynamically return available origin/cache servers for Prometheus to scrape
	PromDiscoveryItem struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}

	// Util struct to keep track of director-based health tests it created
	healthTestUtil struct {
		ErrGrp        *errgroup.Group
		ErrGrpContext context.Context
		Cancel        context.CancelFunc
		Status        HealthTestStatus
	}
	// Utility struct to keep track of the `stat` call the director made to the origin/cache servers
	serverStatUtil struct {
		Context  context.Context
		Cancel   context.CancelFunc
		Errgroup *errgroup.Group
	}
)

const (
	HealthStatusDisabled HealthTestStatus = "Health Test Disabled"
	HealthStatusUnknown  HealthTestStatus = "Unknown"
	HealthStatusInit     HealthTestStatus = "Initializing"
	HealthStatusOK       HealthTestStatus = "OK"
	HealthStatusError    HealthTestStatus = "Error"
)

const (
	// The number of caches to send in the Link header. As discussed in issue
	// https://github.com/PelicanPlatform/pelican/issues/1247, the client stops
	// after three attempts, so there's really no need to send every cache we know
	serverResLimit = 6
)

var (
	minClientVersion, _ = version.NewVersion("7.0.0")
	minOriginVersion, _ = version.NewVersion("7.0.0")
	minCacheVersion, _  = version.NewVersion("7.3.0")
	// TODO: Consolidate the two maps into server_structs.Advertisement. [#1391]
	healthTestUtils      = make(map[string]*healthTestUtil) // The utilities for the director file tests. The key is string form of ServerAd.URL
	healthTestUtilsMutex = sync.RWMutex{}

	statUtils      = make(map[string]serverStatUtil) // The utilities for the stat call. The key is string form of ServerAd.URL
	statUtilsMutex = sync.RWMutex{}
)

func getRedirectURL(reqPath string, ad server_structs.ServerAd, requiresAuth bool) (redirectURL url.URL) {
	var serverURL url.URL
	if requiresAuth && ad.AuthURL.String() != "" {
		serverURL = ad.AuthURL
		if ad.AuthURL == (url.URL{}) {
			serverURL = ad.URL
		}
	} else {
		serverURL = ad.URL
	}
	reqPath = path.Clean("/" + reqPath)
	if requiresAuth {
		redirectURL.Scheme = "https"
	} else {
		redirectURL.Scheme = "https"
		if ad.FromTopology {
			redirectURL.Scheme = "http"
		}
	}
	redirectURL.Host = serverURL.Host
	redirectURL.Path = reqPath
	return
}

// Calculate the depth attribute of Link header given the path to the file
// and the prefix of the namespace that can serve the file
//
// Ref: https://www.rfc-editor.org/rfc/rfc6249.html#section-3.4
func getLinkDepth(filepath, prefix string) (int, error) {
	if filepath == "" || prefix == "" {
		return 0, errors.New("either filepath or prefix is an empty path")
	}
	if !strings.HasPrefix(filepath, prefix) {
		return 0, errors.New("filepath does not contain the prefix")
	}
	// We want to remove shared prefix between filepath and prefix, then split the remaining string by slash.
	// To make the final calculation easier, we also remove the head slash from the file path.
	// e.g. filepath = /foo/bar/barz.txt   prefix = /foo
	// we want commonPath = bar/barz.txt
	if !strings.HasSuffix(prefix, "/") && prefix != "/" {
		prefix += "/"
	}
	commonPath := strings.TrimPrefix(filepath, prefix)
	pathDepth := len(strings.Split(commonPath, "/"))
	return pathDepth, nil
}

// Aggregate various request parameters from header and query to a single url.Values struct
func getRequestParameters(req *http.Request) (requestParams url.Values) {
	requestParams = url.Values{}
	authz := ""
	if authzQuery := req.URL.Query()["authz"]; len(authzQuery) > 0 {
		authz = authzQuery[0]
		// if the authz URL query is coming from XRootD, it probably has a "Bearer " tacked in front
		// even though it's coming via a URL
		authz = strings.TrimPrefix(authz, "Bearer ")
	} else if authzHeader := req.Header["Authorization"]; len(authzHeader) > 0 {
		authz = strings.TrimPrefix(authzHeader[0], "Bearer ")
	}

	timeout := ""
	if timeoutQuery := req.URL.Query()["pelican.timeout"]; len(timeoutQuery) > 0 {
		timeout = timeoutQuery[0]
	} else if timeoutHeader := req.Header["X-Pelican-Timeout"]; len(timeoutHeader) > 0 {
		timeout = timeoutHeader[0]
	}

	directRead := req.URL.Query().Has(utils.QueryDirectRead.String())
	skipStat := req.URL.Query().Has(utils.QuerySkipStat.String())
	preferCached := req.URL.Query().Has(utils.QueryPreferCached.String())

	// url.Values.Encode will help us escape all them
	if authz != "" {
		requestParams.Add("authz", authz)
	}
	if timeout != "" {
		requestParams.Add("pelican.timeout", timeout)
	}
	if skipStat {
		requestParams.Add(utils.QuerySkipStat.String(), "")
	}
	if preferCached {
		requestParams.Add(utils.QueryPreferCached.String(), "")
	}
	if directRead {
		requestParams.Add(utils.QueryDirectRead.String(), "")
	}
	return
}

// Generates the X-Pelican-Authorization header (when applicable) for responses that have
// issued a request where token generation may be needed. This header informs the client
// of the issuer that can be used to generate a token for the requested resource.
func generateXAuthHeader(ginCtx *gin.Context, namespaceAd server_structs.NamespaceAdV2) {
	if len(namespaceAd.Issuer) != 0 {
		issStrings := []string{}
		for _, tokIss := range namespaceAd.Issuer {
			issStrings = append(issStrings, "issuer="+tokIss.IssuerUrl.String())
		}
		ginCtx.Writer.Header()["X-Pelican-Authorization"] = issStrings
	}
}

// Generates the X-Pelican-Token-Generation header (when applicable) for responses that have
// issued a request where token generation may be needed.
func generateXTokenGenHeader(ginCtx *gin.Context, namespaceAd server_structs.NamespaceAdV2) {
	if len(namespaceAd.Generation) != 0 {
		tokenGen := ""
		first := true
		// TODO: At some point, the director stopped sending the `base-path` key in the token gen header. I'm unsure of the _proper_ way
		// to fix this because the token gen header uses the issuer URL from NamespaceAdV2.Generation.CredentialIssuer, whereas basepaths
		// come from NamespaceAdV2.Issuer.BasePaths. For now, connecting these two means checking if they have the same issuer URL. This
		// really needs to be cleaned up in the future, and maybe we need to give more thought to why we have these two structs in the
		// ad. See https://github.com/PelicanPlatform/pelican/issues/1540
		var basePath string
		for _, issuer := range namespaceAd.Issuer {
			if issuer.IssuerUrl.String() == namespaceAd.Generation[0].CredentialIssuer.String() {
				if len(issuer.BasePaths) > 0 {
					basePath = issuer.BasePaths[0]
				}
				break
			}
		}

		hdrVals := []string{namespaceAd.Generation[0].CredentialIssuer.String(), fmt.Sprint(namespaceAd.Generation[0].MaxScopeDepth),
			string(namespaceAd.Generation[0].Strategy), basePath}
		for idx, hdrKey := range []string{"issuer", "max-scope-depth", "strategy", "base-path"} {
			hdrVal := hdrVals[idx]
			if hdrVal == "" {
				continue
			} else if hdrKey == "max-scope-depth" && hdrVal == "0" {
				// don't send a 0 max-scope-depth because it's malformed and probably means there should be no token generation header
				continue
			}
			if !first {
				tokenGen += ", "
			}
			first = false
			tokenGen += hdrKey + "=" + hdrVal
		}

		if tokenGen != "" {
			ginCtx.Writer.Header()["X-Pelican-Token-Generation"] = []string{tokenGen}
		}
	}
}

func generateXNamespaceHeader(ginCtx *gin.Context, namespaceAd server_structs.NamespaceAdV2, collUrl string) {
	xPelicanNamespace := fmt.Sprintf("namespace=%s, require-token=%v", namespaceAd.Path, !namespaceAd.Caps.PublicReads)
	if collUrl != "" {
		xPelicanNamespace += fmt.Sprintf(", collections-url=%s", collUrl)
	}
	ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{xPelicanNamespace}
}

func getFinalRedirectURL(rurl url.URL, requstParams url.Values) string {
	rQuery := rurl.Query()
	for key, vals := range requstParams {
		for _, val := range vals {
			rQuery.Add(key, val)
		}
	}
	rurl.RawQuery = rQuery.Encode()
	return rurl.String()
}

// Helper function to extract version and service from User-Agent
func extractVersionAndService(ginCtx *gin.Context) (reqVer *version.Version, service string, err error) {
	userAgentSlc := ginCtx.Request.Header["User-Agent"]
	if len(userAgentSlc) < 1 {
		return nil, "", errors.New("No user agent could be found")
	}

	userAgent := userAgentSlc[0]
	reqVerStr, service := utils.ExtractVersionAndServiceFromUserAgent(userAgent)
	if reqVerStr == "" || service == "" {
		return nil, "", nil
	}
	reqVer, err = version.NewVersion(reqVerStr)
	if err != nil {
		return nil, "", errors.Wrapf(err, "Could not parse service version as a semantic version: %s\n", reqVerStr)
	}
	return reqVer, service, nil
}

func versionCompatCheck(reqVer *version.Version, service string) error {
	var minCompatVer *version.Version
	switch service {
	case "client":
		minCompatVer = minClientVersion
	case "origin":
		minCompatVer = minOriginVersion
	case "cache":
		minCompatVer = minCacheVersion
	case "": // service not provided, ie: using curl
		return nil
	default:
		return errors.Errorf("Invalid version format. The director does not support your %s version (%s).", service, reqVer.String())
	}

	if reqVer == nil { // version not provided, ie: using curl
		return nil
	}

	if reqVer.LessThan(minCompatVer) {
		return errors.Errorf("The director does not support your %s version (%s). Please update to %s or newer.", service, reqVer.String(), minCompatVer.String())
	}

	return nil
}

// Check and validate the director-specific query params from the redirect request
func checkRedirectQuery(query url.Values) error {
	_, hasDirectRead := query[utils.QueryDirectRead.String()]
	_, hasPreferCached := query[utils.QueryPreferCached.String()]

	if hasDirectRead && hasPreferCached {
		return errors.New("cannot have both directread and prefercached query parameters")
	}
	return nil
}

func redirectToCache(ginCtx *gin.Context) {
	reqVer, service, _ := extractVersionAndService(ginCtx)
	err := versionCompatCheck(reqVer, service)
	if err != nil {
		log.Warningf("A version incompatibility was encountered while redirecting to a cache and no response was served: %v", err)
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Incompatible versions detected: %v", err),
		})
		return
	}

	if err = checkRedirectQuery(ginCtx.Request.URL.Query()); err != nil {
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters: " + err.Error(),
		})
		return
	}

	collectClientVersionMetric(reqVer, service)

	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/object")
	ipAddr := utils.ClientIPAddr(ginCtx)

	reqParams := getRequestParameters(ginCtx.Request)

	disableStat := !param.Director_EnableStat.GetBool()

	// Skip the stat check for object availability
	// If either disableStat or skipstat is set, then skip the stat query
	skipStat := ginCtx.Request.URL.Query().Has("skipstat") || disableStat

	namespaceAd, originAds, cacheAds := getAdsForPath(reqPath)
	// if GetAdsForPath doesn't find any ads because the prefix doesn't exist, we should
	// report the lack of path first -- this is most important for the user because it tells them
	// they're trying to get an object that simply doesn't exist
	if namespaceAd.Path == "" {
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No namespace found for path. Either it doesn't exist, or the Director is experiencing problems",
		})
		return
	}
	// if err != nil, depth == 0, which is the default value for depth
	// so we can use it as the value for the header even with err
	depth, err := getLinkDepth(reqPath, namespaceAd.Path)
	if err != nil {
		log.Errorf("Failed to get depth attribute for the redirecting request to %q, with best match namespace prefix %q", reqPath, namespaceAd.Path)
	}

	// If the namespace requires a token yet there's no token available, skip the stat.
	if !namespaceAd.Caps.PublicReads && reqParams.Get("authz") == "" {
		skipStat = true
	}

	// Stat origins and caches for object availability
	// For origins, we only want ones with the object
	// For caches, we still list all in the response but turn down priorities for ones that don't have the object
	originAdsWObject := []server_structs.ServerAd{}
	// An array to keep track of object availability of each caches
	cachesAvailabilityMap := make(map[string]bool, len(cacheAds))

	if skipStat {
		originAdsWObject = originAds
		for _, cAd := range cacheAds {
			cachesAvailabilityMap[cAd.URL.String()] = true
		}
	} else {
		// Query Origins and check if the object exists on the server
		q := NewObjectStat()
		st := server_structs.NewServerType()
		st.SetList([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
		// Set max response to all available origin and cache servers to ensure we stat against origins
		// if no cache server has the file
		// TODO: come back and re-evaluate if we need this many responses and potential origin/cache
		// server performance issue out of this
		maxRes := len(cacheAds) + len(originAds)
		qr := q.Query(context.Background(), reqPath, st, 1, maxRes,
			withOriginAds(originAds), withCacheAds(cacheAds), WithToken(reqParams.Get("authz")))
		log.Debugf("Stat result for %s: %s", reqPath, qr.String())

		// For successful response, we got a list of URLs to access the object.
		// We will use the host of the object url to match the URL field in originAds and cacheAds
		if qr.Status == querySuccessful {
			for _, obj := range qr.Objects {
				serverHost := obj.URL.Host
				for _, oAd := range originAds {
					if oAd.URL.Host == serverHost || oAd.AuthURL.Host == serverHost {
						originAdsWObject = append(originAdsWObject, oAd)
					}
				}
				for _, cAd := range cacheAds {
					if cAd.URL.Host == serverHost || cAd.AuthURL.Host == serverHost {
						cachesAvailabilityMap[cAd.URL.String()] = true
					}
				}
			}
		} else if qr.Status == queryFailed {
			if qr.ErrorType != queryInsufficientResErr {
				ginCtx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("Failed to query origins with error %s: %s", string(qr.ErrorType), qr.Msg),
				})
				return
			}
			// For denied servers, append them to availableOriginAds
			// The qr.DeniedServers is a list of AuthURLs of servers that respond with 403
			// Here, we need to match against the AuthURL field of originAds
			for _, ds := range qr.DeniedServers {
				for _, oAd := range originAds {
					if oAd.Type == server_structs.OriginType.String() && oAd.AuthURL.String() == ds {
						originAdsWObject = append(originAdsWObject, oAd)
					}
				}
				for _, cAd := range cacheAds {
					if cAd.AuthURL.String() == ds {
						cachesAvailabilityMap[cAd.URL.String()] = true
					}
				}
			}
		}
	}

	// If the namespace prefix DOES exist, then it makes sense to say we couldn't find a valid cache.
	// In this case, we append originAd(s) to cacheAds if the origin enabled DirectReads
	if len(cacheAds) == 0 {
		for _, originAd := range originAdsWObject {
			// Find the first origin that enables direct reads as the fallback
			if originAd.Caps.DirectReads {
				cacheAds = append(cacheAds, originAd)
				break
			}
		}
		if len(cacheAds) == 0 {
			ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "No cache or fallback origin found for this object. The object may not exist in the federation",
			})
			return
		}
	}

	cacheAds, err = sortServerAds(ipAddr, cacheAds, cachesAvailabilityMap)
	if err != nil {
		log.Error("Error determining server ordering for cacheAds: ", err)
		ginCtx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to determine server ordering",
		})
		return
	}

	// "smart" sorting method takes care of availability factor
	if param.Director_CacheSortMethod.GetString() != "smart" {
		// Re-sort by availability, where caches having the object have higher priority
		sortServerAdsByAvailability(cacheAds, cachesAvailabilityMap)
	}

	redirectURL := getRedirectURL(reqPath, cacheAds[0], !namespaceAd.Caps.PublicReads)

	linkHeader := ""
	first := true
	cachesToSend := serverResLimit
	if numCAds := len(cacheAds); numCAds < serverResLimit {
		cachesToSend = numCAds
	}
	for idx, ad := range cacheAds[:cachesToSend] {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad, !namespaceAd.Caps.PublicReads)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; pri=%d; depth=%d`, redirectURL.String(), idx+1, depth)
	}
	ginCtx.Writer.Header()["Link"] = []string{linkHeader}

	// Generate headers needed for token generation/verification
	generateXAuthHeader(ginCtx, namespaceAd)
	generateXTokenGenHeader(ginCtx, namespaceAd)

	var colUrl string
	// If the namespace or the origin does not allow directory listings, then we should not advertise a collections-url.
	// This is because the configuration of the origin/namespace should override the inclusion of "dirlisthost" for that origin.
	// Listings is true by default so if it is ever set to false we should accept that config over the dirlisthost.
	if namespaceAd.Caps.Listings && len(originAdsWObject) > 0 && originAdsWObject[0].Caps.Listings {
		if !namespaceAd.Caps.PublicReads && originAdsWObject[0].AuthURL != (url.URL{}) {
			colUrl = originAdsWObject[0].AuthURL.String()
		} else {
			colUrl = originAdsWObject[0].URL.String()
		}
	}
	generateXNamespaceHeader(ginCtx, namespaceAd, colUrl)

	// Note we only append the `authz` query parameter in the case of the redirect response and not the
	// duplicate link metadata above.  This is purposeful: the Link header might get too long if we repeat
	// the token 20 times for 20 caches.  This means a "normal HTTP client" will correctly redirect but
	// anything parsing the `Link` header for metalinks will need logic for redirecting appropriately.
	ginCtx.Redirect(307, getFinalRedirectURL(redirectURL, reqParams))
}

func redirectToOrigin(ginCtx *gin.Context) {
	reqVer, service, _ := extractVersionAndService(ginCtx)
	err := versionCompatCheck(reqVer, service)
	if err != nil {
		log.Warningf("A version incompatibility was encountered while redirecting to an origin and no response was served: %v", err)
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Incompatible versions detected: %v", err),
		})
		return
	}

	if err = checkRedirectQuery(ginCtx.Request.URL.Query()); err != nil {
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid query parameters: " + err.Error(),
		})
		return
	}

	collectClientVersionMetric(reqVer, service)

	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/origin")

	// /pelican/monitoring is the path for director-based health test
	// where we have /director/healthTest API to mock a test object for caches to pull (as if it's from an origin)
	if strings.HasPrefix(reqPath, "/pelican/monitoring/") {
		ginCtx.Redirect(http.StatusTemporaryRedirect, param.Server_ExternalWebUrl.GetString()+"/api/v1.0/director/healthTest"+reqPath)
		return
	}

	ipAddr := utils.ClientIPAddr(ginCtx)

	reqParams := getRequestParameters(ginCtx.Request)

	// Skip the stat check for object availability if either disableStat or skipstat is set
	skipStat := reqParams.Has(utils.QuerySkipStat.String()) || !param.Director_EnableStat.GetBool()

	// Include caches in the response if Director.CachesPullFromCaches is enabled
	// AND prefercached query parameter is set
	includeCaches := param.Director_CachesPullFromCaches.GetBool() && reqParams.Has(utils.QueryPreferCached.String())

	namespaceAd, originAds, cacheAds := getAdsForPath(reqPath)
	// if GetAdsForPath doesn't find any ads because the prefix doesn't exist, we should
	// report the lack of path first -- this is most important for the user because it tells them
	// they're trying to get an object that simply doesn't exist
	if namespaceAd.Path == "" {
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No namespace found for path. Either it doesn't exist, or the Director is experiencing problems",
		})
		return
	}

	// If the namespace requires a token yet there's no token available, skip the stat.
	if !namespaceAd.Caps.PublicReads && reqParams.Get("authz") == "" {
		skipStat = true
	}

	var q *ObjectStat

	availableAds := []server_structs.ServerAd{}
	// Skip stat query for PUT (upload), PROPFIND (listing) or whenever the skipStat query flag is on
	if ginCtx.Request.Method == http.MethodPut || ginCtx.Request.Method == "PROPFIND" || skipStat {
		availableAds = originAds
	} else {
		// Query Origins and check if the object exists
		q = NewObjectStat()
		qr := q.Query(context.Background(), reqPath, server_structs.OriginType, 1, 3,
			withOriginAds(originAds), WithToken(reqParams.Get("authz")), withAuth(!namespaceAd.Caps.PublicReads))
		log.Debugf("Stat result for %s: %s", reqPath, qr.String())

		// For a successful response, we got a list of object URLs.
		// We then use the host of the object url to match the URL field in originAds
		if qr.Status == querySuccessful {
			for _, obj := range qr.Objects {
				serverHost := obj.URL.Host
				for _, oAd := range originAds {
					// TODO: have a UNIQUE id for each server
					// Also check AuthURL in case we retried on the AuthURL for some servers
					if oAd.URL.Host == serverHost || oAd.AuthURL.Host == serverHost {
						availableAds = append(availableAds, oAd)
					}
				}
			}
		} else if qr.Status == queryFailed {
			if qr.ErrorType != queryInsufficientResErr {
				ginCtx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("Failed to query origins with error %s: %s", string(qr.ErrorType), qr.Msg),
				})
				return
			}
			// For denied servers, append them to availableOriginAds,
			// we don't check if DeniedServers is empty as we might be able to pull the object from other caches.
			// The qr.DeniedServers is a list of AuthURLs of servers that respond with 403
			// Here, we need to match against the AuthURL field of originAds
			for _, ds := range qr.DeniedServers {
				for _, oAd := range originAds {
					if oAd.AuthURL.String() == ds {
						availableAds = append(availableAds, oAd)
					}
				}
			}
		}
	}

	// If CachesPullFromCaches is enabled, we stat caches and append cache servers that have the object,
	// with the following exceptions:
	// - Number of available Origins >= serverResLimit
	// - This is an upload request (PUT) or listing request (PROPFIND)
	// - The request has directread, which means direct read to the origin
	if len(availableAds) < serverResLimit &&
		includeCaches &&
		ginCtx.Request.Method != http.MethodPut &&
		ginCtx.Request.Method != "PROPFIND" &&
		!reqParams.Has(utils.QueryDirectRead.String()) {
		if q == nil {
			q = NewObjectStat()
		}
		qr := q.Query(context.Background(), reqPath, server_structs.CacheType, 1, 3,
			withCacheAds(cacheAds), WithToken(reqParams.Get("authz")))
		log.Debugf("CachesPullFromCaches is enabled. Stat result for %s among caches: %s", reqPath, qr.String())

		// For successful response, we got a list of URL to access the object.
		// We will use the host of the object url to match the URL field in cacheAds
		if qr.Status == querySuccessful {
			for _, obj := range qr.Objects {
				serverHost := obj.URL.Host
				for _, oAd := range cacheAds {
					// TODO: have a UNIQUE id for each server
					// Also check AuthURL in case we retried on the AuthURL for some servers
					if oAd.URL.Host == serverHost || oAd.AuthURL.Host == serverHost {
						availableAds = append(availableAds, oAd)
					}
				}
			}
		} else if qr.Status == queryFailed {
			if qr.ErrorType != queryInsufficientResErr {
				log.Debugf("CachesPullFromCaches is enabled, but error occurred when querying caches for the object %s: %s %s", reqPath, string(qr.ErrorType), qr.Msg)
			} else if len(qr.DeniedServers) == 0 { // Insufficient response
				log.Debugf("CachesPullFromCaches is enabled, but no caches found for the object %s", reqPath)
			} else {
				// For denied cache servers, append them to availableAds
				// The qr.DeniedServers is a list of AuthURLs of servers that respond with 403
				// Here, we need to match against the AuthURL field of cacheAds
				for _, ds := range qr.DeniedServers {
					for _, oAd := range cacheAds {
						if oAd.AuthURL.String() == ds {
							availableAds = append(availableAds, oAd)
						}
					}
				}
			}
		}
	}

	// No available originAds or cacheAds if CachesPullFromCaches is enabled, object does not exist
	if len(availableAds) == 0 {
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "There are currently no origins hosting the object: available origin Ads is 0",
		})
		return
	}

	// if err != nil, depth == 0, which is the default value for depth
	// so we can use it as the value for the header even with err
	depth, err := getLinkDepth(reqPath, namespaceAd.Path)
	if err != nil {
		log.Errorf("Failed to get depth attribute for the redirecting request to %q, with best match namespace prefix %q", reqPath, namespaceAd.Path)
	}

	availableAds, err = sortServerAds(ipAddr, availableAds, nil)
	if err != nil {
		log.Error("Error determining server ordering for originAds: ", err)
		ginCtx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to determine origin ordering",
		})
		return
	}

	linkHeader := ""
	first := true
	serversToSend := serverResLimit
	if numCAds := len(availableAds); numCAds < serverResLimit {
		serversToSend = numCAds
	}
	for idx, ad := range availableAds[:serversToSend] {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad, !namespaceAd.Caps.PublicReads)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; pri=%d; depth=%d`, redirectURL.String(), idx+1, depth)
	}
	ginCtx.Writer.Header()["Link"] = []string{linkHeader}

	var colUrl string
	// If the namespace or the origin does not allow directory listings, then we should not advertise a collections-url.
	// This is because the configuration of the origin/namespace should override the inclusion of "dirlisthost" for that origin.
	// Listings is true by default so if it is ever set to false we should accept that config over the dirlisthost.
	if namespaceAd.Caps.Listings && len(availableAds) > 0 && availableAds[0].Caps.Listings {
		if !namespaceAd.Caps.PublicReads && availableAds[0].AuthURL != (url.URL{}) {
			colUrl = availableAds[0].AuthURL.String()
		} else {
			colUrl = availableAds[0].URL.String()
		}
	}
	generateXNamespaceHeader(ginCtx, namespaceAd, colUrl)

	var redirectURL url.URL

	// If we are doing a PROPFIND, check if origins enable dirlistings
	if ginCtx.Request.Method == "PROPFIND" {
		for idx, ad := range availableAds {
			if ad.Caps.Listings && namespaceAd.Caps.Listings {
				redirectURL = getRedirectURL(reqPath, availableAds[idx], !namespaceAd.Caps.PublicReads)
				if brokerUrl := availableAds[idx].BrokerURL; brokerUrl.String() != "" {
					ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
				}
				ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, reqParams))
				return
			}
		}
		ginCtx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No origins on specified endpoint allow collection listings",
		})
	}

	// We know this can be easily bypassed, we need to eventually enforce this
	// Origin should only be redirected to if it allows direct reads or the cache is the one it is talking to.
	// Any client that uses this api that doesn't set directreads can talk directly to an origin

	// Check if we are doing a DirectRead and if it is allowed
	if reqParams.Has(utils.QueryDirectRead.String()) {
		for idx, originAd := range availableAds {
			if originAd.Caps.DirectReads && namespaceAd.Caps.DirectReads {
				redirectURL = getRedirectURL(reqPath, availableAds[idx], !namespaceAd.Caps.PublicReads)
				if brokerUrl := availableAds[idx].BrokerURL; brokerUrl.String() != "" {
					ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
				}
				ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, reqParams))
				return
			}
		}
		ginCtx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No origins on specified endpoint have direct reads enabled",
		})
		return
	}

	// Generate headers needed for token generation/verification
	generateXAuthHeader(ginCtx, namespaceAd)
	generateXTokenGenHeader(ginCtx, namespaceAd)

	// If we are doing a PUT, check to see if any origins are writeable
	if ginCtx.Request.Method == "PUT" {
		for idx, ad := range availableAds {
			if ad.Caps.Writes {
				redirectURL = getRedirectURL(reqPath, availableAds[idx], !namespaceAd.Caps.PublicReads)
				if brokerUrl := availableAds[idx].BrokerURL; brokerUrl.String() != "" {
					ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
				}
				ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, reqParams))
				return
			}
		}
		ginCtx.JSON(http.StatusMethodNotAllowed, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No origins on specified endpoint have direct reads enabled",
		})
		return
	} else { // Otherwise, we are doing a GET
		redirectURL := getRedirectURL(reqPath, availableAds[0], !namespaceAd.Caps.PublicReads)
		if brokerUrl := availableAds[0].BrokerURL; brokerUrl.String() != "" {
			ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
		}

		for _, prefix := range param.Director_X509ClientAuthenticationPrefixes.GetStringSlice() {
			if strings.HasPrefix(reqPath, prefix) {
				ginCtx.Writer.Header().Add("X-Osdf-X509", "true")
				break
			}
		}

		// See note in RedirectToCache as to why we only add the authz query parameter to this URL,
		// not those in the `Link`.
		ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, reqParams))
	}
}

func checkHostnameRedirects(c *gin.Context, incomingHost string) {
	oRedirectHosts := param.Director_OriginResponseHostnames.GetStringSlice()
	cRedirectHosts := param.Director_CacheResponseHostnames.GetStringSlice()

	for _, hostname := range oRedirectHosts {
		if hostname == incomingHost {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				log.Debugln("Director is serving an origin based on incoming 'Host' header value of '" + hostname + "'")
				return
			}
		}
	}
	for _, hostname := range cRedirectHosts {
		if hostname == incomingHost {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				redirectToCache(c)
				c.Abort()
				log.Debugln("Director is serving a cache based on incoming 'Host' header value of '" + hostname + "'")
				return
			}
		}
	}
}

// Middleware sends GET /foo/bar to the RedirectToCache function, as if the
// original request had been made to /api/v1.0/director/object/foo/bar
func ShortcutMiddleware(defaultResponse string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If this is a request for getting public key, don't modify the path
		// If this is a request to the Prometheus API, don't modify the path
		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/") ||
			(strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/") && !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/")) {
			c.Next()
			return
		}
		// Regardless of the remainder of the settings, we currently handle a PUT as a query to the origin endpoint
		if c.Request.Method == "PUT" {
			c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
			redirectToOrigin(c)
			c.Abort()
			return
		}

		// We grab the host and x-forwarded-host headers, which can be set by a client with the intent of changing the
		// Director's default behavior (eg the director normally forwards to caches, but if it receives a request with
		// a pre-configured hostname in its x-forwarded-host header, that indicates we should actually serve an origin.)
		host, hostPresent := c.Request.Header["Host"]
		xForwardedHost, xForwardedHostPresent := c.Request.Header["X-Forwarded-Host"]

		if hostPresent {
			checkHostnameRedirects(c, host[0])
		} else if xForwardedHostPresent {
			checkHostnameRedirects(c, xForwardedHost[0])
		}

		// If we are doing a PROPFIND, we should always redirect to the origin
		if c.Request.Method == "PROPFIND" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == "PROPFIND" || c.Request.Method == "HEAD") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				return
			}
		}

		// Check for the DirectRead query paramater and redirect to the origin if it's set if the origin allows DirectReads
		if c.Request.URL.Query().Has(utils.QueryDirectRead.String()) {
			log.Debugln("directread query parameter detected, redirecting to origin")
			// We'll redirect to origin here and the origin will decide if it can serve the request (if direct reads are enabled)
			redirectToOrigin(c)
			c.Abort()
			return
		}

		// If we're configured for cache mode or we haven't set the flag,
		// we should use cache middleware
		if defaultResponse == "cache" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == "GET" || c.Request.Method == "HEAD") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				redirectToCache(c)
				c.Abort()
				return
			}

			// If the path starts with the correct prefix, continue with the next handler
			c.Next()
		} else if defaultResponse == "origin" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") && (c.Request.Method == "GET" || c.Request.Method == "HEAD") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				return
			}
			c.Next()
		}
	}
}

func registerServeAd(engineCtx context.Context, ctx *gin.Context, sType server_structs.ServerType) {
	ctx.Set("serverType", sType.String())
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bearer token not present in the 'Authorization' header",
		})
		return
	}

	reqVer, service, _ := extractVersionAndService(ctx)
	err := versionCompatCheck(reqVer, service)
	if err != nil {
		log.Warningf("A version incompatibility was encountered while registering %s and no response was served: %v", sType, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Incompatible versions detected: " + fmt.Sprintf("%v", err),
		})
		return
	}

	ad := server_structs.OriginAdvertiseV1{}
	adV2 := server_structs.OriginAdvertiseV2{}
	err = ctx.ShouldBindBodyWith(&ad, binding.JSON)
	if err != nil {
		// Failed binding to a V1 type, so should now check to see if it's a V2 type
		adV2 = server_structs.OriginAdvertiseV2{}
		err = ctx.ShouldBindBodyWith(&adV2, binding.JSON)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid %s registration", sType),
			})
			return
		}
	} else {
		// If the OriginAdvertisement is a V1 type, convert to a V2 type
		adV2 = server_structs.ConvertOriginAdV1ToV2(ad)
	}

	// Set to ctx for metrics handler downstream
	ctx.Set("serverName", adV2.Name)
	ctx.Set("serverWebUrl", adV2.WebURL)

	// Iterate over each advertised namespace and join the paths together
	// into a string where each path is separated by a space
	// i.e. "<path> <path> <path>"
	var namespacePaths string
	for _, namespace := range adV2.Namespaces {
		path := namespace.Path
		namespacePaths = fmt.Sprintf("%s %s", namespacePaths, path)
	}
	namespacePaths = strings.TrimSpace(namespacePaths)
	ctx.Set("namespacePaths", namespacePaths)

	adUrl, err := url.Parse(adV2.DataURL)
	if err != nil {
		log.Warningf("Failed to parse %s URL %v: %v\n", sType, adV2.DataURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. %s.URL %s is not a valid URL", sType, sType, adV2.DataURL), // Origin.URL / Cache.URL
		})
		return
	}

	adWebUrl, err := url.Parse(adV2.WebURL)
	if err != nil && adV2.WebURL != "" { // We allow empty WebURL string for backward compatibility
		log.Warningf("Failed to parse server Web URL %v: %v\n", adV2.WebURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. Server.ExternalWebUrl %s is not a valid URL", sType, adV2.WebURL),
		})
		return
	}

	brokerUrl, err := url.Parse(adV2.BrokerURL)
	if err != nil {
		log.Warningf("Failed to parse broker URL %s: %s", adV2.BrokerURL, err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid %s registration. BrokerURL %s is not a valid URL", sType, adV2.BrokerURL),
		})
	}

	// Verify server registration
	token := strings.TrimPrefix(tokens[0], "Bearer ")

	registryPrefix := adV2.RegistryPrefix
	verifyServer := true
	if registryPrefix == "" {
		if sType == server_structs.OriginType {
			// For origins < 7.9.0, they are not registered, and we skip the verification
			verifyServer = false
		} else {
			// For caches <= 7.8.1, they don't have RegistryPrefix
			// so we fall back to Name
			registryPrefix = server_structs.GetCacheNS(adV2.Name)
		}
	}

	approvalErrMsg := "You may find more information on " + param.Server_ExternalWebUrl.GetString()
	// Prepare the admin approval error message
	if param.Director_SupportContactEmail.GetString() != "" && param.Director_SupportContactUrl.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Contact %s or visit %s for help.", param.Director_SupportContactEmail.GetString(), param.Director_SupportContactUrl.GetString())
	} else if param.Director_SupportContactEmail.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Contact %s for help.", param.Director_SupportContactEmail.GetString())
	} else if param.Director_SupportContactUrl.GetString() != "" {
		approvalErrMsg = fmt.Sprintf("Visit %s for help.", param.Director_SupportContactUrl.GetString())
	}

	if verifyServer {
		ok, err := verifyAdvertiseToken(engineCtx, token, registryPrefix)
		if err != nil {
			if err == adminApprovalErr {
				log.Warningf("Failed to verify token. %s %q was not approved", sType.String(), adV2.Name)
				ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("%s %q was not approved by an administrator. %s", sType.String(), ad.Name, approvalErrMsg)})
				return
			} else {
				log.Warningln("Failed to verify token:", err)
				ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    fmt.Sprintf("Authorization token verification failed %v", err),
				})
				return
			}
		}
		if !ok {
			log.Warningf("%s %v advertised without valid token scope\n", sType, adV2.Name)
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authorization token verification failed. Token missing required scope",
			})
			return
		}
	}

	// For origin, also verify namespace registrations
	if sType == server_structs.OriginType {
		for _, namespace := range adV2.Namespaces {
			// We're assuming there's only one token in the slice
			token := strings.TrimPrefix(tokens[0], "Bearer ")
			ok, err := verifyAdvertiseToken(engineCtx, token, namespace.Path)
			if err != nil {
				if err == adminApprovalErr {
					log.Warningf("Failed to verify advertise token. Namespace %q requires administrator approval", namespace.Path)
					ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("The namespace %q was not approved by an administrator. %s", namespace.Path, approvalErrMsg)})
					return
				} else {
					log.Warningln("Failed to verify token:", err)
					ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
						Status: server_structs.RespFailed,
						Msg:    fmt.Sprintf("Authorization token verification failed: %v", err),
					})
					return
				}
			}
			if !ok {
				log.Warningf("%s %v advertised to namespace %v without valid token scope\n",
					sType, adV2.Name, namespace.Path)
				ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Authorization token verification failed. Token missing required scope",
				})
				return
			}
		}
	}

	st := adV2.StorageType
	// Defaults to POSIX
	if st == "" {
		st = server_structs.OriginStoragePosix
	}
	// Disable director test if the server isn't POSIX
	if st != server_structs.OriginStoragePosix && !adV2.DisableDirectorTest {
		log.Warningf("%s server %s with storage type %s enabled director test. This is not supported.", sType, adV2.Name, string(st))
		adV2.DisableDirectorTest = true
	}

	sAd := server_structs.ServerAd{
		Name:                adV2.Name,
		StorageType:         st,
		DisableDirectorTest: adV2.DisableDirectorTest,
		URL:                 *adUrl,
		WebURL:              *adWebUrl,
		BrokerURL:           *brokerUrl,
		Type:                sType.String(),
		Caps:                adV2.Caps,
		IOLoad:              0.0, // Explicitly set to 0. The sort algorithm takes 0.0 as unknown load
	}

	recordAd(engineCtx, sAd, &adV2.Namespaces)

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK, Msg: "Successful registration"})
}

func serverAdMetricMiddleware(ctx *gin.Context) {
	ctx.Next()

	serverName := "Unknown"
	serverWebUrl := ctx.ClientIP()
	statusCode := ctx.Writer.Status()

	if ctx.GetString("serverName") != "" {
		serverName = ctx.GetString("serverName")
	}
	if ctx.GetString("serverWebUrl") != "" {
		serverWebUrl = ctx.GetString("serverWebUrl")
	}

	// Separate each path by the space separator
	namespacePaths := strings.Split(ctx.GetString("namespacePaths"), " ")
	// Update metrics for each path
	for _, namespacePath := range namespacePaths {
		if len(namespacePath) == 0 {
			continue
		}
		metrics.PelicanDirectorAdvertisementsRecievedTotal.With(
			prometheus.Labels{
				"server_name":      serverName,
				"server_web_url":   serverWebUrl,
				"server_type":      ctx.GetString("serverType"),
				"status_code":      strconv.Itoa(statusCode),
				"namespace_prefix": namespacePath,
			}).Inc()
	}
}

// Return a list of registered origins and caches in Prometheus HTTP SD format
// for director's Prometheus service discovery
func discoverOriginCache(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorServiceDiscovery},
	}

	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		log.Warningf("Cannot verify token for accessing director's service discovery: %v", err)
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	promDiscoveryRes := make([]PromDiscoveryItem, 0)
	for _, ad := range serverAds.Items() {
		serverAd := ad.Value()
		if serverAd.WebURL.String() == "" {
			// Origins and caches fetched from topology can't be scraped as they
			// don't have a WebURL
			continue
		}
		var auth_url string
		if serverAd.AuthURL == (url.URL{}) {
			auth_url = serverAd.URL.String()
		} else {
			auth_url = serverAd.AuthURL.String()
		}
		promDiscoveryRes = append(promDiscoveryRes, PromDiscoveryItem{
			Targets: []string{serverAd.WebURL.Hostname() + ":" + serverAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(serverAd.Type),
				"server_name":     serverAd.Name,
				"server_auth_url": auth_url,
				"server_url":      serverAd.URL.String(),
				"server_web_url":  serverAd.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", serverAd.Latitude),
				"server_long":     fmt.Sprintf("%.4f", serverAd.Longitude),
			},
		})
	}
	ctx.JSON(200, promDiscoveryRes)
}

func listNamespacesV1(ctx *gin.Context) {
	namespaceAdsV2 := listNamespacesFromOrigins()

	namespaceAdsV1 := server_structs.ConvertNamespaceAdsV2ToV1(namespaceAdsV2)

	ctx.JSON(http.StatusOK, namespaceAdsV1)
}

func listNamespacesV2(ctx *gin.Context) {
	namespacesAdsV2 := listNamespacesFromOrigins()
	namespacesAdsV2 = append(namespacesAdsV2, server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{
			PublicReads: true,
			Reads:       true,
		},
		Path: "/pelican/monitoring",
	})
	ctx.JSON(http.StatusOK, namespacesAdsV2)
}

func getPrefixByPath(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	if pathParam == "" || pathParam == "/" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Bad request. Path is empty or '/' ",
		})
		return
	}

	originNs, _, _ := getAdsForPath(pathParam)

	// If originNs.Path is an empty value, then the namespace is not found
	if originNs.Path == "" {
		ctx.AbortWithStatusJSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Namespace prefix not found for " + pathParam,
		})
		return
	}

	res := server_structs.GetPrefixByPathRes{Prefix: originNs.Path}
	ctx.JSON(http.StatusOK, res)
}

// Generate a mock file for caches to fetch. This is for director-based health tests for caches
// So that we don't require an origin to feed the test file to the cache
func getHealthTestFile(ctx *gin.Context) {
	// Expected path: /pelican/monitoring/directorTest/2006-01-02T15:04:05Z07:00.txt
	pathParam := ctx.Param("path")
	cleanedPath := path.Clean(pathParam)
	if cleanedPath == "" || !strings.HasPrefix(cleanedPath, server_utils.MonitoringBaseNs+"/") {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path parameter is not a valid health test path: " + cleanedPath})
		return
	}
	fileName := strings.TrimPrefix(cleanedPath, server_utils.MonitoringBaseNs+"/")
	if fileName == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Path parameter is not a valid health test path: " + cleanedPath})
		return
	}

	fileNameSplit := strings.SplitN(fileName, ".", 2)

	if len(fileNameSplit) != 2 {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Test file name is missing file extension: " + cleanedPath})
		return
	}

	fileContent := server_utils.DirectorTestBody + "\n"

	if ctx.Request.Method == "HEAD" {
		ctx.Header("Content-Length", strconv.Itoa(len(fileContent)))
	} else {
		ctx.String(http.StatusOK, fileContent)
	}
}

// collectClientVersionMetric will get the user agent of an incoming request
// parse out the version from it and update the pelican_director_client_version_total metric
//
// In the case that parser fails, then metric is not updated
func collectClientVersionMetric(reqVer *version.Version, service string) {
	if reqVer == nil || service == "" {
		metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": "other", "service": "other"}).Inc()
		return
	}

	directorVersion, err := version.NewVersion(config.GetVersion())
	if err != nil {
		return
	}

	if reqVer.GreaterThan(directorVersion) {
		metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": "pelican-future", "service": service}).Inc()
	}

	versionSegments := reqVer.Segments()
	if len(versionSegments) < 2 {
		return
	}

	strSegments := []string{
		fmt.Sprintf("%d", versionSegments[0]),
		fmt.Sprintf("%d", versionSegments[1]),
	}

	shortendVersion := strings.Join(strSegments, ".")

	metrics.PelicanDirectorClientVersionTotal.With(prometheus.Labels{"version": shortendVersion, "service": service}).Inc()
}

func RegisterDirectorAPI(ctx context.Context, router *gin.RouterGroup) {
	directorAPIV1 := router.Group("/api/v1.0/director")
	{
		// Establish the routes used for cache/origin redirection
		directorAPIV1.GET("/object/*any", redirectToCache)
		directorAPIV1.HEAD("/object/*any", redirectToCache)
		directorAPIV1.GET("/origin/*any", redirectToOrigin)
		directorAPIV1.HEAD("/origin/*any", redirectToOrigin)
		directorAPIV1.PUT("/origin/*any", redirectToOrigin)
		directorAPIV1.POST("/registerOrigin", serverAdMetricMiddleware, func(gctx *gin.Context) { registerServeAd(ctx, gctx, server_structs.OriginType) })
		directorAPIV1.POST("/registerCache", serverAdMetricMiddleware, func(gctx *gin.Context) { registerServeAd(ctx, gctx, server_structs.CacheType) })
		directorAPIV1.GET("/listNamespaces", listNamespacesV1)
		directorAPIV1.GET("/namespaces/prefix/*path", getPrefixByPath)
		directorAPIV1.GET("/healthTest/*path", getHealthTestFile)
		directorAPIV1.HEAD("/healthTest/*path", getHealthTestFile)
		directorAPIV1.Any("/origin", func(gctx *gin.Context) { // Need to do this for PROPFIND since gin does not support it
			if gctx.Request.Method == "PROPFIND" {
				redirectToOrigin(gctx)
			}
		})

		// In the foreseeable feature, director will scrape all servers in Pelican ecosystem (including registry)
		// so that director can be our point of contact for collecting system-level metrics.
		// Rename the endpoint to reflect such plan.
		directorAPIV1.GET("/discoverServers", discoverOriginCache)
	}

	directorAPIV2 := router.Group("/api/v2.0/director")
	{
		directorAPIV2.GET("/listNamespaces", listNamespacesV2)
	}
}
