/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/pelicanplatform/pelican/param"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type PromDiscoveryItem struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

var (
	minClientVersion, _        = version.NewVersion("7.0.0")
	minOriginVersion, _        = version.NewVersion("7.0.0")
	minCacheVersion, _         = version.NewVersion("7.3.0")
	healthTestCancelFuncs      = make(map[ServerAd]context.CancelFunc)
	healthTestCancelFuncsMutex = sync.RWMutex{}
)

// The endpoint for director Prometheus instance to discover Pelican servers
// for scraping (origins/caches).
//
// TODO: Add registry server as well to this endpoint when we need to scrape from it
const DirectorServerDiscoveryEndpoint = "/api/v1.0/director/discoverServers"

func getRedirectURL(reqPath string, ad ServerAd, requiresAuth bool) (redirectURL url.URL) {
	var serverURL url.URL
	if requiresAuth {
		serverURL = ad.AuthURL
	} else {
		serverURL = ad.URL
	}
	reqPath = path.Clean("/" + reqPath)
	if requiresAuth {
		redirectURL.Scheme = "https"
	} else {
		redirectURL.Scheme = "http"
	}
	redirectURL.Host = serverURL.Host
	redirectURL.Path = reqPath
	return
}

func getRealIP(ginCtx *gin.Context) (ipAddr netip.Addr, err error) {
	ip_addr_list := ginCtx.Request.Header["X-Real-Ip"]
	if len(ip_addr_list) == 0 {
		ipAddr, err = netip.ParseAddr(ginCtx.RemoteIP())
		if err != nil {
			ginCtx.String(500, "Failed to parse IP address: %s", err.Error())
		}
		return
	} else {
		ipAddr, err = netip.ParseAddr(ip_addr_list[0])
		if err != nil {
			ginCtx.String(500, "Failed to parse X-Real-Ip header: %s", err.Error())
		}
		return
	}

}

func getAuthzEscaped(req *http.Request) (authzEscaped string) {
	if authzQuery := req.URL.Query()["authz"]; len(authzQuery) > 0 {
		authzEscaped = authzQuery[0]
		// if the authz URL query is coming from XRootD, it probably has a "Bearer " tacked in front
		// even though it's coming via a URL
		authzEscaped = strings.TrimPrefix(authzEscaped, "Bearer ")
	} else if authzHeader := req.Header["Authorization"]; len(authzHeader) > 0 {
		authzEscaped = strings.TrimPrefix(authzHeader[0], "Bearer ")
		authzEscaped = url.QueryEscape(authzEscaped)
	}
	return
}

func getFinalRedirectURL(rurl url.URL, authzEscaped string) string {
	if len(authzEscaped) > 0 {
		if len(rurl.RawQuery) > 0 {
			rurl.RawQuery += "&"
		}
		rurl.RawQuery += "authz=" + authzEscaped
	}
	return rurl.String()
}

func versionCompatCheck(ginCtx *gin.Context) error {
	// Check that the version of whichever service (eg client, origin, etc) is talking to the Director
	// is actually something the Director thinks it can communicate with

	// The service/version is sent via User-Agent header in the form "pelican-<service>/<version>"
	userAgentSlc := ginCtx.Request.Header["User-Agent"]
	if len(userAgentSlc) < 1 {
		return errors.New("No user agent could be found")
	}

	// gin gives us a slice of user agents. Since pelican services should only ever
	// send one UA, assume that it is the 0-th element of the slice.
	userAgent := userAgentSlc[0]

	// Make sure we're working with something that's formatted the way we expect. If we
	// don't match, then we're definitely not coming from one of the services, so we
	// let things go without an error. Maybe someone is using curl?
	uaRegExp := regexp.MustCompile(`^pelican-[^\/]+\/\d+\.\d+\.\d+`)
	if matches := uaRegExp.MatchString(userAgent); !matches {
		return nil
	}

	userAgentSplit := strings.Split(userAgent, "/")
	// Grab the actual service/version that's using the Director. There may be different versioning
	// requirements between origins, clients, and other services.
	service := (strings.Split(userAgentSplit[0], "-"))[1]
	reqVerStr := userAgentSplit[1]
	reqVer, err := version.NewVersion(reqVerStr)
	if err != nil {
		return errors.Wrapf(err, "Could not parse service version as a semantic version: %s\n", reqVerStr)
	}

	var minCompatVer *version.Version
	switch service {
	case "client":
		minCompatVer = minClientVersion
	case "origin":
		minCompatVer = minOriginVersion
	case "cache":
		minCompatVer = minCacheVersion
	default:
		return errors.Errorf("Invalid version format. The director does not support your %s version (%s).", service, reqVer.String())
	}

	if reqVer.LessThan(minCompatVer) {
		return errors.Errorf("The director does not support your %s version (%s). Please update to %s or newer.", service, reqVer.String(), minCompatVer.String())
	}

	return nil
}

func RedirectToCache(ginCtx *gin.Context) {
	err := versionCompatCheck(ginCtx)
	if err != nil {
		log.Debugf("A version incompatibility was encountered while redirecting to a cache and no response was served: %v", err)
		ginCtx.JSON(500, gin.H{"error": "Incompatible versions detected: " + fmt.Sprintf("%v", err)})
		return
	}

	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/object")
	ipAddr, err := getRealIP(ginCtx)
	if err != nil {
		ginCtx.String(500, "Internal error: Unable to determine client IP")
		return
	}

	authzBearerEscaped := getAuthzEscaped(ginCtx.Request)

	namespaceAd, originAds, cacheAds := GetAdsForPath(reqPath)
	// if GetAdsForPath doesn't find any ads because the prefix doesn't exist, we should
	// report the lack of path first -- this is most important for the user because it tells them
	// they're trying to get an object that simply doesn't exist
	if namespaceAd.Path == "" {
		ginCtx.String(404, "No namespace found for path. Either it doesn't exist, or the Director is experiencing problems\n")
		return
	}
	// If the namespace prefix DOES exist, then it makes sense to say we couldn't find a valid cache.
	if len(cacheAds) == 0 {
		for _, originAd := range originAds {
			if originAd.EnableFallbackRead {
				cacheAds = append(cacheAds, originAd)
				break
			}
		}
		if len(cacheAds) == 0 {
			ginCtx.String(http.StatusNotFound, "No cache found for path")
			return
		}
	} else {
		cacheAds, err = SortServers(ipAddr, cacheAds)
		if err != nil {
			ginCtx.String(http.StatusInternalServerError, "Failed to determine server ordering")
			return
		}
	}
	redirectURL := getRedirectURL(reqPath, cacheAds[0], !namespaceAd.Caps.PublicRead)

	linkHeader := ""
	first := true
	for idx, ad := range cacheAds {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad, !namespaceAd.Caps.PublicRead)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; pri=%d`, redirectURL.String(), idx+1)
	}
	ginCtx.Writer.Header()["Link"] = []string{linkHeader}
	if len(namespaceAd.Issuer) != 0 {

		issStrings := []string{}
		for _, tokIss := range namespaceAd.Issuer {
			issStrings = append(issStrings, "issuer="+tokIss.IssuerUrl.String())
		}
		ginCtx.Writer.Header()["X-Pelican-Authorization"] = issStrings
	}

	if len(namespaceAd.Generation) != 0 {
		tokenGen := ""
		first := true
		hdrVals := []string{namespaceAd.Generation[0].CredentialIssuer.String(), fmt.Sprint(namespaceAd.Generation[0].MaxScopeDepth), string(namespaceAd.Generation[0].Strategy),
			string(namespaceAd.Generation[0].Strategy)}
		for idx, hdrKey := range []string{"issuer", "max-scope-depth", "strategy", "vault-server"} {
			hdrVal := hdrVals[idx]
			if hdrVal == "" {
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

	var colUrl string
	if namespaceAd.PublicRead {
		colUrl = originAds[0].URL.String()
	} else {
		colUrl = originAds[0].AuthURL.String()
	}
	ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{fmt.Sprintf("namespace=%s, require-token=%v, collections-url=%s",
		namespaceAd.Path, !namespaceAd.PublicRead, colUrl)}

	// Note we only append the `authz` query parameter in the case of the redirect response and not the
	// duplicate link metadata above.  This is purposeful: the Link header might get too long if we repeat
	// the token 20 times for 20 caches.  This means a "normal HTTP client" will correctly redirect but
	// anything parsing the `Link` header for metalinks will need logic for redirecting appropriately.
	ginCtx.Redirect(307, getFinalRedirectURL(redirectURL, authzBearerEscaped))
}

func RedirectToOrigin(ginCtx *gin.Context) {
	err := versionCompatCheck(ginCtx)
	if err != nil {
		log.Debugf("A version incompatibility was encountered while redirecting to an origin and no response was served: %v", err)
		ginCtx.JSON(500, gin.H{"error": "Incompatible versions detected: " + fmt.Sprintf("%v", err)})
		return
	}

	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/origin")

	// Each namespace may be exported by several origins, so we must still
	// do the geolocation song and dance if we want to get the closest origin...
	ipAddr, err := getRealIP(ginCtx)
	if err != nil {
		return
	}

	authzBearerEscaped := getAuthzEscaped(ginCtx.Request)

	namespaceAd, originAds, _ := GetAdsForPath(reqPath)
	// if GetAdsForPath doesn't find any ads because the prefix doesn't exist, we should
	// report the lack of path first -- this is most important for the user because it tells them
	// they're trying to get an object that simply doesn't exist
	if namespaceAd.Path == "" {
		ginCtx.String(http.StatusNotFound, "No namespace found for path. Either it doesn't exist, or the Director is experiencing problems\n")
		return
	}
	// If the namespace prefix DOES exist, then it makes sense to say we couldn't find the origin.
	if len(originAds) == 0 {
		ginCtx.String(http.StatusNotFound, "There are currently no origins exporting the provided namespace prefix\n")
		return
	}

	originAds, err = SortServers(ipAddr, originAds)
	if err != nil {
		ginCtx.String(http.StatusInternalServerError, "Failed to determine origin ordering")
		return
	}

	var colUrl string

	if namespaceAd.PublicRead {
		colUrl = originAds[0].URL.String()
	} else {
		colUrl = originAds[0].AuthURL.String()
	}
	ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{fmt.Sprintf("namespace=%s, require-token=%v, collections-url=%s",
		namespaceAd.Path, !namespaceAd.PublicRead, colUrl)}

	var redirectURL url.URL
	// If we are doing a PUT, check to see if any origins are writeable
	if ginCtx.Request.Method == "PUT" {
		for idx, ad := range originAds {
			if ad.EnableWrite {
				redirectURL = getRedirectURL(reqPath, originAds[idx], !namespaceAd.PublicRead)
				ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, authzBearerEscaped))
				return
			}
		}
		ginCtx.String(http.StatusMethodNotAllowed, "No origins on specified endpoint are writeable\n")
		return
	} else { // Otherwise, we are doing a GET
		redirectURL := getRedirectURL(reqPath, originAds[0], !namespaceAd.PublicRead)
		// See note in RedirectToCache as to why we only add the authz query parameter to this URL,
		// not those in the `Link`.
		ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, authzBearerEscaped))
	}
}

func checkHostnameRedirects(c *gin.Context, incomingHost string) {
	oRedirectHosts := param.Director_OriginResponseHostnames.GetStringSlice()
	cRedirectHosts := param.Director_CacheResponseHostnames.GetStringSlice()

	for _, hostname := range oRedirectHosts {
		if hostname == incomingHost {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				RedirectToOrigin(c)
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
				RedirectToCache(c)
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
			RedirectToOrigin(c)
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

		// If we're configured for cache mode or we haven't set the flag,
		// we should use cache middleware
		if defaultResponse == "cache" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				RedirectToCache(c)
				c.Abort()
				return
			}

			// If the path starts with the correct prefix, continue with the next handler
			c.Next()
		} else if defaultResponse == "origin" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				RedirectToOrigin(c)
				c.Abort()
				return
			}
			c.Next()
		}
	}
}

func ConvertNamespaceAdsV1ToV2(nsAdsV1 []NamespaceAdV1) []NamespaceAdV2 {
	//Convert a list of V1 namespace ads to a list of V2 namespace ads, note that this
	//isn't the most efficient way of doing so (an interative search as opposed to some sort
	//of index or hash based search)
	nsAdsV2 := []NamespaceAdV2{}
	for _, nsAd := range nsAdsV1 {
		nsFound := false
		for i := range nsAdsV2 {
			//Namespace exists, so check if issuer already exists
			if nsAdsV2[i].Path == nsAd.Path {
				nsFound = true
				issFound := false
				tokIssuers := nsAdsV2[i].Issuer
				for j := range tokIssuers {
					//Issuer exists, so add the basepaths to the list
					if tokIssuers[j].IssuerUrl == nsAd.Issuer {
						issFound = true
						bps := tokIssuers[j].BasePaths
						bps = append(bps, nsAd.BasePath)
						tokIss := &nsAdsV2[i].Issuer[j]
						(*tokIss).BasePaths = bps
						break
					}
				}
				//Issuer doesn't exist for the URL, so create a new one
				if !issFound {
					tGen := TokenGen{
						Strategy:         nsAd.Strategy,
						VaultServer:      nsAd.VaultServer,
						MaxScopeDepth:    nsAd.MaxScopeDepth,
						CredentialIssuer: nsAd.Issuer,
					}
					tIss := TokenIssuer{
						BasePaths:       []string{nsAd.BasePath},
						RestrictedPaths: []string{},
						IssuerUrl:       nsAd.Issuer,
					}
					v2NS := &nsAdsV2[i]
					(*v2NS).Issuer = []TokenIssuer{tIss}
					(*v2NS).Generation = []TokenGen{tGen}
				}
			}
			break
		}
		//Namespace doesn't exist for the Path, so create a new one
		if !nsFound {
			tGen := TokenGen{
				Strategy:         nsAd.Strategy,
				VaultServer:      nsAd.VaultServer,
				MaxScopeDepth:    nsAd.MaxScopeDepth,
				CredentialIssuer: nsAd.Issuer,
			}
			tIss := TokenIssuer{
				BasePaths:       []string{nsAd.BasePath},
				RestrictedPaths: []string{},
				IssuerUrl:       nsAd.Issuer,
			}
			caps := Capabilities{
				PublicRead: !nsAd.RequireToken,
				Read:       true,
				Write:      true,
				Listing:    true,
			}

			newNS := NamespaceAdV2{
				PublicRead: !nsAd.RequireToken,
				Caps:       caps,
				Path:       nsAd.Path,
				Generation: []TokenGen{tGen},
				Issuer:     []TokenIssuer{tIss},
			}
			nsAdsV2 = append(nsAdsV2, newNS)
		}
	}
	return nsAdsV2
}

func convertOriginAd(oAd1 OriginAdvertiseV1) OriginAdvertiseV2 {
	nsAdsV2 := ConvertNamespaceAdsV1ToV2(oAd1.Namespaces)
	tokIssuers := []TokenIssuer{}

	for _, v2Ad := range nsAdsV2 {
		tokIssuers = append(tokIssuers, v2Ad.Issuer...)
	}
	caps := Capabilities{
		PublicRead: true,
		Read:       true,
		Write:      oAd1.EnableWrite,
		Listing:    true,
	}

	oAd2 := OriginAdvertiseV2{
		Name:       oAd1.Name,
		DataURL:    oAd1.URL,
		WebURL:     oAd1.WebURL,
		Caps:       caps,
		Namespaces: nsAdsV2,
		Issuer:     tokIssuers,
	}
	return oAd2
}

func registerServeAd(engineCtx context.Context, ctx *gin.Context, sType ServerType) {
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "Bearer token not present in the 'Authorization' header"})
		return
	}

	err := versionCompatCheck(ctx)
	if err != nil {
		log.Debugf("A version incompatibility was encountered while registering %s and no response was served: %v", sType, err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Incompatible versions detected: " + fmt.Sprintf("%v", err)})
		return
	}

	ad := OriginAdvertiseV1{}
	adV2 := OriginAdvertiseV2{}
	err = ctx.ShouldBindBodyWith(&ad, binding.JSON)
	if err != nil {
		// Failed binding to a V1 type, so should now check to see if it's a V2 type
		adV2 = OriginAdvertiseV2{}
		err = ctx.ShouldBindBodyWith(&adV2, binding.JSON)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + sType + " registration"})
			return
		}
	} else {
		// If the OriginAdvertisement is a V1 type, convert to a V2 type
		adV2 = convertOriginAd(ad)
	}

	if sType == OriginType {
		for _, namespace := range adV2.Namespaces {
			// We're assuming there's only one token in the slice
			token := strings.TrimPrefix(tokens[0], "Bearer ")
			ok, err := VerifyAdvertiseToken(engineCtx, token, namespace.Path)
			if err != nil {
				if err == adminApprovalErr {
					log.Warningf("Failed to verify advertise token. Namespace %q requires administrator approval", namespace.Path)
					ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("The namespace %q was not approved by an administrator", namespace.Path)})
					return
				} else {
					log.Warningln("Failed to verify token:", err)
					ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed"})
					return
				}
			}
			if !ok {
				log.Warningf("%s %v advertised to namespace %v without valid token scope\n",
					sType, adV2.Name, namespace.Path)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed. Token missing required scope"})
				return
			}
		}
	} else {
		token := strings.TrimPrefix(tokens[0], "Bearer ")
		prefix := path.Join("caches", adV2.Name)
		ok, err := VerifyAdvertiseToken(engineCtx, token, prefix)
		if err != nil {
			if err == adminApprovalErr {
				log.Warningf("Failed to verify token. Cache %q was not approved", ad.Name)
				ctx.JSON(http.StatusForbidden, gin.H{"approval_error": true, "error": fmt.Sprintf("Cache %q was not approved by an administrator", ad.Name)})
				return
			} else {
				log.Warningln("Failed to verify token:", err)
				ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed."})
				return
			}
		}
		if !ok {
			log.Warningf("%s %v advertised without valid token scope\n", sType, adV2.Name)
			ctx.JSON(http.StatusForbidden, gin.H{"error": "Authorization token verification failed. Token missing required scope"})
			return
		}
	}

	ad_url, err := url.Parse(adV2.DataURL)
	if err != nil {
		log.Warningf("Failed to parse %s URL %v: %v\n", sType, adV2.DataURL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + sType + " URL"})
		return
	}

	adWebUrl, err := url.Parse(ad.WebURL)
	if err != nil && adV2.WebURL != "" { // We allow empty WebURL string for backward compatibility
		log.Warningf("Failed to parse server Web URL %v: %v\n", adV2.WebURL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server Web URL"})
		return
	}

	sAd := ServerAd{
		Name:    adV2.Name,
		AuthURL: *ad_url,
		URL:     *ad_url,
		WebURL:  *adWebUrl,
		Type:    sType,
	}

	hasOriginAdInCache := serverAds.Has(sAd)
	RecordAd(sAd, &adV2.Namespaces)

	// Start director periodic test of origin's health status if origin AD
	// has WebURL field AND it's not already been registered
	healthTestCancelFuncsMutex.Lock()
	defer healthTestCancelFuncsMutex.Unlock()
	if adV2.WebURL != "" && !hasOriginAdInCache {
		if _, ok := healthTestCancelFuncs[sAd]; ok {
			// If somehow we didn't clear the key, we call cancel first before
			// adding a new test cycle
			healthTestCancelFuncs[sAd]()
		}
		ctx, cancel := context.WithCancel(context.Background())
		healthTestCancelFuncs[sAd] = cancel
		LaunchPeriodicDirectorTest(ctx, sAd)
	}

	ctx.JSON(http.StatusOK, gin.H{"msg": "Successful registration"})
}

// Return a list of registered origins and caches in Prometheus HTTP SD format
// for director's Prometheus service discovery
func DiscoverOriginCache(ctx *gin.Context) {
	// Check token for authorization
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(401, gin.H{"error": "Bearer token not present in the 'Authorization' header"})
		return
	}
	token := strings.TrimPrefix(tokens[0], "Bearer ")
	ok, err := VerifyDirectorSDToken(token)
	if err != nil {
		log.Warningln("Failed to verify director service discovery token:", err)
		ctx.JSON(401, gin.H{"error": fmt.Sprintf("Authorization token verification failed: %v\n", err)})
		return
	}
	if !ok {
		log.Warningf("Invalid token for accessing director's sevice discovery")
		ctx.JSON(401, gin.H{"error": "Invalid token for accessing director's sevice discovery"})
		return
	}

	serverAdMutex.RLock()
	defer serverAdMutex.RUnlock()
	serverAds := serverAds.Keys()
	promDiscoveryRes := make([]PromDiscoveryItem, 0)
	for _, ad := range serverAds {
		if ad.WebURL.String() == "" {
			// Origins and caches fetched from topology can't be scraped as they
			// don't have a WebURL
			continue
		}
		promDiscoveryRes = append(promDiscoveryRes, PromDiscoveryItem{
			Targets: []string{ad.WebURL.Hostname() + ":" + ad.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(ad.Type),
				"server_name":     ad.Name,
				"server_auth_url": ad.AuthURL.String(),
				"server_url":      ad.URL.String(),
				"server_web_url":  ad.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", ad.Latitude),
				"server_long":     fmt.Sprintf("%.4f", ad.Longitude),
			},
		})
	}
	ctx.JSON(200, promDiscoveryRes)
}

func RegisterOrigin(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, OriginType)
}

func RegisterCache(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, CacheType)
}

func convertNamespaceAdsV2ToV1(nsV2 []NamespaceAdV2) []NamespaceAdV1 {
	// Converts a list of V2 namespace ads to a list of V1 namespace ads.
	// This is for backwards compatibility in the case an old version of a client calls
	// out to a newer verion of the director
	nsV1 := []NamespaceAdV1{}

	for _, nsAd := range nsV2 {
		if len(nsAd.Issuer) != 0 {
			for _, iss := range nsAd.Issuer {
				for _, bp := range iss.BasePaths {
					v1Ad := NamespaceAdV1{
						Path:          nsAd.Path,
						RequireToken:  !nsAd.Caps.PublicRead,
						Issuer:        iss.IssuerUrl,
						BasePath:      bp,
						Strategy:      nsAd.Generation[0].Strategy,
						VaultServer:   nsAd.Generation[0].VaultServer,
						MaxScopeDepth: nsAd.Generation[0].MaxScopeDepth,
					}
					nsV1 = append(nsV1, v1Ad)
				}
			}
		} else {
			v1Ad := NamespaceAdV1{
				Path:         nsAd.Path,
				RequireToken: false,
			}
			nsV1 = append(nsV1, v1Ad)
		}
	}

	return nsV1
}

func ListNamespacesV1(ctx *gin.Context) {
	namespaceAdsV2 := ListNamespacesFromOrigins()

	namespaceAdsV1 := convertNamespaceAdsV2ToV1(namespaceAdsV2)

	ctx.JSON(http.StatusOK, namespaceAdsV1)
}

func ListNamespacesV2(ctx *gin.Context) {
	namespacesAdsV2 := ListNamespacesFromOrigins()
	ctx.JSON(http.StatusOK, namespacesAdsV2)
}

func RegisterDirector(ctx context.Context, router *gin.RouterGroup) {
	// Establish the routes used for cache/origin redirection
	router.GET("/api/v1.0/director/object/*any", RedirectToCache)
	router.GET("/api/v1.0/director/origin/*any", RedirectToOrigin)
	router.PUT("/api/v1.0/director/origin/*any", RedirectToOrigin)
	router.POST("/api/v1.0/director/registerOrigin", func(gctx *gin.Context) { RegisterOrigin(ctx, gctx) })
	// In the foreseeable feature, director will scrape all servers in Pelican ecosystem (including registry)
	// so that director can be our point of contact for collecting system-level metrics.
	// Rename the endpoint to reflect such plan.
	router.GET(DirectorServerDiscoveryEndpoint, DiscoverOriginCache)
	router.POST("/api/v1.0/director/registerCache", func(gctx *gin.Context) { RegisterCache(ctx, gctx) })
	router.GET("/api/v1.0/director/listNamespaces", ListNamespacesV1)
	router.GET("/api/v2.0/director/listNamespaces", ListNamespacesV2)
}
