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
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	"golang.org/x/sync/errgroup"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	HealthTestStatus  string
	PromDiscoveryItem struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}

	healthTestUtil struct {
		ErrGrp        *errgroup.Group
		ErrGrpContext context.Context
		Cancel        context.CancelFunc
		Status        HealthTestStatus
	}
	originStatUtil struct {
		Context  context.Context
		Cancel   context.CancelFunc
		Errgroup *errgroup.Group
	}
)

const (
	HealthStatusUnknown HealthTestStatus = "Unknown"
	HealthStatusInit    HealthTestStatus = "Initializing"
	HealthStatusOK      HealthTestStatus = "OK"
	HealthStatusError   HealthTestStatus = "Error"
)

var (
	minClientVersion, _  = version.NewVersion("7.0.0")
	minOriginVersion, _  = version.NewVersion("7.0.0")
	minCacheVersion, _   = version.NewVersion("7.3.0")
	healthTestUtils      = make(map[common.ServerAd]*healthTestUtil)
	healthTestUtilsMutex = sync.RWMutex{}

	originStatUtils      = make(map[url.URL]originStatUtil)
	originStatUtilsMutex = sync.RWMutex{}
)

func getRedirectURL(reqPath string, ad common.ServerAd, requiresAuth bool) (redirectURL url.URL) {
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

func redirectToCache(ginCtx *gin.Context) {
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

	namespaceAd, originAds, cacheAds := getAdsForPath(reqPath)
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
		cacheAds, err = sortServers(ipAddr, cacheAds)
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

func redirectToOrigin(ginCtx *gin.Context) {
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

	namespaceAd, originAds, _ := getAdsForPath(reqPath)
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

	originAds, err = sortServers(ipAddr, originAds)
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
				if brokerUrl := originAds[idx].BrokerURL; brokerUrl.String() != "" {
					ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
				}
				ginCtx.Redirect(http.StatusTemporaryRedirect, getFinalRedirectURL(redirectURL, authzBearerEscaped))
				return
			}
		}
		ginCtx.String(http.StatusMethodNotAllowed, "No origins on specified endpoint are writeable\n")
		return
	} else { // Otherwise, we are doing a GET
		redirectURL := getRedirectURL(reqPath, originAds[0], !namespaceAd.PublicRead)
		if brokerUrl := originAds[0].BrokerURL; brokerUrl.String() != "" {
			ginCtx.Header("X-Pelican-Broker", brokerUrl.String())
		}

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

		// If we're configured for cache mode or we haven't set the flag,
		// we should use cache middleware
		if defaultResponse == "cache" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				redirectToCache(c)
				c.Abort()
				return
			}

			// If the path starts with the correct prefix, continue with the next handler
			c.Next()
		} else if defaultResponse == "origin" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director/") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				redirectToOrigin(c)
				c.Abort()
				return
			}
			c.Next()
		}
	}
}

func registerServeAd(engineCtx context.Context, ctx *gin.Context, sType common.ServerType) {
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

	ad := common.OriginAdvertiseV1{}
	adV2 := common.OriginAdvertiseV2{}
	err = ctx.ShouldBindBodyWith(&ad, binding.JSON)
	if err != nil {
		// Failed binding to a V1 type, so should now check to see if it's a V2 type
		adV2 = common.OriginAdvertiseV2{}
		err = ctx.ShouldBindBodyWith(&adV2, binding.JSON)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid " + sType + " registration"})
			return
		}
	} else {
		// If the OriginAdvertisement is a V1 type, convert to a V2 type
		adV2 = convertOriginAd(ad)
	}

	if sType == common.OriginType {
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
		prefix := path.Join("/caches", adV2.Name)
		ok, err := VerifyAdvertiseToken(engineCtx, token, prefix)
		if err != nil {
			if err == adminApprovalErr {
				log.Warningf("Failed to verify token. Cache %q was not approved", adV2.Name)
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

	adWebUrl, err := url.Parse(adV2.WebURL)
	if err != nil && adV2.WebURL != "" { // We allow empty WebURL string for backward compatibility
		log.Warningf("Failed to parse server Web URL %v: %v\n", adV2.WebURL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid server Web URL"})
		return
	}

	brokerUrl, err := url.Parse(adV2.BrokerURL)
	if err != nil {
		log.Warningf("Failed to parse broker URL %s: %s", adV2.BrokerURL, err)
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid broker URL"})
	}

	sAd := common.ServerAd{
		Name:               adV2.Name,
		AuthURL:            *ad_url,
		URL:                *ad_url,
		WebURL:             *adWebUrl,
		BrokerURL:          *brokerUrl,
		Type:               sType,
		EnableWrite:        adV2.Caps.Write,
		EnableFallbackRead: adV2.Caps.FallBackRead,
	}

	recordAd(sAd, &adV2.Namespaces)

	// Start director periodic test of origin's health status if origin AD
	// has WebURL field AND it's not already been registered
	healthTestUtilsMutex.Lock()
	defer healthTestUtilsMutex.Unlock()
	if sAd.Type == common.OriginType && adV2.WebURL != "" {
		if existingUtil, ok := healthTestUtils[sAd]; ok {
			// Existing registration
			if existingUtil != nil {
				if existingUtil.ErrGrp != nil {
					if existingUtil.ErrGrpContext.Err() != nil {
						// ErrGroup has been Done. Start a new one
						errgrp, errgrpCtx := errgroup.WithContext(engineCtx)
						cancelCtx, cancel := context.WithCancel(errgrpCtx)

						errgrp.SetLimit(1)
						healthTestUtils[sAd] = &healthTestUtil{
							Cancel:        cancel,
							ErrGrp:        errgrp,
							ErrGrpContext: errgrpCtx,
							Status:        HealthStatusInit,
						}
						errgrp.Go(func() error {
							LaunchPeriodicDirectorTest(cancelCtx, sAd)
							return nil
						})
						log.Debugf("New director test suite issued for %s %s. Errgroup was evicted", string(sType), sAd.URL.String())
					} else {
						cancelCtx, cancel := context.WithCancel(existingUtil.ErrGrpContext)
						started := existingUtil.ErrGrp.TryGo(func() error {
							LaunchPeriodicDirectorTest(cancelCtx, sAd)
							return nil
						})
						if !started {
							cancel()
							log.Debugf("New director test suite blocked for %s %s, existing test has been running", string(sType), sAd.URL.String())
						} else {
							log.Debugf("New director test suite issued for %s %s. Existing registration", string(sType), sAd.URL.String())
							existingUtil.Cancel()
							existingUtil.Cancel = cancel
						}
					}
				} else {
					log.Errorf("%s %s registration didn't start a new director test cycle: errgroup is nil", string(sType), &sAd.URL)
				}
			} else {
				log.Errorf("%s %s registration didn't start a new director test cycle: healthTestUtils item is nil", string(sType), &sAd.URL)
			}
		} else { // No healthTestUtils found, new registration
			errgrp, errgrpCtx := errgroup.WithContext(engineCtx)
			cancelCtx, cancel := context.WithCancel(errgrpCtx)

			errgrp.SetLimit(1)
			healthTestUtils[sAd] = &healthTestUtil{
				Cancel:        cancel,
				ErrGrp:        errgrp,
				ErrGrpContext: errgrpCtx,
				Status:        HealthStatusUnknown,
			}
			errgrp.Go(func() error {
				LaunchPeriodicDirectorTest(cancelCtx, sAd)
				return nil
			})
		}
	}

	if sType == common.OriginType {
		originStatUtilsMutex.Lock()
		defer originStatUtilsMutex.Unlock()
		statUtil, ok := originStatUtils[sAd.URL]
		if !ok || statUtil.Errgroup == nil {
			baseCtx, cancel := context.WithCancel(engineCtx)
			concLimit := param.Director_StatConcurrencyLimit.GetInt()
			statErrGrp := errgroup.Group{}
			statErrGrp.SetLimit(concLimit)
			newUtil := originStatUtil{
				Errgroup: &statErrGrp,
				Cancel:   cancel,
				Context:  baseCtx,
			}
			originStatUtils[sAd.URL] = newUtil
		}
	}

	ctx.JSON(http.StatusOK, gin.H{"msg": "Successful registration"})
}

// Return a list of registered origins and caches in Prometheus HTTP SD format
// for director's Prometheus service discovery
func discoverOriginCache(ctx *gin.Context) {
	authOption := utils.AuthOption{
		Sources: []utils.TokenSource{utils.Header},
		Issuers: []utils.TokenIssuer{utils.Issuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_DirectorServiceDiscovery},
	}

	ok := utils.CheckAnyAuth(ctx, authOption)
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

func registerOrigin(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, common.OriginType)
}

func registerCache(ctx context.Context, gctx *gin.Context) {
	registerServeAd(ctx, gctx, common.CacheType)
}

func listNamespacesV1(ctx *gin.Context) {
	namespaceAdsV2 := listNamespacesFromOrigins()

	namespaceAdsV1 := convertNamespaceAdsV2ToV1(namespaceAdsV2)

	ctx.JSON(http.StatusOK, namespaceAdsV1)
}

func listNamespacesV2(ctx *gin.Context) {
	namespacesAdsV2 := listNamespacesFromOrigins()
	ctx.JSON(http.StatusOK, namespacesAdsV2)
}

func getPrefixByPath(ctx *gin.Context) {
	pathParam := ctx.Param("path")
	if pathParam == "" || pathParam == "/" {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Bad request. Path is empty or '/' "})
		return
	}
	namespaceKeysMutex.Lock()
	defer namespaceKeysMutex.Unlock()

	originNs, _, _ := getAdsForPath(pathParam)

	// If originNs.Path is an empty value, then the namespace is not found
	if originNs.Path == "" {
		ctx.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Namespace prefix not found for " + pathParam})
		return
	}

	res := common.GetPrefixByPathRes{Prefix: originNs.Path}
	ctx.JSON(http.StatusOK, res)
}

func RegisterDirector(ctx context.Context, router *gin.RouterGroup) {
	directorAPIV1 := router.Group("/api/v1.0/director")
	{
		// Establish the routes used for cache/origin redirection
		directorAPIV1.GET("/object/*any", redirectToCache)
		directorAPIV1.GET("/origin/*any", redirectToOrigin)
		directorAPIV1.PUT("/origin/*any", redirectToOrigin)
		directorAPIV1.POST("/registerOrigin", func(gctx *gin.Context) { registerOrigin(ctx, gctx) })
		directorAPIV1.POST("/registerCache", func(gctx *gin.Context) { registerCache(ctx, gctx) })
		directorAPIV1.GET("/listNamespaces", listNamespacesV1)
		directorAPIV1.GET("/namespaces/prefix/*path", getPrefixByPath)

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
