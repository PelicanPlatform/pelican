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
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hashicorp/go-version"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var (
	minClientVersion, _ = version.NewVersion("7.0.0")
	minOriginVersion, _ = version.NewVersion("7.0.0")
)

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
	} else if authzHeader := req.Header["Authorization"]; len(authzHeader) > 0 {
		authzEscaped = url.QueryEscape(authzHeader[0])
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

	namespaceAd, _, cacheAds := GetAdsForPath(reqPath)
	if len(cacheAds) == 0 {
		ginCtx.String(404, "No cache found for path\n")
		return
	}
	if namespaceAd.Path == "" {
		ginCtx.String(404, "No namespace found for path. Either it doesn't exist, or the Director is experiencing problems\n")
		return
	}
	cacheAds, err = SortServers(ipAddr, cacheAds)
	if err != nil {
		ginCtx.String(500, "Failed to determine server ordering")
		return
	}
	redirectURL := getRedirectURL(reqPath, cacheAds[0], namespaceAd.RequireToken)

	linkHeader := ""
	first := true
	for idx, ad := range cacheAds {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad, namespaceAd.RequireToken)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; pri=%d`, redirectURL.String(), idx+1)
	}
	ginCtx.Writer.Header()["Link"] = []string{linkHeader}
	if namespaceAd.Issuer.Host != "" {
		ginCtx.Writer.Header()["X-Pelican-Authorization"] = []string{"issuer=" + namespaceAd.Issuer.String()}

		tokenGen := ""
		first := true
		hdrVals := []string{namespaceAd.Issuer.String(), fmt.Sprint(namespaceAd.MaxScopeDepth), string(namespaceAd.Strategy),
			namespaceAd.BasePath, namespaceAd.VaultServer}
		for idx, hdrKey := range []string{"issuer", "max-scope-depth", "strategy", "base-path", "vault-server"} {
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
	ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{fmt.Sprintf("namespace=%s, require-token=%v",
		namespaceAd.Path, namespaceAd.RequireToken)}

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
	if namespaceAd.Path == "" {
		ginCtx.String(404, "No origin found for path\n")
		return
	}

	originAds, err = SortServers(ipAddr, originAds)
	if err != nil {
		ginCtx.String(500, "Failed to determine origin ordering")
		return
	}

	redirectURL := getRedirectURL(reqPath, originAds[0], namespaceAd.RequireToken)
	// See note in RedirectToCache as to why we only add the authz query parameter to this URL,
	// not those in the `Link`.
	ginCtx.Redirect(307, getFinalRedirectURL(redirectURL, authzBearerEscaped))

}

// Middleware sends GET /foo/bar to the RedirectToCache function, as if the
// original request had been made to /api/v1.0/director/object/foo/bar
func ShortcutMiddleware(defaultResponse string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// If we're configured for cache mode or we haven't set the flag,
		// we should use cache middleware
		if defaultResponse == "cache" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director") {
				c.Request.URL.Path = "/api/v1.0/director/object" + c.Request.URL.Path
				RedirectToCache(c)
				c.Abort()
				return
			}

			// If the path starts with the correct prefix, continue with the next handler
			c.Next()
		} else if defaultResponse == "origin" {
			if !strings.HasPrefix(c.Request.URL.Path, "/api/v1.0/director") {
				c.Request.URL.Path = "/api/v1.0/director/origin" + c.Request.URL.Path
				RedirectToOrigin(c)
				c.Abort()
				return
			}
			c.Next()
		}
	}
}

func RegisterOrigin(ctx *gin.Context) {
	tokens, present := ctx.Request.Header["Authorization"]
	if !present || len(tokens) == 0 {
		ctx.JSON(401, gin.H{"error": "Bearer token not present in the 'Authorization' header"})
		return
	}

	err := versionCompatCheck(ctx)
	if err != nil {
		log.Debugf("A version incompatibility was encountered while registering an origin and no response was served: %v", err)
		ctx.JSON(500, gin.H{"error": "Incompatible versions detected: " + fmt.Sprintf("%v", err)})
		return
	}

	ad := OriginAdvertise{}
	if ctx.ShouldBind(&ad) != nil {
		ctx.JSON(400, gin.H{"error": "Invalid origin registration"})
		return
	}

	for _, namespace := range ad.Namespaces {
		// We're assuming there's only one token in the slice
		token := strings.TrimPrefix(tokens[0], "Bearer ")
		ok, err := VerifyAdvertiseToken(token, namespace.Path)
		if err != nil {
			log.Warningln("Failed to verify token:", err)
			ctx.JSON(400, gin.H{"error": "Authorization token verification failed"})
			return
		}
		if !ok {
			log.Warningf("Origin %v advertised to namespace %v without valid registration\n",
				ad.Name, namespace.Path)
			ctx.JSON(400, gin.H{"error": "Origin not authorized to advertise to this namespace"})
			return
		}
	}

	ad_url, err := url.Parse(ad.URL)
	if err != nil {
		log.Warningf("Failed to parse origin URL %v: %v\n", ad.URL, err)
		ctx.JSON(400, gin.H{"error": "Invalid origin URL"})
		return
	}

	originAd := ServerAd{
		Name:    ad.Name,
		AuthURL: *ad_url,
		URL:     *ad_url,
		Type:    OriginType,
	}
	RecordAd(originAd, &ad.Namespaces)
	ctx.JSON(200, gin.H{"msg": "Successful registration"})
}

func RegisterDirector(router *gin.RouterGroup) {
	// Establish the routes used for cache/origin redirection
	router.GET("/api/v1.0/director/object/*any", RedirectToCache)
	router.GET("/api/v1.0/director/origin/*any", RedirectToOrigin)
	router.POST("/api/v1.0/director/registerOrigin", RegisterOrigin)
}
