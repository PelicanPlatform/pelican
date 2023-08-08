package director

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
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

func RedirectToCache(ginCtx *gin.Context) {
	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/object")
	ipAddr, err := getRealIP(ginCtx)
	if err != nil {
		return
	}
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
		ginCtx.Writer.Header()["X-Pelican-Namespace"] = []string{fmt.Sprintf("namespace=%s, require-token=%v",
			namespaceAd.Path, namespaceAd.RequireToken)}
	}

	ginCtx.Redirect(307, redirectURL.String())
}

func RedirectToOrigin(ginCtx *gin.Context) {
	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	reqPath = strings.TrimPrefix(reqPath, "/api/v1.0/director/origin")

	// Each namespace may be exported by several origins, so we must still
	// do the geolocation song and dance if we want to get the closest origin...
	ipAddr, err := getRealIP(ginCtx)
	if err != nil {
		return
	}

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
	ginCtx.Redirect(307, redirectURL.String())

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
	ad := OriginAdvertise{}
	if ctx.ShouldBind(&ad) != nil {
		ctx.JSON(400, gin.H{"error": "Invalid origin registration"})
		return
	}

	for _, namespace := range ad.Namespaces {
		ok, err := VerifyAdvertiseToken(tokens[0], namespace.Path)
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
