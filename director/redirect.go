package director

import (
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"github.com/gin-gonic/gin"
)

func getRedirectURL(reqPath string, serverURL url.URL) (redirectURL url.URL) {
	reqPath = path.Clean("/" + reqPath)
	redirectURL.Scheme = "https"
	redirectURL.Host = serverURL.Host
	redirectURL.Path = path.Clean(serverURL.Path + reqPath)
	return
}

func RedirectToCache(ginCtx *gin.Context) {
	reqPath := path.Clean("/" + ginCtx.Request.URL.Path)
	ip_addr_list := ginCtx.Request.Header["X-Real-Ip"]
	var ipAddr netip.Addr
	if len(ip_addr_list) == 0 {
		var err error
		ipAddr, err = netip.ParseAddr(ginCtx.RemoteIP())
		if err != nil {
			ginCtx.String(500, "Failed to parse IP address: %s", err.Error())
			return
		}
	} else {
		var err error
		ipAddr, err = netip.ParseAddr(ip_addr_list[0])
		if err != nil {
			ginCtx.String(500, "Failed to parse X-Real-Ip header: %s", err.Error())
			return
		}
	}
	namespaceAd, ads := GetCacheAdsForPath(reqPath)
	if len(ads) == 0 {
		ginCtx.String(404, "No cache found for path")
		return
	}
	if namespaceAd.Path == "" {
		ginCtx.String(404, "No origin found for path")
		return
	}

	ads, err := SortCaches(ipAddr, ads)
	if err != nil {
		ginCtx.String(500, "Failed to determine server ordering")
		return
	}

	redirectURL := getRedirectURL(reqPath, ads[0].URL)

	linkHeader := ""
	first := true
	for idx, ad := range ads {
		if first {
			first = false
		} else {
			linkHeader += ", "
		}
		redirectURL := getRedirectURL(reqPath, ad.URL)
		linkHeader += fmt.Sprintf(`<%s>; rel="duplicate"; prio=%d`, redirectURL.String(), idx + 1)
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

func RegisterDirector(router *gin.RouterGroup) {
	router.GET("/", RedirectToCache)
}
