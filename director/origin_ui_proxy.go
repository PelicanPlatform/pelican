/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

// Director-hosted origin web-UI proxy (WS5 of "reduce origin requirements").
//
// A firewalled / DNS-less origin cannot be reached by an admin's browser, so its
// web UI is unusable directly. The director — always reachable and already
// equipped with a broker-aware transport — proxies the origin's UI so the admin
// works entirely against the director.
//
// The origin's Next.js bundle is a *static export* with a build-time basePath of
// "/view", and every UI API call is host-relative ("/api/v1.0/..."). Rather than
// re-host that bundle under a per-origin URL prefix (which a static basePath
// cannot express without rebuilding or rewriting served bytes), the director:
//
//  1. Serves the origin UI *pages* (and /view/_next assets) from its OWN copy of
//     the identical embedded bundle — nothing is proxied or rewritten, and the
//     "/view" basePath is honoured as-is.
//  2. Reverse-proxies only the origin-owned *API* calls those pages make
//     (/api/v1.0/origin_ui, /config, /auth, /issuer/ns) to the selected origin
//     over the broker.
//
// Which origin is being viewed is carried in a browser cookie set by the
// "select" control endpoint (admin-gated), not encoded in the URL — so "view
// origin X" is a browser mode. The origin still mints and verifies its own login
// JWT (bound to its issuer); the proxy bridges that cookie under a distinct name
// so it coexists with the director's own session.
package director

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// viewOriginCookie carries the ServerID of the origin whose UI the director is
// currently proxying for this browser ("view origin" mode). The name is shared
// with web_ui via server_structs so both packages agree without an import cycle.
const viewOriginCookie = server_structs.ViewOriginCookieName

const (
	// originUIControlPrefix hosts the enter/exit control endpoints. It is a fresh
	// top-level prefix (NOT under /api/v1.0/director/, which has a catch-all that
	// forbids sibling routes) and uses a hyphen to stay clear of the origin's own
	// hyphenless /api/v1.0/origin_ui API.
	originUIControlPrefix = "/api/v1.0/origin-ui"

	// viewOriginTTL is how long a view-origin selection lasts.
	viewOriginTTL = 8 * time.Hour
)

// originUIProxyPathPrefixes are the origin-owned request prefixes that, while
// view-origin mode is active, the director reverse-proxies to the selected
// origin instead of handling locally. UI pages and static assets (/view,
// /view/_next) are deliberately absent: the director serves those from its own
// identical bundle.
var originUIProxyPathPrefixes = []string{
	"/api/v1.0/origin_ui/", // origin's own web API (exports, collections, ...)
	"/api/v1.0/auth/",       // login / whoami / oauth — the origin's session
	"/api/v1.0/config",      // config viewing/editing
	"/api/v1.0/issuer/ns/",  // embedded-issuer endpoints (device verify page, ...)
}

// originCookieBridge maps a cookie the origin sets (real name) to the distinct
// name the browser stores it under while talking to the director, so it does not
// collide with the director's own same-named cookies.
var originCookieBridge = map[string]string{
	"login":           "origin-login",
	"pelican-session": "origin-pelican-session",
}

// bridgedCookieToReal is the inverse of originCookieBridge.
var bridgedCookieToReal = func() map[string]string {
	m := make(map[string]string, len(originCookieBridge))
	for real, bridged := range originCookieBridge {
		m[bridged] = real
	}
	return m
}()

// isOriginUIProxyPath reports whether a request path is origin-owned and should
// be forwarded to the viewed origin.
func isOriginUIProxyPath(p string) bool {
	for _, prefix := range originUIProxyPathPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

// resolveViewedOrigin returns the web URL of the currently-advertised origin
// whose ServerID matches serverID. Requiring a live advertisement means a
// tampered cookie can only select a known federation origin, never an arbitrary
// host.
func resolveViewedOrigin(serverID string) (url.URL, bool) {
	if serverID == "" {
		return url.URL{}, false
	}
	for _, ad := range getServerAdsSnapshot() {
		if ad.ServerAd.Type == server_structs.OriginType.String() && ad.ServerAd.ServerID == serverID {
			return ad.ServerAd.WebURL, true
		}
	}
	return url.URL{}, false
}

// bridgeOriginSetCookies rewrites Set-Cookie headers coming FROM the origin so
// the browser stores the origin's session cookies under proxy-specific names,
// avoiding collision with the director's own same-named cookies.
func bridgeOriginSetCookies(resp *http.Response) {
	sc := resp.Header["Set-Cookie"]
	for i, c := range sc {
		for real, bridged := range originCookieBridge {
			if strings.HasPrefix(c, real+"=") {
				sc[i] = bridged + strings.TrimPrefix(c, real)
				break
			}
		}
	}
}

// bridgeBrowserCookieHeader rewrites the request Cookie header going TO the
// origin: the browser's proxy-specific cookies are sent under their real names,
// and the director's own same-named cookies are dropped so they never reach (or
// confuse) the origin.
func bridgeBrowserCookieHeader(req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}
	out := make([]string, 0, len(cookies))
	for _, ck := range cookies {
		if real, ok := bridgedCookieToReal[ck.Name]; ok {
			out = append(out, real+"="+ck.Value)
		} else if _, isReal := originCookieBridge[ck.Name]; isReal {
			continue // drop the director's own login / pelican-session
		} else {
			out = append(out, ck.Name+"="+ck.Value)
		}
	}
	if len(out) == 0 {
		req.Header.Del("Cookie")
		return
	}
	req.Header.Set("Cookie", strings.Join(out, "; "))
}

// rewriteOriginRedirectLocation rebases a redirect the origin emits so the
// browser stays on the director. An absolute Location pointing at the origin
// host is re-pointed at the director; an embedded redirect_uri (an OIDC login
// bounce to an external IdP) that points back at the origin is likewise
// re-pointed so the IdP returns the browser to the director, where the callback
// is proxied back to the origin.
func rewriteOriginRedirectLocation(resp *http.Response, originHost, directorHost string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil {
		return
	}
	changed := false
	if u.Host == originHost {
		u.Host = directorHost
		changed = true
	}
	if ru := u.Query().Get("redirect_uri"); ru != "" {
		if p, e := url.Parse(ru); e == nil && p.Host == originHost {
			p.Host = directorHost
			q := u.Query()
			q.Set("redirect_uri", p.String())
			u.RawQuery = q.Encode()
			changed = true
		}
	}
	if changed {
		resp.Header.Set("Location", u.String())
	}
}

// newOriginUIReverseProxy builds the reverse proxy to a viewed origin's web
// endpoint. config.GetTransport() is broker-aware on the director, so a
// firewalled origin's web port is reachable transparently.
func newOriginUIReverseProxy(originWebURL url.URL, directorHost string) *httputil.ReverseProxy {
	originHost := originWebURL.Host
	return &httputil.ReverseProxy{
		Transport: config.GetTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = originWebURL.Scheme
			req.URL.Host = originWebURL.Host
			req.Host = originWebURL.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			bridgeOriginSetCookies(resp)
			rewriteOriginRedirectLocation(resp, originHost, directorHost)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warnf("Origin UI proxy: upstream error reaching origin %s: %v", originHost, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
}

// ViewOriginProxyMiddleware intercepts origin-owned API requests while a
// view-origin selection is active and forwards them to the selected origin
// over the broker. It no-ops (falls through) for every other request, so it is
// safe to install globally.
func ViewOriginProxyMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		serverID, err := ctx.Cookie(viewOriginCookie)
		if err != nil || serverID == "" {
			ctx.Next()
			return
		}
		if !isOriginUIProxyPath(ctx.Request.URL.Path) {
			ctx.Next()
			return
		}
		originWebURL, ok := resolveViewedOrigin(serverID)
		if !ok {
			// Stale or invalid selection: let the request be handled locally.
			ctx.Next()
			return
		}
		directorHost := ""
		if ext, e := url.Parse(param.Server_ExternalWebUrl.GetString()); e == nil {
			directorHost = ext.Host
		}
		bridgeBrowserCookieHeader(ctx.Request)
		newOriginUIReverseProxy(originWebURL, directorHost).ServeHTTP(ctx.Writer, ctx.Request)
		ctx.Abort()
	}
}

// handleSelectOrigin enters view-origin mode for the named origin, then sends
// the browser to the origin UI home. Admin-gated by the caller.
func handleSelectOrigin(ctx *gin.Context) {
	serverID := ctx.Param("serverID")
	if _, ok := resolveViewedOrigin(serverID); !ok {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "no such origin is currently advertised"})
		return
	}
	ctx.SetCookie(viewOriginCookie, serverID, int(viewOriginTTL.Seconds()), "/", "", true, true)
	ctx.Redirect(http.StatusTemporaryRedirect, "/view/origin/")
}

// handleExitOrigin leaves view-origin mode. It requires no director session so
// it always works, even while the mode is shadowing the director's own auth.
func handleExitOrigin(ctx *gin.Context) {
	ctx.SetCookie(viewOriginCookie, "", -1, "/", "", true, true)
	ctx.Redirect(http.StatusTemporaryRedirect, "/view/director/")
}

// RegisterOriginUIControls mounts the view-origin enter/exit control
// endpoints. The enter endpoint is admin-gated via the supplied middleware; exit
// is intentionally open. The interception middleware is installed separately (in
// the launcher, before the web UI routes are registered) so it precedes them in
// the handler chain.
func RegisterOriginUIControls(router *gin.RouterGroup, adminAuth ...gin.HandlerFunc) {
	selectHandlers := append(append([]gin.HandlerFunc{}, adminAuth...), handleSelectOrigin)
	router.GET(originUIControlPrefix+"/select/:serverID", selectHandlers...)
	router.GET(originUIControlPrefix+"/exit", handleExitOrigin)
}
