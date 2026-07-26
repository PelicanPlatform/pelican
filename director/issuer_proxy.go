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

// Director-hosted OAuth2 issuer proxy (WS4 of "reduce origin requirements").
// A firewalled/DNS-less origin cannot be reached by clients to acquire or
// validate tokens; the director — which is always reachable and already has a
// broker-aware transport — proxies the origin's embedded-issuer HTTP surface so
// clients talk to the director instead. The origin still mints the tokens; the
// director just carries the HTTP (over the broker when the origin is firewalled)
// and rewrites the one place the origin bakes absolute URLs: its per-namespace
// openid-configuration discovery document.
//
// Routes are mounted under a director-specific prefix
// (/api/v1.0/issuer-proxy/ns/*) rather than mirroring the origin's own
// /api/v1.0/issuer/ns/* so this can run in a process that is ALSO an origin
// (which registers the latter) without a route collision — and deliberately not
// under /api/v1.0/director/, which has a catch-all wildcard that forbids sibling
// routes. The origin advertises this director URL as its issuer (a separate,
// gated change) so token `iss`, discovery, and JWKS all resolve here consistently.
package director

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// issuerProxyPathPrefix is the director path under which the issuer proxy is
// mounted; the part after it mirrors the origin's own /api/v1.0/issuer/ns tail
// (namespace + action). It is deliberately NOT under /api/v1.0/director/ —
// RegisterDirectorAPI registers a catch-all wildcard there (/api/v1.0/director/*any)
// and gin forbids any sibling route under a catch-all prefix.
const issuerProxyPathPrefix = "/api/v1.0/issuer-proxy/ns"

// originIssuerPathPrefix is the origin's own issuer route prefix (the tail the
// proxy re-targets to). Cookies the origin sets during the flow are scoped to
// this prefix and must be re-pathed onto issuerProxyPathPrefix so the browser
// sends them back to the director, not the (unreachable) origin.
const originIssuerPathPrefix = "/api/v1.0/issuer/ns"

// rewriteIssuerCookiePaths re-paths any Set-Cookie whose Path attribute is under
// the origin's issuer prefix onto the proxy prefix. The origin scopes cookies
// (e.g. the device-verify CSRF cookie) to /api/v1.0/issuer/ns/<ns>/...; without
// this a browser talking to the proxy at /api/v1.0/issuer-proxy/ns/<ns>/... would
// store them under a path it never revisits and drop them on the follow-up POST.
func rewriteIssuerCookiePaths(resp *http.Response) {
	cookies := resp.Header["Set-Cookie"]
	for i, c := range cookies {
		cookies[i] = strings.ReplaceAll(c, "Path="+originIssuerPathPrefix, "Path="+issuerProxyPathPrefix)
	}
}

// rewriteIssuerDiscoveryDoc rewrites the absolute URLs in an origin's
// per-namespace openid-configuration so they point at the director proxy instead
// of the origin. originIssuerBase is the origin's issuer base for this namespace
// (e.g. https://origin.example/api/v1.0/issuer/ns/foo); proxyIssuerBase is the
// director's (e.g. https://director.example/api/v1.0/issuer-proxy/ns/foo).
//
// The issuer + *_endpoint fields sit under originIssuerBase and are re-based
// directly. jwks_uri is special: on the origin it points at the server-root
// .well-known/issuer.jwks (the origin's signing key, NOT the director's
// federation key), so it is rewritten to a namespaced proxy path the director
// serves by proxying back to that origin root — keeping validators on the
// origin's key.
func rewriteIssuerDiscoveryDoc(body []byte, originIssuerBase, proxyIssuerBase string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, err
	}
	for k, v := range doc {
		s, ok := v.(string)
		if !ok {
			continue
		}
		switch {
		case k == "jwks_uri":
			doc[k] = proxyIssuerBase + "/.well-known/issuer.jwks"
		case strings.HasPrefix(s, originIssuerBase):
			doc[k] = proxyIssuerBase + strings.TrimPrefix(s, originIssuerBase)
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// rebaseIssuerJSONURLs rewrites every top-level JSON string field whose value
// starts with originIssuerBase so it points at proxyIssuerBase instead. Unlike
// the discovery document there is no jwks_uri special case. It is used for the
// device-authorization response, whose verification_uri / verification_uri_complete
// are shown to a human to open in a browser and so must point at the reachable
// director proxy, never the (firewalled) origin.
func rebaseIssuerJSONURLs(body []byte, originIssuerBase, proxyIssuerBase string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return body, err
	}
	for k, v := range doc {
		if s, ok := v.(string); ok && strings.HasPrefix(s, originIssuerBase) {
			doc[k] = proxyIssuerBase + strings.TrimPrefix(s, originIssuerBase)
		}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// issuerProxyHandler resolves the origin serving the requested namespace and
// reverse-proxies the issuer request to it (over the broker when firewalled),
// rewriting the discovery document on the way back.
func issuerProxyHandler(ginCtx *gin.Context) {
	issuerTail := ginCtx.Param("issuerpath") // e.g. "/foo/token" or "/foo/.well-known/openid-configuration"
	if issuerTail == "" || issuerTail == "/" {
		ginCtx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "missing issuer namespace/action"})
		return
	}

	oAds, _ := getAdsForPath(issuerTail)
	if len(oAds) == 0 {
		ginCtx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "no origin serves the requested issuer namespace"})
		return
	}
	originWebURL := oAds[0].ServerAd.WebURL
	if originWebURL.Host == "" {
		ginCtx.JSON(http.StatusBadGateway, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "the origin advertised no web URL"})
		return
	}
	ns := oAds[0].NamespaceAd.Path
	action := strings.TrimPrefix(issuerTail, ns)

	// The origin serves per-namespace issuer endpoints under /api/v1.0/issuer/ns,
	// except its JWKS, which is at the server root.
	var targetPath string
	if action == "/.well-known/issuer.jwks" {
		targetPath = "/.well-known/issuer.jwks"
	} else {
		targetPath = "/api/v1.0/issuer/ns" + issuerTail
	}

	originIssuerBase := originWebURL.Scheme + "://" + originWebURL.Host + "/api/v1.0/issuer/ns" + ns
	proxyIssuerBase := strings.TrimSuffix(param.Server_ExternalWebUrl.GetString(), "/") + issuerProxyPathPrefix + ns

	proxy := &httputil.ReverseProxy{
		// config.GetTransport() is broker-aware on the director, so a firewalled
		// origin's web port is reachable transparently.
		Transport: config.GetTransport(),
		Director: func(req *http.Request) {
			req.URL.Scheme = originWebURL.Scheme
			req.URL.Host = originWebURL.Host
			req.Host = originWebURL.Host
			req.URL.Path = targetPath
		},
		ModifyResponse: func(resp *http.Response) error {
			// Re-path any cookies the origin scoped to its issuer prefix onto the
			// proxy prefix, for every response, so the browser keeps sending them
			// back to the director through the rest of the flow.
			rewriteIssuerCookiePaths(resp)

			// A couple of responses bake absolute origin URLs that must be
			// re-based onto the director so a client that reached us via the proxy
			// keeps talking to the proxy (never the unreachable origin):
			//   - the discovery document (issuer + *_endpoint + jwks_uri), and
			//   - the device-authorization response, whose verification_uri /
			//     verification_uri_complete are shown to a human to open in a browser.
			var rewrite func([]byte) ([]byte, error)
			switch action {
			case "/.well-known/openid-configuration":
				rewrite = func(b []byte) ([]byte, error) {
					return rewriteIssuerDiscoveryDoc(b, originIssuerBase, proxyIssuerBase)
				}
			case "/device_authorization":
				rewrite = func(b []byte) ([]byte, error) {
					return rebaseIssuerJSONURLs(b, originIssuerBase, proxyIssuerBase)
				}
			default:
				return nil
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				return err
			}
			rewritten, err := rewrite(body)
			if err != nil {
				// On a rewrite failure, pass the original bytes through unchanged
				// rather than break the flow.
				log.Warnf("Issuer proxy: failed to rewrite %s response for %s: %v", action, ns, err)
				rewritten = body
			}
			resp.Body = io.NopCloser(strings.NewReader(string(rewritten)))
			resp.ContentLength = int64(len(rewritten))
			resp.Header.Set("Content-Length", strconv.Itoa(len(rewritten)))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warnf("Issuer proxy: upstream error reaching origin %s: %v", originWebURL.Host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(ginCtx.Writer, ginCtx.Request)
}

// RegisterIssuerProxy mounts the director issuer proxy. Safe to run alongside a
// co-located origin because the path prefix differs from the origin's own issuer
// routes.
func RegisterIssuerProxy(router *gin.RouterGroup) {
	router.Any(issuerProxyPathPrefix+"/*issuerpath", issuerProxyHandler)
}
