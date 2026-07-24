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

package issuer

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

// oidcDiscoverySuffix is the path suffix of the per-namespace OIDC discovery
// document, which is public, non-sensitive metadata.
const oidcDiscoverySuffix = "/.well-known/openid-configuration"

// corsMiddleware lets browser-based applications read the embedded issuer's
// endpoints cross-origin. It follows the two CORS conventions already used
// elsewhere in Pelican:
//
//   - The OIDC discovery document is public, non-sensitive metadata, so any
//     origin may read it (Access-Control-Allow-Origin: *), matching the
//     server-level discovery endpoint in server_utils/oidc.go. Because the
//     namespace is not yet resolved when this middleware runs, a URL path
//     ending in the discovery suffix may still dispatch to a different,
//     credentialed handler (e.g. oidc-cm/<id>/.well-known/openid-configuration
//     is a client-configuration read); the wildcard on the *response* is
//     therefore set by handleIssuerDiscovery itself, and this middleware only
//     approves the wildcard for the discovery-suffix *preflight*, which by
//     itself grants no access to response data.
//   - The credentialed endpoints (token, userinfo, introspection, ...) echo
//     the request's Origin back only when it is one of the configured
//     Issuer.RedirectUris, matching the OA4MP proxy in oa4mp/proxy.go, so
//     untrusted sites cannot script them.
//
// It also answers CORS preflight (OPTIONS) requests directly, since the
// dispatch handlers only cover GET/POST/PUT/DELETE.
func corsMiddleware(ctx *gin.Context) {
	origin := ctx.Request.Header.Get("Origin")
	if origin != "" {
		// All responses here depend on the request's Origin header, so caches
		// must not reuse one site's response (allowed or denied) for another.
		ctx.Header("Vary", "Origin")
		if ctx.Request.Method == http.MethodOptions && strings.HasSuffix(ctx.Request.URL.Path, oidcDiscoverySuffix) {
			ctx.Header("Access-Control-Allow-Origin", "*")
		} else if isRegisteredOrigin(origin) {
			ctx.Header("Access-Control-Allow-Origin", origin)
		}
		ctx.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		ctx.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
	}

	// Short-circuit preflight requests so they do not fall through to
	// namespace resolution or the dispatch handlers.
	if ctx.Request.Method == http.MethodOptions {
		ctx.AbortWithStatus(http.StatusNoContent)
	}
}

// isRegisteredOrigin reports whether the given browser Origin (scheme://host)
// matches the scheme and host of one of the configured Issuer.RedirectUris.
// Scheme and host are compared case-insensitively per RFC 3986 (browsers
// normalize the Origin header to lowercase, but the configured redirect URIs
// may use any case).
func isRegisteredOrigin(origin string) bool {
	for _, uri := range param.Issuer_RedirectUris.GetStringSlice() {
		parsed, err := url.Parse(uri)
		if err != nil {
			log.Warningf("Skipping malformed Issuer.RedirectUris entry %q while evaluating CORS: %v", uri, err)
			continue
		}
		if parsed.Scheme != "" && parsed.Host != "" && strings.EqualFold(parsed.Scheme+"://"+parsed.Host, origin) {
			return true
		}
	}
	return false
}
