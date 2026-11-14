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
	"path"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
)

// handleAccessQuery answers GET <issuer>/access: what may the bearer's user
// do through this issuer right now? It lets an application such as a
// JupyterLab file browser show which namespaces and collections a user can
// read or write without decoding tokens or holding broad ones. The answer is
// computed on every request from the user's current groups and ACLs, by the
// same code that mints tokens, and is returned as RFC 9396
// authorization_details.
//
// Like userinfo, it describes the user rather than a resource, so the token
// presented must carry the openid scope.
func handleAccessQuery(provider *OIDCProvider) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		r := ctx.Request
		rCtx := r.Context()

		scheme, bearer, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || bearer == "" {
			ctx.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		session := DefaultOIDCSession("", provider.Issuer(), nil, nil)
		_, ar, err := provider.Provider().IntrospectToken(rCtx, bearer, fosite.AccessToken, session)
		if err != nil {
			ctx.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		if !slices.Contains(ar.GetGrantedScopes(), "openid") {
			ctx.JSON(http.StatusForbidden, gin.H{"error": "insufficient_scope", "error_description": "This endpoint requires a token with the openid scope"})
			return
		}

		db := database.ServerDatabase
		if db == nil {
			db = provider.storage.db
		}
		user, err := database.GetUserByUsername(db, ar.GetSession().GetSubject())
		if err != nil || user.Status != database.UserStatusActive {
			ctx.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		groups, err := database.GroupNamesForGranting(db, user.ID)
		if err != nil {
			log.WithError(err).Warn("Embedded issuer: failed to look up group memberships")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}
		allowed, _, _ := provider.userAllowedScopes(user.Username, user.ID, groups)

		ctx.Header("Cache-Control", "no-store")
		ctx.JSON(http.StatusOK, gin.H{
			"sub":                   user.Username,
			"iss":                   provider.Issuer(),
			"namespace":             provider.Namespace,
			"groups":                groups,
			"authorization_details": describeGrantedAccess(allowed, accessLocation(provider.Namespace)),
		})
	}
}

// accessLocation maps an issuer-relative scope path to the pelican:// URL an
// application would use to reach it, or to the federation path when no
// federation is configured.
func accessLocation(namespace string) func(scopePath string) string {
	federationHost := ""
	if discovery, err := url.Parse(param.Federation_DiscoveryUrl.GetString()); err == nil {
		federationHost = discovery.Host
	}
	return func(scopePath string) string {
		fullPath := scopePath
		if namespace != "" && namespace != LocalIssuerNamespace {
			fullPath = path.Join(namespace, scopePath)
		}
		if federationHost == "" {
			return fullPath
		}
		return "pelican://" + federationHost + fullPath
	}
}
