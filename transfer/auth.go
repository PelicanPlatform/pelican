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

package transfer

import (
	"net/http"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const (
	ctxKeyOwnerUserID = "TransferOwnerUserID"
)

// TransferAuthMiddleware verifies that the request carries a valid token with
// the pelican.transfer scope. It accepts tokens from the local issuer
// (config.GetLocalIssuerUrl), the federation issuer, and — when the transfer
// API runs on an origin — the origin's issuer (Origin.Url).
//
// Authorization depends on the token source:
//   - Bearer tokens (Authorization header): the pelican.transfer scope IS the
//     authorization. The Transfer.EnabledGroups gate is applied when the scope
//     is minted — the local issuer only grants pelican.transfer to members of
//     the configured groups (see transferAccessAllowed in oauth2/issuer). A
//     federation- or origin-issued pelican.transfer token is trusted as issued
//     (the operator opts into those issuers by accepting them here).
//   - Cookie (web-UI session): additionally re-checked against
//     Transfer.EnabledGroups below, using the groups the local issuer stamped
//     into the login cookie.
//
// Groups are read from the verified token's wlcg.groups claim rather than
// web_ui.GetUserGroups: that helper short-circuits to the (unset) context
// "Groups" once VerifyAndExtract has stored "User", and token verification
// deliberately keeps wlcg.groups out of the gin context (federated group claims
// must not be trusted as local identity).
//
// The token's issuer and subject are resolved to a users-table entry and the
// resulting user ID is stored in the gin context for downstream handlers.
func TransferAuthMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		authOption := token.AuthOption{
			Sources: []token.TokenSource{token.Header, token.Cookie},
			Issuers: []token.TokenIssuer{token.LocalIssuer, token.FederationIssuer},
			Scopes:  []token_scopes.TokenScope{token_scopes.Pelican_Transfer},
		}

		result, status, ok, err := token.VerifyAndExtract(c, authOption)
		if !ok {
			// If the standard issuers rejected the token, try the origin's
			// issuer when Origin.Url is configured and differs from the
			// server's web URL (otherwise LocalIssuer already covers it).
			originURL := param.Origin_Url.GetString()
			serverURL := param.Server_ExternalWebUrl.GetString()
			if originURL != "" && originURL != serverURL {
				if originErr := token.CheckOriginIssuer(c, extractRawToken(c),
					[]token_scopes.TokenScope{token_scopes.Pelican_Transfer}, false); originErr == nil {
					// Re-extract the verified token that CheckOriginIssuer stored
					// in context. Origin-issued tokens are always presented as
					// bearer credentials, so mark the source Header explicitly
					// (CheckOriginIssuer does not set it) — this keeps the
					// cookie-only group check below from firing on a stale source.
					result = &token.VerifyResult{Source: token.Header}
					if t, exists := c.Get("VerifiedToken"); exists {
						result.Token = t.(jwt.Token)
					}
					ok = true
				}
			}

			if !ok {
				log.Debugf("Transfer auth failed: %v", err)
				c.AbortWithStatusJSON(status, ErrorResponse{
					Code:  "UNAUTHORIZED",
					Error: "Authentication required: valid token with pelican.transfer scope needed",
				})
				return
			}
		}

		if result.Token == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Token verification succeeded but parsed token is unavailable",
			})
			return
		}

		issuer := result.Token.Issuer()
		subject := result.Token.Subject()
		if issuer == "" || subject == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
				Code:  "INVALID_TOKEN",
				Error: "Token must contain both issuer and subject claims",
			})
			return
		}

		// Cookie (web-UI) sessions are additionally gated on Transfer.EnabledGroups.
		// Bearer tokens are authorized by their pelican.transfer scope alone (the
		// issuer applied the group gate when it minted the scope).
		if enabledGroups := param.Transfer_EnabledGroups.GetStringSlice(); len(enabledGroups) > 0 && result.Source == token.Cookie {
			if !groupsOverlap(tokenGroups(result.Token), enabledGroups) {
				c.AbortWithStatusJSON(http.StatusForbidden, ErrorResponse{
					Code:  "FORBIDDEN",
					Error: "User is not a member of any permitted transfer group",
				})
				return
			}
		}

		// Resolve (issuer, subject) → users table ID, creating the user if needed.
		// The bearer authenticated themselves via their token, so the user row is
		// self-enrolled (as with OIDC first login).
		user, err := database.GetOrCreateUser(db, subject, subject, issuer, database.CreatorSelf())
		if err != nil {
			log.Errorf("Failed to resolve user (sub=%s, iss=%s): %v", subject, issuer, err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, ErrorResponse{
				Code:  "INTERNAL",
				Error: "Failed to resolve user identity",
			})
			return
		}

		c.Set(ctxKeyOwnerUserID, user.ID)
		c.Next()
	}
}

// extractRawToken retrieves the raw JWT string from the request.
// This is used only as a fallback for CheckOriginIssuer when the standard
// VerifyAndExtract flow did not succeed.
func extractRawToken(c *gin.Context) string {
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		if t, found := strings.CutPrefix(authHeader, "Bearer "); found {
			return t
		}
	}
	if cookie, err := c.Cookie("login"); err == nil && cookie != "" {
		return cookie
	}
	return ""
}

// tokenGroups returns the wlcg.groups claim from a verified token. Groups are
// read from the token (not web_ui.GetUserGroups) because that helper returns
// the unset context "Groups" once VerifyAndExtract has stored "User", and token
// verification deliberately keeps wlcg.groups out of the gin context.
func tokenGroups(tok jwt.Token) []string {
	v, ok := tok.Get("wlcg.groups")
	if !ok {
		return nil
	}
	switch g := v.(type) {
	case []interface{}:
		out := make([]string, 0, len(g))
		for _, x := range g {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return g
	default:
		return nil
	}
}

// groupsOverlap returns true if any element in userGroups appears in
// allowedGroups.
func groupsOverlap(userGroups, allowedGroups []string) bool {
	for _, g := range userGroups {
		if slices.Contains(allowedGroups, g) {
			return true
		}
	}
	return false
}

// getOwner extracts the owner identity from the gin context set by TransferAuthMiddleware
func getOwner(c *gin.Context) (ownerIdentity, error) {
	userID, ok := c.Get(ctxKeyOwnerUserID)
	if !ok {
		return ownerIdentity{}, errors.New("owner identity not found in request context")
	}
	return ownerIdentity{
		UserID: userID.(string),
	}, nil
}
