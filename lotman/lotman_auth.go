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

package lotman

// Authorization helpers for the /api/v1.0/lots/* HTTP surface.
//
// Each request is accepted via one of two INDEPENDENT paths:
//
//   1. Web-admin cookie path: a `login` cookie produced by
//      web_ui.AuthHandler/CheckAdmin identifies the caller as a server admin.
//      Admins may perform any operation against any lot; the lotman caller
//      is recorded as the federation issuer URL (which is always an
//      authorized owner of any lot rooted at "root").
//
//   2. Bearer-token path: the request bears an Authorization bearer token
//      (or `?authz=` query) whose signing key matches an authorized owner
//      of the lot (or, for lot creation, the parent lot determined by path),
//      and whose `scope` claim contains the operation-specific scope.
//
// The two paths are tried in order: cookie first (cheap, no JWKS fetch),
// then bearer. Note that we deliberately DO NOT use token.GetAuthzEscaped
// here, because it falls back to the `login` cookie and would silently
// re-interpret a non-admin web user's session cookie as a federation
// bearer token (an issuer-confusion vulnerability). See getBearerToken
// below.

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/utils/registry_jwks"
	"github.com/pelicanplatform/pelican/web_ui"
)

// getBearerToken extracts a bearer token from the request, looking ONLY
// at the Authorization header (with "Bearer " prefix) or the "authz" query
// parameter. Unlike token.GetAuthzEscaped this deliberately does NOT fall
// back to the `login` cookie; cookie-based auth is handled separately via
// tryAdminCookie so that the two paths cannot be confused.
func getBearerToken(ctx *gin.Context) string {
	if authzHeader := ctx.Request.Header["Authorization"]; len(authzHeader) > 0 {
		return strings.TrimPrefix(authzHeader[0], "Bearer ")
	}
	if authzQuery := ctx.Request.URL.Query()["authz"]; len(authzQuery) > 0 {
		return strings.TrimPrefix(authzQuery[0], "Bearer ")
	}
	return ""
}

// verifyTokenSignedByAnyIssuer is a low-level signature primitive: it walks
// the supplied issuer URL list, fetches each issuer's JWKS, and returns the
// first parsed token whose signature verifies against one of those keys.
//
// This function intentionally answers ONLY the question "is this token
// signed by one of these issuers?". It is unaware of the operation being
// authorized; the caller (requireAuth, requireAuthForPath,
// requireAuthForCreate) is responsible for picking the appropriate set of
// candidate issuers (the lot's owners for modify, the path's parents'
// owners for path-keyed reads, the parent lot's owners for create) and
// for checking the token's scope claim against the operation.
func verifyTokenSignedByAnyIssuer(strToken string, candidateIssuers []string) (bool, *jwt.Token, error) {
	for _, owner := range candidateIssuers {
		kSet, err := registry_jwks.GetJWKSFromIssUrl(owner)
		if err != nil {
			log.Debugf("Error getting JWKS for owner %s: %v", owner, err)
			continue
		}
		tok, err := token.VerifyWithKeyset(strToken, *kSet)
		if err != nil {
			log.Debugf("Token verification failed with owner %s: %v -- skipping", owner, err)
			continue
		}
		return true, &tok, nil
	}
	return false, nil, errors.New("token not signed by any candidate issuer")
}

// resolveParentsForPath returns the lot names that should serve as parents
// for a new lot covering the given filesystem path, using lotman's
// path-derived lookup. Two synthetic rootly lots exist alongside any
// operator-defined hierarchy:
//
//   - "root":    every operator-defined lot ultimately roots here.
//   - "default": catches paths not aligned with any explicit lot. It is
//     its own self-parent (a rootly lot in lotman's terms).
//
// When lotman returns no covering lots for `path`, or returns the synthetic
// "default" lot, we report "root" as the effective parent: every
// Pelican-managed lot ultimately roots there, and using "default" as the
// parent of an arbitrary new lot would drag it under default's bounded
// budgets. The returned slice always has at least one entry. (Note:
// capacity endpoints query "default" directly when appropriate, rather
// than going through this resolver — see getAvailableCapacity.)
func resolveParentsForPath(path string) ([]string, error) {
	goLots, err := GetLotsFromDir(path, false, time.Now().UnixMilli())
	if err != nil {
		return nil, errors.Wrapf(err, "error resolving parent lots for path %s", path)
	}
	if len(goLots) == 0 || goLots[0] == "default" {
		return []string{"root"}, nil
	}
	return goLots, nil
}

// resolveOwnerForPath maps a filesystem path to the namespace that owns
// it (via the federation director) and returns that namespace's issuer URL.
// This is the canonical Pelican-managed Owner string for any new lot that
// covers `path`, regardless of whether the lot was created via the admin
// cookie path or the bearer-token path.
func resolveOwnerForPath(path string) (string, error) {
	const errPrefix = "could not determine the lot owner because "
	fedInfo, err := config.GetFederation(context.Background())
	if err != nil {
		return "", errors.Wrap(err, errPrefix+"the federation information could not be retrieved")
	}
	if fedInfo.DirectorEndpoint == "" {
		return "", errors.New(errPrefix + "the federation director URL is not set")
	}
	directorUrl, err := url.Parse(fedInfo.DirectorEndpoint)
	if err != nil {
		return "", errors.Wrap(err, errPrefix+"the federation director URL is not a valid URL")
	}
	directorUrl.Path, err = url.JoinPath("/api/v1.0/director/object", path)
	if err != nil {
		return "", errors.Wrap(err, errPrefix+"the director's object path could not be constructed")
	}

	httpClient := config.GetClientNoRedirect()
	req, err := http.NewRequest("GET", directorUrl.String(), nil)
	if err != nil {
		return "", errors.Wrap(err, errPrefix+"the director request could not be created")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", errors.Wrapf(err, errPrefix+"the director couldn't be queried for path %s", path)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", errors.Errorf(errPrefix+"the director returned a bad status for path %s: %s", path, resp.Status)
	}

	namespaceHeader := resp.Header.Values("X-Pelican-Namespace")
	if len(namespaceHeader) == 0 {
		return "", errors.Errorf(errPrefix+"the director did not return a namespace header for path %s", path)
	}
	xPelicanNamespaceMap := utils.HeaderParser(namespaceHeader[0])
	namespace := xPelicanNamespaceMap["namespace"]

	nsIssuerUrl, err := registry_jwks.GetNSIssuerURL(namespace)
	if err != nil {
		return "", errors.Wrapf(err, errPrefix+"no issuer could be found for namespace %s", namespace)
	}
	return nsIssuerUrl, nil
}

// authorizedCallersForPath returns the set of issuer URLs whose tokens may
// authorize an operation against any lot that covers `path`. This is the
// union of the path-derived parent lots' authorized callers, deduplicated.
func authorizedCallersForPath(path string) ([]string, error) {
	parents, err := resolveParentsForPath(path)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(parents))
	for _, parent := range parents {
		callers, err := GetAuthorizedCallers(parent)
		if err != nil {
			log.Debugf("authorizedCallersForPath: GetAuthorizedCallers(%s) failed: %v", parent, err)
			continue
		}
		for _, c := range *callers {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, errors.Errorf("no authorized callers found for path %s", path)
	}
	return out, nil
}

// VerifyNewLotToken verifies that strToken authorizes creation of `lot`. As
// a side effect, the lot's Parents and Owner fields are populated from the
// path-derived parent lookup and the namespace-issuer-URL lookup so that
// CreateLot has a fully-formed record.
//
// Returns true iff the token is signed by an authorized caller of one of
// the lot's parents (or, when the parent is "root", the federation issuer)
// and contains the lot.create scope.
func VerifyNewLotToken(lot *Lot, strToken string) (bool, error) {
	if lot == nil || len(lot.Paths) == 0 {
		return false, errors.New("lot must include at least one path")
	}
	path := lot.Paths[0].Path
	log.Debugf("Attempting to add lot for path: %s", path)

	parents, err := resolveParentsForPath(path)
	if err != nil {
		return false, err
	}
	lot.Parents = parents

	// Build the set of authorized callers. When the parent is the synthetic
	// root, only the federation issuer signs; otherwise we union the
	// authorized callers of each parent lot.
	var authorizedCallers []string
	if len(parents) == 1 && parents[0] == "root" {
		issuerUrl, err := getFederationIssuer()
		if err != nil {
			return false, err
		}
		authorizedCallers = []string{issuerUrl}
	} else {
		seen := make(map[string]struct{})
		for _, parent := range parents {
			callers, err := GetAuthorizedCallers(parent)
			if err != nil {
				return false, errors.Wrapf(err, "error fetching authorized callers for parent lot %s", parent)
			}
			for _, c := range *callers {
				if _, ok := seen[c]; !ok {
					seen[c] = struct{}{}
					authorizedCallers = append(authorizedCallers, c)
				}
			}
		}
	}

	signed, tok, err := verifyTokenSignedByAnyIssuer(strToken, authorizedCallers)
	if err != nil || !signed {
		if err == nil {
			err = errors.New("token not signed by any authorized caller")
		}
		return false, err
	}

	scopes, err := extractScopes(*tok)
	if err != nil {
		return false, err
	}
	if !scopesContain(scopes, token_scopes.Lot_Create) {
		return false, errors.New("the token was correctly signed but did not possess the necessary lot.create scope")
	}

	owner, err := resolveOwnerForPath(path)
	if err != nil {
		return false, err
	}
	lot.Owner = owner
	return true, nil
}

// authResult captures the outcome of an authorization decision.
//
// caller is the string passed through to lotman as the "caller" parameter
// on mutating C calls. For the cookie/admin path, this is the federation
// issuer URL. For the bearer-token path, it is the token's `iss` claim.
//
// isAdmin is true iff the request was authorized via the cookie path.
type authResult struct {
	caller  string
	isAdmin bool
}

// tryAdminCookie returns true (and a non-nil authResult) iff the request
// carries a valid Pelican login cookie whose user is recognized as an
// admin per CheckAdmin. Unlike web_ui.AuthHandler, this function does NOT
// abort the gin chain on failure: callers fall through to bearer-based auth
// when admin verification fails.
func tryAdminCookie(ctx *gin.Context) (*authResult, bool) {
	user, userId, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		return nil, false
	}
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
	}
	isAdmin, _ := web_ui.CheckAdmin(identity)
	if !isAdmin {
		return nil, false
	}
	// Fall back to the federation issuer as the lotman caller. Every
	// Pelican-managed lot is rooted under "root", whose owner is the
	// federation issuer, so this always satisfies lotman's authorized-caller
	// check on mutating operations.
	fedIssuer, err := getFederationIssuer()
	if err != nil {
		log.Warnf("Admin cookie verified but federation issuer is unavailable: %v", err)
		return nil, false
	}
	return &authResult{caller: fedIssuer, isAdmin: true}, true
}

// extractScopes pulls the space-delimited `scope` claim out of a parsed token.
func extractScopes(tok jwt.Token) ([]string, error) {
	scopeAny, present := tok.Get("scope")
	if !present {
		return nil, errors.New("no scope claim in token")
	}
	scopeStr, ok := scopeAny.(string)
	if !ok {
		return nil, errors.New("scope claim is not string-valued")
	}
	return strings.Split(scopeStr, " "), nil
}

// scopesContain reports whether scopes contains required.
func scopesContain(scopes []string, required token_scopes.TokenScope) bool {
	target := required.String()
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// requireAuth checks that the request is authorized to perform an operation
// against an existing lot. The lotName is used to fetch the lot's authorized
// callers; the requiredScope must be present in the bearer token's scope
// claim (the cookie path implicitly satisfies all scopes).
//
// On success, the returned authResult.caller is suitable for use as the
// lotman C "caller" parameter. On failure, the response has already been
// written (with an appropriate HTTP status) and the caller should return
// from its handler.
func requireAuth(ctx *gin.Context, lotName string, requiredScope token_scopes.TokenScope) (*authResult, bool) {
	if res, ok := tryAdminCookie(ctx); ok {
		return res, true
	}

	strToken := getBearerToken(ctx)
	if strToken == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Authentication required: provide an admin login cookie or an Authorization bearer token",
		})
		return nil, false
	}

	authzCallers, err := GetAuthorizedCallers(lotName)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "error fetching authorized callers",
		})
		log.Debugf("requireAuth: GetAuthorizedCallers(%s) failed: %v", lotName, err)
		return nil, false
	}

	signed, parsedTok, err := verifyTokenSignedByAnyIssuer(strToken, *authzCallers)
	if err != nil || !signed {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token is not signed by any authorized caller of the lot",
		})
		return nil, false
	}

	scopes, err := extractScopes(*parsedTok)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return nil, false
	}
	if !scopesContain(scopes, requiredScope) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token is missing required scope: " + requiredScope.String(),
		})
		return nil, false
	}

	return &authResult{caller: (*parsedTok).Issuer(), isAdmin: false}, true
}

// requireAuthForPath is the read-only variant of requireAuth used for
// path-keyed queries (e.g. listLotsByPath). The set of authorized callers
// is the union of the authorized callers of all path-derived parent lots,
// so that the namespace owner whose namespace covers `path` can answer
// "what reservations cover my path?" without holding a federation-signed
// token.
func requireAuthForPath(ctx *gin.Context, path string, requiredScope token_scopes.TokenScope) (*authResult, bool) {
	if res, ok := tryAdminCookie(ctx); ok {
		return res, true
	}

	strToken := getBearerToken(ctx)
	if strToken == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Authentication required: provide an admin login cookie or an Authorization bearer token",
		})
		return nil, false
	}

	callers, err := authorizedCallersForPath(path)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "error fetching authorized callers for path",
		})
		log.Debugf("requireAuthForPath: %v", err)
		return nil, false
	}

	signed, parsedTok, err := verifyTokenSignedByAnyIssuer(strToken, callers)
	if err != nil || !signed {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token is not signed by any authorized caller for this path",
		})
		return nil, false
	}

	scopes, err := extractScopes(*parsedTok)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return nil, false
	}
	if !scopesContain(scopes, requiredScope) {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token is missing required scope: " + requiredScope.String(),
		})
		return nil, false
	}

	return &authResult{caller: (*parsedTok).Issuer(), isAdmin: false}, true
}

// requireAuthForCreate is the create-lot variant of requireAuth: there is no
// existing lot to query for authorized callers, so authorization is delegated
// to VerifyNewLotToken (which derives the parent from the lot's path and
// checks the token against the parent's owners). The lot argument's Owner
// and Parents fields are populated as a side effect; the caller's Owner is
// resolved via the namespace-director lookup so that admin-created and
// JWT-created lots end up with identical ACLs.
func requireAuthForCreate(ctx *gin.Context, lot *Lot) (*authResult, bool) {
	if len(lot.Paths) == 0 {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "lot must include at least one path",
		})
		return nil, false
	}
	path := lot.Paths[0].Path

	if res, ok := tryAdminCookie(ctx); ok {
		// Admin path: derive Parents and Owner the same way VerifyNewLotToken
		// would, so that the resulting lot's long-term ACL matches what a
		// JWT-created lot would have at the same path.
		parents, err := resolveParentsForPath(path)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "failed to resolve parent lots for path",
			})
			log.Debugf("requireAuthForCreate(admin): %v", err)
			return nil, false
		}
		lot.Parents = parents

		owner, err := resolveOwnerForPath(path)
		if err != nil {
			// Fall back to the federation issuer if no namespace owns the
			// path. Admins legitimately need to create lots that don't
			// (yet) correspond to a registered namespace; the federation
			// issuer is always an authorized caller of `root`.
			log.Debugf("requireAuthForCreate(admin): owner lookup for %s failed (%v); falling back to federation issuer", path, err)
			owner = res.caller
		}
		lot.Owner = owner
		return res, true
	}

	strToken := getBearerToken(ctx)
	if strToken == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Authentication required: provide an admin login cookie or an Authorization bearer token",
		})
		return nil, false
	}

	ok, err := VerifyNewLotToken(lot, strToken)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "token verification failed",
		})
		log.Debugf("requireAuthForCreate(jwt): %v", err)
		return nil, false
	}
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Token is not authorized to create lots under this path",
		})
		return nil, false
	}

	parsedTok, err := token.UnsafeParseClaims(strToken)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "failed to parse token issuer",
		})
		log.Debugf("requireAuthForCreate(jwt): parse issuer: %v", err)
		return nil, false
	}
	return &authResult{caller: parsedTok.Issuer(), isAdmin: false}, true
}
