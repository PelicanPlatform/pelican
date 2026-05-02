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

package web_ui

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"go.uber.org/atomic"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	UserRole string
	Login    struct {
		User     string `form:"user"`
		Password string `form:"password"`
	}

	InitLogin struct {
		Code string `form:"code"`
	}

	PasswordReset struct {
		Password string `form:"password"`
	}

	WhoAmIRes struct {
		Authenticated bool     `json:"authenticated"`
		Role          UserRole `json:"role"`
		User          string   `json:"user"`
		// DisplayName is the human label from the User row (if any).
		// Surfaced here so the navbar's user menu can render it
		// without a second /me round-trip on every page mount.
		// Empty when the row has no display name set.
		DisplayName string `json:"displayName,omitempty"`
		// Scopes is the caller's effective user-grantable scope set
		// (DB user_scopes ∪ DB group_scopes via membership ∪
		// config-derived grants ∪ admin implications). Used by
		// the frontend to gate UI surfaces below the granularity of
		// Role: e.g. /settings/users/ is reachable by anyone with
		// server.user_admin (which is a subset of server.admin),
		// and the navbar toggles its visibility off scopes rather
		// than role membership. Empty for unauthenticated callers.
		Scopes      []string `json:"scopes,omitempty"`
		RequiresAUP bool     `json:"requires_aup,omitempty"`
		AUPVersion  string   `json:"aup_version,omitempty"`
	}

	OIDCEnabledServerRes struct {
		ODICEnabledServers []string `json:"oidc_enabled_servers"`
	}
)

var (
	authDB       atomic.Pointer[htpasswd.File]
	currentCode  atomic.Pointer[string]
	previousCode atomic.Pointer[string]
)

const (
	AdminRole    UserRole = "admin"
	NonAdminRole UserRole = "user"
)

// Periodically re-read the htpasswd file used for password-based authentication
func periodicAuthDBReload(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Debug("Reloading the auth database")
			_ = doReload()
		case <-ctx.Done():
			return nil
		}
	}
}

func configureAuthDB() error {
	fileName := param.Server_UIPasswordFile.GetString()
	if fileName == "" {
		return errors.New("Location of password file not set")
	}
	fp, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	scanner.Split(bufio.ScanLines)
	hasAdmin := false
	for scanner.Scan() {
		user := strings.Split(scanner.Text(), ":")[0]
		if user == "admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return errors.New("AuthDB does not have 'admin' user")
	}

	auth, err := htpasswd.New(fileName, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	if err != nil {
		return err
	}
	authDB.Store(auth)

	return nil
}

// extractUserFromBearerToken parses and verifies a Bearer token, extracting user info.
// Uses early-exit pattern for cleaner flow control.
//
// Security contract: ONLY tokens issued by *this* server (issuer claim
// equal to Server.ExternalWebUrl AND signed by our key) are trusted to
// carry user_id / oidc_sub / wlcg.groups. Tokens from federation,
// registered-server, or any third-party OIDC issuer must NOT reach this
// code path — those go through the dedicated checkers in token/token_verify.go,
// which deliberately do not extract user-identity claims. The reasoning:
// some IdPs let users self-assert arbitrary non-standard claims, so
// trusting `user_id` from "any verified token" would let the user
// declare themselves into a different account.
func extractUserFromBearerToken(ctx *gin.Context, tokenStr string) (user string, userId string, groups []string, err error) {
	// Parse token without verification first to check issuer
	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		return "", "", nil, err
	}

	// Verify issuer matches local issuer
	serverURL := param.Server_ExternalWebUrl.GetString()
	if serverURL == "" {
		return "", "", nil, errors.New("Server.ExternalWebUrl is not configured; cannot validate bearer tokens")
	}
	if parsed.Issuer() != serverURL {
		return "", "", nil, errors.New("token issuer does not match server URL")
	}

	// Verify signature
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return "", "", nil, err
	}

	verified, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(jwks))
	if err != nil {
		return "", "", nil, err
	}

	// Validate standard claims AND re-pin the issuer in the validator
	// (defense-in-depth: jwt.WithKeySet only proves the signature is
	// from our key, not that the claims are still consistent).
	if err = jwt.Validate(verified, jwt.WithIssuer(serverURL)); err != nil {
		return "", "", nil, err
	}

	// Extract user from subject
	user = verified.Subject()
	if user == "" {
		return "", "", nil, errors.New("token has empty subject")
	}

	// Extract userId claim
	if userIdIface, ok := verified.Get("user_id"); ok {
		if userIdStr, ok := userIdIface.(string); ok && userIdStr != "" {
			userId = userIdStr
		}
	}

	// Extract oidc_sub claim for admin checks against UIAdminUsers
	if oidcSubIface, ok := verified.Get("oidc_sub"); ok {
		if oidcSub, ok := oidcSubIface.(string); ok && oidcSub != "" {
			ctx.Set("OIDCSub", oidcSub)
		}
	}

	// Extract groups
	groupsIface, ok := verified.Get("wlcg.groups")
	if ok {
		if groupsTmp, ok := groupsIface.([]interface{}); ok {
			groups = make([]string, 0, len(groupsTmp))
			for _, groupObj := range groupsTmp {
				if groupStr, ok := groupObj.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		}
	}

	// Set in context for later use
	ctx.Set("User", user)
	if userId != "" {
		ctx.Set("UserId", userId)
	}
	if len(groups) > 0 {
		ctx.Set("Groups", groups)
	}

	return user, userId, groups, nil
}

// Get user information including userId from the login cookie or Bearer token.
// Returns username, userId, sub, issuer, groups, and error.
func GetUserGroups(ctx *gin.Context) (user string, userId string, groups []string, err error) {
	// First check if user info was already set in context (e.g., from Bearer token verification)
	if userIface, exists := ctx.Get("User"); exists {
		if userStr, ok := userIface.(string); ok && userStr != "" {
			user = userStr
			// Extract userId from context if available
			if userIdIface, exists := ctx.Get("UserId"); exists {
				if userIdStr, ok := userIdIface.(string); ok {
					userId = userIdStr
				}
			}
			// Extract groups from context if available
			if groupsIface, exists := ctx.Get("Groups"); exists {
				if groupsSlice, ok := groupsIface.([]string); ok {
					groups = groupsSlice
				}
			}
			return
		}
	}

	// Check for Bearer token in Authorization header
	headerToken := ctx.Request.Header["Authorization"]
	if len(headerToken) > 0 {
		tokenStr, found := strings.CutPrefix(headerToken[0], "Bearer ")
		if found && tokenStr != "" {
			user, userId, groups, err = extractUserFromBearerToken(ctx, tokenStr)
			if err == nil && user != "" {
				return
			}
			// Bearer token failed, fall through to cookie check
		}
	}

	var token string
	token, err = ctx.Cookie("login")
	if err != nil {
		if err == http.ErrNoCookie {
			err = nil
			return
		} else {
			return
		}
	}
	if token == "" {
		err = errors.New("Login cookie is empty")
		return
	}
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwks))
	if err != nil {
		return
	}
	// Verify standard claims AND that the cookie was issued by *this*
	// server. Signature verification alone isn't enough: the local
	// issuer key signs many other token kinds (advertise tokens,
	// federation registration tokens, file-transfer test tokens, ...)
	// and a cookie reader that only checks the signature would happily
	// accept any of them as a session token. Adding the issuer +
	// audience match pins the cookie to the login flow specifically —
	// only setLoginCookie sets both to Server.ExternalWebUrl.
	externalUrl := param.Server_ExternalWebUrl.GetString()
	if externalUrl == "" {
		err = errors.New("Server.ExternalWebUrl is not configured; cannot validate login cookie")
		return
	}
	if err = jwt.Validate(parsed,
		jwt.WithIssuer(externalUrl),
		jwt.WithAudience(externalUrl),
	); err != nil {
		return
	}
	user = parsed.Subject()

	// Extract userId claim. user_id, oidc_sub, oidc_iss, and wlcg.groups
	// are EXTRACTED FROM THE COOKIE, not from the upstream OIDC token
	// directly: they were captured at login time by setLoginCookie and
	// re-asserted by us. Because we just verified the cookie's issuer
	// and audience match the local server, these claims are trustworthy.
	// Do NOT extend this code to read the same claims out of bearer
	// tokens minted by other issuers — see extractUserFromBearerToken
	// for the (more restrictive) rule there.
	userIdIface, ok := parsed.Get("user_id")
	if !ok {
		err = errors.New("Missing user_id claim")
		return
	}
	userId, ok = userIdIface.(string)
	if !ok {
		err = errors.New("Invalid user_id claim")
		return
	}

	// Extract oidc_sub claim (the OIDC subject identifier)
	// This is set in context so admin checks can match against UIAdminUsers
	if oidcSubIface, ok := parsed.Get("oidc_sub"); ok {
		if oidcSub, ok := oidcSubIface.(string); ok && oidcSub != "" {
			ctx.Set("OIDCSub", oidcSub)
		}
	}

	// Extract oidc_iss claim (the OIDC issuer that authenticated this user)
	if oidcIssIface, ok := parsed.Get("oidc_iss"); ok {
		if oidcIss, ok := oidcIssIface.(string); ok && oidcIss != "" {
			ctx.Set("OIDCIss", oidcIss)
		}
	}

	groupsIface, ok := parsed.Get("wlcg.groups")
	if ok {
		if groupsTmp, ok := groupsIface.([]interface{}); ok {
			groups = make([]string, 0, len(groupsTmp))
			for _, groupObj := range groupsTmp {
				if groupStr, ok := groupObj.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		}
	}
	return
}

// Create a JWT and set the "login" cookie to store that JWT
func setLoginCookie(ctx *gin.Context, userRecord *database.User, groups []string) {

	// Lifetime of the login token and the cookie that stores it
	loginLifetime := 16 * time.Hour

	loginCookieTokenCfg := token.NewWLCGToken()
	loginCookieTokenCfg.Lifetime = loginLifetime
	loginCookieTokenCfg.Issuer = param.Server_ExternalWebUrl.GetString()
	loginCookieTokenCfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	loginCookieTokenCfg.Subject = userRecord.Username
	loginCookieTokenCfg.AddScopes(token_scopes.WebUi_Access)
	loginCookieTokenCfg.AddGroups(groups...)

	// For backwards compatibility (see #398), add additional scopes
	// for expert admins who extract the login cookie from their browser
	// and use it to query monitoring endpoints directly.
	identity := UserIdentity{
		Username: loginCookieTokenCfg.Subject,
		ID:       userRecord.ID,
		Sub:      userRecord.Sub,
		Groups:   groups,
	}
	if isAdmin, _ := CheckAdmin(identity); isAdmin {
		loginCookieTokenCfg.AddScopes(token_scopes.Monitoring_Query, token_scopes.Monitoring_Scrape)
	}

	// Add claims for unique user resolution using userId
	loginCookieTokenCfg.Claims = map[string]string{
		"user_id":  userRecord.ID,
		"oidc_sub": userRecord.Sub,
		"oidc_iss": userRecord.Issuer,
	}

	// CreateToken also handles validation for us
	tok, err := loginCookieTokenCfg.CreateToken()
	if err != nil {
		log.Errorln("Failed to create login cookie token:", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Unable to create login cookies",
			})
		return
	}

	// One cookie should be used for all path
	ctx.SetCookie("login", tok, int(loginLifetime.Seconds()), "/", ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)

	// Track last login time
	if userRecord.ID != "" {
		if err := database.UpdateUserLastLogin(database.ServerDatabase, userRecord.ID); err != nil {
			log.Warnf("Failed to update last login time for user %s: %v", userRecord.ID, err)
		}
	}
}

// Check if user is authenticated by checking if the "login" cookie is present and set the user identity to ctx
func AuthHandler(ctx *gin.Context) {
	user, userId, groups, err := GetUserGroups(ctx)
	if user == "" || err != nil {
		if err != nil {
			log.Errorln("Invalid user cookie or unable to parse user cookie:", err)
		}
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication required to perform this operation",
			})
		return
	}

	// Soft-delete / inactive revocation. The cookie is good — but
	// the user record may have been removed (DeletedAt set, which
	// GORM's default scope filters out) or marked inactive since
	// the cookie was issued. Without this check, those state
	// changes don't take effect until the cookie expires (up to
	// 16h). Skip the check when userId is empty (legacy cookie
	// without a user_id claim, or a path that intentionally doesn't
	// carry one); those callers are already minimal-trust.
	if userId != "" && !userRecordIsActive(userId) {
		// Clear the now-revoked cookie so the next request goes
		// through the login flow rather than tripping the same
		// 401 again.
		ctx.SetCookie("login", "", -1, "/", ctx.Request.URL.Host, true, true)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Your account has been deactivated. Please log in again.",
			})
		return
	}

	ctx.Set("User", user)
	ctx.Set("UserId", userId)
	ctx.Set("Groups", groups)
	ctx.Next()
}

// userRecordIsActive reports whether the supplied user ID resolves to
// a live (non-soft-deleted) row whose Status is active. Used by
// AuthHandler to revoke live sessions when an admin deletes or
// inactivates a user — without this, those changes wouldn't take
// effect until the user's 16h cookie expired.
//
// Returns true when the DB isn't reachable, when the lookup fails for
// reasons other than not-found, or when ServerDatabase is nil. We
// fail-OPEN on those error paths because failing-CLOSED would lock
// every authenticated user out of every protected page during a
// transient DB hiccup. The cost is a small "deletion takes effect
// only once the DB recovers" window, which is acceptable.
//
// Special case: the built-in "admin" username comes from the htpasswd
// bootstrap path; if BootstrapAdminAndBackfillOwners hasn't run yet
// (Server.ExternalWebUrl unconfigured), there's no row to look up.
// The caller's userId would be empty in that case, so AuthHandler
// short-circuits before reaching this function.
func userRecordIsActive(userId string) bool {
	if database.ServerDatabase == nil {
		return true
	}
	user, err := database.GetUserByID(database.ServerDatabase, userId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Soft-deleted (GORM filters out via DeletedAt) or never
			// existed. Either way, the cookie is no longer valid.
			return false
		}
		// Unexpected error — log and fail-open per the contract above.
		log.Warnf("Failed to validate user record %s on cookie read: %v", userId, err)
		return true
	}
	return user.Status != database.UserStatusInactive
}

// CurrentAUPVersion lives in web_ui/aup.go alongside the embedded
// default and source-resolution logic.

// userHasAcceptedAUP returns true when the user's AUPVersion matches
// the configured AUP's current version, or when no AUP is configured
// (in which case there is nothing to accept).
func userHasAcceptedAUP(userID string) (bool, error) {
	_, version, err := CurrentAUPVersion()
	if err != nil {
		return false, err
	}
	if version == "" {
		return true, nil
	}
	user, err := database.GetUserByID(database.ServerDatabase, userID)
	if err != nil {
		return false, err
	}
	return user.AUPVersion == version, nil
}

// RequireAUPCompliance is a gate that runs after AuthHandler and blocks
// the request when the caller has not yet agreed to the current AUP.
//
// AUP signing is a hard precondition for using the system per the
// Pelican design contract: a user who refuses must not be able to
// proceed with anything other than (a) reading the AUP, (b) signing it,
// or (c) logging out. Those endpoints are intentionally NOT wrapped in
// this middleware; everything else that touches user-affecting state is.
//
// The 403 body carries `requires_aup: true` so the frontend can route
// the user to the AUP page; the version field matches the one returned
// by /whoami, so the UI can compute "this is the version I need to
// sign" without a separate fetch.
func RequireAUPCompliance(ctx *gin.Context) {
	userID := ctx.GetString("UserId")
	if userID == "" {
		// AuthHandler should have populated this; if it didn't,
		// short-circuit with 401 rather than fail open.
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication required",
			})
		return
	}
	ok, err := userHasAcceptedAUP(userID)
	if err != nil {
		// Don't fail closed on a transient DB / file error: log and
		// allow through. Returning 500 here would lock everyone out
		// any time the AUP file is briefly unreadable, which is worse
		// than the (small) window where an unsigned user gets through.
		log.Warnf("Failed to evaluate AUP compliance for user %s: %v", userID, err)
		ctx.Next()
		return
	}
	if ok {
		ctx.Next()
		return
	}
	_, version, _ := CurrentAUPVersion()
	ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"status":       server_structs.RespFailed,
		"msg":          "You must accept the Acceptable Use Policy before using this server.",
		"requires_aup": true,
		"aup_version":  version,
	})
}

// Require auth; if missing, redirect to the login endpoint.
//
// The current implementation forces the OAuth2 endpoint; future work may instead use a generic
// login page.
func RequireAuthMiddleware(ctx *gin.Context) {
	user, userId, groups, err := GetUserGroups(ctx)
	if user == "" || err != nil {
		origPath := ctx.Request.URL.RequestURI()
		redirUrl := url.URL{
			Path:     oauthLoginPath,
			RawQuery: "nextUrl=" + url.QueryEscape(origPath),
		}
		ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
		ctx.Abort()
	} else {
		ctx.Set("User", user)
		ctx.Set("UserId", userId)
		ctx.Set("Groups", groups)
		ctx.Next()
	}
}

// UserIdentity encapsulates all available information about a user's identity
type UserIdentity struct {
	Username string
	ID       string
	Sub      string // OIDC Subject
	Groups   []string
}

// CheckAdmin reports whether the identity holds the server.admin
// scope. The decision is delegated to EffectiveScopesForIdentity,
// which unions DB-stored user_scopes/group_scopes grants with the
// historical config-derived sources (Server.UIAdminUsers,
// Server.AdminGroups, the built-in "admin" username).
//
// All matches are username-based — never ID, never OIDC Sub — so a
// malicious IdP cannot mint a token with sub == an admin's name and
// inherit privileges. See the user/group design doc for the reason
// usernames are the only authorization handle.
func CheckAdmin(identity UserIdentity) (isAdmin bool, message string) {
	if hasScope(identity, token_scopes.Server_Admin) {
		return true, ""
	}
	// Preserve the historical "neither configured" message so existing
	// monitoring / docs that key off it still work.
	if !param.Server_AdminGroups.IsSet() && !param.Server_UIAdminUsers.IsSet() && identity.Username != "admin" {
		return false, "Server.UIAdminUsers and Server.UIAdminGroups are not set, and user is not root user. Admin check returns false"
	}
	return false, "You don't have permission to perform this action"
}

// CheckUserAdmin reports whether the identity holds the
// server.user_admin scope. server.admin implies it (the
// implication is applied inside EffectiveScopesForIdentity).
func CheckUserAdmin(identity UserIdentity) (bool, string) {
	if hasScope(identity, token_scopes.Server_UserAdmin) {
		return true, ""
	}
	return false, "You don't have user administrator permission"
}

// CheckCollectionAdmin reports whether the identity holds the
// server.collection_admin scope. server.admin implies it.
func CheckCollectionAdmin(identity UserIdentity) (bool, string) {
	if hasScope(identity, token_scopes.Server_CollectionAdmin) {
		return true, ""
	}
	return false, "You don't have collection administrator permission"
}

// IsSystemAdminUserID checks whether the given user ID belongs to a system admin.
// This is used to prevent user administrators from modifying system admin accounts.
func IsSystemAdminUserID(db *gorm.DB, userID string) bool {
	user, err := database.GetUserByID(db, userID)
	if err != nil {
		return false
	}
	identity := UserIdentity{
		Username: user.Username,
		ID:       user.ID,
		Sub:      user.Sub,
	}
	isAdmin, _ := CheckAdmin(identity)
	return isAdmin
}

// UserAdminAuthHandler accepts callers whose effective scope set
// contains EITHER server.admin OR server.user_admin. It is the
// route-level gate for the /api/v1.0/users/* surface and the
// onboarding-invite endpoint: surfaces a system administrator must be
// able to use, and which a "user administrator" (per the design
// contract: manage non-admin users and unprivileged groups) is also
// expected to use. Per-target guards inside the handlers (notably
// IsSystemAdminUserID) prevent a user-admin from acting on a
// system-admin account; this gate just decides who clears the door.
//
// Cascade behind AuthHandler (cookie/bearer parsing must have run
// first so the identity is in context).
func UserAdminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login required to view this page",
			})
		return
	}
	var groups []string
	if v, exists := ctx.Get("Groups"); exists {
		if s, ok := v.([]string); ok {
			groups = s
		}
	}
	identity := UserIdentity{
		Username: user,
		Groups:   groups,
		ID:       ctx.GetString("UserId"),
		Sub:      ctx.GetString("OIDCSub"),
	}
	if isAdmin, _ := CheckAdmin(identity); isAdmin {
		ctx.Next()
		return
	}
	if isUserAdmin, _ := CheckUserAdmin(identity); isUserAdmin {
		ctx.Next()
		return
	}
	ctx.AbortWithStatusJSON(http.StatusForbidden,
		server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "You do not have user administrator permission",
		})
}

// AdminAuthHandler checks the admin status of a logged-in user. This middleware
// should be cascaded behind the [web_ui.AuthHandler]
func AdminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	// This should be done by a regular auth handler from the upstream, but we check here just in case
	if user == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login required to view this page",
			})
		return
	}
	// Get groups from context if available
	var groups []string
	if groupsIface, exists := ctx.Get("Groups"); exists {
		if groupsSlice, ok := groupsIface.([]string); ok {
			groups = groupsSlice
		}
	}

	identity := UserIdentity{
		Username: user,
		Groups:   groups,
		ID:       ctx.GetString("UserId"),
		Sub:      ctx.GetString("OIDCSub"),
	}

	isAdmin, msg := CheckAdmin(identity)
	if isAdmin {
		ctx.Next()
		return
	} else {
		ctx.AbortWithStatusJSON(http.StatusForbidden,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    msg,
			})
	}
}

// DowntimeAuthHandler allows EITHER:
// 1. Admin cookie authentication (req from this server itself), OR
// 2. Server bearer token authentication (req from another server, i.e. origin/cache)
func DowntimeAuthHandler(ctx *gin.Context) {
	// First, try cookie-based admin auth (this block consolidates AuthHandler and AdminAuthHandler)
	user, userId, groups, err := GetUserGroups(ctx)
	if user != "" && err == nil {
		identity := UserIdentity{
			Username: user,
			ID:       userId,
			Groups:   groups,
			Sub:      ctx.GetString("OIDCSub"),
		}

		// User has valid cookie, check if admin
		isAdmin, _ := CheckAdmin(identity)
		if isAdmin {
			ctx.Set("User", user)
			ctx.Set("UserId", userId)
			ctx.Set("Groups", groups)
			ctx.Set("AuthMethod", "admin-cookie")
			ctx.Next()
			return
		}
	}

	// If not admin cookie, try bearer token from header
	var requiredScope token_scopes.TokenScope
	switch ctx.Request.Method {
	case http.MethodPost:
		requiredScope = token_scopes.Pelican_DowntimeCreate
	case http.MethodPut:
		requiredScope = token_scopes.Pelican_DowntimeModify
	case http.MethodDelete:
		requiredScope = token_scopes.Pelican_DowntimeDelete
	default:
		// Fallback: require create/modify/delete not for GETs (which don't hit this handler).
		requiredScope = token_scopes.Pelican_DowntimeModify
	}
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.RegisteredServer},
		Scopes:  []token_scopes.TokenScope{requiredScope},
	})
	if !ok || err != nil {
		ctx.AbortWithStatusJSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Failed to verify the token: ", err),
		})
		return
	}

}

// Handle regular username/password based login.
//
// Login order:
//  1. If a user with (username, externalURL) exists in the database AND has a
//     non-empty password_hash, verify against that hash. This is the primary
//     path for admin-created local accounts.
//  2. Otherwise fall back to the htpasswd file. The htpasswd path is used to
//     bootstrap the built-in "admin" account before any DB password is set
//     and to remain compatible with installations that already have one.
func loginHandler(ctx *gin.Context) {
	htDB := authDB.Load()
	externalUrl := param.Server_ExternalWebUrl.GetString()

	login := Login{}
	if ctx.ShouldBind(&login) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Missing user/password in form data",
			})
		return
	}
	if strings.TrimSpace(login.User) == "" {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "User is required",
			})
		return
	}
	if strings.TrimSpace(login.Password) == "" {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Password is required",
			})
		return
	}

	var userRecord *database.User

	// Step 1: try the local-user database.
	if externalUrl != "" {
		dbUser, dbErr := database.VerifyUserPassword(database.ServerDatabase, login.User, login.Password, externalUrl)
		if dbErr == nil {
			userRecord = dbUser
		} else if !errors.Is(dbErr, database.ErrInvalidPassword) {
			log.Errorf("Local password verification failed for user %s: %s", login.User, dbErr)
			ctx.JSON(http.StatusInternalServerError,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Failed to verify credentials",
				})
			return
		}
	}

	// Step 2: fall back to htpasswd for users not yet in the DB (e.g. the
	// initial "admin" account before any DB password is set).
	if userRecord == nil {
		if htDB == nil {
			// No DB match and no htpasswd configured. If we're not yet
			// initialized, point the client at the bootstrap endpoint;
			// otherwise treat as an auth failure.
			if currentCode.Load() != nil {
				newPath := path.Join(ctx.Request.URL.Path, "..", "initLogin")
				initUrl := ctx.Request.URL
				initUrl.Path = newPath
				ctx.Redirect(307, initUrl.String())
				return
			}
			ctx.JSON(401,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Password and user didn't match",
				})
			return
		}
		if !htDB.Match(login.User, login.Password) {
			ctx.JSON(401,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Password and user didn't match",
				})
			return
		}
		// htpasswd verified — load or create the corresponding User row.
		// First htpasswd login for a new account counts as self-enrollment
		// (the user came in with their own credential, no other user
		// brought the account into existence).
		var err error
		userRecord, err = database.GetOrCreateUser(database.ServerDatabase, login.User, login.User, externalUrl, database.CreatorSelf())
		if err != nil {
			log.Errorf("Failed to get or create user %s: %s", login.User, err)
			ctx.JSON(http.StatusInternalServerError,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Failed to create user session",
				})
			return
		}
	}

	groups, err := generateGroupInfo(userRecord.Username)
	if err != nil {
		log.Errorf("Failed to generate group info for user %s: %s", userRecord.Username, err)
		groups = nil
	}

	setLoginCookie(ctx, userRecord, groups)

	// Return nextUrl in the response so clients can redirect after login.
	// The frontend login page sends nextUrl when it wants the user redirected
	// back to a specific page (e.g. the device code verification page).
	nextUrl := ctx.Query("nextUrl")
	resp := gin.H{
		"status": server_structs.RespOK,
		"msg":    "success",
	}
	if nextUrl != "" {
		resp["nextUrl"] = nextUrl
	}
	ctx.JSON(http.StatusOK, resp)
}

// Handle initial code-based login for admin
func initLoginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication is already initialized",
			})
		return
	}
	curCode := currentCode.Load()
	if curCode == nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Code-based login is not available",
			})
		return
	}
	prevCode := previousCode.Load()

	code := InitLogin{}
	if ctx.ShouldBind(&code) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login code not provided",
			})
		return
	}

	if code.Code != *curCode && (prevCode == nil || code.Code != *prevCode) {
		ctx.JSON(401,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid login code",
			})
		return
	}

	groups, err := generateGroupInfo("admin")
	if err != nil {
		log.Errorln("Failed to generate group info for admin:", err)
		groups = nil
	}

	// Get or create the admin user in the database. The init-code path
	// is the bootstrap admin authenticating themselves — self-enrolled.
	externalUrl := param.Server_ExternalWebUrl.GetString()
	userRecord, err := database.GetOrCreateUser(database.ServerDatabase, "admin", "admin", externalUrl, database.CreatorSelf())
	if err != nil {
		log.Errorf("Failed to get or create admin user: %s", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to create admin session",
			})
		return
	}

	setLoginCookie(ctx, userRecord, groups)
}

// Handle reset password
func resetLoginHandler(ctx *gin.Context) {
	passwordReset := PasswordReset{}
	if ctx.ShouldBind(&passwordReset) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid password reset request",
			})
		return
	}

	user := ctx.GetString("User")

	if err := WritePasswordEntry(user, passwordReset.Password); err != nil {
		log.Errorf("Password reset for user %s failed: %s", user, err)
		ctx.JSON(500,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to reset password",
			})
	} else {
		log.Infof("Password reset for user %s was successful", user)
		ctx.JSON(http.StatusOK,
			server_structs.SimpleApiResp{
				Status: server_structs.RespOK,
				Msg:    "success",
			})
	}
	if err := configureAuthDB(); err != nil {
		log.Errorln("Error in reloading authDB:", err)
	}
}

func logoutHandler(ctx *gin.Context) {
	ctx.SetCookie("login", "", -1, "/", ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.Set("User", "")
	ctx.JSON(http.StatusOK,
		server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "success",
		})
}

// Returns the authentication status of the current user, including user id and role
func whoamiHandler(ctx *gin.Context) {
	res := WhoAmIRes{}
	if user, userId, groups, err := GetUserGroups(ctx); err != nil || user == "" {
		res.Authenticated = false
		ctx.JSON(http.StatusOK, res)
	} else {
		res.Authenticated = true
		res.User = user

		// Set header to carry CSRF token
		ctx.Header("X-CSRF-Token", csrf.Token(ctx.Request))
		identity := UserIdentity{
			Username: user,
			ID:       userId,
			Groups:   groups,
			Sub:      ctx.GetString("OIDCSub"),
		}
		isAdmin, _ := CheckAdmin(identity)
		if isAdmin {
			res.Role = AdminRole
		} else {
			res.Role = NonAdminRole
		}

		// Effective user-grantable scopes (DB grants + config-derived +
		// implications) — used by the frontend to gate /settings/users
		// for user-admins, render scope chips on the profile page, etc.
		effective := EffectiveScopesForIdentity(identity)
		if len(effective) > 0 {
			res.Scopes = make([]string, 0, len(effective))
			for _, s := range effective {
				res.Scopes = append(res.Scopes, s.String())
			}
		}

		// Pull the User row once per call. We use it for two things:
		// the optional DisplayName (surfaced for the navbar's user
		// menu) and the AUP-version comparison below. The cookie's
		// audience+issuer were verified upstream so the row's
		// authority is not a security check — just a label lookup.
		var userRecord *database.User
		if rec, dbErr := database.GetUserByID(database.ServerDatabase, userId); dbErr == nil {
			userRecord = rec
			res.DisplayName = rec.DisplayName
		}

		// Check AUP compliance. resolveAUP centralizes the operator-file
		// vs. embedded-default vs. "none" logic — see web_ui/aup.go.
		if doc, _ := resolveAUP(); doc != nil && userRecord != nil {
			if userRecord.AUPVersion != doc.Version {
				res.RequiresAUP = true
				res.AUPVersion = doc.Version
			}
		}

		ctx.JSON(http.StatusOK, res)
	}
}

func listOIDCEnabledServersHandler(ctx *gin.Context) {
	// All four module types are gated by their own EnableOIDC flag,
	// including the registry. Registry historically forced OIDC on
	// regardless of config; per the user/group design contract that's
	// now opt-in (Registry.EnableOIDC) so the registry can run with
	// only local username/password accounts.
	res := OIDCEnabledServerRes{ODICEnabledServers: []string{}}
	if param.Registry_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.RegistryType.String()))
	}
	if param.Origin_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.OriginType.String()))
	}
	if param.Cache_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.CacheType.String()))
	}
	if param.Director_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.DirectorType.String()))
	}
	ctx.JSON(http.StatusOK, res)
}

// Configure the authentication endpoints for the server web UI
func RegisterAuthEndpoints(ctx context.Context, routerGroup *gin.RouterGroup, egrp *errgroup.Group) error {
	if routerGroup == nil {
		return errors.New("Web engine configuration passed a nil pointer")
	}

	if err := configureAuthDB(); err != nil {
		log.Infoln("Authorization not configured (non-fatal):", err)
	}

	csrfHandler, err := config.GetCSRFHandler()
	if err != nil {
		return err
	}

	// Configure login rate limit middleware with the specified limit
	limit := param.Server_UILoginRateLimit.GetInt()
	loginRateMiddleware := loginRateLimitMiddleware(limit)

	routerGroup.POST("/login", loginRateMiddleware, loginHandler)
	routerGroup.POST("/logout", AuthHandler, logoutHandler)
	routerGroup.POST("/initLogin", ReadOnlyMiddleware, initLoginHandler)
	routerGroup.POST("/resetLogin", ReadOnlyMiddleware, AuthHandler, AdminAuthHandler, resetLoginHandler)
	// Pass csrfhanlder only to the whoami route to generate CSRF token
	// while leaving other routes free of CSRF check (we might want to do it some time in the future)
	routerGroup.GET("/whoami", csrfHandler, whoamiHandler)
	routerGroup.GET("/loginInitialized", func(ctx *gin.Context) {
		db := authDB.Load()
		if db == nil {
			ctx.JSON(200, gin.H{"initialized": false})
		} else {
			ctx.JSON(200, gin.H{"initialized": true})
		}
	})
	routerGroup.GET("/oauth", listOIDCEnabledServersHandler)

	egrp.Go(func() error { return periodicAuthDBReload(ctx) })

	return nil
}
