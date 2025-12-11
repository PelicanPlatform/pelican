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

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"go.uber.org/atomic"
	"golang.org/x/sync/errgroup"

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
func extractUserFromBearerToken(ctx *gin.Context, tokenStr string) (user string, userId string, groups []string, err error) {
	// Parse token without verification first to check issuer
	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		return "", "", nil, err
	}

	// Verify issuer matches local issuer
	serverURL := param.Server_ExternalWebUrl.GetString()
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

	if err = jwt.Validate(verified); err != nil {
		return "", "", nil, err
	}

	// Extract user from subject
	user = verified.Subject()
	if user == "" {
		return "", "", nil, errors.New("token has empty subject")
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
	if err = jwt.Validate(parsed); err != nil {
		return
	}
	user = parsed.Subject()

	// Extract userId claim
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
	if isAdmin, _ := CheckAdmin(loginCookieTokenCfg.Subject, groups); isAdmin {
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
}

// Check if user is authenticated by checking if the "login" cookie is present and set the user identity to ctx
func AuthHandler(ctx *gin.Context) {
	user, _, groups, err := GetUserGroups(ctx)
	if user == "" {
		if err != nil {
			log.Errorln("Invalid user cookie or unable to parse user cookie:", err)
		}
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication required to perform this operation",
			})
	} else {
		ctx.Set("User", user)
		ctx.Set("Groups", groups)
		ctx.Next()
	}
}

// Require auth; if missing, redirect to the login endpoint.
//
// The current implementation forces the OAuth2 endpoint; future work may instead use a generic
// login page.
func RequireAuthMiddleware(ctx *gin.Context) {
	user, _, groups, err := GetUserGroups(ctx)
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
		ctx.Set("Groups", groups)
		ctx.Next()
	}
}

// checkAdmin checks if a user string has admin privilege. It returns boolean and a message
// indicating the error message.
//
// Note that by default it only checks if user == "admin". If you have a custom list of admin identifiers
// to check, you should set Server.UIAdminUsers. If you want to grant admin privileges based on group
// membership, you should set Server.UIAdminGroups.
//
// groups is an optional parameter. If provided, the function will also check if the user belongs to
// any of the configured admin groups.
func CheckAdmin(user string, groups ...[]string) (isAdmin bool, message string) {
	if user == "admin" {
		return true, ""
	}

	// Check admin groups if groups are provided
	if len(groups) > 0 && groups[0] != nil {
		adminGroups := param.Server_UIAdminGroups.GetStringSlice()
		if param.Server_UIAdminGroups.IsSet() && len(adminGroups) > 0 {
			userGroups := groups[0]
			for _, userGroup := range userGroups {
				for _, adminGroup := range adminGroups {
					if userGroup == adminGroup {
						return true, ""
					}
				}
			}
		}
	}

	// Check admin users
	adminList := param.Server_UIAdminUsers.GetStringSlice()
	if param.Server_UIAdminUsers.IsSet() {
		for _, admin := range adminList {
			if user == admin {
				return true, ""
			}
		}
	}

	// If neither admin groups nor admin users are configured, and user is not "admin", deny access
	if !param.Server_UIAdminGroups.IsSet() && !param.Server_UIAdminUsers.IsSet() {
		return false, "Server.UIAdminUsers and Server.UIAdminGroups are not set, and user is not root user. Admin check returns false"
	}

	return false, "You don't have permission to perform this action"
}

// adminAuthHandler checks the admin status of a logged-in user. This middleware
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
	isAdmin, msg := CheckAdmin(user, groups)
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
	user, _, groups, err := GetUserGroups(ctx)
	if user != "" && err == nil {
		// User has valid cookie, check if admin
		isAdmin, _ := CheckAdmin(user, groups)
		if isAdmin {
			ctx.Set("User", user)
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

// Handle regular username/password based login
func loginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db == nil {
		newPath := path.Join(ctx.Request.URL.Path, "..", "initLogin")
		initUrl := ctx.Request.URL
		initUrl.Path = newPath
		ctx.Redirect(307, initUrl.String())
		return
	}

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
	if !db.Match(login.User, login.Password) {
		ctx.JSON(401,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Password and user didn't match",
			})
		return
	}

	groups, err := generateGroupInfo(login.User)
	if err != nil {
		log.Errorf("Failed to generate group info for user %s: %s", login.User, err)
		groups = nil
	}

	// Get or create the user in the database
	// For password-based login, we use the username as both sub and issuer with server URL
	externalUrl := param.Server_ExternalWebUrl.GetString()
	userRecord, err := database.GetOrCreateUser(database.ServerDatabase, login.User, login.User, externalUrl)
	if err != nil {
		log.Errorf("Failed to get or create user %s: %s", login.User, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to create user session",
			})
		return
	}

	setLoginCookie(ctx, userRecord, groups)
	ctx.JSON(http.StatusOK,
		server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "success",
		})
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

	// Get or create the admin user in the database
	externalUrl := param.Server_ExternalWebUrl.GetString()
	userRecord, err := database.GetOrCreateUser(database.ServerDatabase, "admin", "admin", externalUrl)
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
	if user, _, groups, err := GetUserGroups(ctx); err != nil || user == "" {
		res.Authenticated = false
		ctx.JSON(http.StatusOK, res)
	} else {
		res.Authenticated = true
		res.User = user

		// Set header to carry CSRF token
		ctx.Header("X-CSRF-Token", csrf.Token(ctx.Request))
		isAdmin, _ := CheckAdmin(user, groups)
		if isAdmin {
			res.Role = AdminRole
		} else {
			res.Role = NonAdminRole
		}
		ctx.JSON(http.StatusOK, res)
	}
}

func listOIDCEnabledServersHandler(ctx *gin.Context) {
	// Registry has OIDC enabled by default
	res := OIDCEnabledServerRes{ODICEnabledServers: []string{strings.ToLower(server_structs.RegistryType.String())}}
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
func configureAuthEndpoints(ctx context.Context, router *gin.Engine, egrp *errgroup.Group) error {
	if router == nil {
		return errors.New("Web engine configuration passed a nil pointer")
	}

	if err := configureAuthDB(); err != nil {
		log.Infoln("Authorization not configured (non-fatal):", err)
	}

	csrfHandler, err := config.GetCSRFHandler()
	if err != nil {
		return err
	}
	limit := param.Server_UILoginRateLimit.GetInt()
	if limit <= 0 {
		log.Warning("Invalid Server.UILoginRateLimit. Value is less than 1. Fallback to 1")
		limit = 1
	}

	store := ratelimit.InMemoryStore(&ratelimit.InMemoryOptions{
		Rate:  time.Second,
		Limit: uint(limit),
	})
	mw := ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: func(ctx *gin.Context, info ratelimit.Info) {
			ctx.JSON(http.StatusTooManyRequests,
				server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "Too many requests. Try again in " + time.Until(info.ResetTime).String(),
				})
		},
		KeyFunc: func(ctx *gin.Context) string { return ctx.ClientIP() },
	})

	group := router.Group("/api/v1.0/auth")
	group.POST("/login", mw, loginHandler)
	group.POST("/logout", AuthHandler, logoutHandler)
	group.POST("/initLogin", initLoginHandler)
	group.POST("/resetLogin", AuthHandler, AdminAuthHandler, resetLoginHandler)
	// Pass csrfhanlder only to the whoami route to generate CSRF token
	// while leaving other routes free of CSRF check (we might want to do it some time in the future)
	group.GET("/whoami", csrfHandler, whoamiHandler)
	group.GET("/loginInitialized", func(ctx *gin.Context) {
		db := authDB.Load()
		if db == nil {
			ctx.JSON(200, gin.H{"initialized": false})
		} else {
			ctx.JSON(200, gin.H{"initialized": true})
		}
	})
	group.GET("/oauth", listOIDCEnabledServersHandler)

	egrp.Go(func() error { return periodicAuthDBReload(ctx) })

	return nil
}
