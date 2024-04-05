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
	"net/http"
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
	"github.com/pelicanplatform/pelican/param"
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

// Get the "subject" claim from the JWT that "login" cookie stores,
// where subject is set to be the username. Return empty string if no "login" cookie is present
func GetUser(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie("login")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", nil
		} else {
			return "", err
		}
	}
	if token == "" {
		return "", errors.New("Login cookie is empty")
	}
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return "", err
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwks))
	if err != nil {
		return "", err
	}
	if err = jwt.Validate(parsed); err != nil {
		return "", err
	}
	return parsed.Subject(), nil
}

// Create a JWT and set the "login" cookie to store that JWT
func setLoginCookie(ctx *gin.Context, user string) {
	loginCookieTokenCfg := token.NewWLCGToken()
	loginCookieTokenCfg.Lifetime = 30 * time.Minute
	loginCookieTokenCfg.Issuer = param.Server_ExternalWebUrl.GetString()
	loginCookieTokenCfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	loginCookieTokenCfg.Subject = user
	loginCookieTokenCfg.AddScopes(token_scopes.WebUi_Access, token_scopes.Monitoring_Query, token_scopes.Monitoring_Scrape)

	// CreateToken also handles validation for us
	tok, err := loginCookieTokenCfg.CreateToken()
	if err != nil {
		log.Errorln("Failed to create login cookie token:", err)
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to create login cookies"})
		return
	}

	// One cookie should be used for all path
	ctx.SetCookie("login", tok, 30*60, "/", ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)
}

// Check if user is authenticated by checking if the "login" cookie is present and set the user identity to ctx
func AuthHandler(ctx *gin.Context) {
	user, err := GetUser(ctx)
	if err != nil || user == "" {
		log.Errorln("Invalid user cookie or unable to parse user cookie:", err)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required to perform this operation"})
	} else {
		ctx.Set("User", user)
		ctx.Next()
	}
}

// checkAdmin checks if a user string has admin privilege. It returns boolean and a message
// indicating the error message.
//
// Note that by default it only checks if user == "admin". If you have a custom list of admin identifiers
// to check, you should set Server.UIAdminUsers. See parameters.yaml for details.
func CheckAdmin(user string) (isAdmin bool, message string) {
	if user == "admin" {
		return true, ""
	}
	adminList := param.Server_UIAdminUsers.GetStringSlice()
	if !param.Server_UIAdminUsers.IsSet() {
		return false, "Server.UIAdminUsers is not set, and user is not root user. Admin check returns false"
	}
	for _, admin := range adminList {
		if user == admin {
			return true, ""
		}
	}
	return false, "You don't have permission to perform this action"
}

// adminAuthHandler checks the admin status of a logged-in user. This middleware
// should be cascaded behind the [web_ui.AuthHandler]
func AdminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	// This should be done by a regular auth handler from the upstream, but we check here just in case
	if user == "" {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Login required to view this page"})
	}
	isAdmin, msg := CheckAdmin(user)
	if isAdmin {
		ctx.Next()
		return
	} else {
		ctx.JSON(http.StatusForbidden, gin.H{"error": msg})
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
		ctx.JSON(400, gin.H{"error": "Missing user/password in form data"})
		return
	}
	if strings.TrimSpace(login.User) == "" {
		ctx.JSON(400, gin.H{"error": "User is required"})
		return
	}
	if strings.TrimSpace(login.Password) == "" {
		ctx.JSON(400, gin.H{"error": "Password is required"})
		return
	}
	if !db.Match(login.User, login.Password) {
		ctx.JSON(401, gin.H{"error": "Password and user didn't match"})
		return
	}

	setLoginCookie(ctx, login.User)
	ctx.JSON(200, gin.H{"msg": "Success"})
}

// Handle initial code-based login for admin
func initLoginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db != nil {
		ctx.JSON(400, gin.H{"error": "Authentication is already initialized"})
		return
	}
	curCode := currentCode.Load()
	if curCode == nil {
		ctx.JSON(400, gin.H{"error": "Code-based login is not available"})
		return
	}
	prevCode := previousCode.Load()

	code := InitLogin{}
	if ctx.ShouldBind(&code) != nil {
		ctx.JSON(400, gin.H{"error": "Login code not provided"})
		return
	}

	if code.Code != *curCode && (prevCode == nil || code.Code != *prevCode) {
		ctx.JSON(401, gin.H{"error": "Invalid login code"})
		return
	}

	setLoginCookie(ctx, "admin")
}

// Handle reset password
func resetLoginHandler(ctx *gin.Context) {
	passwordReset := PasswordReset{}
	if ctx.ShouldBind(&passwordReset) != nil {
		ctx.JSON(400, gin.H{"error": "Invalid password reset request"})
		return
	}

	user := ctx.GetString("User")

	if err := WritePasswordEntry(user, passwordReset.Password); err != nil {
		log.Errorf("Password reset for user %s failed: %s", user, err)
		ctx.JSON(500, gin.H{"error": "Failed to reset password"})
	} else {
		log.Infof("Password reset for user %s was successful", user)
		ctx.JSON(200, gin.H{"msg": "Success"})
	}
	if err := configureAuthDB(); err != nil {
		log.Errorln("Error in reloading authDB:", err)
	}
}

func logoutHandler(ctx *gin.Context) {
	ctx.SetCookie("login", "", -1, "/", ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.Set("User", "")
	ctx.JSON(http.StatusOK, gin.H{"message": "Success"})
}

// Returns the authentication status of the current user, including user id and role
func whoamiHandler(ctx *gin.Context) {
	res := WhoAmIRes{}
	if user, err := GetUser(ctx); err != nil || user == "" {
		res.Authenticated = false
		ctx.JSON(http.StatusOK, res)
	} else {
		res.Authenticated = true
		res.User = user

		// Set header to carry CSRF token
		ctx.Header("X-CSRF-Token", csrf.Token(ctx.Request))
		isAdmin, _ := CheckAdmin(user)
		if isAdmin {
			res.Role = AdminRole
		} else {
			res.Role = NonAdminRole
		}
		ctx.JSON(http.StatusOK, res)
	}
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
			ctx.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Try again in " + time.Until(info.ResetTime).String()})
		},
		KeyFunc: func(ctx *gin.Context) string { return ctx.ClientIP() },
	})

	group := router.Group("/api/v1.0/auth")
	group.POST("/login", mw, loginHandler)
	group.POST("/logout", AuthHandler, logoutHandler)
	group.POST("/initLogin", initLoginHandler)
	group.POST("/resetLogin", AuthHandler, resetLoginHandler)
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

	egrp.Go(func() error { return periodicAuthDBReload(ctx) })

	return nil
}
