/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"crypto/ecdsa"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"go.uber.org/atomic"
)

type (
	Login struct {
		User     string `form:"user"`
		Password string `form:"password"`
	}

	InitLogin struct {
		Code string `form:"code"`
	}

	PasswordReset struct {
		Password string `form:"password"`
	}
)

var (
	authDB       atomic.Pointer[htpasswd.File]
	currentCode  atomic.Pointer[string]
	previousCode atomic.Pointer[string]
)

// Periodically re-read the htpasswd file used for password-based authentication
func periodicAuthDBReload() {
	for {
		time.Sleep(30 * time.Second)
		log.Debug("Reloading the auth database")
		_ = doReload()
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

// Get the "subjuect" claim from the JWT that "login" cookie stores,
// where subject is set to be the username. Return empty string if no "login" cookie is present
func getUser(ctx *gin.Context) (string, error) {
	token, err := ctx.Cookie("login")
	if err != nil {
		return "", nil
	}
	if token == "" {
		return "", errors.New("Login cookie is empty")
	}
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", err
	}
	var raw ecdsa.PrivateKey
	if err = key.Raw(&raw); err != nil {
		return "", errors.New("Failed to extract cookie signing key")
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKey(jwa.ES256, raw.PublicKey))
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
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		log.Errorln("Failure when loading the cookie signing key:", err)
		ctx.JSON(500, gin.H{"error": "Unable to create login cookies"})
		return
	}

	now := time.Now()
	tok, err := jwt.NewBuilder().
		Claim("scope", []string{"web_ui.access", "prometheus.read"}).
		Issuer(param.Server_ExternalWebUrl.GetString()).
		IssuedAt(now).
		Expiration(now.Add(30 * time.Minute)).
		NotBefore(now).
		Subject(user).
		Build()
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to build token"})
		return
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		ctx.JSON(500, gin.H{"error": "Failed to sign login token"})
		return
	}

	ctx.SetCookie("login", string(signed), 30*60, "/api/v1.0",
		ctx.Request.URL.Host, true, true)
	// Explicitly set Cookie for /metrics endpoint as they are in different paths
	ctx.SetCookie("login", string(signed), 30*60, "/metrics",
		ctx.Request.URL.Host, true, true)
	ctx.SetSameSite(http.SameSiteStrictMode)
}

// Check if user is authenticated by checking if the "login" cookie is present and set the user identity to ctx
func authHandler(ctx *gin.Context) {
	user, err := getUser(ctx)
	if err != nil || user == "" {
		log.Errorln("Invalid user cookie or unable to parse user cookie:", err)
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required to perform this operation"})
	} else {
		ctx.Set("User", user)
		ctx.Next()
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
	if !db.Match(login.User, login.Password) {
		ctx.JSON(401, gin.H{"error": "Login failed"})
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

// Configure the authentication endpoints for the server web UI
func configureAuthEndpoints(router *gin.Engine) error {
	if router == nil {
		return errors.New("Web engine configuration passed a nil pointer")
	}

	if err := configureAuthDB(); err != nil {
		log.Infoln("Authorization not configured (non-fatal):", err)
	}

	group := router.Group("/api/v1.0/auth")
	group.POST("/login", loginHandler)
	group.POST("/initLogin", initLoginHandler)
	group.POST("/resetLogin", authHandler, resetLoginHandler)
	group.GET("/whoami", func(ctx *gin.Context) {
		if user, err := getUser(ctx); err != nil || user == "" {
			ctx.JSON(200, gin.H{"authenticated": false})
		} else {
			ctx.JSON(200, gin.H{"authenticated": true, "user": user})
		}
	})
	group.GET("/loginInitialized", func(ctx *gin.Context) {
		db := authDB.Load()
		if db == nil {
			ctx.JSON(200, gin.H{"initialized": false})
		} else {
			ctx.JSON(200, gin.H{"initialized": true})
		}
	})

	go periodicAuthDBReload()

	return nil
}
