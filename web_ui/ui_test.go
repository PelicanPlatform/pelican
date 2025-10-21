//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func setupTestAuthDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := path.Join(tmpDir, "authdb")
	_, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	passFile, err := htpasswd.New(dbPath, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	require.NoError(t, err)

	authDB.Store(passFile)
}

func cleanupAuthDB() {
	authDB.Store(nil)
}

func setupWebUIEnv(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel := context.WithCancel(context.Background())
	egrp, ctx := errgroup.WithContext(ctx)
	defer func() {
		if err := egrp.Wait(); err != nil {
			t.Fatal("Failure when shutting down service:", err)
		}
	}()
	defer cancel()

	testCfgDir := t.TempDir()
	server_utils.ResetTestState()
	viper.Set("ConfigDir", testCfgDir)

	//set a temporary password file:
	tempFile, err := os.CreateTemp("", "web-ui-passwd")
	if err != nil {
		t.Fatal("Failed to setup web-ui-passwd file:", err)
	}
	t.Cleanup(func() {
		os.Remove(tempFile.Name())
	})
	tempPasswdFile = tempFile
	//Override viper default for testing
	viper.Set(param.Server_UIPasswordFile.GetName(), tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		t.Fatal("Error making temp jwk dir:", err)
	}
	t.Cleanup(func() {
		os.RemoveAll(tempJWKDir)
	})

	//Override viper default for testing
	viper.Set(param.IssuerKeysDirectory.GetName(), filepath.Join(tempJWKDir, "issuer-keys"))

	// Ensure we load up the default configs.
	dirname, err := os.MkdirTemp("", "tmpDir")
	if err != nil {
		t.Fatal("Error making temp config dir:", err)
	}
	viper.Set("ConfigDir", dirname)
	viper.Set(param.Server_UILoginRateLimit.GetName(), 100)

	test_utils.MockFederationRoot(t, nil, nil)
	if err := config.InitServer(ctx, server_structs.OriginType); err != nil {
		t.Fatal("Failed to initialize server config:", err)
	}

	//Get keys
	_, err = config.GetIssuerPublicJWKS()
	if err != nil {
		t.Fatal("Error issuing jwks:", err)
	}
	router = gin.Default()

	//Configure Web API
	err = ConfigureServerWebAPI(ctx, router, egrp)
	if err != nil {
		t.Fatal("Error configuring web UI:", err)
	}
}

func TestHandleWebUIAuth(t *testing.T) {
	route := gin.New()
	route.GET("/view/*requestPath", handleWebUIAuth, func(ctx *gin.Context) { ctx.Status(200) })

	t.Run("redirect-to-init-without-db", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/initialization/code/", r.Result().Header.Get("Location"))
	})

	t.Run("init-page-no-redirct-without-db", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/initialization/password/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
	})

	t.Run("no-redirect-without-db-on-init-page", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
	})

	t.Run("no-redirect-to-login-with-db-initialized", func(t *testing.T) {
		// We let the frontend to handle unauthorized user (if the password is initialized)
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages, so we will pass the admin check and return 200
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages, so we will pass the admin check and return 200
		req, err = http.NewRequest("GET", "/view/registry/origin", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		r = httptest.NewRecorder()
		// This route **is** in ui.go/adminAccessPages,
		// so we will check if the user is logged in and if not redirect to login
		req, err = http.NewRequest("GET", "/view/origin", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, http.StatusFound, r.Result().StatusCode)

		authDB.Store(nil)
	})

	t.Run("403-for-logged-in-non-admin-user", func(t *testing.T) {
		server_utils.ResetTestState()
		// We let the frontend to handle unauthorized user (if the password is initialized)
		setupTestAuthDB(t)
		t.Cleanup(func() {
			cleanupAuthDB()
			server_utils.ResetTestState()
		})

		tmpDir := t.TempDir()
		issuerDirectory := filepath.Join(tmpDir, "issuer-keys")
		viper.Set(param.IssuerKeysDirectory.GetName(), issuerDirectory)
		viper.Set(param.Server_ExternalWebUrl.GetName(), "https://example.com")

		_, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)

		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "regular-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages
		req, err := http.NewRequest("GET", "/view/test.html", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route is not in ui.go/adminAccessPages
		req, err = http.NewRequest("GET", "/view/registry/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)

		r = httptest.NewRecorder()
		// This route **is** in ui.go/adminAccessPages, and the user is not logged in as admin.
		// Send them to the 403 page to explain why they can't access the page
		req, err = http.NewRequest("GET", "/view/origin", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusFound, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/cache/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusFound, r.Result().StatusCode)

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/config/", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusFound, r.Result().StatusCode)

		authDB.Store(nil)
	})

	t.Run("init-page-redirect-to-root-with-db-initialized", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/initialization/code/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/", r.Result().Header.Get("Location"))

		r = httptest.NewRecorder()
		req, err = http.NewRequest("GET", "/view/initialization/password/", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, "/view/", r.Result().Header.Get("Location"))

		authDB.Store(nil)
	})

	t.Run("skip-check-on-non-html-file", func(t *testing.T) {
		cleanupAuthDB()
		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/test.js", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-director", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/director/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})

	t.Run("pass-check-on-registry", func(t *testing.T) {
		setupTestAuthDB(t)
		t.Cleanup(cleanupAuthDB)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/view/registry/index.html", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)

		assert.Equal(t, 200, r.Result().StatusCode)
		assert.Equal(t, "", r.Result().Header.Get("Location"))
	})
}

func TestMapPrometheusPath(t *testing.T) {
	t.Run("aggregate-frontend-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/view/_next/static/123.js", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/view/_next/:resource", get)
	})

	t.Run("aggregate-healthtest-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/healthTest/pelican/self-test-monitoring-123-456.txt", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/healthTest/:testfile", get)
	})

	t.Run("aggregate-two-level-origin-redirect-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar/barz", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar/:path", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar.txt", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar/level3/level4/file.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/object/foo/bar/:path", get)
	})

	t.Run("aggregate-two-level-object-redirect-path", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar/barz", nil)
		c.Request = req

		get := mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar/:path", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar.txt", get)

		c, _ = gin.CreateTestContext(httptest.NewRecorder())
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar/level3/level4/file.txt", nil)
		c.Request = req

		get = mapPrometheusPath(c)
		assert.Equal(t, "/api/v1.0/director/origin/foo/bar/:path", get)
	})
}

func TestServerHostRestart(t *testing.T) {
	route := gin.New()
	route.POST("/api/v1.0/restart", AuthHandler, AdminAuthHandler, hotRestartServer)
	viper.Set(param.IssuerKey.GetName(), filepath.Join(t.TempDir(), "issuer.jwk"))

	t.Run("unauthorized-no-token", func(t *testing.T) {
		r := httptest.NewRecorder()
		req, err := http.NewRequest("POST", "/api/v1.0/restart", nil)
		require.NoError(t, err)
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusUnauthorized, r.Result().StatusCode)
	})

	t.Run("forbidden-non-admin-user", func(t *testing.T) {
		// Create token for regular user
		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "regular-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		req, err := http.NewRequest("POST", "/api/v1.0/restart", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: tok})
		route.ServeHTTP(r, req)
		assert.Equal(t, http.StatusForbidden, r.Result().StatusCode)
	})

	t.Run("success-admin-user", func(t *testing.T) {
		// Create a buffered channel for restart flag
		config.RestartFlag = make(chan any, 1)
		// Create token for admin user
		tk := token.NewWLCGToken()
		tk.Issuer = "https://example.com"
		tk.Subject = "admin-user"
		tk.Lifetime = 5 * time.Minute
		tk.AddAudiences("https://example.com")
		tk.AddScopes(token_scopes.WebUi_Access)
		tok, err := tk.CreateToken()
		require.NoError(t, err)

		r := httptest.NewRecorder()
		viper.Set(param.Server_UIAdminUsers.GetName(), []string{"admin1", "admin2"})
		c := gin.CreateTestContextOnly(r, route)
		c.Set("User", "admin1")
		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/restart", nil)
		c.Request = req
		require.NoError(t, err)
		c.Request.AddCookie(&http.Cookie{Name: "login", Value: tok})

		// Create a done channel to signal when the handler completes
		done := make(chan struct{})
		// Start another goroutine to handle the restart flag
		// Handler goroutine: Sends data to channel config.RestartFlag
		// Main test goroutine: Receives data from channel config.RestartFlag
		// This prevents deadlock because both the sender and receiver are
		// running concurrently instead of sequentially
		go func() {
			defer close(done)
			// Call the handler directly with the context
			hotRestartServer(c)
		}()

		// Wait for either the handler to complete or context to timeout
		select {
		case <-done:
			// Handler completed (the done channel is closed)
		case <-c.Done():
			t.Fatal("Handler timed out")
			return
		}

		// Check response status and body
		assert.Equal(t, http.StatusOK, r.Result().StatusCode)
		var resp server_structs.SimpleApiResp
		err = json.NewDecoder(r.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RespOK, resp.Status)
		assert.Equal(t, "Server hot restart initiated", resp.Msg)

		// Verify that the restart flag was sent
		select {
		case flag := <-config.RestartFlag:
			assert.Equal(t, true, flag)
		case <-c.Done():
			t.Fatal("Context timeout while waiting for restart flag")
		case <-time.After(time.Second):
			t.Fatal("Timeout waiting for restart flag")
		}
	})
}

// Create an authentication token for testing purpose. This token can pass AuthHandler and AdminAuthHandler,
// allowing tests to proceed without authentication constraints
func generateTestAdminUserToken(t *testing.T) string {
	// Create token for admin user in test
	tk := token.NewWLCGToken()
	issuer := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, issuer, "Server ExternalWebUrl must be set for tests")
	tk.Issuer = issuer
	tk.Subject = "admin-user"
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(param.Server_ExternalWebUrl.GetString())
	tk.AddScopes(token_scopes.WebUi_Access)
	// Add OIDC claims required by GetUserGroups
	tk.Claims = map[string]string{
		"user_id": "admin-user",
	}
	tok, err := tk.CreateToken()
	if err != nil {
		t.Fatal("Failed to create test admin user token:", err)
	}
	return tok
}

func generateToken(t *testing.T, scopes []token_scopes.TokenScope, subject string) string {
	tk := token.NewWLCGToken()
	issuer := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, issuer, "Server ExternalWebUrl must be set for tests")
	tk.Issuer = issuer
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(param.Server_ExternalWebUrl.GetString())
	tk.AddScopes(scopes...)
	// Add OIDC claims required by GetUserGroups
	tk.Claims = map[string]string{
		"user_id": subject,
	}
	tok, err := tk.CreateToken()
	if err != nil {
		t.Fatal("Failed to create test token:", err)
	}
	return tok
}

func TestApiToken(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	route := gin.New()
	err := configureCommonEndpoints(route)
	require.NoError(t, err)
	route.GET("/privilegedRoute", func(ctx *gin.Context) {
		authOption := token.AuthOption{
			Sources: []token.TokenSource{token.Header},
			Issuers: []token.TokenIssuer{token.APITokenIssuer},
			Scopes:  []token_scopes.TokenScope{token_scopes.Monitoring_Scrape},
		}

		status, ok, err := token.Verify(ctx, authOption)
		if err != nil {
			ctx.JSON(status, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		} else if !ok {
			ctx.JSON(status, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Unable to verify token with the current authorization options",
			})
			return
		}
	})

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Set("ConfigDir", dirName)
	viper.Set(param.Server_UIAdminUsers.GetName(), "admin-user")
	test_utils.MockFederationRoot(t, nil, nil)
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	// Create a token to pass auth middlewares
	cookieValue := generateTestAdminUserToken(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")
	err = database.ServerDatabase.AutoMigrate(&server_structs.ApiKey{})
	require.NoError(t, err, "Failed to migrate DB for API key table")

	err = database.ServerDatabase.AutoMigrate(&database.Collection{})
	require.NoError(t, err, "Failed to migrate DB for collections table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMember{})
	require.NoError(t, err, "Failed to migrate DB for collection members table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMetadata{})
	require.NoError(t, err, "Failed to migrate DB for collection metadata table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionACL{})
	require.NoError(t, err, "Failed to migrate DB for collection ACLs table")
	err = database.ServerDatabase.AutoMigrate(&database.Group{})
	require.NoError(t, err, "Failed to migrate DB for groups table")
	err = database.ServerDatabase.AutoMigrate(&database.GroupMember{})
	require.NoError(t, err, "Failed to migrate DB for group members table")
	err = database.ServerDatabase.AutoMigrate(&database.User{})
	require.NoError(t, err, "Failed to migrate DB for users table")

	testCases := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "create-and-delete-token",
			run: func(t *testing.T) {
				// Create a token
				req, err := http.NewRequest("POST", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				createTokenReq := CreateApiTokenReq{
					Name:       "test-token",
					Expiration: "never",
					Scopes:     []string{token_scopes.Monitoring_Scrape.String()},
				}
				createTokenBody, err := json.Marshal(createTokenReq)
				assert.NoError(t, err)
				req.Body = io.NopCloser(bytes.NewReader(createTokenBody))

				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				require.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

				// Parse the response to retrieve the token
				var createTokenResp map[string]string
				err = json.NewDecoder(recorder.Body).Decode(&createTokenResp)
				assert.NoError(t, err)
				tokenStr := createTokenResp["token"]
				assert.NotEmpty(t, tokenStr)

				// Delete the token using its ID (the part before the dot)
				tokenID := strings.Split(tokenStr, ".")[0]
				endpoint := fmt.Sprintf("/api/v1.0/tokens/%s", tokenID)
				req, err = http.NewRequest("DELETE", endpoint, nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				recorder = httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
		{
			name: "unauthorized-create",
			run: func(t *testing.T) {
				req, err := http.NewRequest("POST", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
		{
			name: "unauthorized-delete",
			run: func(t *testing.T) {
				req, err := http.NewRequest("DELETE", "/api/v1.0/tokens/123", nil)
				assert.NoError(t, err)
				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
		{
			name: "unauthorized-privileged-route",
			run: func(t *testing.T) {
				req, err := http.NewRequest("GET", "/privilegedRoute", nil)
				assert.NoError(t, err)
				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
		{
			name: "authorized-privileged-route",
			run: func(t *testing.T) {
				// First, create a token to use for authorization
				req, err := http.NewRequest("POST", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				createTokenReq := CreateApiTokenReq{
					Name:       "test-token",
					Expiration: "never",
					Scopes:     []string{token_scopes.Monitoring_Scrape.String()},
				}
				createTokenBody, err := json.Marshal(createTokenReq)
				assert.NoError(t, err)
				req.Body = io.NopCloser(bytes.NewReader(createTokenBody))

				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				require.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

				var createTokenResp map[string]string
				err = json.NewDecoder(recorder.Body).Decode(&createTokenResp)
				assert.NoError(t, err)
				token := createTokenResp["token"]
				assert.NotEmpty(t, token)

				// Use the valid token to access the privileged route
				req, err = http.NewRequest("GET", "/privilegedRoute", nil)
				assert.NoError(t, err)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
				recorder = httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
		{
			name: "correct-id-wrong-secret",
			run: func(t *testing.T) {
				// Create a token
				req, err := http.NewRequest("POST", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				createTokenReq := CreateApiTokenReq{
					Name:       "test-token",
					Expiration: "never",
					Scopes:     []string{token_scopes.Monitoring_Scrape.String()},
				}
				createTokenBody, err := json.Marshal(createTokenReq)
				assert.NoError(t, err)
				req.Body = io.NopCloser(bytes.NewReader(createTokenBody))

				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

				var createTokenResp map[string]string
				err = json.NewDecoder(recorder.Body).Decode(&createTokenResp)
				assert.NoError(t, err)
				token := createTokenResp["token"]
				assert.NotEmpty(t, token)

				// Use a valid token ID but an incorrect secret to access the privileged route
				tokenID := strings.Split(token, ".")[0]
				incorrectSecret := "a25956257878eb0bf6ef69ef7a34812fdf03b0c191b8ac66258fd06b3c902e02"
				incorrectToken := fmt.Sprintf("%s.%s", tokenID, incorrectSecret)

				req, err = http.NewRequest("GET", "/privilegedRoute", nil)
				assert.NoError(t, err)
				req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", incorrectToken))
				recorder = httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusForbidden, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
				assert.Contains(t, recorder.Body.String(), "Invalid API token")
			},
		},
		{
			name: "list-tokens",
			run: func(t *testing.T) {
				// we need to create a token first
				req, err := http.NewRequest("POST", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				createTokenReq := CreateApiTokenReq{
					Name:       "test-token",
					Expiration: "never",
					Scopes:     []string{token_scopes.Monitoring_Scrape.String()},
				}
				createTokenBody, err := json.Marshal(createTokenReq)
				assert.NoError(t, err)
				req.Body = io.NopCloser(bytes.NewReader(createTokenBody))

				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

				var createTokenResp map[string]string
				err = json.NewDecoder(recorder.Body).Decode(&createTokenResp)
				assert.NoError(t, err)
				token := createTokenResp["token"]
				tokenID := strings.Split(token, ".")[0]
				assert.NotEmpty(t, token)

				// list tokens
				req, err = http.NewRequest("GET", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)
				req.AddCookie(&http.Cookie{Name: "login", Value: cookieValue})

				recorder = httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))

				var listTokensResp []server_structs.ApiKeyResponse
				err = json.NewDecoder(recorder.Body).Decode(&listTokensResp)
				assert.NoError(t, err)
				assert.NotEmpty(t, listTokensResp)

				for _, apiKey := range listTokensResp {
					if apiKey.ID == tokenID {
						assert.Equal(t, "test-token", apiKey.Name)
						assert.Equal(t, "admin-user", apiKey.CreatedBy)
						assert.Equal(t, time.Time{}, apiKey.ExpiresAt)
						assert.Equal(t, []string([]string{"monitoring.scrape"}), apiKey.Scopes)
						return
					}
				}
			},
		},
		{
			name: "list-tokens-unauthorized",
			run: func(t *testing.T) {
				req, err := http.NewRequest("GET", "/api/v1.0/tokens", nil)
				assert.NoError(t, err)

				recorder := httptest.NewRecorder()
				route.ServeHTTP(recorder, req)
				assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
			},
		},
	}

	// Run all the test cases
	for _, tc := range testCases {
		t.Run(tc.name, tc.run)
	}
}

func TestGroupManagementAPI(t *testing.T) {
	route := gin.New()
	err := configureCommonEndpoints(route)
	require.NoError(t, err)
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	viper.Set("ConfigDir", dirName)
	viper.Set(param.Server_UIAdminUsers.GetName(), "admin-user")

	test_utils.MockFederationRoot(t, nil, nil)
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)
	// set up database
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	err = database.ServerDatabase.AutoMigrate(&database.Collection{})
	require.NoError(t, err, "Failed to migrate DB for collections table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMember{})
	require.NoError(t, err, "Failed to migrate DB for collection members table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMetadata{})
	require.NoError(t, err, "Failed to migrate DB for collection metadata table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionACL{})
	require.NoError(t, err, "Failed to migrate DB for collection ACLs table")
	err = database.ServerDatabase.AutoMigrate(&database.Group{})
	require.NoError(t, err, "Failed to migrate DB for groups table")
	err = database.ServerDatabase.AutoMigrate(&database.GroupMember{})
	require.NoError(t, err, "Failed to migrate DB for group members table")
	err = database.ServerDatabase.AutoMigrate(&database.User{})
	require.NoError(t, err, "Failed to migrate DB for users table")

	t.Run("test-group-lifecycle", func(t *testing.T) {
		// 1. Create a group as 'owner-user'
		groupName := "test-group-lifecycle"
		createGroupReq := map[string]string{"name": groupName, "description": "test group"}
		body, err := json.Marshal(createGroupReq)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)

		ownerToken := generateTestAdminUserToken(t)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		var createGroupResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createGroupResp)
		require.NoError(t, err)
		groupID := createGroupResp["id"]
		require.NotEmpty(t, groupID)

		// 2. Add a member to the group as 'owner-user'
		createUserReq := map[string]string{"username": "new-member", "sub": "new-member-sub", "issuer": "https://test-issuer.org"}
		body, err = json.Marshal(createUserReq)
		require.NoError(t, err)

		// Pre-create the user before adding them to the group
		req, err = http.NewRequest("POST", "/api/v1.0/users", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)

		var createUserResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createUserResp)
		require.NoError(t, err)
		userID := createUserResp["id"]
		require.NotEmpty(t, userID)

		addMemberReq := map[string]string{"userId": userID}
		body, err = json.Marshal(addMemberReq)
		require.NoError(t, err)

		req, err = http.NewRequest("POST", "/api/v1.0/groups/"+groupID+"/members", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")

		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		// 3. Try to add a member as a different user ('other-user') - should fail
		otherToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "other-user")

		// Re-marshal the addMemberReq to reuse it
		body, err = json.Marshal(addMemberReq)
		require.NoError(t, err)

		req, err = http.NewRequest("POST", "/api/v1.0/groups/"+groupID+"/members", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: otherToken})
		req.Header.Set("Content-Type", "application/json")

		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		// 4. Try to remove a member as 'other-user' - should fail
		req, err = http.NewRequest("DELETE", "/api/v1.0/groups/"+groupID+"/members/"+userID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: otherToken})

		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))

		// 5. Remove the member from the group as 'owner-user'
		req, err = http.NewRequest("DELETE", "/api/v1.0/groups/"+groupID+"/members/"+userID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})

		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))
	})

	t.Run("test-regular-user-can-create-group", func(t *testing.T) {
		// Test that a regular (non-admin) user can create a group
		groupName := "test-regular-user-group"
		createGroupReq := map[string]string{"name": groupName, "description": "test group by regular user"}
		body, err := json.Marshal(createGroupReq)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)

		// Use a regular user token (not admin)
		regularUserToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "regular-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: regularUserToken})
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		var createGroupResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createGroupResp)
		require.NoError(t, err)
		groupID := createGroupResp["id"]
		require.NotEmpty(t, groupID)

		// Verify the regular user can manage their own group
		createUserReq := map[string]string{"username": "new-member2", "sub": "new-member-sub2", "issuer": "https://test-issuer.org"}
		body, err = json.Marshal(createUserReq)
		require.NoError(t, err)

		// Pre-create the user before adding them to the group
		req, err = http.NewRequest("POST", "/api/v1.0/users", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: regularUserToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)

		var createUserResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createUserResp)
		require.NoError(t, err)
		userID := createUserResp["id"]
		require.NotEmpty(t, userID)

		addMemberReq := map[string]string{"userId": userID}
		body, err = json.Marshal(addMemberReq)
		require.NoError(t, err)

		req, err = http.NewRequest("POST", "/api/v1.0/groups/"+groupID+"/members", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: regularUserToken})
		req.Header.Set("Content-Type", "application/json")

		recorder = httptest.NewRecorder()
		route.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
	})
}
