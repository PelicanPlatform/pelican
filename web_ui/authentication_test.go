//go:build !windows

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
	"context"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestWaitUntilLogin(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	go func() {
		err := waitUntilLogin(ctx)
		require.NoError(t, err)
	}()
	activationCodeFile := param.Server_UIActivationCodeFile.GetString()
	start := time.Now()
	for {
		time.Sleep(10 * time.Millisecond)
		contents, err := os.ReadFile(activationCodeFile)
		if os.IsNotExist(err) {
			if time.Since(start) > 10*time.Second {
				require.Fail(t, "The UI activation code file did not appear within 10 seconds")
			}
			continue
		} else {
			require.NoError(t, err)
		}
		contentsStr := string(contents[:len(contents)-1])
		require.Equal(t, *currentCode.Load(), contentsStr)
		break
	}
	cancel()
	start = time.Now()
	for {
		time.Sleep(10 * time.Millisecond)
		if _, err := os.Stat(activationCodeFile); err == nil {
			if time.Since(start) > 10*time.Second {
				require.Fail(t, "The UI activation code file was not cleaned up")
				return
			}
			continue
		} else if !os.IsNotExist(err) {
			require.NoError(t, err)
		}
		break
	}
}

func TestCodeBasedLogin(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)

	//Invoke the code login API with the correct code, ensure we get a valid code back
	t.Run("With valid code", func(t *testing.T) {
		newCode := fmt.Sprintf("%06v", rand.Intn(1000000))
		currentCode.Store(&newCode)
		req, err := http.NewRequest("POST", "/api/v1.0/auth/initLogin", strings.NewReader(fmt.Sprintf(`{"code": "%s"}`, newCode)))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check the HTTP response code
		assert.Equal(t, 200, recorder.Code)
		//Check that we get a cookie back
		cookies := recorder.Result().Cookies()
		foundCookie := false
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				foundCookie = true
			}
		}
		assert.True(t, foundCookie)
	})

	//Invoke the code login with the wrong code, ensure we get a 401
	t.Run("With invalid code", func(t *testing.T) {
		require.True(t, param.Server_EnableUI.GetBool())
		req, err := http.NewRequest("POST", "/api/v1.0/auth/initLogin", strings.NewReader(`{"code": "20"}`))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check the HTTP response code
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"msg":"Invalid login code", "status":"error"}`, recorder.Body.String())
	})
}

func TestPasswordResetAPI(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	viper.Set("Origin.Port", 8443)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	//////////////////////////////SETUP////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err = tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = configureAuthDB()
	assert.NoError(t, err)

	//Create a user for testing
	user := "admin" // With admin privilege
	err = WritePasswordEntry(user, "password")
	assert.NoError(t, err, "error writing a user")
	password := "password"
	payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, password)

	//Create a request
	req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	//Check ok http response
	assert.Equal(t, http.StatusOK, recorder.Code)
	//Check that success message returned
	require.JSONEq(t, `{"msg":"success", "status":"success"}`, recorder.Body.String())
	//Get the cookie to pass to password reset
	loginCookie := recorder.Result().Cookies()
	cookieValue := loginCookie[0].Value

	///////////////////////////////////////////////////////////////////
	//Test invoking reset with valid authorization
	t.Run("With valid authorization", func(t *testing.T) {
		resetPayload := `{"password": "newpassword"}`
		reqReset, err := http.NewRequest("POST", "/api/v1.0/auth/resetLogin", strings.NewReader(resetPayload))
		assert.NoError(t, err)

		reqReset.Header.Set("Content-Type", "application/json")

		reqReset.AddCookie(&http.Cookie{
			Name:  "login",
			Value: cookieValue,
		})

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http response
		assert.Equal(t, 200, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"success", "status":"success"}`, recorderReset.Body.String())

		//After password reset, test authorization with newly generated password
		loginWithNewPasswordPayload := `{"user": "admin", "password": "newpassword"}`

		reqLoginWithNewPassword, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(loginWithNewPasswordPayload))
		assert.NoError(t, err)

		reqLoginWithNewPassword.Header.Set("Content-Type", "application/json")

		recorderLoginWithNewPassword := httptest.NewRecorder()
		router.ServeHTTP(recorderLoginWithNewPassword, reqLoginWithNewPassword)

		//Check HTTP response code 200
		assert.Equal(t, http.StatusOK, recorderLoginWithNewPassword.Code)

		//Check that the response body contains the success message
		assert.JSONEq(t, `{"msg":"success", "status":"success"}`, recorderLoginWithNewPassword.Body.String())
	})

	//Invoking password reset without a cookie should result in failure
	t.Run("Without admin privilege", func(t *testing.T) {
		resetPayload := `{"password": "newpassword"}`
		reqReset, err := http.NewRequest("POST", "/api/v1.0/auth/resetLogin", strings.NewReader(resetPayload))
		assert.NoError(t, err)

		reqReset.Header.Set("Content-Type", "application/json")

		loginCookieTokenCfg := token.NewWLCGToken()
		loginCookieTokenCfg.Lifetime = 30 * time.Minute
		loginCookieTokenCfg.Issuer = param.Server_ExternalWebUrl.GetString()
		loginCookieTokenCfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
		loginCookieTokenCfg.Subject = "user" // general user
		loginCookieTokenCfg.AddScopes(token_scopes.WebUi_Access, token_scopes.Monitoring_Query, token_scopes.Monitoring_Scrape)

		// CreateToken also handles validation for us
		tok, err := loginCookieTokenCfg.CreateToken()
		require.NoError(t, err)

		reqReset.AddCookie(&http.Cookie{
			Name:  "login",
			Value: tok,
		})

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http response
		assert.Equal(t, 403, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"Server.UIAdminUsers is not set, and user is not root user. Admin check returns false", "status":"error"}`, recorderReset.Body.String())
	})

	//Invoking password reset without a cookie should result in failure
	t.Run("Without valid cookie", func(t *testing.T) {
		resetPayload := `{"password": "newpassword"}`
		reqReset, err := http.NewRequest("POST", "/api/v1.0/auth/resetLogin", strings.NewReader(resetPayload))
		assert.NoError(t, err)

		reqReset.Header.Set("Content-Type", "application/json")

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http response
		assert.Equal(t, 401, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"Authentication required to perform this operation", "status":"error"}`, recorderReset.Body.String())
	})

}

func TestPasswordBasedLoginAPI(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)

	///////////////////////////SETUP///////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err = tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = configureAuthDB()
	assert.NoError(t, err)

	//Create a user for testing
	err = WritePasswordEntry("user", "password")
	assert.NoError(t, err, "error writing a user")
	password := "password"
	user := "user"
	///////////////////////////////////////////////////////////////////

	//Invoke with valid password, should get a cookie back
	t.Run("Successful Login", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, password)

		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check ok http response
		assert.Equal(t, http.StatusOK, recorder.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"success", "status":"success"}`, recorder.Body.String())
		//Check for a cookie being returned
		cookies := recorder.Result().Cookies()
		foundCookie := false
		for _, cookie := range cookies {
			if cookie.Name == "login" {
				foundCookie = true
			}
		}
		assert.True(t, foundCookie)
	})

	//Invoke without a password should fail
	t.Run("Without password", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s"}`, user)
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http response code 400
		assert.Equal(t, 400, recorder.Code)
		assert.JSONEq(t, `{"msg":"Password is required", "status":"error"}`, recorder.Body.String())
	})

	//Invoke with incorrect password should fail
	t.Run("With incorrect password", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, "incorrectpassword")
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http response code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"msg":"Password and user didn't match", "status":"error"}`, recorder.Body.String())
	})

	//Invoke with incorrect user should fail
	t.Run("With incorrect user", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, "incorrectuser", password)
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http response code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"msg":"Password and user didn't match", "status":"error"}`, recorder.Body.String())
	})

	//Invoke with invalid user, should fail
	t.Run("Without user", func(t *testing.T) {
		payload := fmt.Sprintf(`{"password": "%s"}`, password)
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http response code 400
		assert.Equal(t, 400, recorder.Code)
		assert.JSONEq(t, `{"msg":"User is required", "status":"error"}`, recorder.Body.String())
	})
}

func TestWhoamiAPI(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	config.InitConfig()
	viper.Set("ConfigDir", dirName)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	///////////////////////////SETUP///////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err = tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = configureAuthDB()
	assert.NoError(t, err)

	//Create a user for testing
	err = WritePasswordEntry("user", "password")
	assert.NoError(t, err, "error writing a user")
	password := "password"
	user := "user"
	payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, password)

	//Create a request
	req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	//Check ok http response
	assert.Equal(t, http.StatusOK, recorder.Code)
	//Check that success message returned
	assert.JSONEq(t, `{"msg":"success", "status":"success"}`, recorder.Body.String())
	//Get the cookie to test 'whoami'
	loginCookie := recorder.Result().Cookies()
	cookieValue := loginCookie[0].Value

	///////////////////////////////////////////////////////////////////

	//Invoked with valid cookie, should return the username in the cookie
	t.Run("With valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("GET", "/api/v1.0/auth/whoami", nil)
		assert.NoError(t, err)

		req.AddCookie(&http.Cookie{
			Name:  "login",
			Value: cookieValue,
		})

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		expectedRes := WhoAmIRes{Authenticated: true, Role: "user", User: "user"}
		resStr, err := json.Marshal(expectedRes)
		require.NoError(t, err)

		//Check for http response code 200
		assert.Equal(t, 200, recorder.Code)
		assert.JSONEq(t, string(resStr), recorder.Body.String())
		assert.NotZero(t, recorder.Header().Get("X-CSRF-Token"))
	})
	//Invoked without valid cookie, should return there is no logged-in user
	t.Run("Without a valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("GET", "/api/v1.0/auth/whoami", nil)
		assert.NoError(t, err)

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		expectedRes := WhoAmIRes{}
		resStr, err := json.Marshal(expectedRes)
		require.NoError(t, err)

		//Check for http response code 200
		assert.Equal(t, 200, recorder.Code)
		assert.JSONEq(t, string(resStr), recorder.Body.String())
	})
}

func TestAdminAuthHandler(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name          string
		setupUserFunc func(*gin.Context) // Function to setup user and admin list
		expectedCode  int                // Expected HTTP status code
		expectedError string             // Expected error message
	}{
		{
			name: "user-not-logged-in",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "")
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: "Login required to view this page",
		},
		{
			name: "general-admin-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{})
				ctx.Set("User", "admin")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "specific-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "admin1")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "non-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{"admin1", "admin2"})
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-empty",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{})
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-multiple-users",
			setupUserFunc: func(ctx *gin.Context) {
				viper.Set("Server.UIAdminUsers", []string{"admin1", "admin2", "admin3"})
				ctx.Set("User", "admin2")
			},
			expectedCode: http.StatusOK,
		},
	}

	// Initialize Gin and set it to test mode
	gin.SetMode(gin.TestMode)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.Default()
			// If admin middleware didn't abort, the response will have status code == 200
			router.GET("/test",
				func(ctx *gin.Context) { tc.setupUserFunc(ctx) },
				AdminAuthHandler,
				func(ctx *gin.Context) { ctx.AbortWithStatus(http.StatusOK) },
			)
			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code)
			if tc.expectedError != "" {
				assert.Contains(t, w.Body.String(), tc.expectedError)
			}
			viper.Reset()
		})
	}
}

func TestLogoutAPI(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	viper.Reset()
	config.InitConfig()
	viper.Set("ConfigDir", dirName)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer(ctx, config.OriginType)
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256(), false)
	require.NoError(t, err)
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	///////////////////////////SETUP///////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err = tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = configureAuthDB()
	assert.NoError(t, err)

	//Create a user for testing
	err = WritePasswordEntry("user", "password")
	assert.NoError(t, err, "error writing a user")
	password := "password"
	user := "user"
	payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, password)

	//Create a request
	req, err := http.NewRequest("POST", "/api/v1.0/auth/login", strings.NewReader(payload))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	//Check ok http response
	assert.Equal(t, http.StatusOK, recorder.Code)
	//Check that success message returned
	assert.JSONEq(t, `{"msg":"success", "status":"success"}`, recorder.Body.String())
	//Get the cookie to test 'logout'
	loginCookie := recorder.Result().Cookies()
	cookieValue := loginCookie[0].Value

	///////////////////////////////////////////////////////////////////

	//Invoked with valid cookie, should return the username in the cookie
	t.Run("With valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("POST", "/api/v1.0/auth/logout", nil)
		assert.NoError(t, err)

		req.AddCookie(&http.Cookie{
			Name:  "login",
			Value: cookieValue,
		})

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check for http response code 200
		assert.Equal(t, 200, recorder.Code)
		assert.Equal(t, 1, len(recorder.Result().Cookies()))
		assert.Equal(t, "login", recorder.Result().Cookies()[0].Name)
		assert.Greater(t, time.Now(), recorder.Result().Cookies()[0].Expires)
	})
	//Invoked without valid cookie, should return there is no logged-in user
	t.Run("Without a valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("POST", "/api/v1.0/auth/logout", nil)
		assert.NoError(t, err)

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check for http response code 200
		assert.Equal(t, 401, recorder.Code)
	})
}

func TestListOIDCEnabledServersHandler(t *testing.T) {
	router := gin.New()
	router.GET("/oauth", listOIDCEnabledServersHandler)
	t.Cleanup(func() {
		viper.Reset()
	})
	t.Run("registry-included-by-default", func(t *testing.T) {
		viper.Reset()
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"registry"}}
		req, err := http.NewRequest("GET", "/oauth", nil)
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		body, err := io.ReadAll(recorder.Result().Body)
		require.NoError(t, err)

		getResult := OIDCEnabledServerRes{}
		err = json.Unmarshal(body, &getResult)
		require.NoError(t, err)

		assert.Equal(t, expected, getResult)
	})

	t.Run("origin-included-if-flag-is-on", func(t *testing.T) {
		viper.Reset()
		viper.Set("Origin.EnableOIDC", true)
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"registry", "origin"}}
		req, err := http.NewRequest("GET", "/oauth", nil)
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		body, err := io.ReadAll(recorder.Result().Body)
		require.NoError(t, err)

		getResult := OIDCEnabledServerRes{}
		err = json.Unmarshal(body, &getResult)
		require.NoError(t, err)

		assert.Equal(t, expected, getResult)
	})

	t.Run("cache-included-if-flag-is-on", func(t *testing.T) {
		viper.Reset()
		viper.Set("Cache.EnableOIDC", true)
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"registry", "cache"}}
		req, err := http.NewRequest("GET", "/oauth", nil)
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		body, err := io.ReadAll(recorder.Result().Body)
		require.NoError(t, err)

		getResult := OIDCEnabledServerRes{}
		err = json.Unmarshal(body, &getResult)
		require.NoError(t, err)

		assert.Equal(t, expected, getResult)
	})

	t.Run("director-included-if-flag-is-on", func(t *testing.T) {
		viper.Reset()
		viper.Set("Director.EnableOIDC", true)
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"registry", "director"}}
		req, err := http.NewRequest("GET", "/oauth", nil)
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		body, err := io.ReadAll(recorder.Result().Body)
		require.NoError(t, err)

		getResult := OIDCEnabledServerRes{}
		err = json.Unmarshal(body, &getResult)
		require.NoError(t, err)

		assert.Equal(t, expected, getResult)
	})

	t.Run("origin-cache-both-included-if-flags-are-on", func(t *testing.T) {
		viper.Reset()
		viper.Set("Origin.EnableOIDC", true)
		viper.Set("Cache.EnableOIDC", true)
		viper.Set("Director.EnableOIDC", true)
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"registry", "origin", "cache", "director"}}
		req, err := http.NewRequest("GET", "/oauth", nil)
		assert.NoError(t, err)

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)

		body, err := io.ReadAll(recorder.Result().Body)
		require.NoError(t, err)

		getResult := OIDCEnabledServerRes{}
		err = json.Unmarshal(body, &getResult)
		require.NoError(t, err)

		assert.Equal(t, expected, getResult)
	})
}
