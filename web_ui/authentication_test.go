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
	"context"
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
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func migrateTestDB(t *testing.T) {
	err := database.ServerDatabase.AutoMigrate(&database.Collection{})
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
	// User struct intentionally has no PasswordHash field; this helper
	// adds the password_hash column so password-based login tests work.
	require.NoError(t, database.AutoMigrateCredentialsForTests(database.ServerDatabase),
		"Failed to migrate DB for user credentials column")
	err = database.ServerDatabase.AutoMigrate(&database.GroupInviteLink{})
	require.NoError(t, err, "Failed to migrate DB for group invite links table")
	err = database.ServerDatabase.AutoMigrate(&database.UserIdentity{})
	require.NoError(t, err, "Failed to migrate DB for user identities table")
	err = database.ServerDatabase.AutoMigrate(&database.AUPDocument{})
	require.NoError(t, err, "Failed to migrate DB for AUP documents table")
	err = database.ServerDatabase.AutoMigrate(&database.UserScope{})
	require.NoError(t, err, "Failed to migrate DB for user_scopes table")
	err = database.ServerDatabase.AutoMigrate(&database.GroupScope{})
	require.NoError(t, err, "Failed to migrate DB for group_scopes table")
}

func TestWaitUntilLogin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	dirName := t.TempDir()
	server_utils.ResetTestState()
	require.NoError(t, param.ConfigDir.Set(dirName))

	test_utils.MockFederationRoot(t, nil, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	setupWebUIEnv(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	migrateTestDB(t)

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
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
		assert.JSONEq(t, `{"msg":"Invalid login code", "status":"error"}`, recorder.Body.String())
	})
}

func TestPasswordResetAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	setupWebUIEnv(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	migrateTestDB(t)

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
	assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		loginCookieTokenCfg.Claims = map[string]string{
			"user_id": "user",
		}

		// CreateToken also handles validation for us
		tok, err := loginCookieTokenCfg.CreateToken()
		require.NoError(t, err)

		// AuthHandler now revalidates the user record on every cookie
		// read; without a backing User row, the cookie 401s before
		// reaching the AdminAuthHandler that this subtest is meant
		// to exercise.
		require.NoError(t, database.ServerDatabase.Create(&database.User{
			ID: "user", Username: "user", Sub: "user",
			Issuer: param.Server_ExternalWebUrl.GetString(),
			Status: database.UserStatusActive,
		}).Error)

		reqReset.AddCookie(&http.Cookie{
			Name:  "login",
			Value: tok,
		})

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http response
		assert.Equal(t, 403, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"Server.UIAdminUsers and Server.UIAdminGroups are not set, and user is not root user. Admin check returns false", "status":"error"}`, recorderReset.Body.String())
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	setupWebUIEnv(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	migrateTestDB(t)

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
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusBadRequest, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusBadRequest, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
		assert.JSONEq(t, `{"msg":"User is required", "status":"error"}`, recorder.Body.String())
	})
}

func TestWhoamiAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	setupWebUIEnv(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	migrateTestDB(t)

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
	assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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

		// The whoami response also reports AUP-acceptance state (see
		// the embedded default AUP in web_ui/aup.go). For this test the
		// user hasn't yet signed; assert the core fields directly and
		// ignore the optional aup_version / requires_aup details.
		expectedRes := WhoAmIRes{Authenticated: true, Role: "user", User: "user", RequiresAUP: true}
		var actual WhoAmIRes
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &actual))

		//Check for http response code 200
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
		assert.Equal(t, expectedRes.Authenticated, actual.Authenticated)
		assert.Equal(t, expectedRes.Role, actual.Role)
		assert.Equal(t, expectedRes.User, actual.User)
		assert.Equal(t, expectedRes.RequiresAUP, actual.RequiresAUP)
		assert.NotEmpty(t, actual.AUPVersion)
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
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
		assert.JSONEq(t, string(resStr), recorder.Body.String())
	})
}

func TestCheckAdmin(t *testing.T) {
	testCases := []struct {
		name          string
		user          string
		id            string
		sub           string
		groups        []string
		adminUsers    []string
		adminGroups   []string
		expectedAdmin bool
		expectedMsg   string
	}{
		{
			name:          "root-admin-user",
			user:          "admin",
			groups:        nil,
			adminUsers:    nil,
			adminGroups:   nil,
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-in-admin-users-list",
			user:          "admin1",
			groups:        nil,
			adminUsers:    []string{"admin1", "admin2"},
			adminGroups:   nil,
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-not-in-admin-users-list",
			user:          "user1",
			groups:        nil,
			adminUsers:    []string{"admin1", "admin2"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "user-in-admin-group",
			user:          "user1",
			groups:        []string{"pelican-admins"},
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-in-multiple-groups-one-admin",
			user:          "user1",
			groups:        []string{"pelican-users", "pelican-admins", "other-group"},
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-not-in-admin-group",
			user:          "user1",
			groups:        []string{"pelican-users"},
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "user-in-admin-group-and-admin-users",
			user:          "user1",
			groups:        []string{"pelican-admins"},
			adminUsers:    []string{"user1"},
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-in-admin-group-not-in-admin-users",
			user:          "user1",
			groups:        []string{"pelican-admins"},
			adminUsers:    []string{"admin1"},
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-in-admin-users-not-in-admin-group",
			user:          "user1",
			groups:        []string{"pelican-users"},
			adminUsers:    []string{"user1"},
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "user-with-empty-groups",
			user:          "user1",
			groups:        []string{},
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "user-with-nil-groups",
			user:          "user1",
			groups:        nil,
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins"},
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "multiple-admin-groups-user-in-one",
			user:          "user1",
			groups:        []string{"pelican-users"},
			adminUsers:    nil,
			adminGroups:   []string{"pelican-admins", "pelican-users", "other-admins"},
			expectedAdmin: true,
			expectedMsg:   "",
		},
		{
			name:          "no-admin-config-no-groups",
			user:          "user1",
			groups:        nil,
			adminUsers:    nil,
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "Server.UIAdminUsers and Server.UIAdminGroups are not set, and user is not root user. Admin check returns false",
		},
		{
			name:          "admin-groups-empty-list",
			user:          "user1",
			groups:        []string{"pelican-admins"},
			adminUsers:    nil,
			adminGroups:   []string{},
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		// CheckAdmin matches the *Username* against Server.UIAdminUsers
		// only — never the opaque internal ID and never the OIDC Sub.
		// Per the user/group design contract, Username is the sole
		// authorization handle; ID is internal-only and Sub is a
		// third-party-controlled OIDC subject claim. Each of the four
		// test cases below would have granted admin under the old
		// permissive matcher; under the current contract they MUST not.
		{
			name:          "id-matches-admin-list-must-not-elevate",
			user:          "user1",
			id:            "internal-id-123",
			adminUsers:    []string{"internal-id-123"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "sub-matches-admin-list-must-not-elevate",
			user:          "user1",
			sub:           "http://cilogon.org/serverA/users/12345",
			adminUsers:    []string{"http://cilogon.org/serverA/users/12345"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "id-matches-but-username-does-not",
			user:          "user1",
			id:            "internal-id-456",
			adminUsers:    []string{"internal-id-456", "other-admin"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "sub-matches-but-username-does-not",
			user:          "user1",
			sub:           "oidc-sub-789",
			adminUsers:    []string{"oidc-sub-789"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "empty-id-and-sub-no-false-positive",
			user:          "user1",
			id:            "",
			sub:           "",
			adminUsers:    []string{"admin1"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "empty-id-sub-dont-match-empty-admin-entry",
			user:          "user1",
			id:            "",
			sub:           "",
			adminUsers:    []string{""},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			name:          "id-and-sub-present-username-not-in-list",
			user:          "display-name",
			id:            "stable-id",
			sub:           "oidc-sub",
			adminUsers:    []string{"some-other-admin"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
		{
			// Renaming a user doesn't preserve admin status via the
			// stable internal ID — the admin list is a list of
			// usernames. After a rename, the admin entry must be
			// updated to the new username, or the admin loses their
			// privilege. This is intentional: ID-based matching would
			// silently re-grant admin if a malicious actor could pin
			// an ID matching an entry on the admin list.
			name:          "rename-does-not-preserve-admin-via-id",
			user:          "new-display-name",
			id:            "stable-id-001",
			sub:           "oidc-sub-001",
			adminUsers:    []string{"stable-id-001"},
			adminGroups:   nil,
			expectedAdmin: false,
			expectedMsg:   "You don't have permission to perform this action",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()

			// Setup admin users config
			// Only set if explicitly provided (nil means not set, empty slice means set but empty)
			if tc.adminUsers != nil {
				require.NoError(t, param.Server_UIAdminUsers.Set(tc.adminUsers))
			}

			// Setup admin groups config
			// Only set if explicitly provided (nil means not set, empty slice means set but empty)
			if tc.adminGroups != nil {
				require.NoError(t, param.Server_AdminGroups.Set(tc.adminGroups))
			}

			// Call CheckAdmin
			var isAdmin bool
			var msg string
			identity := UserIdentity{
				Username: tc.user,
				ID:       tc.id,
				Sub:      tc.sub,
				Groups:   tc.groups,
			}
			isAdmin, msg = CheckAdmin(identity)

			// Verify results
			assert.Equal(t, tc.expectedAdmin, isAdmin, "Admin status mismatch for user %s", tc.user)
			if tc.expectedMsg != "" {
				assert.Equal(t, tc.expectedMsg, msg, "Error message mismatch")
			}
		})
	}
}

func TestAdminAuthHandler(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
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
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1", "admin2"}))
				ctx.Set("User", "")
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: "Login required to view this page",
		},
		{
			name: "general-admin-access",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				ctx.Set("User", "admin")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "specific-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1", "admin2"}))
				ctx.Set("User", "admin1")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "non-admin-user-access",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1", "admin2"}))
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-empty",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				ctx.Set("User", "user")
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
		},
		{
			name: "admin-list-multiple-users",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin1", "admin2", "admin3"}))
				ctx.Set("User", "admin2")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "admin-group-access",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				require.NoError(t, param.Server_AdminGroups.Set([]string{"pelican-admins"}))
				ctx.Set("User", "user1")
				ctx.Set("Groups", []string{"pelican-admins"})
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "non-admin-group-access",
			setupUserFunc: func(ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{}))
				require.NoError(t, param.Server_AdminGroups.Set([]string{"pelican-admins"}))
				ctx.Set("User", "user1")
				ctx.Set("Groups", []string{"pelican-users"})
			},
			expectedCode:  http.StatusForbidden,
			expectedError: "You don't have permission to perform this action",
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
			server_utils.ResetTestState()
		})
	}
}

// TestUserAdminAuthHandler pins the route gate's contract: a caller
// holding EITHER server.admin or server.user_admin clears the
// door, anyone else gets 403. This is the gate that the user-report
// "added a group with server.user_admin scope, gave the user no
// powers" was tripping on — the route used to use AdminAuthHandler
// (admin only) and a user-admin would 403 before any handler
// could even read the request.
//
// Group-membership-derived scope grants need a backing DB, so we
// migrate user/group/group_scopes/group_members and seed both kinds
// of grants (direct and via membership). Config-derived grants
// (Server.UIAdminUsers etc.) don't need a DB and are covered too.
func TestUserAdminAuthHandler(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	gin.SetMode(gin.TestMode)

	// Helper: a fresh DB for each subtest with the tables
	// EffectiveScopes touches. Restored afterwards.
	setupDB := func(t *testing.T) {
		t.Helper()
		prev := database.ServerDatabase
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(
			&database.User{},
			&database.Group{},
			&database.GroupMember{},
			&database.UserScope{},
			&database.GroupScope{},
		))
		database.ServerDatabase = db
		t.Cleanup(func() { database.ServerDatabase = prev })
	}

	cases := []struct {
		name         string
		setup        func(t *testing.T, ctx *gin.Context)
		expectedCode int
		expectedMsg  string
	}{
		{
			name: "unauthenticated caller blocked",
			setup: func(t *testing.T, ctx *gin.Context) {
				ctx.Set("User", "")
			},
			expectedCode: http.StatusUnauthorized,
			expectedMsg:  "Login required to view this page",
		},
		{
			name: "config-derived admin clears the gate",
			setup: func(t *testing.T, ctx *gin.Context) {
				require.NoError(t, param.Server_UIAdminUsers.Set([]string{"alice"}))
				ctx.Set("User", "alice")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "config-derived user_admin clears the gate",
			setup: func(t *testing.T, ctx *gin.Context) {
				require.NoError(t, param.Server_UserAdminUsers.Set([]string{"bob"}))
				ctx.Set("User", "bob")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "DB-granted user_admin via direct user_scopes clears the gate",
			setup: func(t *testing.T, ctx *gin.Context) {
				setupDB(t)
				require.NoError(t, database.ServerDatabase.Create(&database.User{
					ID:       "u-carol",
					Username: "carol",
					Sub:      "carol",
					Issuer:   "https://example.com",
					Status:   database.UserStatusActive,
				}).Error)
				require.NoError(t, database.GrantUserScope(
					database.ServerDatabase, "u-carol",
					token_scopes.Server_UserAdmin, database.CreatorSelf(),
				))
				ctx.Set("User", "carol")
				ctx.Set("UserId", "u-carol")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "DB-granted user_admin via group membership clears the gate",
			setup: func(t *testing.T, ctx *gin.Context) {
				setupDB(t)
				// This is the exact path the user reported was broken:
				// a group carries server.user_admin and a member of
				// the group calls a user-admin-walled route.
				require.NoError(t, database.ServerDatabase.Create(&database.User{
					ID:       "u-dan",
					Username: "dan",
					Sub:      "dan",
					Issuer:   "https://example.com",
					Status:   database.UserStatusActive,
				}).Error)
				require.NoError(t, database.ServerDatabase.Create(&database.Group{
					ID:        "g-priv",
					Name:      "privileged",
					CreatedBy: database.CreatorSelfEnrolled,
				}).Error)
				require.NoError(t, database.ServerDatabase.Create(&database.GroupMember{
					GroupID: "g-priv",
					UserID:  "u-dan",
				}).Error)
				require.NoError(t, database.GrantGroupScope(
					database.ServerDatabase, "g-priv",
					token_scopes.Server_UserAdmin, database.CreatorSelf(),
				))
				ctx.Set("User", "dan")
				ctx.Set("UserId", "u-dan")
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "ordinary user with no management scopes is blocked",
			setup: func(t *testing.T, ctx *gin.Context) {
				setupDB(t)
				require.NoError(t, database.ServerDatabase.Create(&database.User{
					ID:       "u-eve",
					Username: "eve",
					Sub:      "eve",
					Issuer:   "https://example.com",
					Status:   database.UserStatusActive,
				}).Error)
				ctx.Set("User", "eve")
				ctx.Set("UserId", "u-eve")
			},
			expectedCode: http.StatusForbidden,
			expectedMsg:  "user administrator permission",
		},
		{
			name: "config-derived collection_admin alone is NOT user_admin",
			setup: func(t *testing.T, ctx *gin.Context) {
				// collection_admin is a sibling scope, not a parent —
				// only admin implies user_admin. A pure
				// collection-admin must be refused at this gate.
				require.NoError(t, param.Server_CollectionAdminUsers.Set([]string{"frank"}))
				ctx.Set("User", "frank")
			},
			expectedCode: http.StatusForbidden,
			expectedMsg:  "user administrator permission",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			router := gin.Default()
			router.GET("/test",
				func(ctx *gin.Context) { tc.setup(t, ctx) },
				UserAdminAuthHandler,
				func(ctx *gin.Context) { ctx.AbortWithStatus(http.StatusOK) },
			)
			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.expectedCode, w.Code, "body: %s", w.Body.String())
			if tc.expectedMsg != "" {
				assert.Contains(t, w.Body.String(), tc.expectedMsg)
			}
			server_utils.ResetTestState()
		})
	}
}

// setupUserStatusTestDB attaches a fresh in-memory SQLite to
// database.ServerDatabase and migrates the user table. The cleanup
// restores whatever DB was attached before so the broader test suite
// stays happy. We use this minimal setup (no full config.InitServer)
// because userRecordIsActive only touches the User row.
func setupUserStatusTestDB(t *testing.T) {
	t.Helper()
	prev := database.ServerDatabase
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	// User is the row userRecordIsActive looks up; the rest are
	// here because DeleteUser (used in the soft-delete subtest)
	// also cleans up CollectionACL rows referencing the user's
	// personal-group name and GroupMember rows referencing the
	// user.
	require.NoError(t, db.AutoMigrate(
		&database.User{},
		&database.GroupMember{},
		&database.CollectionACL{},
	))
	require.NoError(t, database.AutoMigrateCredentialsForTests(db))
	database.ServerDatabase = db
	t.Cleanup(func() { database.ServerDatabase = prev })
}

// TestUserRecordIsActive pins the contract that AuthHandler's
// per-request validation:
//   - returns true for an active user record,
//   - returns false when the user has been soft-deleted (DeletedAt
//     set; GORM's default scope filters them out),
//   - returns false when the user is marked inactive,
//   - fails OPEN when the lookup hits an unrelated DB error or
//     ServerDatabase is nil (otherwise a transient hiccup would
//     lock every user out).
func TestUserRecordIsActive(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("nil ServerDatabase fails open", func(t *testing.T) {
		prev := database.ServerDatabase
		database.ServerDatabase = nil
		t.Cleanup(func() { database.ServerDatabase = prev })
		assert.True(t, userRecordIsActive("anything"),
			"with no DB, we cannot prove the user is revoked — must fail open")
	})

	t.Run("active user passes", func(t *testing.T) {
		setupUserStatusTestDB(t)
		require.NoError(t, database.ServerDatabase.Create(&database.User{
			ID:       "user-active",
			Username: "alice",
			Sub:      "alice",
			Issuer:   "https://example.com",
			Status:   database.UserStatusActive,
		}).Error)
		assert.True(t, userRecordIsActive("user-active"),
			"a real, active row is what authenticated users hit on every request")
	})

	t.Run("inactive user is revoked", func(t *testing.T) {
		setupUserStatusTestDB(t)
		require.NoError(t, database.ServerDatabase.Create(&database.User{
			ID:       "user-inactive",
			Username: "bob",
			Sub:      "bob",
			Issuer:   "https://example.com",
			Status:   database.UserStatusInactive,
		}).Error)
		assert.False(t, userRecordIsActive("user-inactive"),
			"a row with status=inactive must be treated as revoked, even though it still exists in the DB")
	})

	t.Run("soft-deleted user is revoked", func(t *testing.T) {
		setupUserStatusTestDB(t)
		require.NoError(t, database.ServerDatabase.Create(&database.User{
			ID:       "user-deleted",
			Username: "carol",
			Sub:      "carol",
			Issuer:   "https://example.com",
			Status:   database.UserStatusActive,
		}).Error)
		// Soft-delete via the public deletion path (admin self-driven
		// is the easiest path that doesn't require a separate
		// requestor); GORM marks DeletedAt and the default scope
		// hides the row from subsequent reads.
		require.NoError(t, database.DeleteUser(database.ServerDatabase, "user-deleted", "user-deleted", false))
		assert.False(t, userRecordIsActive("user-deleted"),
			"a soft-deleted user must lose authority on the next cookie read; not at the next 16h cookie expiration")
	})

	t.Run("unknown user ID is revoked", func(t *testing.T) {
		setupUserStatusTestDB(t)
		assert.False(t, userRecordIsActive("user-never-existed"),
			"a cookie referring to a user ID that doesn't exist must not be honored")
	})
}

func TestLogoutAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	setupWebUIEnv(t)

	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	migrateTestDB(t)

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
	assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
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

		//Check for http response code 401
		assert.Equal(t, http.StatusUnauthorized, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
	})
}

func TestListOIDCEnabledServersHandler(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	router := gin.New()
	router.GET("/oauth", listOIDCEnabledServersHandler)
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	// All four module types — including the registry — are now gated by
	// their own EnableOIDC flag. The registry no longer forces OIDC on
	// unconditionally; per the user/group design contract, a registry
	// can run with only local username/password accounts.
	t.Run("none-by-default", func(t *testing.T) {
		server_utils.ResetTestState()
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{}}
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

	t.Run("registry-included-only-if-flag-is-on", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Registry_EnableOIDC.Set(true))
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
		server_utils.ResetTestState()
		require.NoError(t, param.Origin_EnableOIDC.Set(true))
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"origin"}}
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
		server_utils.ResetTestState()
		require.NoError(t, param.Cache_EnableOIDC.Set(true))
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"cache"}}
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
		server_utils.ResetTestState()
		require.NoError(t, param.Director_EnableOIDC.Set(true))
		expected := OIDCEnabledServerRes{ODICEnabledServers: []string{"director"}}
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

	t.Run("all-modules-included-when-all-flags-on", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Registry_EnableOIDC.Set(true))
		require.NoError(t, param.Origin_EnableOIDC.Set(true))
		require.NoError(t, param.Cache_EnableOIDC.Set(true))
		require.NoError(t, param.Director_EnableOIDC.Set(true))
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
