//go:build !windows

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

package origin_ui

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	//set a temporary password file:
	tempFile, err := os.CreateTemp("", "origin-ui-passwd")
	if err != nil {
		fmt.Println("Failed to setup origin-ui-passwd file")
		os.Exit(1)
	}
	tempPasswdFile = tempFile
	//Override viper default for testing
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		fmt.Println("Error making temp jwk dir")
		os.Exit(1)
	}

	//Override viper default for testing
	viper.Set("IssuerKey", filepath.Join(tempJWKDir, "issuer.jwk"))

	// Ensure we load up the default configs.
	config.InitConfig()
	if err := config.InitServer(); err != nil {
		fmt.Println("Failed to configure the test module")
		os.Exit(1)
	}

	//Get keys
	_, err = config.GetIssuerPublicJWKS()
	if err != nil {
		fmt.Println("Error issuing jwks")
		os.Exit(1)
	}
	router = gin.Default()

	//Configure UI
	err = ConfigureOriginUI(router)
	if err != nil {
		fmt.Println("Error configuring origin UI")
		os.Exit(1)
	}
	//Run the tests
	exitCode := m.Run()

	//Clean up created files by removing them and exit
	os.Remove(tempPasswdFile.Name())
	os.RemoveAll(tempJWKDir)
	os.Exit(exitCode)
}

func TestWaitUntilLogin(t *testing.T) {
	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	err := config.InitServer()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		err := WaitUntilLogin(ctx)
		require.NoError(t, err)
	}()
	activationCodeFile := param.Origin_UIActivationCodeFile.GetString()
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
	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	config.InitConfig()
	err := config.InitServer()
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256())
	require.NoError(t, err)

	//Invoke the code login API with the correct code, ensure we get a valid code back
	t.Run("With valid code", func(t *testing.T) {
		newCode := fmt.Sprintf("%06v", rand.Intn(1000000))
		currentCode.Store(&newCode)
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/initLogin", strings.NewReader(fmt.Sprintf(`{"code": "%s"}`, newCode)))
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
		require.True(t, param.Origin_EnableUI.GetBool())
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/initLogin", strings.NewReader(`{"code": "20"}`))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check the HTTP response code
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"error":"Invalid login code"}`, recorder.Body.String())
	})
}

func TestPasswordResetAPI(t *testing.T) {
	dirName := t.TempDir()
	viper.Reset()
	viper.Set("ConfigDir", dirName)
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer()
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256())
	require.NoError(t, err)
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())

	//////////////////////////////SETUP////////////////////////////////
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
	req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)

	//Check ok http reponse
	assert.Equal(t, http.StatusOK, recorder.Code)
	//Check that success message returned
	require.JSONEq(t, `{"msg":"Success"}`, recorder.Body.String())
	//Get the cookie to pass to password reset
	loginCookie := recorder.Result().Cookies()
	cookieValue := loginCookie[0].Value

	///////////////////////////////////////////////////////////////////
	//Test invoking reset with valid authorization
	t.Run("With valid authorization", func(t *testing.T) {
		resetPayload := `{"password": "newpassword"}`
		reqReset, err := http.NewRequest("POST", "/api/v1.0/origin-ui/resetLogin", strings.NewReader(resetPayload))
		assert.NoError(t, err)

		reqReset.Header.Set("Content-Type", "application/json")

		reqReset.AddCookie(&http.Cookie{
			Name:  "login",
			Value: cookieValue,
		})

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http reponse
		assert.Equal(t, 200, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"Success"}`, recorderReset.Body.String())

		//After password reset, test authorization with newly generated password
		loginWithNewPasswordPayload := `{"user": "user", "password": "newpassword"}`

		reqLoginWithNewPassword, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(loginWithNewPasswordPayload))
		assert.NoError(t, err)

		reqLoginWithNewPassword.Header.Set("Content-Type", "application/json")

		recorderLoginWithNewPassword := httptest.NewRecorder()
		router.ServeHTTP(recorderLoginWithNewPassword, reqLoginWithNewPassword)

		//Check HTTP response code 200
		assert.Equal(t, http.StatusOK, recorderLoginWithNewPassword.Code)

		//Check that the response body contains the success message
		assert.JSONEq(t, `{"msg":"Success"}`, recorderLoginWithNewPassword.Body.String())
	})

	//Invoking password reset without a cookie should result in failure
	t.Run("Without valid cookie", func(t *testing.T) {
		resetPayload := `{"password": "newpassword"}`
		reqReset, err := http.NewRequest("POST", "/api/v1.0/origin-ui/resetLogin", strings.NewReader(resetPayload))
		assert.NoError(t, err)

		reqReset.Header.Set("Content-Type", "application/json")

		recorderReset := httptest.NewRecorder()
		router.ServeHTTP(recorderReset, reqReset)

		//Check ok http reponse
		assert.Equal(t, 403, recorderReset.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"error":"Password reset only available to logged-in users"}`, recorderReset.Body.String())
	})

}

func TestPasswordBasedLoginAPI(t *testing.T) {
	viper.Reset()
	config.InitConfig()
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer()
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
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
		assert.NoError(t, err)

		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check ok http reponse
		assert.Equal(t, http.StatusOK, recorder.Code)
		//Check that success message returned
		assert.JSONEq(t, `{"msg":"Success"}`, recorder.Body.String())
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
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http reponse code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"error":"Login failed"}`, recorder.Body.String())
	})

	//Invoke with incorrect password should fail
	t.Run("With incorrect password", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, user, "incorrectpassword")
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http reponse code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"error":"Login failed"}`, recorder.Body.String())
	})

	//Invoke with incorrect user should fail
	t.Run("With incorrect user", func(t *testing.T) {
		payload := fmt.Sprintf(`{"user": "%s", "password": "%s"}`, "incorrectuser", password)
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http reponse code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"error":"Login failed"}`, recorder.Body.String())
	})

	//Invoke with invalid user, should fail
	t.Run("Without user", func(t *testing.T) {
		payload := fmt.Sprintf(`{"password": "%s"}`, password)
		//Create a request
		req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		//Check http reponse code 401
		assert.Equal(t, 401, recorder.Code)
		assert.JSONEq(t, `{"error":"Login failed"}`, recorder.Body.String())
	})
}

func TestWhoamiAPI(t *testing.T) {
	dirName := t.TempDir()
	viper.Reset()
	config.InitConfig()
	viper.Set("ConfigDir", dirName)
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())
	err := config.InitServer()
	require.NoError(t, err)
	err = config.GeneratePrivateKey(param.IssuerKey.GetString(), elliptic.P256())
	require.NoError(t, err)
	viper.Set("Origin.UIPasswordFile", tempPasswdFile.Name())

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
	req, err := http.NewRequest("POST", "/api/v1.0/origin-ui/login", strings.NewReader(payload))
	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	//Check ok http reponse
	assert.Equal(t, http.StatusOK, recorder.Code)
	//Check that success message returned
	assert.JSONEq(t, `{"msg":"Success"}`, recorder.Body.String())
	//Get the cookie to test 'whoami'
	loginCookie := recorder.Result().Cookies()
	cookieValue := loginCookie[0].Value

	///////////////////////////////////////////////////////////////////

	//Invoked with valid cookie, should return the username in the cookie
	t.Run("With valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("GET", "/api/v1.0/origin-ui/whoami", nil)
		assert.NoError(t, err)

		req.AddCookie(&http.Cookie{
			Name:  "login",
			Value: cookieValue,
		})

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check for http reponse code 200
		assert.Equal(t, 200, recorder.Code)
		assert.JSONEq(t, `{"authenticated":true, "user":"user"}`, recorder.Body.String())
	})
	//Invoked without valid cookie, should return there is no logged-in user
	t.Run("Without  valid cookie", func(t *testing.T) {
		req, err = http.NewRequest("GET", "/api/v1.0/origin-ui/whoami", nil)
		assert.NoError(t, err)

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)

		//Check for http reponse code 200
		assert.Equal(t, 200, recorder.Code)
		assert.JSONEq(t, `{"authenticated":false}`, recorder.Body.String())
	})
}
