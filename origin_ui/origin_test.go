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
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	//set a temporary password file:
	tempPasswdFile, err := os.CreateTemp("", "origin-ui-passwd")
	if err != nil {
		fmt.Println("Failed to setup origin-ui-passwd file")
		os.Exit(1)
	}
	defer tempPasswdFile.Close()
	//Override viper default for testing
	viper.Set("OriginUI.PasswordFile", tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		fmt.Println("Error making temp jwk dir")
		os.Exit(1)
	}
	defer os.RemoveAll(tempJWKDir)

	//Override viper default for testing
	viper.Set("IssuerKey", filepath.Join(tempJWKDir, "issuer.jwk"))
	//Get keys
	_, err = config.GenerateIssuerJWKS()
	if err != nil {
		fmt.Println("Error issuing jwks")
		os.Exit(1)
	}
	router = gin.Default()
}

func TestCodeBasedLogin(t *testing.T) {
	//Configure UI
	err := ConfigureOriginUI(router)
	assert.NoError(t, err)
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
	//////////////////////////////SETUP////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err := tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = ConfigureOriginUI(router)
	assert.NoError(t, err)

	//Create a user for testing
	err = writePasswordEntry("user", "password")
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
	///////////////////////////SETUP///////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err := tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = ConfigureOriginUI(router)
	assert.NoError(t, err)

	//Create a user for testing
	err = writePasswordEntry("user", "password")
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
	///////////////////////////SETUP///////////////////////////////////
	//Add an admin user to file to configure
	content := "admin:password\n"
	_, err := tempPasswdFile.WriteString(content)
	assert.NoError(t, err, "Error writing to temp password file")

	//Configure UI
	err = ConfigureOriginUI(router)

	//Create a user for testing
	err = writePasswordEntry("user", "password")
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
