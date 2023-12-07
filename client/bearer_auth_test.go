/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBearerAuthenticator_Authorize(t *testing.T) {
	// Set up a test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the Authorization header is correct
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer some_token_1234_abc", authHeader)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	authenticator := &bearerAuthenticator{token: "some_token_1234_abc"}
	client := &http.Client{}

	// Create a HTTP request to be authorized
	request, err := http.NewRequest("GET", server.URL, nil)
	assert.NoError(t, err)
	err = authenticator.Authorize(client, request, "/test/path")
	assert.NoError(t, err)

	// Send the request and verify
	response, err := client.Do(request)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestBearerAuthenticator_Verify(t *testing.T) {
	authenticator := &bearerAuthenticator{token: "some_token_1234_abc"}
	client := &http.Client{}

	// Create a dummy HTTP response with a 401 status
	response := &http.Response{
		StatusCode: http.StatusUnauthorized,
	}

	// Verify the authentication
	redo, err := authenticator.Verify(client, response, "/test/path")
	assert.Error(t, err)
	assert.True(t, redo, "Expected Verify to return true for 401 Unauthorized")

	// Create a dummy HTTP response with a 200 OK status
	responseOK := &http.Response{
		StatusCode: http.StatusOK,
	}

	// Verify the authentication
	redo, err = authenticator.Verify(client, responseOK, "/test/path")
	assert.NoError(t, err)
	assert.False(t, redo, "Expected Verify to return false for 200 OK")
}
