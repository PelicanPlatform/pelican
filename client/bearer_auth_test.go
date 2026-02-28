/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

	"github.com/pelicanplatform/pelican/config"
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

	token := newTokenGenerator(nil, nil, config.TokenSharedRead, false)
	token.SetToken("some_token_1234_abc")
	authenticator := &bearerAuthenticator{token: token}
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

// Test the retry logic for bearer authentication
func TestBearerAuthenticator_Verify(t *testing.T) {
	token := newTokenGenerator(nil, nil, config.TokenSharedRead, false)
	token.SetToken("some_token_1234_abc")
	authenticator := &bearerAuthenticator{token: token}

	// First three 401/403 responses assert `redo=true` with the "retrying with a fresh credential" message
	for i := 0; i < 3; i++ {
		redo, err := authenticator.Verify(nil, &http.Response{StatusCode: http.StatusUnauthorized}, "/test/path")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "retrying with a fresh credential")
		assert.True(t, redo, "unauthorized attempt %d should trigger a retry", i+1)
	}

	// The fourth 401/403 response asserts `redo=false` with the "authentication failed" message
	redo, err := authenticator.Verify(nil, &http.Response{StatusCode: http.StatusUnauthorized}, "/test/path")
	assert.Error(t, err)
	assert.False(t, redo, "fourth unauthorized response should stop retrying")
	assert.Contains(t, err.Error(), "authentication failed")

	// Successful response should reset the failure counter.
	redo, err = authenticator.Verify(nil, &http.Response{StatusCode: http.StatusOK}, "/test/path")
	assert.NoError(t, err)
	assert.False(t, redo, "successful responses should not trigger retry")

	// After a success, the next unauthorized response should allow one more retry.
	redo, err = authenticator.Verify(nil, &http.Response{StatusCode: http.StatusForbidden}, "/test/path")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "retrying with a fresh credential")
	assert.True(t, redo, "failure counter should reset after a success")
}
