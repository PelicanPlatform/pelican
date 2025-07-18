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

package client_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestSharingUrl(t *testing.T) {
	// Construct a local server that we can poke with QueryDirector. Start with a placeholder handler
	// so that we can update the server.URL with the actual server address in the handler we overwrite later.
	log.SetLevel(log.DebugLevel)
	// Placeholder handler
	handler := func(w http.ResponseWriter, r *http.Request) {}

	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	defer server.Close()

	// Actual handler using the updated server.URL
	handler = func(w http.ResponseWriter, r *http.Request) {
		issuerLoc := server.URL + "/issuer"
		if strings.HasPrefix(r.URL.Path, "/test") {
			w.Header().Set("Location", server.URL)
			w.Header().Set("X-Pelican-Namespace", "namespace=/test, require-token=true")
			w.Header().Set("X-Pelican-Authorization", fmt.Sprintf("issuer=%s", issuerLoc))
			w.Header().Set("X-Pelican-Token-Generation", fmt.Sprintf("issuer=%s, base-path=/test, strategy=OAuth2, max-scope-depth=3", issuerLoc))
			w.WriteHeader(http.StatusTemporaryRedirect)
		} else if r.URL.Path == "/issuer/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusOK)
			oidcConfig := fmt.Sprintf(`{"token_endpoint": "%s/token", "registration_endpoint": "%s/register", "grant_types_supported": ["urn:ietf:params:oauth:grant-type:device_code"], "device_authorization_endpoint": "%s/device_authz"}`, issuerLoc, issuerLoc, issuerLoc)
			_, err := w.Write([]byte(oidcConfig))
			assert.NoError(t, err)
		} else if r.URL.Path == "/.well-known/pelican-configuration" { // to serve discovery information
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(fmt.Sprintf(`{"director_endpoint": "%s"}`, server.URL)))
			assert.NoError(t, err)
		} else if r.URL.Path == "/issuer/register" {
			clientConfig := `{"client_id": "client1", "client_secret": "secret", "client_secret_expires_at": 0}`
			w.WriteHeader(http.StatusCreated)
			_, err := w.Write([]byte(clientConfig))
			assert.NoError(t, err)
		} else if r.URL.Path == "/issuer/device_authz" {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"device_code": "1234", "user_code": "5678", "interval": 1, "verification_uri": "https://example.com", "expires_in": 20}`))
			assert.NoError(t, err)
		} else if r.URL.Path == "/issuer/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"access_token": "token1234", "token_type": "jwt"}`))
			assert.NoError(t, err)
		} else {
			fmt.Println(r)
			requestBytes, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			fmt.Println(string(requestBytes))
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
	// Restart the server with the updated handler
	server.Config.Handler = http.HandlerFunc(handler)

	_, err := config.SetPreferredPrefix(config.PelicanPrefix)
	assert.NoError(t, err)

	os.Setenv("PELICAN_SKIP_TERMINAL_CHECK", "password")
	defer os.Unsetenv("PELICAN_SKIP_TERMINAL_CHECK")

	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName():           "debug",
		param.TLSSkipVerify.GetName():           true,
		param.Federation_DiscoveryUrl.GetName(): server.URL,
	})

	// Call QueryDirector with the test server URL and a source path
	testObj, err := url.Parse("/test/foo/bar")
	require.NoError(t, err)
	os.Setenv(config.GetPreferredPrefix().String()+"_SKIP_TERMINAL_CHECK", "true")
	token, err := client.CreateSharingUrl(context.Background(), testObj, true)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	fmt.Println(token)
	os.Unsetenv(config.GetPreferredPrefix().String() + "_SKIP_TERMINAL_CHECK")
}
