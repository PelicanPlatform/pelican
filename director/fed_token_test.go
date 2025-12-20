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

package director

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

var setGinTestModeOnce sync.Once

func setGinTestMode() {
	setGinTestModeOnce.Do(func() {
		gin.SetMode(gin.TestMode)
		// Route gin logs through logrus so they appear under the test log hook.
		gin.DefaultWriter = log.StandardLogger().WriterLevel(log.InfoLevel)
		gin.DefaultErrorWriter = log.StandardLogger().WriterLevel(log.WarnLevel)
	})
}

func TestValidateRequest(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name           string
		host           []string // Using slices here so we can trigger errors on purpose
		sType          []string
		tok            string
		authFromHeader bool
		expectErr      bool
		errStr         string
	}{
		{
			name:           "Valid request",
			host:           []string{"cache1"},
			sType:          []string{"Cache"},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      false,
			errStr:         "",
		},
		{
			name:           "No hostname",
			host:           []string{},
			sType:          []string{"Cache"},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "no hostname found in the 'host' url parameter",
		},
		{
			name:           "Multiple hostnames",
			host:           []string{"cache1", "cache2"},
			sType:          []string{"Cache"},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "multiple hostnames found in the 'host' url parameter",
		},
		{
			name:           "No server type",
			host:           []string{"cache1"},
			sType:          []string{},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "host 'cache1' generated request with no server type found in the 'sType' url parameter",
		},
		{
			name:           "Invalid server type",
			host:           []string{"cache1"},
			sType:          []string{"Invalid"},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "host 'cache1' generated request with invalid server type 'Invalid' as value of 'sType' url parameter",
		},
		{
			name:           "Multiple server types",
			host:           []string{"cache1"},
			sType:          []string{"Cache", "Origin"},
			tok:            "token1",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "host 'cache1' generated request with multiple server types in the 'sType' url parameter",
		},
		{
			name:           "No token",
			host:           []string{"cache1"},
			sType:          []string{"Cache"},
			tok:            "",
			authFromHeader: false,
			expectErr:      true,
			errStr:         "host 'cache1' generated request with no authorization token in 'Authorization' header or 'authz' url parameter",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			params := url.Values{}
			if len(tc.host) > 0 {
				for _, h := range tc.host {
					params.Add("host", h)
				}
			}
			if len(tc.sType) > 0 {
				for _, st := range tc.sType {
					params.Add("sType", st)
				}
			}
			if !tc.authFromHeader && tc.tok != "" {
				params.Add("authz", tc.tok)
			}

			req := httptest.NewRequest("GET", "/test?"+params.Encode(), nil)

			// Add authorization headers AFTER request creation -- they will be overwritten otherwise
			if tc.authFromHeader && tc.tok != "" {
				req.Header.Add("Authorization", tc.tok)
			}
			c.Request = req

			rInfo, err := validateFedTokRequest(c)

			if tc.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errStr)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, rInfo.Host, tc.host[0])
			assert.Equal(t, rInfo.SType.String(), tc.sType[0])
			assert.Equal(t, tc.tok, rInfo.Tok)
		})
	}
}

func parseJWT(tokenString string) (scopes []string, issuer string, err error) {
	// Parse without verification
	tok, err := jwt.ParseInsecure([]byte(tokenString))
	if err != nil {
		return nil, "", err
	}

	issuer = tok.Issuer()
	if raw, exists := tok.Get("scope"); exists {
		if scopeStr, ok := raw.(string); ok {
			scopes = strings.Split(scopeStr, " ")
		}
	}

	return scopes, issuer, nil
}

func TestCreateFedTok(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name            string
		host            string
		sType           server_structs.ServerType
		discoveryUrl    string
		allowedPrefixes map[string]map[string]struct{}
		expectErr       bool
		errContains     string
	}{
		{
			name:         "Valid request",
			host:         "test-cache.example.com",
			sType:        server_structs.CacheType,
			discoveryUrl: "https://my-federation.com",
			allowedPrefixes: map[string]map[string]struct{}{
				"test-cache.example.com": {
					"/foo": struct{}{},
					"/bar": struct{}{},
				},
				"different-cache.example.com": {
					"/baz": struct{}{},
				},
			},
			expectErr: false,
		},
		{
			name:         "No allowed prefixes defaults to root of namespace",
			host:         "test-cache.example.com",
			sType:        server_structs.CacheType,
			discoveryUrl: "https://my-federation.com",
			allowedPrefixes: map[string]map[string]struct{}{
				"different-cache.example.com": {
					"/baz": struct{}{},
				},
			},
			expectErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			defer server_utils.ResetTestState()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			confDir := t.TempDir()
			kDir := filepath.Join(confDir, "keys")
			require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
			require.NoError(t, param.Set("ConfigDir", confDir))

			config.ResetFederationForTest()
			fed := pelican_url.FederationDiscovery{
				// Most of these aren't actually used by the test, but to prevent auto discovery
				// and needing to spin up a separate mock discovery server, set them all.
				DiscoveryEndpoint: tc.discoveryUrl,
				DirectorEndpoint:  "https://dne-director.com",
				RegistryEndpoint:  "https://dne-registry.com",
				JwksUri:           "https://dne-jwks.com",
				BrokerEndpoint:    "https://dne-broker.com",
			}
			config.SetFederation(fed)
			err := initServerForTest(t, c, server_structs.RegistryType) // Helps us populate the keys directory with a signing key
			require.NoError(t, err)

			allowedPrefixesForCaches.Store(&tc.allowedPrefixes)
			rInfo := requestInfo{
				Host:  tc.host,
				SType: tc.sType,
			}

			tok, err := createFedTok(c, rInfo)

			if tc.expectErr {
				assert.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}

			// Make sure we don't have an error and that we _do_ have a token
			assert.NoError(t, err)
			assert.NotEmpty(t, tok)

			// Verify token contents
			scopes, issuer, err := parseJWT(tok)
			assert.NoError(t, err)
			assert.Equal(t, tc.discoveryUrl, issuer)
			if _, exists := tc.allowedPrefixes[tc.host]; !exists {
				assert.Len(t, scopes, 1)
				assert.Equal(t, "storage.read:/", scopes[0])
			} else {
				assert.Len(t, scopes, len(tc.allowedPrefixes[tc.host]))
				for _, scope := range scopes {
					scope = strings.Split(scope, ":")[1]
					assert.Contains(t, tc.allowedPrefixes[tc.host], scope)
				}
			}
		})
	}
}
