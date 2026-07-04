//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package server_utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// TestDiscoveryEmbeddedIssuerNamespace verifies the server-level
// /.well-known/openid-configuration discovery document.
//
// The server-level document describes the server's *local* issuer, not any data
// export: its "issuer" is the server issuer URL, and its OAuth endpoints point
// at the reserved LocalIssuerNamespace. Per-namespace data issuers are
// advertised to the director and discovered at their own
// /api/v1.0/issuer/ns/<prefix> endpoints, so the server-level document never
// leaks a data-export prefix.
//
// The key behaviors under test:
//  1. Embedded issuer: OAuth endpoints point at /api/v1.0/issuer/ns/pelican/local-issuer
//     and the issuer is the server URL, regardless of the exports.
//  2. Without the embedded issuer enabled, no OIDC endpoints are set.
//  3. OA4MP mode keeps the legacy single-issuer endpoints.
func TestDiscoveryEmbeddedIssuerNamespace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// callDiscovery creates a gin router, registers the OIDC discovery
	// endpoint, and performs a GET request, returning the decoded response.
	callDiscovery := func(t *testing.T) server_structs.OpenIdDiscoveryResponse {
		t.Helper()
		router := gin.New()
		group := router.Group("")
		RegisterOIDCAPI(group, false)

		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
		require.NoError(t, err)
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		var resp server_structs.OpenIdDiscoveryResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		return resp
	}

	// setupExports loads YAML config into viper and populates the exports cache.
	setupExports := func(t *testing.T, yamlCfg string) {
		t.Helper()
		viper.SetConfigType("yaml")
		require.NoError(t, viper.ReadConfig(strings.NewReader(yamlCfg)))

		// Override StoragePrefix placeholders with real temp files
		exports := viper.Get("origin.exports").([]interface{})
		for _, export := range exports {
			exportMap := export.(map[string]interface{})
			for k, v := range exportMap {
				if v == "SHOULD-OVERRIDE" {
					exportMap[k] = getTmpFile(t)
				}
			}
		}
		require.NoError(t, param.Origin_Exports.Set(exports))
		require.NoError(t, param.Server_IssuerUrl.Set("https://origin.example.com:8444"))

		_, err := GetOriginExports()
		require.NoError(t, err)
	}

	// localIssuerBase is where the server-level document must point its OAuth
	// endpoints: the reserved local-issuer namespace, rooted at ExternalWebUrl.
	localIssuerBase := "https://origin.example.com:8444/api/v1.0/issuer/ns" + server_structs.LocalIssuerNamespace

	t.Run("EmbeddedUsesLocalIssuer", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		setupExports(t, `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /data
      StoragePrefix: SHOULD-OVERRIDE
      Capabilities: ["Reads", "Writes"]
Server:
  ExternalWebUrl: https://origin.example.com:8444
`)

		resp := callDiscovery(t)

		// The issuer is the server issuer URL, not a data-export namespace.
		assert.Equal(t, "https://origin.example.com:8444", resp.Issuer,
			"Issuer should be the server issuer URL, not a data export")
		assert.Equal(t, localIssuerBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, localIssuerBase+"/oidc-cm", resp.RegistrationEndpoint)
		assert.Equal(t, localIssuerBase+"/device_authorization", resp.DeviceEndpoint)
		assert.Equal(t, localIssuerBase+"/authorize", resp.AuthorizationEndpoint)
		assert.Equal(t, localIssuerBase+"/userinfo", resp.UserInfoEndpoint)
		assert.Equal(t, localIssuerBase+"/revoke", resp.RevocationEndpoint)
		assert.Contains(t, resp.GrantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code")
	})

	t.Run("MultipleExportsNoDataPrefixLeaks", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		setupExports(t, `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /public
      StoragePrefix: SHOULD-OVERRIDE
      Capabilities: ["PublicReads"]
    - FederationPrefix: /private
      StoragePrefix: SHOULD-OVERRIDE
      Capabilities: ["Reads", "Writes"]
    - FederationPrefix: /also-private
      StoragePrefix: SHOULD-OVERRIDE
      Capabilities: ["Reads"]
Server:
  ExternalWebUrl: https://origin.example.com:8444
`)

		resp := callDiscovery(t)

		// No data-export prefix must leak into the server-level document,
		// regardless of how many exports (public or not) the origin has.
		assert.Equal(t, "https://origin.example.com:8444", resp.Issuer)
		assert.Equal(t, localIssuerBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, localIssuerBase+"/authorize", resp.AuthorizationEndpoint)
		for _, field := range []string{resp.Issuer, resp.TokenEndpoint, resp.AuthorizationEndpoint} {
			assert.NotContains(t, field, "/private")
			assert.NotContains(t, field, "/public")
			assert.NotContains(t, field, "/ns/data")
		}
	})

	t.Run("EmbeddedIssuerDisabledNoEndpoints", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))
		require.NoError(t, param.Origin_EnableIssuer.Set(false))

		resp := callDiscovery(t)

		assert.Equal(t, "https://origin.example.com:8444", resp.Issuer)
		assert.Empty(t, resp.TokenEndpoint, "No token endpoint when issuer disabled")
		assert.Empty(t, resp.RegistrationEndpoint, "No registration endpoint when issuer disabled")
		assert.Empty(t, resp.DeviceEndpoint, "No device endpoint when issuer disabled")
	})

	t.Run("OA4MPModeLegacyPaths", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))
		require.NoError(t, param.Origin_EnableIssuer.Set(true))
		require.NoError(t, param.Origin_IssuerMode.Set("oa4mp"))

		resp := callDiscovery(t)

		legacyBase := "https://origin.example.com:8444/api/v1.0/issuer"
		assert.Equal(t, legacyBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, legacyBase+"/oidc-cm", resp.RegistrationEndpoint)
		assert.Equal(t, legacyBase+"/device_authorization", resp.DeviceEndpoint)
		// Issuer itself should NOT contain /ns/
		assert.NotContains(t, resp.Issuer, "/ns/")
	})
}
