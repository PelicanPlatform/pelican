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

// TestDiscoveryEmbeddedIssuerNamespace verifies that the server-level
// /.well-known/openid-configuration discovery document advertises the
// correct namespace-scoped URLs when the embedded issuer is enabled.
//
// The key behaviors under test:
//  1. With a single auth-requiring export, the issuer and all endpoint
//     URLs must include /api/v1.0/issuer/ns/<prefix>.
//  2. With multiple exports (some public-read-only, some auth-requiring),
//     the first auth-requiring export's namespace is used.
//  3. Without the embedded issuer enabled, no OIDC endpoints are set.
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

	t.Run("SingleAuthExport", func(t *testing.T) {
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

		expectedBase := "https://origin.example.com:8444/api/v1.0/issuer/ns/data"
		assert.Equal(t, expectedBase, resp.Issuer,
			"Issuer should be scoped to the /data namespace")
		assert.Equal(t, expectedBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, expectedBase+"/oidc-cm", resp.RegistrationEndpoint)
		assert.Equal(t, expectedBase+"/device_authorization", resp.DeviceEndpoint)
		assert.Equal(t, expectedBase+"/authorize", resp.AuthorizationEndpoint)
		assert.Equal(t, expectedBase+"/userinfo", resp.UserInfoEndpoint)
		assert.Equal(t, expectedBase+"/revoke", resp.RevocationEndpoint)
		assert.Contains(t, resp.GrantTypesSupported, "urn:ietf:params:oauth:grant-type:device_code")
	})

	t.Run("MultipleExportsPicksFirstAuthRequiring", func(t *testing.T) {
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

		// /public is public-read-only, so it should be skipped.
		// /private is the first auth-requiring export.
		expectedBase := "https://origin.example.com:8444/api/v1.0/issuer/ns/private"
		assert.Equal(t, expectedBase, resp.Issuer,
			"Issuer should use /private (first auth-requiring export), not /public")
		assert.Equal(t, expectedBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, expectedBase+"/oidc-cm", resp.RegistrationEndpoint)
		assert.Equal(t, expectedBase+"/device_authorization", resp.DeviceEndpoint)
		assert.Equal(t, expectedBase+"/authorize", resp.AuthorizationEndpoint)

		// Ensure it didn't pick /public or /also-private
		assert.NotContains(t, resp.Issuer, "/public")
		assert.NotContains(t, resp.Issuer, "/also-private")
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

	t.Run("JWKSReadableCrossOrigin", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()

		// Point key generation at a temp dir so GetIssuerPublicJWKS succeeds.
		require.NoError(t, param.IssuerKeysDirectory.Set(t.TempDir()))

		router := gin.New()
		group := router.Group("")
		RegisterOIDCAPI(group, false)

		w := httptest.NewRecorder()
		req, err := http.NewRequest("GET", "/.well-known/issuer.jwks", nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://app.example.com")
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		// Browser-based OIDC clients follow the discovery document's jwks_uri
		// here to validate token signatures, so the public JWKS must be
		// readable from any origin like the discovery document itself.
		assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
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

	// The "issuer" and "jwks_uri" fields follow GetServerIssuerURL() — they
	// describe the server issuer's identity — but the embedded OAuth
	// endpoints must be derived from Server.ExternalWebUrl, never from
	// GetServerIssuerURL(). The next three cases drive the inputs
	// GetServerIssuerURL keys off of (Server.IssuerUrl,
	// Server.IssuerHostname, and the co-located sub-path) and assert none
	// of them leak into or distort the emitted OAuth endpoints.

	embeddedDataYaml := `
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
`

	t.Run("ServerIssuerUrlIgnoredForEmbeddedDiscovery", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		setupExports(t, embeddedDataYaml)
		// A Server.IssuerUrl pointing at a different host defines the
		// issuer identity (the "issuer" and "jwks_uri" fields) but must
		// NOT leak into the embedded OAuth endpoints — those are always
		// ExternalWebUrl-based.
		require.NoError(t, param.Server_IssuerUrl.Set("https://issuer.example.com:9999"))

		resp := callDiscovery(t)

		assert.Equal(t, "https://issuer.example.com:9999", resp.Issuer)
		assert.Equal(t, "https://issuer.example.com:9999/.well-known/issuer.jwks", resp.JwksUri)
		assert.Equal(t, localIssuerBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, localIssuerBase+"/authorize", resp.AuthorizationEndpoint)
		// The configured issuer host must be nowhere in the OAuth endpoints.
		assert.NotContains(t, resp.TokenEndpoint, "issuer.example.com")
		assert.NotContains(t, resp.AuthorizationEndpoint, "issuer.example.com")
		assert.NotContains(t, resp.RegistrationEndpoint, "issuer.example.com")
		assert.NotContains(t, resp.DeviceEndpoint, "issuer.example.com")
	})

	t.Run("ServerIssuerHostnameIgnoredForEmbeddedDiscovery", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		setupExports(t, embeddedDataYaml)
		// Clear Server.IssuerUrl so GetServerIssuerURL falls through to the
		// Server.IssuerHostname/Server.IssuerPort precedence, then confirm
		// that likewise doesn't leak into the embedded OAuth endpoints.
		require.NoError(t, param.Server_IssuerUrl.Set(""))
		require.NoError(t, param.Server_IssuerHostname.Set("issuer.example.com"))
		require.NoError(t, param.Server_IssuerPort.Set(9999))

		resp := callDiscovery(t)

		assert.Equal(t, "https://issuer.example.com:9999", resp.Issuer)
		assert.Equal(t, "https://issuer.example.com:9999/.well-known/issuer.jwks", resp.JwksUri)
		assert.Equal(t, localIssuerBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, localIssuerBase+"/authorize", resp.AuthorizationEndpoint)
		assert.NotContains(t, resp.TokenEndpoint, "issuer.example.com")
		assert.NotContains(t, resp.AuthorizationEndpoint, "issuer.example.com")
	})

	t.Run("CoLocatedOriginDirectorNoDoublePath", func(t *testing.T) {
		ResetTestState()
		defer ResetTestState()
		defer ResetOriginExports()

		setupExports(t, embeddedDataYaml)
		// In fed-in-a-box (origin + director in one process),
		// GetServerIssuerURL returns the co-located
		// "<ExternalWebUrl>/api/v1.0/origin" sub-path. Setting
		// Server.IssuerUrl to that value reproduces the exact issuerStr the
		// discovery handler would see, without toggling the process-global
		// enabled-servers set. The issuer identity keeps the sub-path, but
		// the embedded OAuth endpoints must still be based on the bare
		// ExternalWebUrl, with no doubled path.
		require.NoError(t, param.Server_IssuerUrl.Set("https://origin.example.com:8444/api/v1.0/origin"))

		resp := callDiscovery(t)

		assert.Equal(t, "https://origin.example.com:8444/api/v1.0/origin", resp.Issuer)
		assert.Equal(t, "https://origin.example.com:8444/api/v1.0/origin/.well-known/issuer.jwks", resp.JwksUri)
		assert.Equal(t, localIssuerBase+"/token", resp.TokenEndpoint)
		assert.Equal(t, localIssuerBase+"/authorize", resp.AuthorizationEndpoint)

		// Guard against building endpoints on GetServerIssuerURL's
		// sub-path, which would double "/api/v1.0/origin" into the issuer
		// path.
		const doubled = "/api/v1.0/origin/api/v1.0/issuer"
		assert.NotContains(t, resp.Issuer, doubled)
		assert.NotContains(t, resp.TokenEndpoint, doubled)
		assert.NotContains(t, resp.AuthorizationEndpoint, doubled)
		assert.NotContains(t, resp.TokenEndpoint, "/api/v1.0/origin")
		assert.NotContains(t, resp.AuthorizationEndpoint, "/api/v1.0/origin")
	})
}
