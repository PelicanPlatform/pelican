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

// Collection CLI → local-issuer device-code → collections API end-to-end test.
//
// The collections management API (/api/v1.0/origin_ui/collections) is a
// control-plane surface gated by web_ui.AuthHandler, whose bearer path pins the
// token issuer to the origin's *local* issuer (config.GetLocalIssuerUrl). The
// `pelican collection` CLI must therefore obtain its token from the origin's
// local issuer, NOT from the origin's base-URL discovery document (which
// describes a data-namespace issuer whose tokens the collections API rejects).
//
// This test drives the real device-code flow against the local issuer's
// per-namespace endpoints (the same URL cmd/origin_collections.go now
// discovers) and proves the resulting bearer token is accepted by the
// collections API. It also pins the two properties that make that work:
//   - the local issuer is registered even without the transfer API, and
//   - the local issuer mints the namespace-agnostic collection.* scopes.

package fed_tests

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/oauth2/issuer"
	"github.com/pelicanplatform/pelican/param"
)

func TestCollectionCLILocalIssuerE2E(t *testing.T) {
	ft, testUserPassword, _ := setupFedAndUsers(t)
	serverURL := param.Server_ExternalWebUrl.GetString()

	// The collection CLI discovers the origin's LOCAL issuer (see
	// cmd/origin_collections.go), not its bare web URL. Mirror that here.
	localIssuerURL := serverURL + "/api/v1.0/issuer/ns" + issuer.LocalIssuerNamespace

	issuerMeta, err := config.GetIssuerMetadata(localIssuerURL)
	require.NoError(t, err, "local issuer discovery must succeed at %s (is the local provider registered?)", localIssuerURL)
	require.NotEmpty(t, issuerMeta.RegistrationURL, "local issuer must advertise a dynamic-registration endpoint")
	require.NotEmpty(t, issuerMeta.DeviceAuthURL, "local issuer must advertise a device-authorization endpoint")

	// Register a client and run the real device-code flow for a collection scope.
	// collection.read is what the collections list endpoint requires; it is one
	// of the namespace-agnostic management scopes any authenticated user holds.
	scopes := []string{"collection.read:/"}
	drcp := oauth2.DCRPConfig{
		ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
		Transport:                     config.GetTransport(),
		Metadata: oauth2.Metadata{
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			ResponseTypes:           []string{"code"},
			ClientName:              "Pelican Collections CLI Client",
			Scopes:                  scopes,
		},
	}
	dcrResp, err := drcp.Register()
	require.NoError(t, err, "dynamic client registration against the local issuer should succeed")

	oauth2Config := oauth2.Config{
		ClientID:     dcrResp.ClientID,
		ClientSecret: dcrResp.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       issuerMeta.AuthURL,
			TokenURL:      issuerMeta.TokenURL,
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
		},
		Scopes: scopes,
	}

	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(ft.Ctx, oauth2.HTTPClient, httpClient)
	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	require.NoError(t, err)

	// Approve the device code as testuser against the local issuer's namespace.
	simulateUserApproval(t, serverURL, issuer.LocalIssuerNamespace, deviceAuth.UserCode, testUserPassword)

	var accessToken string
	pollValues := url.Values{
		"client_id":   {dcrResp.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceAuth.DeviceCode},
	}
	require.Eventually(t, func() bool {
		tok, err := oauth2.RetrieveToken(ctx, dcrResp.ClientID, dcrResp.ClientSecret, issuerMeta.TokenURL, pollValues)
		if err != nil {
			return false
		}
		accessToken = tok.AccessToken
		return true
	}, 30*time.Second, 2*time.Second, "device-code token retrieval should succeed after approval")
	require.NotEmpty(t, accessToken)

	// The token must carry iss == GetLocalIssuerUrl() — exactly what
	// web_ui.AuthHandler requires — and the namespace-agnostic collection.read
	// scope the local issuer mints via the shared authorize handler. (We decode
	// the claims directly rather than via validateWLCGToken, which asserts the
	// presence of storage scopes a control-plane collection token has none of.)
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3, "access token must be a three-part JWT")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, config.GetLocalIssuerUrl(), claims["iss"],
		"token must be minted by the server's local issuer (what web_ui.AuthHandler requires)")
	assert.Equal(t, "testuser", claims["sub"])
	assert.Contains(t, extractScopes(claims), "collection.read:/",
		"the local issuer should mint the namespace-agnostic collection.read scope")

	// The payoff: the collections API accepts this local-issuer bearer token.
	// Before the fix the CLI discovered the origin's data-namespace issuer,
	// whose tokens web_ui.AuthHandler rejects (wrong issuer) with a 401.
	listURL := serverURL + "/api/v1.0/origin_ui/collections"
	req, err := http.NewRequest("GET", listURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"collections API must accept the local-issuer bearer token; got %d (body: %s)", resp.StatusCode, string(body))
}
