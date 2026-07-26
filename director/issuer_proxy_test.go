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

package director

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteIssuerDiscoveryDoc(t *testing.T) {
	originBase := "https://origin.example:8443/api/v1.0/issuer/ns/foo"
	proxyBase := "https://director.example/api/v1.0/director/issuer/ns/foo"

	doc := `{
		"issuer": "https://origin.example:8443/api/v1.0/issuer/ns/foo",
		"token_endpoint": "https://origin.example:8443/api/v1.0/issuer/ns/foo/token",
		"authorization_endpoint": "https://origin.example:8443/api/v1.0/issuer/ns/foo/authorize",
		"device_authorization_endpoint": "https://origin.example:8443/api/v1.0/issuer/ns/foo/device_authorization",
		"jwks_uri": "https://origin.example:8443/.well-known/issuer.jwks",
		"response_types_supported": ["code"],
		"grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"]
	}`

	out, err := rewriteIssuerDiscoveryDoc([]byte(doc), originBase, proxyBase)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(out, &m))

	// issuer + endpoint URLs are re-based onto the director proxy.
	assert.Equal(t, proxyBase, m["issuer"])
	assert.Equal(t, proxyBase+"/token", m["token_endpoint"])
	assert.Equal(t, proxyBase+"/authorize", m["authorization_endpoint"])
	assert.Equal(t, proxyBase+"/device_authorization", m["device_authorization_endpoint"])

	// jwks_uri (origin server-root) is routed to the namespaced director path so
	// validators still fetch the ORIGIN's signing key (proxied), not the
	// director's federation key.
	assert.Equal(t, proxyBase+"/.well-known/issuer.jwks", m["jwks_uri"])

	// Non-URL fields are untouched.
	assert.Equal(t, []any{"code"}, m["response_types_supported"])
	assert.Len(t, m["grant_types_supported"], 2)
}

func TestRewriteIssuerDiscoveryDoc_MalformedIsError(t *testing.T) {
	_, err := rewriteIssuerDiscoveryDoc([]byte("not json"), "https://o/api/v1.0/issuer/ns/foo", "https://d/x")
	require.Error(t, err)
}

// TestRebaseIssuerJSONURLs covers the device-authorization response: the
// verification_uri(_complete) a human must open in a browser has to point at the
// reachable director proxy, not the (firewalled) origin, so a client that began
// the device flow through the proxy can complete it.
func TestRebaseIssuerJSONURLs(t *testing.T) {
	originBase := "https://origin.example:8443/api/v1.0/issuer/ns/foo"
	proxyBase := "https://director.example/api/v1.0/issuer-proxy/ns/foo"

	resp := `{
		"device_code": "abc123",
		"user_code": "WDJB-MJHT",
		"verification_uri": "https://origin.example:8443/api/v1.0/issuer/ns/foo/device",
		"verification_uri_complete": "https://origin.example:8443/api/v1.0/issuer/ns/foo/device?user_code=WDJB-MJHT",
		"expires_in": 600,
		"interval": 5
	}`

	out, err := rebaseIssuerJSONURLs([]byte(resp), originBase, proxyBase)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(out, &m))

	// The user-facing URLs are re-based onto the director proxy.
	assert.Equal(t, proxyBase+"/device", m["verification_uri"])
	assert.Equal(t, proxyBase+"/device?user_code=WDJB-MJHT", m["verification_uri_complete"])

	// Opaque, non-URL fields are left untouched.
	assert.Equal(t, "abc123", m["device_code"])
	assert.Equal(t, "WDJB-MJHT", m["user_code"])
	assert.EqualValues(t, 600, m["expires_in"])
}

func TestRebaseIssuerJSONURLs_MalformedIsError(t *testing.T) {
	_, err := rebaseIssuerJSONURLs([]byte("not json"), "https://o/api/v1.0/issuer/ns/foo", "https://d/x")
	require.Error(t, err)
}

// TestRewriteIssuerCookiePaths covers the device-verify CSRF cookie: the origin
// scopes it to its own issuer path, which the proxy must re-path onto its prefix
// so the browser sends it back to the director on the follow-up POST.
func TestRewriteIssuerCookiePaths(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "csrf_token=abc; Path=/api/v1.0/issuer/ns/foo/device; HttpOnly; Secure")
	// A cookie scoped elsewhere (e.g. a session cookie at the server root) is left
	// untouched — only issuer-scoped cookies are re-pathed.
	resp.Header.Add("Set-Cookie", "session=xyz; Path=/; HttpOnly")

	rewriteIssuerCookiePaths(resp)

	got := resp.Header["Set-Cookie"]
	require.Len(t, got, 2)
	assert.Equal(t, "csrf_token=abc; Path=/api/v1.0/issuer-proxy/ns/foo/device; HttpOnly; Secure", got[0])
	assert.Equal(t, "session=xyz; Path=/; HttpOnly", got[1])
}
