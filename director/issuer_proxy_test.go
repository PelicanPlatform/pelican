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
