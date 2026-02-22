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

package local_cache

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestGetAcls_PublicNamespaceWithInvalidToken verifies that getAcls grants
// PublicReads ACLs even when the bearer token is invalid or issued by an
// untrusted issuer.  This is a regression test for a bug where an untrusted
// token caused getResourceScopes to fail, and getAcls returned early before
// adding any public-namespace ACLs.
func TestGetAcls_PublicNamespaceWithInvalidToken(t *testing.T) {
	ac := &authConfig{}

	// Configure a public namespace with no issuers (like an HTTPS-backed origin).
	nsAds := []server_structs.NamespaceAdV2{
		{
			Path: "/public",
			Caps: server_structs.Capabilities{
				PublicReads: true,
				Reads:       true,
			},
			Issuer: nil,
		},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	t.Run("EmptyToken", func(t *testing.T) {
		acls, trusted, err := ac.getAcls("")
		require.NoError(t, err)
		assert.True(t, trusted, "empty token should be treated as trusted (no token)")
		require.Len(t, acls, 1)
		assert.Equal(t, token_scopes.Wlcg_Storage_Read, acls[0].Authorization)
		assert.Equal(t, "/public", acls[0].Resource)
	})

	t.Run("GarbageToken", func(t *testing.T) {
		acls, trusted, err := ac.getAcls("not-a-real-jwt")
		require.NoError(t, err)
		assert.False(t, trusted, "garbage token should not be trusted")
		require.Len(t, acls, 1, "Public ACLs must still be granted")
		assert.Equal(t, token_scopes.Wlcg_Storage_Read, acls[0].Authorization)
		assert.Equal(t, "/public", acls[0].Resource)
	})
}

// TestGetAcls_MixedNamespaces verifies that when public and private namespaces
// coexist, an invalid token still gets public ACLs but NOT private ones.
func TestGetAcls_MixedNamespaces(t *testing.T) {
	ac := &authConfig{}

	issuerURL, _ := url.Parse("https://issuer.example.com")
	nsAds := []server_structs.NamespaceAdV2{
		{
			Path: "/public",
			Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
		},
		{
			Path: "/private",
			Caps: server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{
				{
					IssuerUrl: *issuerURL,
					BasePaths: []string{"/"},
				},
			},
		},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	t.Run("InvalidTokenGetsOnlyPublicACLs", func(t *testing.T) {
		acls, trusted, err := ac.getAcls("bad-token")
		require.NoError(t, err)
		assert.False(t, trusted)

		// Should have public ACL only, NOT private
		require.Len(t, acls, 1, "Should only get public ACL, not private")
		assert.Equal(t, "/public", acls[0].Resource)
	})
}
