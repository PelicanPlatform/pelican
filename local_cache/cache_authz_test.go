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
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

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

// TestUpdateConfig_InvalidatesTokenCache verifies that when updateConfig
// installs a new namespace list, the tokenAuthz cache is cleared so that
// stale ACLs computed against the old list are not reused.
func TestUpdateConfig_InvalidatesTokenCache(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, ctx := errgroup.WithContext(ctx)

	ac := newAuthConfig(ctx, egrp)

	// Initial config: only /alpha is public.
	nsAds := []server_structs.NamespaceAdV2{
		{Path: "/alpha", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	// Empty-token request should be authorized for /alpha/file (public).
	ok, _ := ac.authorize(token_scopes.Wlcg_Storage_Read, "/alpha/file", "")
	assert.True(t, ok, "should be authorized for public /alpha/file")

	// Empty-token request should NOT be authorized for /beta/file (unknown namespace).
	ok, reason := ac.authorize(token_scopes.Wlcg_Storage_Read, "/beta/file", "")
	assert.False(t, ok, "should NOT be authorized for unknown /beta/file")
	assert.NotEmpty(t, reason)

	// Add /beta as a new public namespace (simulates a new origin registering
	// with the director).
	nsAds = append(nsAds, server_structs.NamespaceAdV2{
		Path: "/beta",
		Caps: server_structs.Capabilities{PublicReads: true, Reads: true},
	})
	require.NoError(t, ac.updateConfig(nsAds))

	// The token cache was invalidated by updateConfig, so /beta/file should
	// now be authorized immediately — no need to wait for TTL expiry.
	ok, _ = ac.authorize(token_scopes.Wlcg_Storage_Read, "/beta/file", "")
	assert.True(t, ok, "should be authorized for /beta/file after namespace update")

	// Original namespace should still work.
	ok, _ = ac.authorize(token_scopes.Wlcg_Storage_Read, "/alpha/file", "")
	assert.True(t, ok, "/alpha/file should still be authorized")

	// Re-applying the same list should NOT invalidate the cache.
	// Populate the cache entry for /alpha/file.
	ok, _ = ac.authorize(token_scopes.Wlcg_Storage_Read, "/alpha/file", "")
	require.True(t, ok)

	// Cache should contain a result for the empty token.
	require.NotNil(t, ac.tokenAuthz.Get(""), "cache should be populated before no-op update")

	// Update with an identical list.
	nsAdsCopy := make([]server_structs.NamespaceAdV2, len(nsAds))
	copy(nsAdsCopy, nsAds)
	require.NoError(t, ac.updateConfig(nsAdsCopy))

	// Cache should still be populated — no semantic change.
	require.NotNil(t, ac.tokenAuthz.Get(""), "cache should survive a no-op config update")

	cancel()
	_ = egrp.Wait()
}

// TestGetAcls_HierarchicalNamespaceOR verifies that authorization is the
// OR of all matching namespace rules.  A public parent namespace grants
// read access to paths under a private child namespace.  Two sibling
// private namespaces with different issuers both contribute ACLs.
func TestGetAcls_HierarchicalNamespaceOR(t *testing.T) {
	ac := &authConfig{}

	t.Run("PublicParentCoversPrivateChild", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://issuer.example.com")
		nsAds := []server_structs.NamespaceAdV2{
			{Path: "/data", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
			{
				Path: "/data/private",
				Caps: server_structs.Capabilities{Reads: true},
				Issuer: []server_structs.TokenIssuer{{
					IssuerUrl: *issuerURL,
					BasePaths: []string{"/"},
				}},
			},
		}
		require.NoError(t, ac.updateConfig(nsAds))

		acls, _, err := ac.getAcls("")
		require.NoError(t, err)
		// Only the public namespace contributes (no valid token).
		require.Len(t, acls, 1)
		assert.Equal(t, "/data", acls[0].Resource)

		// The parent's public-read ACL covers paths under the private child.
		childScope := token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/private/file")
		assert.True(t, acls[0].Contains(childScope),
			"public parent /data should cover /data/private/file")
	})

	t.Run("PrivateParentDoesNotCoverChildWithoutToken", func(t *testing.T) {
		issuerURL, _ := url.Parse("https://issuer.example.com")
		nsAds := []server_structs.NamespaceAdV2{
			{
				Path: "/secure",
				Caps: server_structs.Capabilities{Reads: true},
				Issuer: []server_structs.TokenIssuer{{
					IssuerUrl: *issuerURL,
					BasePaths: []string{"/"},
				}},
			},
			{Path: "/secure/public", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		}
		require.NoError(t, ac.updateConfig(nsAds))

		acls, _, err := ac.getAcls("")
		require.NoError(t, err)
		// Only the child's public namespace contributes.
		require.Len(t, acls, 1)
		assert.Equal(t, "/secure/public", acls[0].Resource)

		// Public child covers deeper paths.
		deepScope := token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/secure/public/deep/file")
		assert.True(t, acls[0].Contains(deepScope),
			"public child /secure/public should cover /secure/public/deep/file")

		// But the public child does NOT cover the private parent.
		parentScope := token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/secure/other")
		assert.False(t, acls[0].Contains(parentScope),
			"/secure/public ACL should NOT cover /secure/other")
	})

	t.Run("UnrelatedNamespacesDoNotInterfere", func(t *testing.T) {
		nsAds := []server_structs.NamespaceAdV2{
			{Path: "/alpha", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
			{Path: "/beta", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		}
		require.NoError(t, ac.updateConfig(nsAds))

		acls, _, err := ac.getAcls("")
		require.NoError(t, err)
		require.Len(t, acls, 2)

		// /alpha ACL should NOT cover /beta paths.
		alphaScope := token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/alpha/file")
		betaScope := token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/beta/file")

		alphaACL := acls[0]
		if alphaACL.Resource == "/beta" {
			alphaACL = acls[1]
		}
		assert.True(t, alphaACL.Contains(alphaScope))
		assert.False(t, alphaACL.Contains(betaScope),
			"/alpha ACL should not cover /beta path")
	})
}

// TestAuthorize_HierarchicalNamespaceOR exercises the full authorize path
// (with tokenAuthz caching) to verify hierarchical OR behavior.
func TestAuthorize_HierarchicalNamespaceOR(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp, ctx := errgroup.WithContext(ctx)

	ac := newAuthConfig(ctx, egrp)

	issuerURL, _ := url.Parse("https://issuer.example.com")
	nsAds := []server_structs.NamespaceAdV2{
		{Path: "/data", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		{
			Path: "/data/restricted",
			Caps: server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: *issuerURL,
				BasePaths: []string{"/"},
			}},
		},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	// Public parent should grant read to paths under the private child.
	ok, _ := ac.authorize(token_scopes.Wlcg_Storage_Read, "/data/restricted/file", "")
	assert.True(t, ok, "public /data should grant read to /data/restricted/file (hierarchical OR)")

	// Unrelated namespace should remain unauthorized.
	ok, _ = ac.authorize(token_scopes.Wlcg_Storage_Read, "/other/file", "")
	assert.False(t, ok, "unrelated /other/file should be denied")

	cancel()
	_ = egrp.Wait()
}

func TestNsAdsAuthzEqual(t *testing.T) {
	issuerA, _ := url.Parse("https://issuer-a.example.com")
	issuerB, _ := url.Parse("https://issuer-b.example.com")

	base := []server_structs.NamespaceAdV2{
		{Path: "/public", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}},
		{
			Path: "/private",
			Caps: server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: *issuerA, BasePaths: []string{"/"}, RestrictedPaths: []string{"/sub"},
			}},
		},
	}

	t.Run("IdenticalLists", func(t *testing.T) {
		cp := make([]server_structs.NamespaceAdV2, len(base))
		copy(cp, base)
		assert.True(t, nsAdsAuthzEqual(base, cp))
	})

	t.Run("DifferentOrder", func(t *testing.T) {
		reversed := []server_structs.NamespaceAdV2{base[1], base[0]}
		assert.True(t, nsAdsAuthzEqual(base, reversed), "order should not matter")
	})

	t.Run("AddedNamespace", func(t *testing.T) {
		extended := append(base, server_structs.NamespaceAdV2{
			Path: "/new", Caps: server_structs.Capabilities{PublicReads: true},
		})
		assert.False(t, nsAdsAuthzEqual(base, extended))
	})

	t.Run("RemovedNamespace", func(t *testing.T) {
		assert.False(t, nsAdsAuthzEqual(base, base[:1]))
	})

	t.Run("ChangedCapability", func(t *testing.T) {
		cp := make([]server_structs.NamespaceAdV2, len(base))
		copy(cp, base)
		cp[0].Caps.Writes = true
		assert.False(t, nsAdsAuthzEqual(base, cp))
	})

	t.Run("ChangedIssuerURL", func(t *testing.T) {
		cp := make([]server_structs.NamespaceAdV2, len(base))
		copy(cp, base)
		cp[1].Issuer = []server_structs.TokenIssuer{{
			IssuerUrl: *issuerB, BasePaths: []string{"/"}, RestrictedPaths: []string{"/sub"},
		}}
		assert.False(t, nsAdsAuthzEqual(base, cp))
	})

	t.Run("ChangedBasePaths", func(t *testing.T) {
		cp := make([]server_structs.NamespaceAdV2, len(base))
		copy(cp, base)
		cp[1].Issuer = []server_structs.TokenIssuer{{
			IssuerUrl: *issuerA, BasePaths: []string{"/other"}, RestrictedPaths: []string{"/sub"},
		}}
		assert.False(t, nsAdsAuthzEqual(base, cp))
	})

	t.Run("ChangedRestrictedPaths", func(t *testing.T) {
		cp := make([]server_structs.NamespaceAdV2, len(base))
		copy(cp, base)
		cp[1].Issuer = []server_structs.TokenIssuer{{
			IssuerUrl: *issuerA, BasePaths: []string{"/"}, RestrictedPaths: []string{"/other"},
		}}
		assert.False(t, nsAdsAuthzEqual(base, cp))
	})

	t.Run("BothEmpty", func(t *testing.T) {
		assert.True(t, nsAdsAuthzEqual(nil, nil))
		assert.True(t, nsAdsAuthzEqual([]server_structs.NamespaceAdV2{}, []server_structs.NamespaceAdV2{}))
	})
}
