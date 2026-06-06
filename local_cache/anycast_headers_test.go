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
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestBestNamespaceAd(t *testing.T) {
	ac := &authConfig{}
	issuerURL, _ := url.Parse("https://issuer.example.com")
	nsAds := []server_structs.NamespaceAdV2{
		{Path: "/foo", Caps: server_structs.Capabilities{Reads: true}},
		{
			Path: "/foo/bar",
			Caps: server_structs.Capabilities{Reads: true},
			Issuer: []server_structs.TokenIssuer{
				{IssuerUrl: *issuerURL, BasePaths: []string{"/foo/bar"}},
			},
		},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	got := ac.bestNamespaceAd("/foo/bar/baz.txt")
	require.NotNil(t, got)
	assert.Equal(t, "/foo/bar", got.Path)

	got = ac.bestNamespaceAd("/foo/other.txt")
	require.NotNil(t, got)
	assert.Equal(t, "/foo", got.Path)

	assert.Nil(t, ac.bestNamespaceAd("/nope/x"))

	// Empty config -> nil.
	assert.Nil(t, (&authConfig{}).bestNamespaceAd("/foo"))
}

// TestSetTokenHintHeaders verifies that a cache configured with a token-required
// namespace emits the director-style X-Pelican-* headers, exactly as the client
// expects from an anycast endpoint's 403 response.
func TestSetTokenHintHeaders(t *testing.T) {
	ac := &authConfig{}
	issuerURL, _ := url.Parse("https://issuer.example.com")
	nsAds := []server_structs.NamespaceAdV2{
		{
			Path: "/protected",
			Caps: server_structs.Capabilities{Reads: true}, // PublicReads false -> require-token
			Issuer: []server_structs.TokenIssuer{
				{IssuerUrl: *issuerURL, BasePaths: []string{"/protected"}},
			},
			Generation: []server_structs.TokenGen{
				{
					Strategy:         server_structs.OAuthStrategy,
					MaxScopeDepth:    3,
					CredentialIssuer: *issuerURL,
				},
			},
		},
	}
	require.NoError(t, ac.updateConfig(nsAds))

	pc := &PersistentCache{ac: ac}
	hdr := http.Header{}
	pc.setTokenHintHeaders(hdr, "/protected/secret.txt")

	assert.Equal(t, "namespace=/protected, require-token=true", hdr.Get("X-Pelican-Namespace"))
	assert.Equal(t, "issuer=https://issuer.example.com", hdr.Get("X-Pelican-Authorization"))
	assert.Contains(t, hdr.Get("X-Pelican-Token-Generation"), "strategy=OAuth2")

	// Confirm the client-side parser reads them back (round-trip symmetry).
	resp := &http.Response{Header: hdr}
	var ns server_structs.XPelNs
	require.NoError(t, (&ns).ParseRawResponse(resp))
	assert.Equal(t, "/protected", ns.Namespace)
	assert.True(t, ns.RequireToken)
}

// TestSetTokenHintHeaders_CollectionsUrl verifies that, for a listing-enabled
// namespace, the cache advertises ITS OWN data URL as the collections-url so
// directory listings flow through the (anycast) cache, which proxies PROPFIND to
// the origin.
func TestSetTokenHintHeaders_CollectionsUrl(t *testing.T) {
	const cacheDataUrl = "https://cache.example.com/api/v1.0/cache/data/fed"
	require.NoError(t, param.Cache_Url.Set(cacheDataUrl))
	t.Cleanup(func() { _ = param.Cache_Url.Set("") })

	ac := &authConfig{}
	issuerURL, _ := url.Parse("https://issuer.example.com")
	listingNs := server_structs.NamespaceAdV2{
		Path: "/protected",
		Caps: server_structs.Capabilities{Reads: true, Listings: true},
		Issuer: []server_structs.TokenIssuer{
			{IssuerUrl: *issuerURL, BasePaths: []string{"/protected"}},
		},
	}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAdV2{listingNs}))

	pc := &PersistentCache{ac: ac}
	hdr := http.Header{}
	pc.setTokenHintHeaders(hdr, "/protected/dir/")

	assert.Equal(t,
		"namespace=/protected, require-token=true, collections-url="+cacheDataUrl,
		hdr.Get("X-Pelican-Namespace"))

	// The client parser recovers the cache's collections URL.
	var ns server_structs.XPelNs
	require.NoError(t, (&ns).ParseRawResponse(&http.Response{Header: hdr}))
	require.NotNil(t, ns.CollectionsUrl)
	assert.Equal(t, cacheDataUrl, ns.CollectionsUrl.String())
}

// TestSetTokenHintHeaders_NoCollectionsWhenListingsDisabled verifies that a
// namespace without listing capability does not get a collections-url even
// though the cache could proxy it.
func TestSetTokenHintHeaders_NoCollectionsWhenListingsDisabled(t *testing.T) {
	require.NoError(t, param.Cache_Url.Set("https://cache.example.com/api/v1.0/cache/data/fed"))
	t.Cleanup(func() { _ = param.Cache_Url.Set("") })

	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAdV2{
		{Path: "/protected", Caps: server_structs.Capabilities{Reads: true}}, // Listings false
	}))
	pc := &PersistentCache{ac: ac}
	hdr := http.Header{}
	pc.setTokenHintHeaders(hdr, "/protected/x.txt")
	assert.Equal(t, "namespace=/protected, require-token=true", hdr.Get("X-Pelican-Namespace"))
}

// TestSetTokenHintHeaders_NoMatch verifies no headers are emitted when no
// namespace matches the requested path.
func TestSetTokenHintHeaders_NoMatch(t *testing.T) {
	ac := &authConfig{}
	require.NoError(t, ac.updateConfig([]server_structs.NamespaceAdV2{{Path: "/foo"}}))
	pc := &PersistentCache{ac: ac}
	hdr := http.Header{}
	pc.setTokenHintHeaders(hdr, "/bar/x.txt")
	assert.Empty(t, hdr.Get("X-Pelican-Namespace"))
}
