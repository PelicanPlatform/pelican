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

package server_structs

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	require.NoError(t, err)
	return *u
}

// authNamespaceAd builds a namespace ad requiring a token, with issuer and
// generation info, for header-builder tests.
func authNamespaceAd(t *testing.T) NamespaceAdV2 {
	issuer := mustParseURL(t, "https://issuer.example.com")
	return NamespaceAdV2{
		Path: "/foo/bar",
		Caps: Capabilities{PublicReads: false, Reads: true, Listings: true},
		Issuer: []TokenIssuer{{
			IssuerUrl: issuer,
			BasePaths: []string{"/foo"},
		}},
		Generation: []TokenGen{{
			Strategy:         OAuthStrategy,
			MaxScopeDepth:    3,
			CredentialIssuer: issuer,
		}},
	}
}

func TestSetXAuthHeader(t *testing.T) {
	hdr := http.Header{}
	SetXAuthHeader(hdr, authNamespaceAd(t))
	assert.Equal(t, []string{"issuer=https://issuer.example.com"}, hdr["X-Pelican-Authorization"])

	// No issuers -> header not set.
	hdr2 := http.Header{}
	SetXAuthHeader(hdr2, NamespaceAdV2{Path: "/foo"})
	assert.Empty(t, hdr2["X-Pelican-Authorization"])
}

func TestSetXTokenGenHeader(t *testing.T) {
	hdr := http.Header{}
	SetXTokenGenHeader(hdr, authNamespaceAd(t))
	got := hdr.Get("X-Pelican-Token-Generation")
	assert.Contains(t, got, "issuer=https://issuer.example.com")
	assert.Contains(t, got, "max-scope-depth=3")
	assert.Contains(t, got, "strategy=OAuth2")
	assert.Contains(t, got, "base-path=/foo")

	// No generation info -> header not set.
	hdr2 := http.Header{}
	SetXTokenGenHeader(hdr2, NamespaceAdV2{Path: "/foo"})
	assert.Empty(t, hdr2.Get("X-Pelican-Token-Generation"))
}

func TestSetXNamespaceHeader(t *testing.T) {
	// Token-required namespace.
	hdr := http.Header{}
	SetXNamespaceHeader(hdr, nil, authNamespaceAd(t))
	assert.Equal(t, "namespace=/foo/bar, require-token=true", hdr.Get("X-Pelican-Namespace"))

	// Public namespace.
	hdr2 := http.Header{}
	SetXNamespaceHeader(hdr2, nil, NamespaceAdV2{Path: "/pub", Caps: Capabilities{PublicReads: true}})
	assert.Equal(t, "namespace=/pub, require-token=false", hdr2.Get("X-Pelican-Namespace"))
}

func TestSetXNamespaceHeaderWithCollections(t *testing.T) {
	t.Run("listings-enabled-advertises-collections", func(t *testing.T) {
		ad := authNamespaceAd(t) // Caps.Listings == true
		hdr := http.Header{}
		SetXNamespaceHeaderWithCollections(hdr, "https://cache.example.com/api/v1.0/cache/data/fed", ad)
		assert.Equal(t,
			"namespace=/foo/bar, require-token=true, collections-url=https://cache.example.com/api/v1.0/cache/data/fed",
			hdr.Get("X-Pelican-Namespace"))

		// The client parser should recover the collections URL.
		var ns XPelNs
		require.NoError(t, (&ns).ParseRawResponse(&http.Response{Header: hdr}))
		require.NotNil(t, ns.CollectionsUrl)
		assert.Equal(t, "https://cache.example.com/api/v1.0/cache/data/fed", ns.CollectionsUrl.String())
	})

	t.Run("listings-disabled-omits-collections", func(t *testing.T) {
		ad := authNamespaceAd(t)
		ad.Caps.Listings = false
		hdr := http.Header{}
		SetXNamespaceHeaderWithCollections(hdr, "https://cache.example.com/data", ad)
		assert.Equal(t, "namespace=/foo/bar, require-token=true", hdr.Get("X-Pelican-Namespace"))
	})
}

// TestSetXHeadersRoundTrip verifies that headers written by the Set* builders
// are parsed back by the XPel* ParseRawResponse readers (the symmetry the
// client relies on when talking to an anycast cache).
func TestSetXHeadersRoundTrip(t *testing.T) {
	ad := authNamespaceAd(t)
	hdr := http.Header{}
	SetXNamespaceHeader(hdr, nil, ad)
	SetXAuthHeader(hdr, ad)
	SetXTokenGenHeader(hdr, ad)

	resp := &http.Response{Header: hdr}

	var ns XPelNs
	require.NoError(t, (&ns).ParseRawResponse(resp))
	assert.Equal(t, "/foo/bar", ns.Namespace)
	assert.True(t, ns.RequireToken)

	var auth XPelAuth
	require.NoError(t, (&auth).ParseRawResponse(resp))
	require.Len(t, auth.Issuers, 1)
	assert.Equal(t, "https://issuer.example.com", auth.Issuers[0].String())

	var tokGen XPelTokGen
	require.NoError(t, (&tokGen).ParseRawResponse(resp))
	require.Len(t, tokGen.Issuers, 1)
	assert.Equal(t, "https://issuer.example.com", tokGen.Issuers[0].String())
	assert.Equal(t, uint(3), tokGen.MaxScopeDepth)
	assert.Equal(t, OAuthStrategy, tokGen.Strategy)
}

func TestLongestNSMatch(t *testing.T) {
	ads := []NamespaceAdV2{
		{Path: "/foo"},
		{Path: "/foo/bar"},
		{Path: "/other"},
	}

	t.Run("longest-prefix", func(t *testing.T) {
		got := LongestNSMatch("/foo/bar/baz.txt", ads)
		require.NotNil(t, got)
		assert.Equal(t, "/foo/bar", got.Path)
	})

	t.Run("shorter-prefix", func(t *testing.T) {
		got := LongestNSMatch("/foo/other.txt", ads)
		require.NotNil(t, got)
		assert.Equal(t, "/foo", got.Path)
	})

	t.Run("no-match", func(t *testing.T) {
		assert.Nil(t, LongestNSMatch("/nope/x", ads))
	})

	t.Run("empty", func(t *testing.T) {
		assert.Nil(t, LongestNSMatch("/foo", nil))
	})
}
