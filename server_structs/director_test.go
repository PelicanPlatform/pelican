/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConversion(t *testing.T) {

	credUrl, err := url.Parse("https://origin-url.org")
	require.NoError(t, err, "error parsing test issuer url")

	issUrl1, err := url.Parse("https://issuer1.org")
	require.NoError(t, err, "error parsing test issuer url")

	issUrl2, err := url.Parse("https://issuer2.org")
	require.NoError(t, err, "error parsing test issuer url")

	v2Ads := []NamespaceAdV2{{
		Caps: Capabilities{
			PublicReads: false,
			Reads:       true,
			Writes:      true,
			DirectReads: false,
			Listings:    true,
		},
		Path: "/foo/bar",
		Generation: []TokenGen{{
			Strategy:         "OAuth2",
			MaxScopeDepth:    3,
			CredentialIssuer: *credUrl,
		}},
		Issuer: []TokenIssuer{
			{
				BasePaths:       []string{"/foo/bar/baz", "/foo/bar/wazzit"},
				IssuerUrl:       *issUrl1,
				RestrictedPaths: []string{},
			},
			{
				BasePaths:       []string{"/foo/bar/baz"},
				IssuerUrl:       *issUrl2,
				RestrictedPaths: []string{},
			}},
	},
		{
			Caps: Capabilities{
				PublicReads: true,
				Reads:       true,
				Writes:      true,
				DirectReads: false,
				Listings:    true,
			},
			Path: "/baz/bar",
		},
	}

	v1Ads := []NamespaceAdV1{
		{
			RequireToken:  true,
			Path:          "/foo/bar",
			Issuer:        *issUrl1,
			MaxScopeDepth: 3,
			Strategy:      "OAuth2",
			BasePath:      "/foo/bar/baz",
		},
		{
			RequireToken:  true,
			Path:          "/foo/bar",
			Issuer:        *issUrl1,
			MaxScopeDepth: 3,
			Strategy:      "OAuth2",
			BasePath:      "/foo/bar/wazzit",
		},
		{
			RequireToken:  true,
			Path:          "/foo/bar",
			Issuer:        *issUrl2,
			MaxScopeDepth: 3,
			Strategy:      "OAuth2",
			BasePath:      "/foo/bar/baz",
		},
		{
			RequireToken: false,
			Path:         "/baz/bar",
		},
	}

	v1Conv := ConvertNamespaceAdsV2ToV1(v2Ads)

	require.Equal(t, v1Ads, v1Conv)

	oAdV1 := OriginAdvertiseV1{
		Name:        "OriginTest",
		URL:         "https://origin-url.org",
		WebURL:      "https://WebUrl.org",
		Namespaces:  v1Ads,
		Writes:      true,
		DirectReads: false,
	}

	oAdV2 := OriginAdvertiseV2{
		Name:       "OriginTest",
		DataURL:    "https://origin-url.org",
		WebURL:     "https://WebUrl.org",
		Namespaces: v2Ads,
		Caps: Capabilities{
			PublicReads: true,
			Writes:      true,
			DirectReads: false,
			Listings:    true,
			Reads:       true,
		},
		Issuer: []TokenIssuer{
			{
				BasePaths:       []string{"/foo/bar/baz", "/foo/bar/wazzit"},
				IssuerUrl:       *issUrl1,
				RestrictedPaths: []string{},
			},
			{
				BasePaths:       []string{"/foo/bar/baz"},
				IssuerUrl:       *issUrl2,
				RestrictedPaths: []string{},
			},
		},
	}

	OAdConv := ConvertOriginAdV1ToV2(oAdV1)

	require.Equal(t, oAdV2, OAdConv)
}

func TestValidTokenStrategy(t *testing.T) {
	t.Run("ValidOAuth2Strategy", func(t *testing.T) {
		require.True(t, IsValidStrategy("OAuth2"))
	})

	t.Run("ValidVaultStrategy", func(t *testing.T) {
		require.True(t, IsValidStrategy("Vault"))
	})

	t.Run("InvalidStrategies", func(t *testing.T) {
		require.False(t, IsValidStrategy("oauth2"))
		require.False(t, IsValidStrategy("vault"))
		require.False(t, IsValidStrategy("foo"))
	})
}

func TestXPelNsParsing(t *testing.T) {
	t.Run("ParseValidRawResponse", func(t *testing.T) {
		xPelNs := XPelNs{}
		err := xPelNs.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-Namespace": {"namespace=foo, require-token=true, collections-url=https://collections-url.org"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, "foo", xPelNs.Namespace)
		assert.True(t, xPelNs.RequireToken)
		assert.Equal(t, "https://collections-url.org", xPelNs.CollectionsUrl.String())
	})

	t.Run("ParseMissingCollectionsUrl", func(t *testing.T) { // Signifies origins that don't enable listings
		xPelNs := XPelNs{}
		err := xPelNs.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-Namespace": {"namespace=foo, require-token=true"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, "foo", xPelNs.Namespace)
		assert.True(t, xPelNs.RequireToken)
		assert.Nil(t, xPelNs.CollectionsUrl)
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelNs := XPelNs{}
		err := xPelNs.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-foo": {"bar"},
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("No %s header found.", xPelNs.GetName()))
	})
}

func TestXPelAuthParsing(t *testing.T) {
	t.Run("ParseValidRawResponse", func(t *testing.T) {
		xPelAuth := XPelAuth{}
		err := xPelAuth.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-Authorization": {"issuer=https://issuer1.com, issuer=https://issuer2.com"},
			},
		})
		assert.NoError(t, err)
		assert.Len(t, xPelAuth.Issuers, 2)
		assert.Equal(t, "https://issuer1.com", xPelAuth.Issuers[0].String())
		assert.Equal(t, "https://issuer2.com", xPelAuth.Issuers[1].String())
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelAuth := XPelAuth{}
		err := xPelAuth.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-foo": {"foo"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, 0, len(xPelAuth.Issuers))
	})
}

func TestXPelTokGenParsing(t *testing.T) {
	t.Run("ParseValidRawResponse", func(t *testing.T) {
		xPelTokGen := XPelTokGen{}
		err := xPelTokGen.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-Token-Generation": {"strategy=OAuth2, max-scope-depth=3, issuer=https://issuer.com, base-path=/foo/bar"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, OAuthStrategy, xPelTokGen.Strategy)
		assert.Equal(t, uint(3), xPelTokGen.MaxScopeDepth)
		assert.Len(t, xPelTokGen.Issuers, 1)
		assert.Equal(t, "https://issuer.com", xPelTokGen.Issuers[0].String())
		// no test for multiple base paths yet because the director doesn't implement it
		assert.Len(t, xPelTokGen.BasePaths, 1)
		assert.Equal(t, "/foo/bar", xPelTokGen.BasePaths[0])
	})

	t.Run("ParseMissingBasePath", func(t *testing.T) {
		xPelTokGen := XPelTokGen{}
		err := xPelTokGen.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-Token-Generation": {"strategy=OAuth2, max-scope-depth=3, issuer=https://issuer.com"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, OAuthStrategy, xPelTokGen.Strategy)
		assert.Equal(t, uint(3), xPelTokGen.MaxScopeDepth)
		assert.Len(t, xPelTokGen.Issuers, 1)
		assert.Equal(t, "https://issuer.com", xPelTokGen.Issuers[0].String())
		// no test for multiple base paths yet because the director doesn't implement it
		assert.Len(t, xPelTokGen.BasePaths, 0)
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelTokGen := XPelTokGen{}
		err := xPelTokGen.ParseRawResponse(&http.Response{
			Header: map[string][]string{
				"X-Pelican-foo": {"foo"},
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, StrategyType(""), xPelTokGen.Strategy)
		assert.Equal(t, uint(0), xPelTokGen.MaxScopeDepth)
		assert.Len(t, xPelTokGen.Issuers, 0)
		assert.Len(t, xPelTokGen.BasePaths, 0)
	})
}
