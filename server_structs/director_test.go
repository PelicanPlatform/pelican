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
	"encoding/json"
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

func TestCapsUnmarshalJSON(t *testing.T) {
	oldCaps := `{"PublicRead":true,"Read":true,"Write":false,"Listing":false,"FallBackRead":true}}`
	newCaps := `{"PublicReads":false,"Reads":true,"Writes":false,"Listings":false,"DirectReads":true}}`

	nsAdV2NoCap := `{"path":"/ncar","token-generation":[{"strategy":"","vault-server":"","max-scope-depth":0,"issuer":{}}],"token-issuer":[],"from-topology":true,"Caps":`
	oAdV2NoCap := `{"name": "example-server","registry-prefix": "/origins/example-server","broker-url": "http://example-broker.com","data-url": "http://example-data.com","web-url": "http://example-web.com","namespaces": [{"path": "/example-namespace","token-generation": [],"token-issuer": [],"from-topology": false}],"token-issuer": [],"storageType": "POSIX","directorTest": false,"capabilities":`
	sAdV2NoCap := `{"name": "example-server","storageType": "POSIX","directorTest": false,"auth_url": {"Scheme": "http", "Host": "example-auth.com"},"broker_url": {"Scheme": "http", "Host": "example-auth.com"},"url": {"Scheme": "http", "Host": "example-auth.com"},"web_url": {"Scheme": "http", "Host": "example-auth.com"},"type": "cache","latitude": 40.7128,"longitude": -74.0060,"from_topology": true,"io_load": 0.75,"capabilities":`

	tests := []struct {
		name     string
		jsonData string
		expected Capabilities
		target   interface{}
	}{
		{
			name:     "NamespaceAdV2 with old caps",
			jsonData: nsAdV2NoCap + oldCaps,
			expected: Capabilities{
				PublicReads: true,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &NamespaceAdV2{},
		},
		{
			name:     "NamespaceAdV2 with new caps",
			jsonData: nsAdV2NoCap + newCaps,
			expected: Capabilities{
				PublicReads: false,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &NamespaceAdV2{},
		},
		{
			name:     "OriginAdvertiseV2 with old caps",
			jsonData: oAdV2NoCap + oldCaps,
			expected: Capabilities{
				PublicReads: true,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &OriginAdvertiseV2{},
		},
		{
			name:     "OriginAdvertiseV2 with new caps",
			jsonData: oAdV2NoCap + newCaps,
			expected: Capabilities{
				PublicReads: false,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &OriginAdvertiseV2{},
		},
		{
			name:     "ServerAd with old caps",
			jsonData: sAdV2NoCap + oldCaps,
			expected: Capabilities{
				PublicReads: true,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &ServerAd{},
		},
		{
			name:     "ServerAd with new caps",
			jsonData: sAdV2NoCap + newCaps,
			expected: Capabilities{
				PublicReads: false,
				Reads:       true,
				Writes:      false,
				Listings:    false,
				DirectReads: true,
			},
			target: &ServerAd{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Unmarshal JSON into the appropriate struct
			if err := json.Unmarshal([]byte(tt.jsonData), tt.target); err != nil {
				t.Fatalf("UnmarshalJSON() error = %v", err)
			}

			// Check Caps field in the struct
			switch v := tt.target.(type) {
			case *NamespaceAdV2:
				if v.Caps != tt.expected {
					t.Errorf("NamespaceAdV2 Caps = %v, want %v", v.Caps, tt.expected)
				}
			case *OriginAdvertiseV2:
				if v.Caps != tt.expected {
					t.Errorf("OriginAdvertiseV2 Caps = %v, want %v", v.Caps, tt.expected)
				}
			case *ServerAd:
				if v.Caps != tt.expected {
					t.Errorf("ServerAd Caps = %v, want %v", v.Caps, tt.expected)
				}
			default:
				t.Errorf("Unknown struct type: %T", tt.target)
			}
		})
	}
}
