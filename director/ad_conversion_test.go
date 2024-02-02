/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"net/url"
	"testing"

	"github.com/pelicanplatform/pelican/common"
	"github.com/stretchr/testify/require"
)

func TestConversion(t *testing.T) {

	credUrl, err := url.Parse("https://origin-url.org")
	require.NoError(t, err, "error parsing test issuer url")

	issUrl1, err := url.Parse("https://issuer1.org")
	require.NoError(t, err, "error parsing test issuer url")

	issUrl2, err := url.Parse("https://issuer2.org")
	require.NoError(t, err, "error parsing test issuer url")

	v2Ads := []common.NamespaceAdV2{{
		PublicRead: false,
		Caps:       common.Capabilities{PublicRead: false, Read: true, Write: true, FallBackRead: false, Listing: true},
		Path:       "/foo/bar",
		Generation: []common.TokenGen{{
			Strategy:         "OAuth2",
			MaxScopeDepth:    3,
			CredentialIssuer: *credUrl,
		}},
		Issuer: []common.TokenIssuer{
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
			PublicRead: true,
			Caps: common.Capabilities{
				PublicRead:   true,
				Read:         true,
				Write:        true,
				Listing:      true,
				FallBackRead: false},
			Path: "/baz/bar",
		},
	}

	v1Ads := []common.NamespaceAdV1{
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

	v1Conv := convertNamespaceAdsV2ToV1(v2Ads)

	require.Equal(t, v1Ads, v1Conv)

	oAdV1 := common.OriginAdvertiseV1{
		Name:               "OriginTest",
		URL:                "https://origin-url.org",
		WebURL:             "https://WebUrl.org",
		Namespaces:         v1Ads,
		EnableWrite:        true,
		EnableFallbackRead: false,
	}

	oAdV2 := common.OriginAdvertiseV2{
		Name:       "OriginTest",
		DataURL:    "https://origin-url.org",
		WebURL:     "https://WebUrl.org",
		Namespaces: v2Ads,
		Caps: common.Capabilities{
			PublicRead:   true,
			Write:        true,
			FallBackRead: false,
			Listing:      true,
			Read:         true,
		},
		Issuer: []common.TokenIssuer{
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

	OAdConv := convertOriginAd(oAdV1)

	require.Equal(t, oAdV2, OAdConv)

}
