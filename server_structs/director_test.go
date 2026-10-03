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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
		h := http.Header{"X-Pelican-Namespace": {"namespace=foo, require-token=true, collections-url=https://collections-url.org"}}
		err := xPelNs.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.Equal(t, "foo", xPelNs.Namespace)
		assert.True(t, xPelNs.RequireToken)
		assert.Equal(t, "https://collections-url.org", xPelNs.CollectionsUrl.String())
	})

	t.Run("ParseMissingCollectionsUrl", func(t *testing.T) { // Signifies origins that don't enable listings
		xPelNs := XPelNs{}
		h := http.Header{"X-Pelican-Namespace": {"namespace=foo, require-token=true"}}
		err := xPelNs.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.Equal(t, "foo", xPelNs.Namespace)
		assert.True(t, xPelNs.RequireToken)
		assert.Nil(t, xPelNs.CollectionsUrl)
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelNs := XPelNs{}
		h := http.Header{"X-Pelican-foo": {"bar"}}
		err := xPelNs.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("o %s header found.", xPelNs.GetName()))
	})
}

func TestXPelAuthParsing(t *testing.T) {
	t.Run("ParseValidRawResponse", func(t *testing.T) {
		xPelAuth := XPelAuth{}
		h := http.Header{"X-Pelican-Authorization": {"issuer=https://issuer1.com, issuer=https://issuer2.com"}}
		err := xPelAuth.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.Len(t, xPelAuth.Issuers, 2)
		assert.Equal(t, "https://issuer1.com", xPelAuth.Issuers[0].String())
		assert.Equal(t, "https://issuer2.com", xPelAuth.Issuers[1].String())
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelAuth := XPelAuth{}
		h := http.Header{"X-Pelican-foo": {"foo"}}
		err := xPelAuth.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.Equal(t, 0, len(xPelAuth.Issuers))
	})
}

func TestXPelTokGenParsing(t *testing.T) {
	t.Run("ParseValidRawResponse", func(t *testing.T) {
		xPelTokGen := XPelTokGen{}
		h := http.Header{"X-Pelican-Token-Generation": {"strategy=OAuth2, max-scope-depth=3, issuer=https://issuer.com, base-path=/foo/bar"}}
		err := xPelTokGen.ParseRawHeader(&h)
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
		h := http.Header{"X-Pelican-Token-Generation": {"strategy=OAuth2, max-scope-depth=3, issuer=https://issuer.com"}}
		err := xPelTokGen.ParseRawHeader(&h)
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
		h := http.Header{"X-Pelican-foo": {"foo"}}
		err := xPelTokGen.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.Equal(t, StrategyType(""), xPelTokGen.Strategy)
		assert.Equal(t, uint(0), xPelTokGen.MaxScopeDepth)
		assert.Len(t, xPelTokGen.Issuers, 0)
		assert.Len(t, xPelTokGen.BasePaths, 0)
	})
}

func TestXPelCoordinateParsing(t *testing.T) {
	t.Run("ParseValidCoordinate", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-Coordinate": {"lat=43.0739,long=-89.3848"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.NoError(t, err)
		assert.InDelta(t, 43.0739, xPelCoord.Coordinate.Lat, 1e-9)
		assert.InDelta(t, -89.3848, xPelCoord.Coordinate.Long, 1e-9)
		assert.Equal(t, CoordinateSource(CoordinateSourceDeclared), xPelCoord.Coordinate.Source)
		assert.Equal(t, uint16(0), xPelCoord.Coordinate.AccuracyRadius)
	})

	t.Run("ParseMissingHeader", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-foo": {"bar"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), fmt.Sprintf("no %s header found.", xPelCoord.GetName()))
	})

	t.Run("ParseMissingLat", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-Coordinate": {"long=-89.3848"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "latitude")
	})

	t.Run("ParseMissingLong", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-Coordinate": {"lat=43.0739"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "longitude")
	})

	t.Run("ParseInvalidLat", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-Coordinate": {"lat=not-a-number,long=-89.3848"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "latitude")
	})

	t.Run("ParseOutOfBoundsCoordinates", func(t *testing.T) {
		xPelCoord := XPelCoordinate{}
		h := http.Header{"X-Pelican-Coordinate": {"lat=91,long=0"}}
		err := xPelCoord.ParseRawHeader(&h)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid coordinates")
	})
}

func TestServerBaseAdAfter(t *testing.T) {
	t.Run("AfterMethod", func(t *testing.T) {
		instanceID := uuid.New().String()
		startTime := time.Now().Unix()

		ad1 := ServerBaseAd{
			GenerationID: 1,
			InstanceID:   instanceID,
			StartTime:    startTime,
		}
		ad2 := ServerBaseAd{}

		assert.Equal(t, ad1.After(ad2), AdAfterUnknown)
	})
}

func TestLongestNSMatch(t *testing.T) {
	nsAd := func(path string) NamespaceAd { return NamespaceAd{Path: path} }

	testCases := []struct {
		name     string
		reqPath  string
		nsAds    []NamespaceAd
		expected string // the Path of the ad expected back, or "" for no match
	}{
		{
			name:     "prefers the deeper of two nested exports",
			reqPath:  "/foo/bar/baz",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/foo/bar")},
			expected: "/foo/bar",
		},
		{
			name:     "ad order does not decide the winner",
			reqPath:  "/foo/bar/baz",
			nsAds:    []NamespaceAd{nsAd("/foo/bar"), nsAd("/foo")},
			expected: "/foo/bar",
		},
		{
			name:     "falls back to the shallower export when the deeper one does not cover the path",
			reqPath:  "/foo/other/baz",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/foo/bar")},
			expected: "/foo",
		},
		{
			name:     "matches a request path equal to the export prefix",
			reqPath:  "/foo/bar",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/foo/bar")},
			expected: "/foo/bar",
		},
		{
			name:     "matches a request path equal to the export prefix with a trailing slash",
			reqPath:  "/foo/bar/",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/foo/bar")},
			expected: "/foo/bar",
		},
		{
			name:     "matches an export prefix stored with a trailing slash",
			reqPath:  "/foo/bar/baz",
			nsAds:    []NamespaceAd{nsAd("/foo/bar/")},
			expected: "/foo/bar/",
		},
		{
			// Path boundaries, not raw string prefixes: /foobar is a sibling of
			// /foo, not a child of it.
			name:     "does not match a sibling whose name merely starts the same",
			reqPath:  "/foobar/baz",
			nsAds:    []NamespaceAd{nsAd("/foo")},
			expected: "",
		},
		{
			name:     "a root export covers everything",
			reqPath:  "/anything/at/all",
			nsAds:    []NamespaceAd{nsAd("/")},
			expected: "/",
		},
		{
			name:     "a deeper export still beats a root export",
			reqPath:  "/foo/bar",
			nsAds:    []NamespaceAd{nsAd("/"), nsAd("/foo")},
			expected: "/foo",
		},
		{
			name:     "returns nil when nothing matches",
			reqPath:  "/nowhere/object",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/bar")},
			expected: "",
		},
		{
			name:     "returns nil when there are no ads at all",
			reqPath:  "/foo/bar",
			nsAds:    nil,
			expected: "",
		},
		{
			// The two spellings of one prefix are the same prefix, so neither
			// outranks the other and the first one listed is kept.
			name:     "a trailing slash does not make an export deeper than its slashless twin",
			reqPath:  "/foo/baz",
			nsAds:    []NamespaceAd{nsAd("/foo"), nsAd("/foo/")},
			expected: "/foo",
		},
		{
			name:     "matches a request equal to an export stored with a trailing slash",
			reqPath:  "/foo/bar",
			nsAds:    []NamespaceAd{nsAd("/foo/bar/")},
			expected: "/foo/bar/",
		},
		{
			name:     "an export deeper than the request does not match",
			reqPath:  "/foo",
			nsAds:    []NamespaceAd{nsAd("/foo/bar")},
			expected: "",
		},
		{
			name:     "a root export matches the root itself",
			reqPath:  "/",
			nsAds:    []NamespaceAd{nsAd("/")},
			expected: "/",
		},
		{
			name:     "a sibling sharing every byte but the boundary does not match",
			reqPath:  "/foo/barbaz",
			nsAds:    []NamespaceAd{nsAd("/foo/bar")},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := LongestNSMatch(tc.reqPath, tc.nsAds)
			if tc.expected == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.expected, got.Path)
		})
	}
}

// TestLongestNSMatchEmptyExportPath pins that an ad carrying no path at all is
// read as the root rather than as a prefix that matches nothing: appending a
// slash to "" is what the slash-normalizing form of this search did.
func TestLongestNSMatchEmptyExportPath(t *testing.T) {
	got := LongestNSMatch("/foo/bar", []NamespaceAd{{Path: ""}})
	require.NotNil(t, got)
	assert.Equal(t, "", got.Path)

	// ...but it still loses to any export that actually covers the path.
	got = LongestNSMatch("/foo/bar", []NamespaceAd{{Path: ""}, {Path: "/foo"}})
	require.NotNil(t, got)
	assert.Equal(t, "/foo", got.Path)
}

// TestLongestNSMatchReturnsACopy pins the contract that makes this search safe
// to call on a shared ad list: callers edit what they get back (director/sort.go
// strips the trailing slash off the returned path before handing it on), and
// the ads live in the director's TTL cache, so handing out an interior pointer
// would let one request mutate what the next one reads.
func TestLongestNSMatchReturnsACopy(t *testing.T) {
	nsAds := []NamespaceAd{{Path: "/foo"}, {Path: "/foo/bar"}}

	got := LongestNSMatch("/foo/bar/baz", nsAds)
	require.NotNil(t, got)
	require.Equal(t, "/foo/bar", got.Path)

	got.Path = "/clobbered"
	got.Caps.Writes = true

	assert.Equal(t, "/foo/bar", nsAds[1].Path, "the caller's slice must not be reachable through the result")
	assert.False(t, nsAds[1].Caps.Writes)
}

// BenchmarkLongestNSMatch guards the allocation behavior rather than the clock.
// A cache advertises every namespace in the federation (cache/advertise.go), and
// the director runs this search once per server ad on every redirect, so an
// allocation in the loop body is multiplied by caches x namespaces per request.
// The count below should stay flat as the ad list grows.
func BenchmarkLongestNSMatch(b *testing.B) {
	for _, n := range []int{1, 100, 1000} {
		nsAds := make([]NamespaceAd, 0, n)
		for i := 0; i < n; i++ {
			nsAds = append(nsAds, NamespaceAd{Path: fmt.Sprintf("/project%04d/export", i)})
		}
		reqPath := nsAds[n-1].Path + "/some/object.dat"

		b.Run(fmt.Sprintf("match/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if LongestNSMatch(reqPath, nsAds) == nil {
					b.Fatal("expected a match")
				}
			}
		})
		b.Run(fmt.Sprintf("nomatch/n=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if LongestNSMatch("/covered/by/nothing", nsAds) != nil {
					b.Fatal("expected no match")
				}
			}
		})
	}
}

func TestSetXNamespaceHeaderWithCollections(t *testing.T) {
	const collUrl = "https://origin.example.com:8443"

	t.Run("AdvertisesCollectionsWhenListingsAllowed", func(t *testing.T) {
		hdr := http.Header{}
		SetXNamespaceHeaderWithCollections(hdr, collUrl, NamespaceAd{
			Path: "/foo",
			Caps: Capabilities{Reads: true, Listings: true},
		})
		assert.Equal(t, "namespace=/foo, require-token=true, collections-url="+collUrl,
			hdr.Get(XPelNs{}.GetName()))
	})

	t.Run("SuppressesCollectionsWhenListingsDenied", func(t *testing.T) {
		// A collections-url the namespace will not answer PROPFIND for would
		// send the client to a guaranteed error, so it is left out entirely.
		hdr := http.Header{}
		SetXNamespaceHeaderWithCollections(hdr, collUrl, NamespaceAd{
			Path: "/foo",
			Caps: Capabilities{Reads: true, Listings: false},
		})
		assert.Equal(t, "namespace=/foo, require-token=true", hdr.Get(XPelNs{}.GetName()))
		assert.NotContains(t, hdr.Get(XPelNs{}.GetName()), "collections-url")
	})

	t.Run("PublicReadsClearsRequireToken", func(t *testing.T) {
		hdr := http.Header{}
		SetXNamespaceHeaderWithCollections(hdr, collUrl, NamespaceAd{
			Path: "/foo",
			Caps: Capabilities{PublicReads: true, Reads: true, Listings: true},
		})
		assert.Equal(t, "namespace=/foo, require-token=false, collections-url="+collUrl,
			hdr.Get(XPelNs{}.GetName()))
	})
}
