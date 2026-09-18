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
	"strings"
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

// LongestNSMatch's contract is that the returned ad is detached from the
// input slice at the top level (a future refactor returning an interior
// pointer must fail here), while the embedded Generation/Issuer slices are
// documented to still alias the input -- on the director, live TTL-cache
// memory that must not be mutated through the return.
func TestLongestNSMatchReturnsDetachedCopy(t *testing.T) {
	ads := []NamespaceAd{
		{
			Path:       "/foo",
			Caps:       Capabilities{PublicReads: true},
			Issuer:     []TokenIssuer{{BasePaths: []string{"/foo"}}},
			Generation: []TokenGen{{MaxScopeDepth: 3}},
		},
	}

	got := LongestNSMatch("/foo/bar", ads)
	require.NotNil(t, got)
	require.NotSame(t, &ads[0], got,
		"LongestNSMatch must not return an interior pointer into the caller's slice")

	// Top-level fields are detached: mutating the copy must not write
	// through to the caller's (cached) ad.
	got.Path = "/mutated"
	got.Caps.PublicReads = false
	assert.Equal(t, "/foo", ads[0].Path)
	assert.True(t, ads[0].Caps.PublicReads)

	// The embedded slices are shallow by documented contract: they alias the
	// input, which is why callers must copy before mutating through them.
	// This assertion pins the current behavior so a change to it (either
	// direction) is a conscious one.
	require.NotEmpty(t, got.Issuer)
	assert.Same(t, &ads[0].Issuer[0], &got.Issuer[0],
		"embedded Issuer slice is documented to alias the input")
	assert.Same(t, &ads[0].Generation[0], &got.Generation[0],
		"embedded Generation slice is documented to alias the input")
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

// longestNSMatchIndexReference is the pre-optimization implementation, kept
// verbatim as the oracle for TestLongestNSMatchIndexMatchesReference.  It
// normalizes each candidate by concatenation and compares whole strings, which
// is the behavior LongestNSMatchIndex's length early-out plus byte-boundary
// check must reproduce exactly.
func longestNSMatchIndexReference(reqPath string, namespaceAds []NamespaceAd) int {
	if !strings.HasSuffix(reqPath, "/") {
		reqPath += "/"
	}
	bestFedPrefix := ""
	bestIdx := -1
	for i, ns := range namespaceAds {
		nsPath := ns.Path
		if !strings.HasSuffix(nsPath, "/") {
			nsPath += "/"
		}
		if !strings.HasPrefix(reqPath, nsPath) {
			continue
		}
		if bestFedPrefix == "" || len(nsPath) > len(bestFedPrefix) {
			bestFedPrefix = nsPath
			bestIdx = i
		}
	}
	return bestIdx
}

// nsMatchCorpus is the shared set of adversarial (reqPath, paths) pairs used by
// the differential and allocation tests.  It leans on the cases where the
// index-arithmetic form could plausibly diverge from string concatenation:
// segment-boundary near-misses (/foo vs /foobar), both spellings of a stored
// path, the root export, degenerate empty and relative paths, and duplicate
// equal-length candidates that exercise tie-breaking.
var nsMatchCorpus = []struct {
	reqPath string
	paths   []string
}{
	{"/foo/bar/baz", []string{"/foo", "/foo/bar"}},
	{"/foo/bar/baz", []string{"/foo/bar", "/foo"}},
	{"/foo/other/baz", []string{"/foo", "/foo/bar"}},
	{"/foo/bar", []string{"/foo", "/foo/bar"}},
	{"/foo/bar/", []string{"/foo", "/foo/bar"}},
	{"/foo/bar/baz", []string{"/foo/bar/"}},
	{"/foo/bar/baz", []string{"/foo/bar/", "/foo/bar"}},
	{"/foo/bar/baz", []string{"/foo/bar", "/foo/bar/"}},
	{"/foobar/baz", []string{"/foo"}},
	{"/foobar/baz", []string{"/foo/", "/foobar"}},
	{"/foo", []string{"/foo/bar"}},
	{"/anything/at/all", []string{"/"}},
	{"/foo/bar", []string{"/", "/foo"}},
	{"/foo/bar", []string{"/foo", "/"}},
	{"/nowhere/object", []string{"/foo", "/bar"}},
	{"/foo/bar", nil},
	// Duplicate candidates: the winner must be the earliest of the tied ads.
	{"/foo/bar/baz", []string{"/foo/bar", "/foo/bar", "/foo"}},
	{"/foo/bar/baz", []string{"/foo", "/foo/bar", "/foo/bar"}},
	// Degenerate stored paths.  An empty path normalizes to "/" and so covers
	// everything, exactly as the reference implementation had it -- pinned
	// here so the optimized form cannot quietly change it.
	{"/foo/bar", []string{""}},
	{"/foo/bar", []string{"", "/foo"}},
	{"/", []string{""}},
	{"/", []string{"/"}},
	{"/", []string{"/foo"}},
	// Relative request paths never reach the director (getAdsForPath runs
	// path.Clean first), but LongestNSMatch is exported, so pin the behavior.
	{"foo/bar", []string{"/foo"}},
	{"foo/bar", []string{"foo"}},
	{"", []string{"/"}},
	{"", []string{""}},
	// Doubled separators: the reference implementation appended at most one
	// "/", so "//" is a distinct prefix from "/" and must stay one.
	{"/foo/bar", []string{"//"}},
	{"//foo/bar", []string{"//"}},
	{"//foo/bar", []string{"/", "//", "//foo"}},
	// Deep paths, to exercise the length early-out on long strings.
	{"/a/b/c/d/e/f/g/h", []string{"/a", "/a/b", "/a/b/c", "/a/b/c/d/e/f/g/h", "/a/b/c/d/e/f/g/h/i"}},
}

func nsAdsFor(paths []string) []NamespaceAd {
	if paths == nil {
		return nil
	}
	ads := make([]NamespaceAd, 0, len(paths))
	for _, p := range paths {
		ads = append(ads, NamespaceAd{Path: p})
	}
	return ads
}

// The optimized scan must agree with the concatenating implementation it
// replaced on every input.  This is the safety net for the change: the
// boundary check is index arithmetic now, and an off-by-one in it would
// silently redirect a request to the wrong namespace's origins.
func TestLongestNSMatchIndexMatchesReference(t *testing.T) {
	for _, tc := range nsMatchCorpus {
		t.Run(fmt.Sprintf("%q_in_%q", tc.reqPath, strings.Join(tc.paths, ",")), func(t *testing.T) {
			ads := nsAdsFor(tc.paths)

			wantIdx := longestNSMatchIndexReference(tc.reqPath, ads)
			assert.Equal(t, wantIdx, LongestNSMatchIndex(tc.reqPath, ads),
				"winning index diverged from the reference implementation")

			// LongestNSMatch is a thin wrapper; keep the two in step.
			got := LongestNSMatch(tc.reqPath, ads)
			if wantIdx < 0 {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, ads[wantIdx].Path, got.Path)
		})
	}
}

// What the director needs from this function is that a deeper export always
// wins over a shallower one covering the same request, whichever way each path
// happens to be spelled -- topology publishes a trailing slash and Pelican
// origins do not.
func TestLongestNSMatchIndexPrefersDeeperExport(t *testing.T) {
	const reqPath = "/foo/bar/baz/object"

	for _, spelling := range [][]string{
		{"/foo", "/foo/bar"},
		{"/foo/", "/foo/bar/"},
		{"/foo/", "/foo/bar"},
		{"/foo", "/foo/bar/"},
		// Order in the slice must not decide it.
		{"/foo/bar", "/foo"},
		{"/foo/bar/", "/foo/"},
	} {
		ads := nsAdsFor(spelling)
		idx := LongestNSMatchIndex(reqPath, ads)
		require.GreaterOrEqual(t, idx, 0, "spelling %v", spelling)
		assert.Equal(t, "/foo/bar", strings.TrimSuffix(ads[idx].Path, "/"),
			"the deeper export should win regardless of spelling or order: %v", spelling)
	}
}

// The property worth guarding is not that the scan allocates nothing, but
// that what it allocates does not grow with the number of candidate ads.  The
// previous implementation normalized each candidate's path by concatenation,
// so a federation advertising more namespaces cost the director more garbage
// on every redirect; a fixed allocation for normalizing reqPath does not.
func TestLongestNSMatchIndexAllocationsDoNotScaleWithAdCount(t *testing.T) {
	perCall := func(ads []NamespaceAd, reqPath string) float64 {
		return testing.AllocsPerRun(200, func() {
			LongestNSMatchIndex(reqPath, ads)
		})
	}

	small, large := benchNSAds(4), benchNSAds(400)
	assert.Equal(t, perCall(small, benchReqPath), perCall(large, benchReqPath),
		"allocations per call grew with the number of candidate ads")

	// The director normalizes the request path once, before its per-server
	// loop, so on the path that actually runs per redirect there is nothing
	// left to allocate at all.
	assert.Zero(t, perCall(large, benchReqPath+"/"),
		"a pre-normalized request path should cost no allocations")
}

func TestNSPathCoversReq(t *testing.T) {
	// Per the helper's precondition, reqPath carries a trailing "/" and nsBase
	// does not -- LongestNSMatchIndex normalizes both before calling.
	testCases := []struct {
		reqPath string
		nsBase  string
		want    bool
	}{
		{"/foo/bar/", "/foo", true},
		// The request path being exactly the export still matches.
		{"/foo/", "/foo", true},
		// A sibling whose name merely starts the same does not.
		{"/foobar/", "/foo", false},
		{"/foo/barbaz/", "/foo/bar", false},
		// A deeper export does not cover a shallower request.
		{"/foo/", "/foo/bar", false},
		{"/foo/bar/baz/", "/foo/bar", true},
		// The empty base is the trimmed form of both "" and "/", the root
		// export, which covers every absolute path...
		{"/anything/", "", true},
		{"/", "", true},
		// ...but shares no boundary with a relative one.
		{"relative/", "", false},
		{"relative/deeper/", "relative", true},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%q_covers_%q", tc.nsBase, tc.reqPath), func(t *testing.T) {
			assert.Equal(t, tc.want, nsPathCoversReq(tc.reqPath, tc.nsBase))
		})
	}
}

// benchNSAds builds an ad set shaped like a real federation's: a few dozen
// exports, mostly two or three segments deep, with the requested namespace
// sitting late in the slice so the scan does not short-circuit early.
func benchNSAds(n int) []NamespaceAd {
	ads := make([]NamespaceAd, 0, n+3)
	for i := 0; i < n; i++ {
		ads = append(ads, NamespaceAd{Path: fmt.Sprintf("/facility%02d/project%02d/data", i, i)})
	}
	// A shallow export that also matches, so the longest-prefix comparison is
	// actually exercised rather than settled by the single match.
	ads = append(ads,
		NamespaceAd{Path: "/ospool"},
		NamespaceAd{Path: "/ospool/protected"},
		NamespaceAd{Path: "/ospool/protected/subdir/"},
	)
	return ads
}

// benchReqPath is unterminated, the shape a caller outside the director passes
// (see origin_serve.SetTokenHintHeaders); benchReqPathNorm is what
// director.getAdsForPath passes, having appended the "/" once before its
// per-server loop.  The difference between the two is the one fixed
// allocation this function can make.
const (
	benchReqPath     = "/ospool/protected/subdir/some/deeply/nested/object"
	benchReqPathNorm = benchReqPath + "/"
)

func BenchmarkLongestNSMatchIndex(b *testing.B) {
	for _, n := range []int{4, 32, 256} {
		ads := benchNSAds(n)
		b.Run(fmt.Sprintf("ads=%d", len(ads)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if LongestNSMatchIndex(benchReqPath, ads) < 0 {
					b.Fatal("expected a match")
				}
			}
		})
	}
}

// The before half of the comparison: the same scan written with the
// concatenating normalization LongestNSMatchIndex replaced.  Keeping it as a
// benchmark alongside the oracle means the performance claim in this change's
// description can be re-derived from the repo at any later commit.
func BenchmarkLongestNSMatchIndexReference(b *testing.B) {
	for _, n := range []int{4, 32, 256} {
		ads := benchNSAds(n)
		b.Run(fmt.Sprintf("ads=%d", len(ads)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if longestNSMatchIndexReference(benchReqPath, ads) < 0 {
					b.Fatal("expected a match")
				}
			}
		})
	}
}

func BenchmarkLongestNSMatch(b *testing.B) {
	for _, n := range []int{4, 32, 256} {
		ads := benchNSAds(n)
		b.Run(fmt.Sprintf("ads=%d", len(ads)), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if LongestNSMatch(benchReqPath, ads) == nil {
					b.Fatal("expected a match")
				}
			}
		})
	}
}

// The director calls LongestNSMatchIndex once per advertised server, so the
// per-redirect cost is this loop, not a single call.  Sized after a federation
// with a few hundred servers each exporting a handful of namespaces, and
// called the way getAdsForPath calls it -- with the request path already
// "/"-terminated, so the whole loop allocates nothing.
func BenchmarkLongestNSMatchIndexPerRedirect(b *testing.B) {
	const servers = 300
	perServer := make([][]NamespaceAd, servers)
	for i := range perServer {
		perServer[i] = benchNSAds(4)
	}
	b.ResetTimer() // discard the ad-set construction above
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, ads := range perServer {
			LongestNSMatchIndex(benchReqPathNorm, ads)
		}
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
