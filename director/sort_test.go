/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"
)

func hasServerAdWithName(ads []copyAd, name string) bool {
	for _, ad := range ads {
		if ad.ServerAd.Name == name {
			return true
		}
	}
	return false
}

// Test getAdsForPath to make sure various nuanced cases work. Under the hood
// this really tests matchesPrefix, but we test this higher level function to
// avoid having to mess with the cache.
func TestGetAdsForPath(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Ensure we start from a clean slate and detect leaks spawned during this test.
	resetHealthTests()
	shutdownStatUtils()

	t.Cleanup(func() {
		shutdownHealthTests()
		shutdownStatUtils()
		serverAds.DeleteAll()
	})

	serverAds.DeleteAll()
	go serverAds.Start()
	t.Cleanup(func() {
		serverAds.DeleteAll()
		serverAds.Stop()
	})

	/*
		FLOW:
			- Set up a few dummy namespaces, origin, and cache ads
			- Record the ads
			- Query for a few paths and make sure the correct ads are returned
	*/
	nsAd1 := server_structs.NamespaceAd{
		Caps: server_structs.Capabilities{PublicReads: false},
		Path: "/chtc",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd2 := server_structs.NamespaceAd{
		Caps: server_structs.Capabilities{PublicReads: true},
		Path: "/chtc/PUBLIC",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd3 := server_structs.NamespaceAd{
		Caps: server_structs.Capabilities{PublicReads: true},
		Path: "/chtc/PUBLIC2/",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAdTopo1 := server_structs.NamespaceAd{
		Caps:         server_structs.Capabilities{PublicReads: true},
		Path:         "/chtc",
		FromTopology: true,
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAdTopoOnly := server_structs.NamespaceAd{
		Caps: server_structs.Capabilities{PublicReads: false},
		Path: "/foo",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	cacheAd1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "cache1.wisc.edu",
		},
		Type: server_structs.CacheType.String(),
	}
	cacheAd1.Initialize("cache1")

	cacheAd2 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "cache2.wisc.edu",
		},
		Type: server_structs.CacheType.String(),
	}
	cacheAd2.Initialize("cache2")

	originAd1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "origin1.wisc.edu",
		},
		Type: server_structs.OriginType.String(),
	}
	originAd1.Initialize("origin1")

	originAd2 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "origin2.wisc.edu",
		},
		Type: server_structs.OriginType.String(),
	}
	originAd2.Initialize("origin2")

	originAdTopo1 := server_structs.ServerAd{
		URL: url.URL{
			Scheme: "https",
			Host:   "topology.wisc.edu",
		},
		Type:         server_structs.OriginType.String(),
		FromTopology: true,
	}
	originAdTopo1.Initialize("topology origin 1")

	o1Slice := []server_structs.NamespaceAd{nsAd1}
	o2Slice := []server_structs.NamespaceAd{nsAd2, nsAd3}
	c1Slice := []server_structs.NamespaceAd{nsAd1, nsAd2, nsAdTopoOnly}
	topoSlice := []server_structs.NamespaceAd{nsAdTopo1, nsAdTopoOnly}
	recordAd(context.Background(), originAd2, &o2Slice)
	recordAd(context.Background(), originAd1, &o1Slice)
	// Add a server from Topology that serves /chtc namespace
	recordAd(context.Background(), originAdTopo1, &topoSlice)
	recordAd(context.Background(), cacheAd1, &c1Slice)
	recordAd(context.Background(), cacheAd2, &o1Slice)

	testCases := []struct {
		name            string
		inPath          string
		outPath         string
		originNames     []string
		cacheNames      []string
		nsCapsToVerify  server_structs.Capabilities
		fromTopoIndices map[int]bool // should only be instantiated if it's populated
	}{
		{
			name:           "no trailing slash, topo filtered",
			inPath:         "/chtc",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:            "topology-only namespace gets topo origin",
			inPath:          "/foo",
			outPath:         "/foo",
			originNames:     []string{"topology origin 1"},
			cacheNames:      []string{"cache1"},
			nsCapsToVerify:  server_structs.Capabilities{},
			fromTopoIndices: map[int]bool{0: true},
		},
		{
			name:           "path with trailing slash",
			inPath:         "/chtc/",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:           "path partially matching public namespace",
			inPath:         "/chtc/PUBLI",
			outPath:        "/chtc",
			originNames:    []string{"origin1"},
			cacheNames:     []string{"cache1", "cache2"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: false},
		},
		{
			name:           "path matching public namespace",
			inPath:         "/chtc/PUBLIC",
			outPath:        "/chtc/PUBLIC",
			originNames:    []string{"origin2"},
			cacheNames:     []string{"cache1"},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: true},
		},
		{
			name:           "path matching public namespace with trailing slash",
			inPath:         "/chtc/PUBLIC2", // This is stored as /chtc/PUBLIC2/
			outPath:        "/chtc/PUBLIC2",
			originNames:    []string{"origin2"},
			cacheNames:     []string{},
			nsCapsToVerify: server_structs.Capabilities{PublicReads: true},
		},
		{
			name:           "nonexistent path",
			inPath:         "/does/not/exist",
			outPath:        "",
			originNames:    []string{},
			cacheNames:     []string{},
			nsCapsToVerify: server_structs.Capabilities{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get the paths
			oAds, cAds := getAdsForPath(tc.inPath)

			// Assert the correct number of each ad type are returned
			assert.Equal(t, len(tc.originNames), len(oAds))
			assert.Equal(t, len(tc.cacheNames), len(cAds))

			if tc.outPath == "" {
				return
			}

			// Verify origin paths, topology, and capabilities
			for i, oAd := range oAds {
				assert.Equal(t, tc.outPath, oAd.NamespaceAd.Path)
				assert.Equal(t, tc.nsCapsToVerify, oAd.NamespaceAd.Caps)
				if tc.fromTopoIndices != nil {
					if _, ok := tc.fromTopoIndices[i]; ok {
						assert.True(t, oAd.ServerAd.FromTopology)
					}
				} else {
					assert.False(t, oAd.ServerAd.FromTopology)
				}
			}

			// Verify cache paths
			for _, cAd := range cAds {
				assert.Equal(t, tc.outPath, cAd.NamespaceAd.Path)
			}

			// Verify names
			for _, name := range tc.originNames {
				assert.True(t, hasServerAdWithName(oAds, name))
			}
			for _, name := range tc.cacheNames {
				assert.True(t, hasServerAdWithName(cAds, name))
			}
		})
	}

	// getAdsForPath trims the trailing "/" that topology puts on a namespace
	// path, and it selects the winning namespace ad by index into the
	// Advertisement held in the TTL cache -- memory other request goroutines
	// are reading at the same time.  The trim must therefore land on a copy,
	// never on the cached ad.  /chtc/PUBLIC2/ is the one export stored with a
	// trailing slash, so it is the case that would catch a write-through.
	t.Run("does not mutate the cached namespace ad", func(t *testing.T) {
		cachedPath := func() string {
			for _, ad := range getServerAdsSnapshot() {
				for _, nsAd := range ad.NamespaceAds {
					if strings.TrimSuffix(nsAd.Path, "/") == "/chtc/PUBLIC2" {
						return nsAd.Path
					}
				}
			}
			return ""
		}

		require.Equal(t, "/chtc/PUBLIC2/", cachedPath(),
			"test fixture no longer stores a trailing-slash export; this test cannot catch a write-through")

		oAds, _ := getAdsForPath("/chtc/PUBLIC2/some/object")
		require.NotEmpty(t, oAds)
		assert.Equal(t, "/chtc/PUBLIC2", oAds[0].NamespaceAd.Path,
			"the returned copy should have the trailing slash trimmed")
		assert.Equal(t, "/chtc/PUBLIC2/", cachedPath(),
			"getAdsForPath wrote the trimmed path back into the TTL cache")

		// Mutating what we were handed must also not reach the cache: callers
		// treat these as detached copies.
		oAds[0].NamespaceAd.Path = "/mutated-by-caller"
		oAds[0].NamespaceAd.Caps.PublicReads = !oAds[0].NamespaceAd.Caps.PublicReads
		assert.Equal(t, "/chtc/PUBLIC2/", cachedPath())
	})

	// Concurrent readers plus the trim above is precisely the shape the race
	// detector is for; run the same call from several goroutines so a future
	// refactor that writes through the returned alias fails under -race
	// instead of corrupting a live federation's ads.
	t.Run("is safe to call concurrently", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					if oAds, _ := getAdsForPath("/chtc/PUBLIC2/some/object"); len(oAds) > 0 {
						oAds[0].NamespaceAd.Path = "/mutated-by-caller"
					}
					getAdsForPath("/chtc/PUBLIC")
					getAdsForPath("/does/not/exist")
				}
			}()
		}
		wg.Wait()
	})
}

func TestAllPredicatesPass(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx := &gin.Context{}
	ad := copyAd{
		ServerAd:    server_structs.ServerAd{},
		NamespaceAd: server_structs.NamespaceAd{},
	}

	alwaysTrue := func(ctx *gin.Context, ad copyAd) bool { return true }
	alwaysFalse := func(ctx *gin.Context, ad copyAd) bool { return false }

	assert.True(t, allPredicatesPass(ctx, ad, alwaysTrue, alwaysTrue), "All predicates should pass")
	assert.False(t, allPredicatesPass(ctx, ad, alwaysTrue, alwaysFalse), "One predicate fails, so all should fail")
	assert.False(t, allPredicatesPass(ctx, ad, alwaysFalse, alwaysFalse), "All predicates fail")
}

func TestOriginSupportsVerb(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name           string
		nsCaps         server_structs.Capabilities
		serverCaps     server_structs.Capabilities
		supportedVerbs []string
	}{
		{
			name: "all verbs supported",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
				Copies:      true,
			},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
				Copies:      true,
			},
			supportedVerbs: []string{
				http.MethodGet,
				http.MethodHead,
				http.MethodPut,
				http.MethodDelete,
				"PROPFIND",
				"COPY",
			},
		},
		{
			name:   "server supports all, ns supports none",
			nsCaps: server_structs.Capabilities{},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			supportedVerbs: []string{},
		},
		{
			name: "server supports none, ns supports all",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			serverCaps:     server_structs.Capabilities{},
			supportedVerbs: []string{},
		},
		{
			name: "subset of verbs supported",
			nsCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
			},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
			},
			supportedVerbs: []string{
				http.MethodGet,
				http.MethodHead,
			},
		},
		{
			name: "copies supported",
			nsCaps: server_structs.Capabilities{
				Copies: true,
			},
			serverCaps: server_structs.Capabilities{
				Copies: true,
			},
			supportedVerbs: []string{
				"COPY",
			},
		},
		{
			name: "copies only in namespace not server",
			nsCaps: server_structs.Capabilities{
				Copies: true,
			},
			serverCaps:     server_structs.Capabilities{},
			supportedVerbs: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Caps: tc.serverCaps,
				},
				NamespaceAd: server_structs.NamespaceAd{
					Caps: tc.nsCaps,
				},
			}

			ctx := &gin.Context{}
			for _, verb := range tc.supportedVerbs {
				assert.True(t, originSupportsVerb(verb)(ctx, ad), verb+" should be supported")
			}
			assert.False(t, originSupportsVerb("UNKNOWN")(ctx, ad), "Unknown verb should not be supported")
		})
	}
}

func TestOriginSupportsQuery(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name       string
		query      string
		nsCaps     server_structs.Capabilities
		serverCaps server_structs.Capabilities
		expected   bool
	}{
		{
			name:  "DirectReads and Listings supported",
			query: pelican_url.QueryDirectRead + "&" + pelican_url.QueryRecursive + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			expected: true,
		},
		{
			name:  "DirectReads not supported by server",
			query: pelican_url.QueryDirectRead + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: false,
			},
			expected: false,
		},
		{
			name:  "DirectReads not supported by ns",
			query: pelican_url.QueryDirectRead + "",
			nsCaps: server_structs.Capabilities{
				DirectReads: false,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
			},
			expected: false,
		},
		{
			name:  "Listings not supported",
			query: pelican_url.QueryRecursive + "",
			nsCaps: server_structs.Capabilities{
				Listings: false,
			},
			serverCaps: server_structs.Capabilities{
				Listings: false,
			},
			expected: false,
		},
		{
			name:  "No query parameters",
			query: "",
			nsCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			serverCaps: server_structs.Capabilities{
				DirectReads: true,
				Listings:    true,
			},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Caps: tc.serverCaps,
				},
				NamespaceAd: server_structs.NamespaceAd{
					Caps: tc.nsCaps,
				},
			}

			ctx := &gin.Context{}
			ctx.Request = &http.Request{
				URL: &url.URL{
					RawQuery: tc.query,
				},
			}

			assert.Equal(t, tc.expected, originSupportsQuery()(ctx, ad))
		})
	}
}

func TestComputeFeaturesUnion(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name              string
		origins           []copyAd
		expectedFeatNames []string
	}{
		{
			name:              "No origins",
			origins:           []copyAd{},
			expectedFeatNames: []string{},
		},
		{
			name: "One origin",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
		{
			name: "Two origins, both with same feature",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
		{
			name: "Two origins, one with feature",
			origins: []copyAd{
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{features.CacheAuthz.GetName()},
					},
				},
				{
					ServerAd: server_structs.ServerAd{
						RequiredFeatures: []string{},
					},
				},
			},
			expectedFeatNames: []string{features.CacheAuthz.GetName()},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			features := computeFeaturesUnion(tc.origins)
			assert.Len(t, features, len(tc.expectedFeatNames), "There should be %d unique features", len(tc.expectedFeatNames))

			if len(tc.expectedFeatNames) == 0 {
				return
			}

			// convert features to a list of their names
			featNames := make([]string, 0, len(features))
			for _, feat := range features {
				featNames = append(featNames, feat.GetName())
			}

			assert.Equal(t, tc.expectedFeatNames, featNames, "The feature names should match")
		})
	}
}

// Helper func to produce named ads in the following tests
func produceAd(name, adType, vString string) copyAd {
	ad := server_structs.ServerAd{
		ServerBaseAd: server_structs.ServerBaseAd{},
		Type:         adType,
	}
	ad.Initialize(name)
	ad.Version = vString
	copyAd := copyAd{
		ServerAd: ad,
	}
	return copyAd
}

func TestFilterOrigins(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name          string
		origins       []copyAd
		predicates    []AdPredicate
		expectedNames []string
	}{
		{
			name: "No predicates passes all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates:    []AdPredicate{},
			expectedNames: []string{"origin1", "origin2"},
		},
		{
			name: "Single predicate filters out one origin",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin1"
				},
			},
			expectedNames: []string{"origin1"},
		},
		{
			name: "Single predicate filters out all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return false
				},
			},
			expectedNames: []string{},
		},
		{
			name: "Single predicate keeps all origins",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return true
				},
			},
			expectedNames: []string{"origin1", "origin2"},
		},
		{
			name: "Origins filtered out by different predicates",
			origins: []copyAd{
				produceAd("origin1", server_structs.OriginType.String(), ""),
				produceAd("origin2", server_structs.OriginType.String(), ""),
			},
			predicates: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin1"
				},
				func(ctx *gin.Context, ad copyAd) bool {
					return ad.ServerAd.Name == "origin2"
				},
			},
			expectedNames: []string{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			origins := filterOrigins(ctx, tc.origins, tc.predicates...)
			assert.Len(t, origins, len(tc.expectedNames), "There should be %d origins", len(tc.expectedNames))

			for _, name := range tc.expectedNames {
				assert.True(t, hasServerAdWithName(origins, name), "Origin %s should be present", name)
			}
		})
	}
}

func TestCacheSupportsFeature(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name             string
		ad               copyAd
		requiredFeatures []string
		supported        bool
	}{
		{
			name:             "CacheAuthz required and supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.16.0"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        true,
		},
		{
			name:             "Unknown server type not marked as supported",
			ad:               produceAd("", "", "v7.16.0"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        false,
		},
		{
			name:             "CacheAuthz required but support unknown",
			ad:               produceAd("", server_structs.CacheType.String(), ""),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			// Technically unknown, but this predicate only checks true/false
			supported: false,
		},
		{
			name:             "CacheAuthz required but not supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.15.999"),
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			supported:        false,
		},
		{
			name:             "CacheAuthz not required but supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.16.0"),
			requiredFeatures: []string{},
			supported:        true,
		},
		{
			name:             "CacheAuthz not required and not supported",
			ad:               produceAd("", server_structs.CacheType.String(), "v7.15.999"),
			requiredFeatures: []string{},
			supported:        true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			featureMap := make(map[string]features.Feature, len(tc.requiredFeatures))
			for _, featureName := range tc.requiredFeatures {
				feature, err := features.GetFeature(featureName)
				require.NoError(t, err, "Feature %s should be supported", featureName)
				featureMap[featureName] = feature
			}
			assert.Equal(t, tc.supported, cacheSupportsFeature(featureMap)(ctx, tc.ad))
		})
	}
}

func TestCacheMightSupportFeature(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name             string
		ad               copyAd
		requiredFeatures []string
		mightSupport     bool
	}{
		{
			name:             "Missing server type means might be supported",
			ad:               produceAd("", "", "v7.16.0"), // unknown server type --> unknown support
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			mightSupport:     true,
		},
		{
			name:             "Missing version means might be supported",
			ad:               produceAd("", server_structs.CacheType.String(), ""), // unknown version --> unknown support
			requiredFeatures: []string{features.CacheAuthz.GetName()},
			mightSupport:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}

			featureMap := make(map[string]features.Feature, len(tc.requiredFeatures))
			for _, featureName := range tc.requiredFeatures {
				feature, err := features.GetFeature(featureName)
				require.NoError(t, err, "Feature %s should be supported", featureName)
				featureMap[featureName] = feature
			}
			assert.Equal(t, tc.mightSupport, cacheMightSupportFeature(featureMap)(ctx, tc.ad))
		})
	}
}

func TestCacheNotFromTopoIfPubReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name        string
		fromTopo    bool
		publicReads bool
		expected    bool
	}{
		{
			name:        "Cache from topology with PublicReads",
			fromTopo:    true,
			publicReads: true,
			expected:    false,
		},
		{
			name:        "Cache not from topology with PublicReads",
			fromTopo:    false,
			publicReads: true,
			expected:    true,
		},
		{
			name:        "Cache from topology without PublicReads",
			fromTopo:    true,
			publicReads: false,
			expected:    true,
		},
		{
			name:        "Cache not from topology without PublicReads",
			fromTopo:    false,
			publicReads: false,
			expected:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					FromTopology: tc.fromTopo,
				},
				NamespaceAd: server_structs.NamespaceAd{
					Caps: server_structs.Capabilities{
						PublicReads: tc.publicReads,
					},
				},
			}

			ctx := &gin.Context{}
			assert.Equal(t, tc.expected, cacheNotFromTopoIfPubReads()(ctx, ad))
		})
	}
}

func TestCacheNotInErrorState(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name     string
		status   metrics.HealthStatusEnum
		expected bool
	}{
		{
			name:     "Cache in healthy state",
			status:   metrics.StatusOK,
			expected: true,
		},
		{
			name:     "Cache in unknown state",
			status:   metrics.StatusUnknown,
			expected: true,
		},
		{
			name:     "Cache in warning state",
			status:   metrics.StatusWarning,
			expected: true,
		},
		{
			name:     "Cache in degraded state",
			status:   metrics.StatusDegraded,
			expected: true,
		},
		{
			name:     "Cache in critical state",
			status:   metrics.StatusCritical,
			expected: false,
		},
		{
			name:     "Cache in shutting down state",
			status:   metrics.StatusShuttingDown,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Status: tc.status.String(),
				},
			}

			ctx := &gin.Context{}
			assert.Equal(t, tc.expected, cacheNotInErrorState()(ctx, ad))
		})
	}
}

func TestFilterCaches(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	testCases := []struct {
		name            string
		ads             []copyAd
		commonPreds     []AdPredicate
		supportedPreds  []AdPredicate
		unknownPreds    []AdPredicate
		expectedSupport []string
		expectedUnknown []string
	}{
		{
			name: "All ads pass common and supported predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			unknownPreds:    []AdPredicate{},
			expectedSupport: []string{"ad1", "ad2"},
			expectedUnknown: []string{},
		},
		{
			name: "All ads pass common but only some pass supported predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad1" },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return false },
			},
			expectedSupport: []string{"ad1"},
			expectedUnknown: []string{},
		},
		{
			name: "Ads pass common but only some pass unknown predicates",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return false },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad2" },
			},
			expectedSupport: []string{},
			expectedUnknown: []string{"ad2"},
		},
		{
			name: "Ads fail common predicate",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
			},
			commonPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return false },
			},
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			expectedSupport: []string{},
			expectedUnknown: []string{},
		},
		{
			name: "Ads split between supported and unknown groups",
			ads: []copyAd{
				produceAd("ad1", server_structs.CacheType.String(), ""),
				produceAd("ad2", server_structs.CacheType.String(), ""),
				produceAd("ad3", server_structs.CacheType.String(), ""),
			},
			commonPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return true },
			},
			supportedPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad1" },
			},
			unknownPreds: []AdPredicate{
				func(ctx *gin.Context, ad copyAd) bool { return ad.ServerAd.Name == "ad2" },
			},
			expectedSupport: []string{"ad1"},
			expectedUnknown: []string{"ad2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &gin.Context{}
			supported, unknown := filterCaches(ctx, tc.ads, tc.commonPreds, tc.supportedPreds, tc.unknownPreds)

			// Verify supported ads
			assert.Len(t, supported, len(tc.expectedSupport), "Number of supported ads should match")
			for _, name := range tc.expectedSupport {
				assert.True(t, hasServerAdWithName(supported, name), "Supported ad %s should be present", name)
			}

			// Verify unknown ads
			assert.Len(t, unknown, len(tc.expectedUnknown), "Number of unknown ads should match")
			for _, name := range tc.expectedUnknown {
				assert.True(t, hasServerAdWithName(unknown, name), "Unknown ad %s should be present", name)
			}
		})
	}
}

// A registry-backed namespace whose origins are all offline is served by the
// caches that confirm a copy of the object, and by nothing else
func TestOriginlessRedirect(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	resetHealthTests()
	shutdownStatUtils()
	serverAds.DeleteAll()
	resetRegistryQueryState()
	t.Cleanup(func() {
		shutdownHealthTests()
		shutdownStatUtils()
		serverAds.DeleteAll()
		resetRegistryQueryState()
		server_utils.ResetTestState()
	})
	// The director has been up for longer than its startup window
	SetStartupTime(time.Now().Add(-10 * time.Minute))
	t.Cleanup(func() { SetStartupTime(time.Now()) })
	require.NoError(t, param.Director_StatTimeout.Set(2*time.Second))
	require.NoError(t, param.Director_CacheSortMethod.Set(server_structs.DistanceType.String()))

	// newCacheAnswering stands up a cache whose presence-check answer is the given handler
	newCacheAnswering := func(t *testing.T, name string, handler http.HandlerFunc) server_structs.ServerAd {
		srv := httptest.NewServer(handler)
		t.Cleanup(srv.Close)
		u, err := url.Parse(srv.URL)
		require.NoError(t, err)
		ad := server_structs.ServerAd{URL: *u, Type: server_structs.CacheType.String(), Caps: server_structs.Capabilities{PublicReads: true, Reads: true}}
		ad.Initialize(name)
		return ad
	}
	// newCache stands up a cache that answers the presence check either as a
	// holder of every object (200 with a positive Age) or as an empty one (404)
	newCache := func(t *testing.T, name string, holds bool) server_structs.ServerAd {
		return newCacheAnswering(t, name, func(w http.ResponseWriter, r *http.Request) {
			if !holds {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", "10")
			w.Header().Set("Age", "42")
			w.WriteHeader(http.StatusOK)
		})
	}
	// newDenyingCache stands up a cache that refuses every presence check (403)
	newDenyingCache := func(t *testing.T, name string) server_structs.ServerAd {
		return newCacheAnswering(t, name, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		})
	}
	// newPlacedCache stands up a cache like newCache does, at the given
	// coordinates, and records in asked whether the presence check reached it
	newPlacedCache := func(t *testing.T, name string, holds bool, lat, long float64, asked *sync.Map) server_structs.ServerAd {
		ad := newCacheAnswering(t, name, func(w http.ResponseWriter, r *http.Request) {
			asked.Store(name, true)
			if !holds {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", "10")
			w.Header().Set("Age", "42")
			w.WriteHeader(http.StatusOK)
		})
		ad.Latitude, ad.Longitude = lat, long
		return ad
	}
	wasAsked := func(asked *sync.Map, name string) bool {
		_, ok := asked.Load(name)
		return ok
	}
	// seed replaces the server ads with the given ones, each advertising nsAd,
	// and gives every one a fresh stat utility so that no presence answer
	// carries over between subtests. The result caches are started so that
	// shutdownStatUtils can stop them.
	seed := func(nsAd server_structs.NamespaceAd, ads ...server_structs.ServerAd) {
		shutdownStatUtils()
		serverAds.DeleteAll()
		statUtilsMutex.Lock()
		defer statUtilsMutex.Unlock()
		for _, ad := range ads {
			serverAds.Set(ad.URL.String(), &server_structs.Advertisement{ServerAd: ad, NamespaceAds: []server_structs.NamespaceAd{nsAd}}, ttlcache.DefaultTTL)
			ctx, cancel := context.WithCancel(context.Background())
			results := ttlcache.New(ttlcache.WithTTL[string, *objectMetadata](time.Minute))
			go results.Start()
			statUtils[ad.URL.String()] = &serverStatUtil{Context: ctx, Cancel: cancel, Errgroup: &utils.Group{}, ResultCache: results}
		}
	}
	setRegistry := func(ads ...server_structs.NamespaceAd) {
		ingested := ingestRegistryNamespaceAds(ads)
		registryNamespaceAds.Store(&ingested)
	}
	request := func(method, target string, headers map[string]string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, target, nil)
		for k, v := range headers {
			c.Request.Header.Set(k, v)
		}
		return c
	}
	count := func(result metrics.DirectorOriginlessResult) float64 {
		return testutil.ToFloat64(metrics.PelicanDirectorOriginlessRedirectsTotal.WithLabelValues(string(result)))
	}
	names := func(ads []copyAd) []string {
		out := make([]string, 0, len(ads))
		for _, ad := range ads {
			out = append(out, ad.ServerAd.Name)
		}
		return out
	}

	public := server_structs.NamespaceAd{Path: "/reg", Caps: server_structs.Capabilities{PublicReads: true, Reads: true}}
	gated := server_structs.NamespaceAd{Path: "/reg", Caps: server_structs.Capabilities{Reads: true}, Issuer: []server_structs.TokenIssuer{{IssuerUrl: url.URL{Scheme: "https", Host: "issuer.example.org"}, BasePaths: []string{"/reg"}}}}
	const object = "/api/v1.0/director/object/reg/obj.txt"

	t.Run("only-the-cache-that-confirms-a-copy-is-returned", func(t *testing.T) {
		require.NoError(t, param.Director_CheckCachePresence.Set(true))
		holder, empty := newCache(t, "holder", true), newCache(t, "empty", false)
		seed(public, holder, empty)
		setRegistry(public)
		before := count(metrics.OriginlessRedirected)

		oAds, cAds, nsAd, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.Empty(t, oAds)
		assert.Equal(t, []string{holder.Name}, names(cAds))
		assert.Equal(t, "/reg", nsAd.Path)
		assert.True(t, nsAd.FromRegistry)
		assert.Equal(t, before+1, count(metrics.OriginlessRedirected))
	})

	t.Run("the-presence-check-ignores-CheckCachePresence", func(t *testing.T) {
		require.NoError(t, param.Director_CheckCachePresence.Set(false))
		t.Cleanup(func() { require.NoError(t, param.Director_CheckCachePresence.Set(true)) })
		holder, empty := newCache(t, "holder", true), newCache(t, "empty", false)
		seed(public, holder, empty)
		setRegistry(public)

		_, cAds, _, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.Equal(t, []string{holder.Name}, names(cAds), "the empty cache must still be excluded with the flag off")
	})

	t.Run("no-cache-confirms-a-copy", func(t *testing.T) {
		seed(public, newCache(t, "empty-1", false), newCache(t, "empty-2", false))
		setRegistry(public)
		before := count(metrics.OriginlessNoCopy)

		_, _, _, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.IsType(t, noCopyInOutageErr{}, err)
		assert.Contains(t, err.Error(), "no origin is online and no cache reports a copy")
		assert.Equal(t, before+1, count(metrics.OriginlessNoCopy))
	})

	t.Run("a-request-that-skips-the-check-is-sent-unchecked", func(t *testing.T) {
		var checks sync.Map
		holder, empty := newPlacedCache(t, "holder", true, 0, 0, &checks), newPlacedCache(t, "empty", false, 0, 0, &checks)
		seed(public, holder, empty)
		setRegistry(public)
		before := count(metrics.OriginlessUnchecked)

		_, cAds, _, err := getSortedAds(request(http.MethodGet, object+"?skipstat", nil), uuid.New())
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{holder.Name, empty.Name}, names(cAds), "a request that skips the check is sent to every cache")
		assert.Equal(t, before+1, count(metrics.OriginlessUnchecked))
		assert.False(t, wasAsked(&checks, holder.Name) || wasAsked(&checks, empty.Name), "no cache was asked for a copy")
	})

	t.Run("a-token-gated-namespace-is-checked-only-with-a-token", func(t *testing.T) {
		// Without a token the caches would refuse the presence check, so the
		// client is sent to every cache, closest first, and none is asked
		var checks sync.Map
		holder, empty := newPlacedCache(t, "holder", true, 0, 0, &checks), newPlacedCache(t, "empty", false, 0, 0, &checks)
		seed(gated, holder, empty)
		setRegistry(gated)
		before := count(metrics.OriginlessUnchecked)

		_, cAds, nsAd, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{holder.Name, empty.Name}, names(cAds), "a request without a token is sent to every cache")
		assert.False(t, nsAd.Caps.PublicReads)
		assert.Equal(t, before+1, count(metrics.OriginlessUnchecked))
		assert.False(t, wasAsked(&checks, holder.Name) || wasAsked(&checks, empty.Name), "no cache was asked for a copy")

		// With a token the presence check runs and only the holder is returned
		_, cAds, nsAd, err = getSortedAds(request(http.MethodGet, object, map[string]string{"Authorization": "Bearer not-checked-by-this-test"}), uuid.New())
		require.NoError(t, err)
		assert.Equal(t, []string{holder.Name}, names(cAds))
		assert.False(t, nsAd.Caps.PublicReads)
		assert.Equal(t, before+1, count(metrics.OriginlessUnchecked))
	})

	t.Run("a-request-the-caches-refuse-is-denied-not-missing", func(t *testing.T) {
		// The denying cache may hold the object; the empty one does not. Neither
		// confirms a copy, but the refusal is what the client needs to hear
		seed(gated, newDenyingCache(t, "denying"), newCache(t, "empty", false))
		setRegistry(gated)
		before := count(metrics.OriginlessDenied)

		_, _, _, err := getSortedAds(request(http.MethodGet, object, map[string]string{"Authorization": "Bearer rejected-by-the-caches"}), uuid.New())
		require.IsType(t, deniedInOutageErr{}, err)
		assert.Contains(t, err.Error(), "1 of the 2 cache(s) asked rejected the request's token")
		assert.Equal(t, before+1, count(metrics.OriginlessDenied))

		// A public read the caches refuse is a denial too, with no token to blame
		seed(public, newDenyingCache(t, "denying"))
		setRegistry(public)
		_, _, _, err = getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.IsType(t, deniedInOutageErr{}, err)
		assert.Contains(t, err.Error(), "1 of the 1 cache(s) asked denied access to the object")
	})

	// The test client gets a random coordinate inside the United States, so
	// a cache placed there is always closer than one at the South Pole
	t.Run("a-copy-beyond-the-closest-caches-is-found-in-a-second-round", func(t *testing.T) {
		limit := param.Director_AdaptiveSortTruncateConstant.GetInt()
		require.NoError(t, param.Director_AdaptiveSortTruncateConstant.Set(2))
		t.Cleanup(func() { require.NoError(t, param.Director_AdaptiveSortTruncateConstant.Set(limit)) })
		var asked sync.Map
		near1 := newPlacedCache(t, "near-empty-1", false, 40, -100, &asked)
		near2 := newPlacedCache(t, "near-empty-2", false, 41, -99, &asked)
		far := newPlacedCache(t, "far-holder", true, -89, 0, &asked)
		seed(public, near1, near2, far)
		setRegistry(public)
		before := count(metrics.OriginlessRedirected)

		_, cAds, _, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.Equal(t, []string{far.Name}, names(cAds), "the far cache holds the only copy")
		assert.True(t, wasAsked(&asked, near1.Name) && wasAsked(&asked, near2.Name), "the closest caches are asked first")
		assert.True(t, wasAsked(&asked, far.Name), "the rest are asked when the closest hold nothing")
		assert.Equal(t, before+1, count(metrics.OriginlessRedirected))
	})

	t.Run("the-second-round-is-skipped-when-a-close-cache-holds-a-copy", func(t *testing.T) {
		limit := param.Director_AdaptiveSortTruncateConstant.GetInt()
		require.NoError(t, param.Director_AdaptiveSortTruncateConstant.Set(1))
		t.Cleanup(func() { require.NoError(t, param.Director_AdaptiveSortTruncateConstant.Set(limit)) })
		var asked sync.Map
		near := newPlacedCache(t, "near-holder", true, 40, -100, &asked)
		far := newPlacedCache(t, "far-empty", false, -89, 0, &asked)
		seed(public, near, far)
		setRegistry(public)

		_, cAds, _, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.Equal(t, []string{near.Name}, names(cAds))
		assert.True(t, wasAsked(&asked, near.Name))
		assert.False(t, wasAsked(&asked, far.Name), "a far cache is not asked when a close one holds a copy")
	})

	t.Run("anything-but-a-cached-read-still-needs-an-origin", func(t *testing.T) {
		seed(public, newCache(t, "holder", true))
		setRegistry(public)
		for _, tc := range []struct{ name, method, target string }{
			{"write", http.MethodPut, object},
			{"listing", "PROPFIND", object},
			{"origin-request", http.MethodGet, "/api/v1.0/director/origin/reg/obj.txt"},
			{"direct-read", http.MethodGet, object + "?directread"},
		} {
			_, _, _, err := getSortedAds(request(tc.method, tc.target, nil), uuid.New())
			assert.IsType(t, noOriginsForNsErr{}, err, tc.name)
		}
	})

	t.Run("a-namespace-the-registry-does-not-know-keeps-the-old-answer", func(t *testing.T) {
		seed(public, newCache(t, "holder", true))
		setRegistry()

		_, _, _, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		assert.IsType(t, noOriginsForNsErr{}, err)
	})

	t.Run("a-live-origin-keeps-the-normal-path", func(t *testing.T) {
		require.NoError(t, param.Director_CheckCachePresence.Set(false))
		require.NoError(t, param.Director_CheckOriginPresence.Set(false))
		t.Cleanup(func() {
			require.NoError(t, param.Director_CheckCachePresence.Set(true))
			require.NoError(t, param.Director_CheckOriginPresence.Set(true))
		})
		origin := server_structs.ServerAd{URL: url.URL{Scheme: "https", Host: "origin.example.org"}, Type: server_structs.OriginType.String(), Caps: server_structs.Capabilities{PublicReads: true, Reads: true}}
		origin.Initialize("origin")
		holder, empty := newCache(t, "holder", true), newCache(t, "empty", false)
		seed(public, origin, holder, empty)
		setRegistry(public)
		before := count(metrics.OriginlessRedirected)

		oAds, cAds, nsAd, err := getSortedAds(request(http.MethodGet, object, nil), uuid.New())
		require.NoError(t, err)
		assert.Equal(t, []string{origin.Name}, names(oAds))
		assert.ElementsMatch(t, []string{holder.Name, empty.Name}, names(cAds), "with an origin online and the flag off no cache is excluded")
		assert.False(t, nsAd.FromRegistry)
		assert.Equal(t, before, count(metrics.OriginlessRedirected))
	})

	// The cache redirect handler turns the two answers into a 307 to the
	// cache that holds the copy, a 404 that names the outage, or a 403 when the
	// caches refuse the request
	t.Run("redirectToCache", func(t *testing.T) {
		router := gin.New()
		router.GET("/api/v1.0/director/object/*any", redirectToCache)
		serve := func(headers map[string]string) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, object, nil)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			router.ServeHTTP(w, req)
			return w
		}

		holder := newCache(t, "holder", true)
		seed(public, holder, newCache(t, "empty", false))
		setRegistry(public)
		w := serve(nil)
		require.Equal(t, http.StatusTemporaryRedirect, w.Code, w.Body.String())
		location, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, holder.URL.Host, location.Host, "Location: %s", location)
		assert.Equal(t, "/reg/obj.txt", location.Path)
		assert.Contains(t, w.Header().Get("X-Pelican-Namespace"), "namespace=/reg")

		seed(public, newCache(t, "empty", false))
		w = serve(nil)
		require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "no origin is online and no cache reports a copy")

		seed(gated, newDenyingCache(t, "denying"))
		setRegistry(gated)
		w = serve(map[string]string{"Authorization": "Bearer rejected-by-the-caches"})
		require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "rejected the request's token")

		// Without a token the same request is a redirect that tells the client
		// where to get one, as on the normal path
		w = serve(nil)
		require.Equal(t, http.StatusTemporaryRedirect, w.Code, w.Body.String())
		assert.Contains(t, w.Header().Get("X-Pelican-Namespace"), "require-token=true")
		assert.Contains(t, w.Header().Get("X-Pelican-Authorization"), "issuer=https://issuer.example.org")
	})
}
