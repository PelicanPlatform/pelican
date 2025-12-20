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
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/features"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
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
	nsAd1 := server_structs.NamespaceAdV2{
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

	nsAd2 := server_structs.NamespaceAdV2{
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

	nsAd3 := server_structs.NamespaceAdV2{
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

	nsAdTopo1 := server_structs.NamespaceAdV2{
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

	nsAdTopoOnly := server_structs.NamespaceAdV2{
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

	o1Slice := []server_structs.NamespaceAdV2{nsAd1}
	o2Slice := []server_structs.NamespaceAdV2{nsAd2, nsAd3}
	c1Slice := []server_structs.NamespaceAdV2{nsAd1, nsAd2, nsAdTopoOnly}
	topoSlice := []server_structs.NamespaceAdV2{nsAdTopo1, nsAdTopoOnly}
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
}

func TestAllPredicatesPass(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx := &gin.Context{}
	ad := copyAd{
		ServerAd:    server_structs.ServerAd{},
		NamespaceAd: server_structs.NamespaceAdV2{},
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
			},
			serverCaps: server_structs.Capabilities{
				Reads:       true,
				PublicReads: true,
				Writes:      true,
				Listings:    true,
			},
			supportedVerbs: []string{
				http.MethodGet,
				http.MethodHead,
				http.MethodPut,
				http.MethodDelete,
				"PROPFIND",
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ad := copyAd{
				ServerAd: server_structs.ServerAd{
					Caps: tc.serverCaps,
				},
				NamespaceAd: server_structs.NamespaceAdV2{
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
				NamespaceAd: server_structs.NamespaceAdV2{
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
				NamespaceAd: server_structs.NamespaceAdV2{
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
