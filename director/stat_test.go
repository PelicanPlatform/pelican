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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jellydator/ttlcache/v3"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"
)

func cleanupMock() {
	statUtilsMutex.Lock()
	defer statUtilsMutex.Unlock()
	serverAds.DeleteAll()
	for sa := range statUtils {
		delete(statUtils, sa)
	}
}

func initMockStatUtils() {
	statUtilsMutex.Lock()
	defer statUtilsMutex.Unlock()

	for _, key := range serverAds.Keys() {
		ctx, cancel := context.WithCancel(context.Background())
		statUtils[key] = &serverStatUtil{
			Context:  ctx,
			Cancel:   cancel,
			Errgroup: &utils.Group{},
			ResultCache: ttlcache.New(
				ttlcache.WithTTL[string, *objectMetadata](300 * time.Minute),
			),
		}
	}
}

func TestQueryServersForObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server_utils.ResetTestState()
	require.NoError(t, param.Set("Director.MinStatResponse", 1))
	require.NoError(t, param.Set("Director.MaxStatResponse", 1))
	require.NoError(t, param.Set("Director.StatTimeout", time.Microsecond*200))

	// Preserve existing serverAds for other test funcs
	oldAds := serverAds

	stat := NewObjectStat()
	stat.ReqHandler = func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error) {
		// For a protected origin with an authURL, if it's from topology, then the serverAd.URL is likely timeout
		if dataUrl.String() == "https://mock-private-topo-origin.com" ||
			(dataUrl.String() == "http://mock-mix-ns-topo-origin.com" && strings.HasPrefix(objectName, "/mix/private")) {
			return nil, &headReqTimeoutErr{"Request timeout"}
		} else {
			return &objectMetadata{URL: *dataUrl.JoinPath(objectName)}, nil
		}
	}

	// The OnEviction function is added to serverAds, which will clear deleted cache item
	// but will have dead-lock for our test cases. Bypass the onEviction function
	// by re-init serverAds
	serverAds = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](15 * time.Minute))

	mockTTLCache := func() {
		mockServerAd1 := server_structs.ServerAd{
			URL:     url.URL{Host: "mock-origin-1.com", Scheme: "https"},
			AuthURL: url.URL{Host: "mock-origin-1-auth.com:8444", Scheme: "https"},
			Caps:    server_structs.Capabilities{PublicReads: true},
			Type:    server_structs.OriginType.String()}
		mockServerAd1.Initialize("origin1")
		mockServerAd2 := server_structs.ServerAd{
			URL:     url.URL{Host: "mock-origin-2.com", Scheme: "https"},
			AuthURL: url.URL{Host: "mock-origin-2-auth.com:8444", Scheme: "https"},
			Caps:    server_structs.Capabilities{PublicReads: true},
			Type:    server_structs.OriginType.String()}
		mockServerAd2.Initialize("origin2")
		mockServerAd3 := server_structs.ServerAd{
			URL:     url.URL{Host: "mock-origin-3.com", Scheme: "https"},
			AuthURL: url.URL{Host: "mock-origin-3-auth.com:8444", Scheme: "https"},
			Caps:    server_structs.Capabilities{PublicReads: true},
			Type:    server_structs.OriginType.String()}
		mockServerAd3.Initialize("origin3")
		mockServerAd4 := server_structs.ServerAd{
			URL:     url.URL{Host: "mock-origin-4.com", Scheme: "https"},
			AuthURL: url.URL{Host: "mock-origin-4-auth.com:8444", Scheme: "https"},
			Caps:    server_structs.Capabilities{PublicReads: true},
			Type:    server_structs.OriginType.String()}
		mockServerAd4.Initialize("origin4")
		mockServerAdPrivateTopology := server_structs.ServerAd{
			URL:          url.URL{Host: "mock-private-topo-origin.com", Scheme: "http"},
			AuthURL:      url.URL{Host: "mock-private-topo-origin-auth.com:8444", Scheme: "https"},
			Caps:         server_structs.Capabilities{PublicReads: false},
			Type:         server_structs.OriginType.String(),
			FromTopology: true}
		mockServerAdPrivateTopology.Initialize("originPrivateTopology")
		mockServerAdPublicTopology := server_structs.ServerAd{
			URL:          url.URL{Host: "mock-public-topo-origin.com", Scheme: "http"},
			AuthURL:      url.URL{Host: "mock-public-topo-origin-auth.com:8444", Scheme: "https"},
			Caps:         server_structs.Capabilities{PublicReads: true},
			Type:         server_structs.OriginType.String(),
			FromTopology: true}
		mockServerAdPublicTopology.Initialize("originPublicTopology")
		mockServerAdPrivateTopologyWOAuthUrl := server_structs.ServerAd{
			URL:          url.URL{Host: "mock-private-topo-origin-no-authurl.com", Scheme: "http"},
			Caps:         server_structs.Capabilities{PublicReads: false},
			Type:         server_structs.OriginType.String(),
			FromTopology: true}
		mockServerAdPrivateTopologyWOAuthUrl.Initialize("originPrivateTopologyNoAuthUrl")
		mockTopoPubServerMixNs := server_structs.ServerAd{
			URL:          url.URL{Host: "mock-mix-ns-topo-origin.com", Scheme: "http"},
			AuthURL:      url.URL{Host: "mock-mix-ns-topo-origin-auth.com:8444", Scheme: "https"},
			Caps:         server_structs.Capabilities{PublicReads: true},
			Type:         server_structs.OriginType.String(),
			FromTopology: true,
		}
		mockTopoPubServerMixNs.Initialize("originMixNsTopology")
		mockServerAd5 := server_structs.ServerAd{
			URL:     url.URL{Host: "cache1.com", Scheme: "https"},
			AuthURL: url.URL{Host: "cache1-auth.com:8444", Scheme: "https"},
			Caps:    server_structs.Capabilities{PublicReads: true},
			Type:    server_structs.CacheType.String()}
		mockServerAd5.Initialize("cache1")
		mockNsAd0 := server_structs.NamespaceAdV2{Path: "/foo"}
		mockNsAd1 := server_structs.NamespaceAdV2{Path: "/foo/bar"}
		mockNsAd2 := server_structs.NamespaceAdV2{Path: "/foo/x"}
		mockNsAd3 := server_structs.NamespaceAdV2{Path: "/foo/bar/barz"}
		mockNsAd4 := server_structs.NamespaceAdV2{Path: "/unrelated"}
		mockNsAd5 := server_structs.NamespaceAdV2{Path: "/caches/hostname"}
		mockNsPrivateTopo := server_structs.NamespaceAdV2{Path: "/protected/topology"}
		mockNsPrivateTopoNoAuth := server_structs.NamespaceAdV2{Path: "/protected/topology/noauth"}
		mockNsPublicTopo := server_structs.NamespaceAdV2{Path: "/public/topology", Caps: server_structs.Capabilities{PublicReads: true}}
		mockMixNsPrivateTopo := server_structs.NamespaceAdV2{Path: "/mix/protected"}
		mockMixNsPublicTopo := server_structs.NamespaceAdV2{Path: "/mix/public", Caps: server_structs.Capabilities{PublicReads: true}}
		mockNsCacheOnly := server_structs.NamespaceAdV2{Path: "/foo/cache/only"}
		serverAds.Set(mockServerAd1.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAd1,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd0},
			}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd2.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAd2,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd1},
			}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd3.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAd3,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd1, mockNsAd4},
			}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd4.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAd4,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd2, mockNsAd3},
			}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd5.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAd5,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd5, mockNsAd0, mockNsAd1, mockNsCacheOnly},
			}, ttlcache.DefaultTTL)
		// Test a topology server with protected object access
		serverAds.Set(mockServerAdPrivateTopology.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAdPrivateTopology,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsPrivateTopo},
			}, ttlcache.DefaultTTL,
		)
		// Test a topology server with public object access
		serverAds.Set(mockServerAdPublicTopology.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAdPublicTopology,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsPublicTopo},
			}, ttlcache.DefaultTTL,
		)
		// Test a topology server with protected object access but does not have AuthURL set
		serverAds.Set(mockServerAdPrivateTopologyWOAuthUrl.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockServerAdPrivateTopologyWOAuthUrl,
				NamespaceAds: []server_structs.NamespaceAdV2{mockNsPrivateTopoNoAuth},
			}, ttlcache.DefaultTTL,
		)
		serverAds.Set(mockTopoPubServerMixNs.URL.String(),
			&server_structs.Advertisement{
				ServerAd:     mockTopoPubServerMixNs,
				NamespaceAds: []server_structs.NamespaceAdV2{mockMixNsPrivateTopo, mockMixNsPublicTopo},
			}, ttlcache.DefaultTTL,
		)
	}

	t.Cleanup(func() {
		cleanupMock()
		// Restore the old serverAds at the end of this test func
		serverAds = oldAds
		server_utils.ResetTestState()
	})

	t.Run("empty-server-ads-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, queryNoPrefixMatchErr, result.ErrorType)
		assert.Nil(t, result.Objects)
	})

	t.Run("invalid-min-max", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 3, 1, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, queryParameterErr, result.ErrorType)
		assert.Nil(t, result.Objects)
	})

	t.Run("unmatched-prefix-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/dne/random.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/dne/random.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, queryNoPrefixMatchErr, result.ErrorType)
		assert.Nil(t, result.Objects)
	})

	t.Run("matched-prefixes-without-utils-returns-err", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		assert.Equal(t, queryInsufficientResErr, result.ErrorType)
		assert.Equal(t, "Number of success response: 0 is less than MinStatResponse (1) required.", result.Msg)
		assert.Nil(t, result.Objects)
	})

	t.Run("matched-prefixes-with-max-1-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.True(t, result.Objects[0].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" ||
			result.Objects[0].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt",
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("prefix-only-in-cache-return-nil-when-only-querying-origin", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/cache/only/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, result.ErrorType, queryNoPrefixMatchErr)
		assert.Nil(t, result.Objects)
	})

	t.Run("prefix-only-in-origin-return-nil-when-only-querying-cache", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		_, cAds := getAdsForPath("/foo/bar/barz/test.txt")
		cServerAds := make([]server_structs.ServerAd, 0, len(cAds))
		for _, ad := range cAds {
			cServerAds = append(cServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/barz/test.txt", server_structs.CacheType, 0, 0, withCacheAds(cServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, result.ErrorType, queryNoPrefixMatchErr)
		assert.Nil(t, result.Objects)
	})

	t.Run("prefix-only-in-cache-returns-when-only-querying-cache", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		_, cAds := getAdsForPath("/foo/cache/only/test.txt")
		cServerAds := make([]server_structs.ServerAd, 0, len(cAds))
		for _, ad := range cAds {
			cServerAds = append(cServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", server_structs.CacheType, 0, 0, withCacheAds(cServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Len(t, result.Objects, 1)
		assert.Equal(t, "https://cache1.com/foo/cache/only/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("prefix-only-in-cache-returns-when-querying-both", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		sType := server_structs.CacheType
		sType.Set(server_structs.OriginType)

		oAds, cAds := getAdsForPath("/foo/cache/only/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		cServerAds := make([]server_structs.ServerAd, 0, len(cAds))
		for _, ad := range cAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		for _, ad := range cAds {
			cServerAds = append(cServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", sType, 0, 0, withOriginAds(oServerAds), withCacheAds(cServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 1)
		assert.Equal(
			t,
			"https://cache1.com/foo/cache/only/test.txt",
			result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String(),
		)
	})

	t.Run("provided-cacheAd-overwrite-cached-ads", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		mockCacheServer := []server_structs.ServerAd{{URL: url.URL{Host: "cache-overwrites.com", Scheme: "https"}}}
		mockCacheServer[0].Initialize("cache-overwrite")

		statUtilsMutex.Lock()
		statUtils[mockCacheServer[0].URL.String()] = &serverStatUtil{
			Context:     ctx,
			Cancel:      cancel,
			Errgroup:    &utils.Group{},
			ResultCache: ttlcache.New[string, *objectMetadata](),
		}
		statUtilsMutex.Unlock()

		result := stat.queryServersForObject(ctx, "/overwrites/test.txt", server_structs.CacheType, 0, 0, withCacheAds(mockCacheServer))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 1)
		assert.Equal(
			t,
			"https://cache-overwrites.com/overwrites/test.txt",
			result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String(),
		)
	})

	t.Run("provided-originAds-overwrite-cached-ads", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		mockOrigin := []server_structs.ServerAd{{URL: url.URL{Host: "origin-overwrites.com", Scheme: "https"}}}
		mockOrigin[0].Initialize("origin-overwrite")

		statUtilsMutex.Lock()
		statUtils[mockOrigin[0].URL.String()] = &serverStatUtil{
			Context:     ctx,
			Cancel:      cancel,
			Errgroup:    &utils.Group{},
			ResultCache: ttlcache.New[string, *objectMetadata](),
		}
		statUtilsMutex.Unlock()

		result := stat.queryServersForObject(ctx, "/overwrites/test.txt", server_structs.OriginType, 0, 0, withOriginAds(mockOrigin))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 1)
		assert.Equal(
			t,
			"https://origin-overwrites.com/overwrites/test.txt",
			result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String(),
		)
	})

	t.Run("matched-prefixes-with-max-2-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		require.NoError(t, param.Set("Director.MaxStatResponse", 2))
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MaxStatResponse", 1))
		})

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 2)
		assert.True(t, result.Objects[0].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt")
		assert.True(t, result.Objects[1].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" || result.Objects[1].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt")
	})

	t.Run("matched-prefixes-with-max-3-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		require.NoError(t, param.Set("Director.MaxStatResponse", 3))
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MaxStatResponse", 1))
		})

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// Response =2 < maxreq, so there won't be any message
		assert.Equal(t, "Stat finished with required number of responses.", result.Msg)
		require.Len(t, result.Objects, 2)
		assert.True(t, result.Objects[0].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt")
		assert.True(t, result.Objects[1].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" || result.Objects[1].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt")
	})

	t.Run("matched-prefixes-with-min-3-returns-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		require.NoError(t, param.Set("Director.MinStatResponse", 3))
		require.NoError(t, param.Set("Director.MaxStatResponse", 4))
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MinStatResponse", 1))
		})
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MaxStatResponse", 1))
		})

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, "Number of success response: 2 is less than MinStatResponse (3) required.", result.Msg)
	})

	t.Run("param-overwrites-config", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		require.NoError(t, param.Set("Director.MinStatResponse", 3))
		require.NoError(t, param.Set("Director.MaxStatResponse", 4))
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MinStatResponse", 1))
		})
		t.Cleanup(func() {
			require.NoError(t, param.Set("Director.MaxStatResponse", 1))
		})

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 1, 1, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 1)
		assert.True(t, result.Objects[0].URL.String() == "https://mock-origin-2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://mock-origin-3.com/foo/bar/test.txt")
	})

	t.Run("cancel-cancels-query", func(t *testing.T) {
		oldHandler := stat.ReqHandler
		defer func() {
			stat.ReqHandler = oldHandler
		}()

		stat.ReqHandler = func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error) {
			time.Sleep(time.Second * 30)
			return &objectMetadata{URL: *dataUrl.JoinPath(objectName)}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}

		msgChan := make(chan string)

		go func() {
			result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))
			msgChan <- result.Msg
		}()

		cancel()

		attempt := 0
		tick := time.Tick(1 * time.Second)
		for {
			select {
			case <-tick:
				attempt += 1
				if attempt > 3 {
					assert.True(t, false, "queryOriginsForObject timeout for response", 0, 0)
					return
				}
			case message := <-msgChan:
				assert.Equal(t, "Director stat for object \"/foo/bar/test.txt\" is cancelled", message)
				return
			}
		}
	})

	t.Run("error-response", func(t *testing.T) {
		oldHandler := stat.ReqHandler
		defer func() {
			stat.ReqHandler = oldHandler
		}()

		stat.ReqHandler = func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error) {
			if dataUrl.Host == "mock-origin-2.com" {
				return nil, &headReqTimeoutErr{}
			}
			if dataUrl.Host == "mock-origin-3.com" {
				return nil, &headReqNotFoundErr{}
			}
			return nil, errors.New("Default error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/foo/bar/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, queryFailed, result.Status)
		assert.Equal(t, "Number of success response: 0 is less than MinStatResponse (1) required.", result.Msg)
		assert.Nil(t, result.Objects)
	})

	t.Run("private-topo-origin-uses-authurl", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/protected/topology/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/protected/topology/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)

		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.Equal(t, "https://mock-private-topo-origin-auth.com:8444/protected/topology/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("public-topo-origin-uses-url", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/public/topology/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/public/topology/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)

		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.Equal(t, "http://mock-public-topo-origin.com/public/topology/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("private-topo-origin-wo-authurl-uses-url", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/protected/topology/noauth/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/protected/topology/noauth/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)

		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.Equal(t, "http://mock-private-topo-origin-no-authurl.com/protected/topology/noauth/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("mix-topo-origin-priv-ns-uses-authurl", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/mix/protected/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/mix/protected/test.txt", server_structs.OriginType, 0, 0, withAuth(true), withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)

		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.Equal(t, "https://mock-mix-ns-topo-origin-auth.com:8444/mix/protected/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("mix-topo-origin-pub-ns-uses-url", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		oAds, _ := getAdsForPath("/mix/public/test.txt")
		oServerAds := make([]server_structs.ServerAd, 0, len(oAds))
		for _, ad := range oAds {
			oServerAds = append(oServerAds, ad.ServerAd)
		}
		result := stat.queryServersForObject(ctx, "/mix/public/test.txt", server_structs.OriginType, 0, 0, withOriginAds(oServerAds))

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)

		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.Equal(t, "http://mock-mix-ns-topo-origin.com/mix/public/test.txt", result.Objects[0].URL.String(),
			"Return value is not expected:", result.Objects[0].URL.String())
	})
}

func TestCache(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	require.NoError(t, param.Reset())
	require.NoError(t, param.Set("Logging.Level", "Debug"))
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	var reqCounter atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		reqCounter.Add(1)
		log.Debugln("Mock server handling request for ", req.URL.String())
		if req.Method == "HEAD" && req.URL.String() == "/foo/test.txt" {
			rw.Header().Set("Content-Length", "1")
			rw.WriteHeader(http.StatusOK)
			return
		} else if req.Method == "HEAD" {
			rw.WriteHeader(http.StatusNotFound)
		} else {
			rw.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	require.NoError(t, param.Set("Server.ExternalWebUrl", server.URL))
	require.NoError(t, param.Set("IssuerUrl", server.URL))
	realServerUrl, err := url.Parse(server.URL)
	require.NoError(t, err)

	serverAds = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](15 * time.Minute))

	mockCacheAd := server_structs.ServerAd{
		Type: server_structs.CacheType.String(),
		URL:  *realServerUrl,
		Caps: server_structs.Capabilities{PublicReads: true},
	}
	mockCacheAd.Initialize("cache")
	mockNsAd := server_structs.NamespaceAdV2{Path: "/foo"}
	serverAds.Set(
		mockCacheAd.URL.String(),
		&server_structs.Advertisement{
			ServerAd:     mockCacheAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNsAd},
		},
		ttlcache.DefaultTTL,
	)
	initMockStatUtils()
	t.Cleanup(cleanupMock)
	require.NoError(t, initServerForTest(t, context.Background(), server_structs.DirectorType))

	t.Run("repeated-cache-access-found", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stat := NewObjectStat()

		_, cAds := getAdsForPath("/foo/test.txt")
		cServerAds := make([]server_structs.ServerAd, 0, len(cAds))
		for _, ad := range cAds {
			cServerAds = append(cServerAds, ad.ServerAd)
		}
		startCtr := reqCounter.Load()
		qResult := stat.queryServersForObject(ctx, "/foo/test.txt", server_structs.CacheType, 1, 1, withCacheAds(cServerAds))
		assert.Equal(t, querySuccessful, qResult.Status)
		require.Len(t, qResult.Objects, 1)
		assert.Equal(t, 1, qResult.Objects[0].ContentLength)
		require.Equal(t, startCtr+1, reqCounter.Load())

		qResult = stat.queryServersForObject(ctx, "/foo/test.txt", server_structs.CacheType, 1, 1, withCacheAds(cServerAds))
		assert.Equal(t, querySuccessful, qResult.Status)
		require.Len(t, qResult.Objects, 1)
		assert.Equal(t, 1, qResult.Objects[0].ContentLength)
		require.Equal(t, startCtr+1, reqCounter.Load())
	})

	t.Run("repeated-cache-access-not-found", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		stat := NewObjectStat()
		_, cAds := getAdsForPath("/foo/notfound.txt")
		cServerAds := make([]server_structs.ServerAd, 0, len(cAds))
		for _, ad := range cAds {
			cServerAds = append(cServerAds, ad.ServerAd)
		}

		startCtr := reqCounter.Load()
		qResult := stat.queryServersForObject(ctx, "/foo/notfound.txt", server_structs.CacheType, 1, 1, withCacheAds(cServerAds))
		assert.Equal(t, queryFailed, qResult.Status)
		assert.Len(t, qResult.Objects, 0)
		assert.Equal(t, queryNoSourcesErr, qResult.ErrorType)
		require.Equal(t, startCtr+1, reqCounter.Load())

		qResult = stat.queryServersForObject(ctx, "/foo/notfound.txt", server_structs.CacheType, 1, 1, withCacheAds(cServerAds))
		assert.Equal(t, queryFailed, qResult.Status)
		assert.Len(t, qResult.Objects, 0)
		assert.Equal(t, queryNoSourcesErr, qResult.ErrorType)
		require.Equal(t, startCtr+1, reqCounter.Load())
	})
}

func TestSendHeadReq(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server_utils.ResetTestState()

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method == "HEAD" && req.URL.String() == "/foo/bar/test.txt" {
			if req.Header.Get("Want-Digest") == "crc32c" {
				rw.Header().Set("Digest", "mockChecksum")
			}
			rw.Header().Set("Content-Length", "1")
			rw.WriteHeader(http.StatusOK)
			return
		} else if req.Method == "HEAD" && req.URL.String() == "/foo/bar/timeout.txt" {
			time.Sleep(2 * time.Second)
			rw.Header().Set("Content-Length", "1")
			rw.WriteHeader(http.StatusOK)
			return
		} else if req.Method == "HEAD" && req.URL.String() == "/foo/bar/error.txt" {
			rw.Header().Set("Content-Length", "1")
			rw.WriteHeader(http.StatusInternalServerError)
			return
		} else {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	defer server.Close()

	require.NoError(t, param.Set("Server.ExternalWebUrl", server.URL))
	require.NoError(t, param.Set("IssuerUrl", server.URL))
	realServerUrl, err := url.Parse(server.URL)
	require.NoError(t, err)

	mockOriginAd := server_structs.ServerAd{Type: server_structs.OriginType.String()}
	mockOriginAd.URL = *realServerUrl

	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))

	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	err = initServerForTest(t, context.Background(), server_structs.DirectorType)
	require.NoError(t, err)

	t.Run("correct-input-gives-no-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReq(ctx, "/foo/bar/test.txt", mockOriginAd.URL, true, "", time.Second)
		require.NoError(t, err)
		assert.NotNil(t, meta)
		assert.Equal(t, 1, meta.ContentLength)
		assert.Equal(t, "mockChecksum", meta.Checksum)
	})

	t.Run("404-input-gives-404-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReq(ctx, "/foo/bar/dne", mockOriginAd.URL, true, "", time.Second)
		require.Error(t, err)
		_, ok := err.(*headReqNotFoundErr)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReq(ctx, "/foo/bar/timeout.txt", mockOriginAd.URL, true, "", 200*time.Millisecond)
		require.Error(t, err)
		_, ok := err.(*headReqTimeoutErr)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("ctx-cancel-gives-cancelled-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		go func() {
			time.Sleep(200 * time.Millisecond)
			cancel()
		}()

		meta, err := stat.sendHeadReq(ctx, "/foo/bar/timeout.txt", mockOriginAd.URL, true, "", 5*time.Second)

		require.Error(t, err)
		_, ok := err.(*headReqCancelledErr)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReq(ctx, "/foo/bar/error.txt", mockOriginAd.URL, true, "", 200*time.Millisecond)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown origin response with status code 500")
		assert.Nil(t, meta)
	})
}

// TestGenerateAvailabilityMaps verifies that the maps returned by generateAvailabilityMaps
// are keyed by ad.Name rather than ad.URL.String(). This is the key that availabilityWeightFn
// uses for lookup, so a mismatch would silently disable the availability axis of adaptive sort.
func TestGenerateAvailabilityMaps(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Save and restore global serverAds so we don't interfere with other tests.
	oldAds := serverAds
	t.Cleanup(func() {
		cleanupMock()
		serverAds = oldAds
	})
	serverAds = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](15 * time.Minute))

	makeCtx := func(method, reqPath string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, reqPath, nil)
		return c
	}

	originAd := server_structs.ServerAd{
		URL:     url.URL{Scheme: "https", Host: "origin.example.com:8443"},
		AuthURL: url.URL{Scheme: "https", Host: "origin-auth.example.com:8444"},
		Caps:    server_structs.Capabilities{PublicReads: true},
		Type:    server_structs.OriginType.String(),
	}
	originAd.Initialize("my-origin")

	cacheAd := server_structs.ServerAd{
		URL:     url.URL{Scheme: "https", Host: "cache.example.com:8443"},
		AuthURL: url.URL{Scheme: "https", Host: "cache-auth.example.com:8444"},
		Caps:    server_structs.Capabilities{PublicReads: true},
		Type:    server_structs.CacheType.String(),
	}
	cacheAd.Initialize("my-cache")

	bestNSAd := server_structs.NamespaceAdV2{
		Path: "/foo",
		Caps: server_structs.Capabilities{PublicReads: true},
	}
	reqID := uuid.New()

	// When stat is skipped (neither CheckCachePresence nor CheckOriginPresence enabled),
	// generateAvailabilityMaps assumes all servers are available and must key those maps
	// by ad.Name — not by ad.URL.String(). Before the fix, the URL-string key meant
	// availabilityWeightFn could never find a match, causing adaptive sort to treat all
	// servers as equally available regardless of stat results.
	t.Run("skip-stat-path-maps-keyed-by-name", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Set(param.Director_CheckCachePresence.GetName(), false))
		require.NoError(t, param.Set(param.Director_CheckOriginPresence.GetName(), false))

		// Use an origin-redirect path so both skipped-stat branches execute.
		ctx := makeCtx(http.MethodGet, "/api/v1.0/director/origin/foo/test.txt")
		oMap, cMap, err := generateAvailabilityMaps(
			ctx,
			[]server_structs.ServerAd{originAd},
			[]server_structs.ServerAd{cacheAd},
			bestNSAd, reqID,
		)
		require.NoError(t, err)

		// Keys MUST be ad.Name — availabilityWeightFn does availMap[ad.Name].
		assert.True(t, oMap[originAd.Name],
			"origin availability map must be keyed by ad.Name %q", originAd.Name)
		assert.False(t, oMap[originAd.URL.String()],
			"origin availability map must NOT be keyed by URL.String() %q", originAd.URL.String())

		assert.True(t, cMap[cacheAd.Name],
			"cache availability map must be keyed by ad.Name %q", cacheAd.Name)
		assert.False(t, cMap[cacheAd.URL.String()],
			"cache availability map must NOT be keyed by URL.String() %q", cacheAd.URL.String())
	})

	// When stat is enabled and a server responds positively, the resulting map entry
	// must still use ad.Name as the key. Before the fix, a successful stat wrote
	// URL.String() — again invisible to availabilityWeightFn.
	t.Run("stat-results-maps-keyed-by-name", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Set(param.Director_CheckCachePresence.GetName(), true))
		require.NoError(t, param.Set(param.Director_CheckOriginPresence.GetName(), false))
		require.NoError(t, param.Set(param.Director_StatTimeout.GetName(), 2*time.Second))
		require.NoError(t, param.Set(param.Director_MinStatResponse.GetName(), 1))
		require.NoError(t, param.Set(param.Director_MaxStatResponse.GetName(), 1))

		// Mock HTTP server that returns 200 with Content-Length for every HEAD request.
		mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "10")
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(mockSrv.Close)

		srvURL, err := url.Parse(mockSrv.URL)
		require.NoError(t, err)

		statCacheAd := server_structs.ServerAd{
			URL:  *srvURL,
			Caps: server_structs.Capabilities{PublicReads: true},
			Type: server_structs.CacheType.String(),
		}
		statCacheAd.Initialize("stat-cache")

		// Populate serverAds and statUtils so queryServersForObject can service the request.
		serverAds.Set(statCacheAd.URL.String(),
			&server_structs.Advertisement{ServerAd: statCacheAd},
			ttlcache.DefaultTTL)
		initMockStatUtils()
		t.Cleanup(cleanupMock)

		// /api/v1.0/director/object paths are cache requests: shouldStatCaches → true,
		// shouldStatOrigins → false (isCacheRequest && len(cAds) > 0).
		ctx := makeCtx(http.MethodGet, "/api/v1.0/director/object/foo/test.txt")
		_, cMap, err := generateAvailabilityMaps(
			ctx,
			[]server_structs.ServerAd{},
			[]server_structs.ServerAd{statCacheAd},
			bestNSAd, reqID,
		)
		require.NoError(t, err)

		assert.True(t, cMap[statCacheAd.Name],
			"cache map must be keyed by ad.Name %q after a successful stat", statCacheAd.Name)
		assert.False(t, cMap[statCacheAd.URL.String()],
			"cache map must NOT be keyed by URL.String() %q after stat — this broke adaptive sort", statCacheAd.URL.String())
	})
}
