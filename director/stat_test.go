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

package director

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestQueryServersForObject(t *testing.T) {
	viper.Reset()
	viper.Set("Director.MinStatResponse", 1)
	viper.Set("Director.MaxStatResponse", 1)
	viper.Set("Director.StatTimeout", time.Microsecond*200)

	// Preserve existing serverAds for other test funcs
	oldAds := serverAds

	stat := NewObjectStat()
	stat.ReqHandler = func(maxCancelCtx context.Context, objectName string, dataUrl url.URL, digest bool, token string, timeout time.Duration) (*objectMetadata, error) {
		return &objectMetadata{URL: *dataUrl.JoinPath(objectName)}, nil
	}

	// The OnEviction function is added to serverAds, which will clear deleted cache item
	// but will have dead-lock for our test cases. Bypass the onEviction function
	// by re-init serverAds
	serverAds = ttlcache.New(ttlcache.WithTTL[string, *server_structs.Advertisement](15 * time.Minute))

	mockTTLCache := func() {
		mockServerAd1 := server_structs.ServerAd{
			Name:    "origin1",
			URL:     url.URL{Host: "example1.com", Scheme: "https"},
			AuthURL: url.URL{Host: "example1.com:8444", Scheme: "https"},
			Type:    server_structs.OriginType}
		mockServerAd2 := server_structs.ServerAd{
			Name:    "origin2",
			URL:     url.URL{Host: "example2.com", Scheme: "https"},
			AuthURL: url.URL{Host: "example2.com:8444", Scheme: "https"},
			Type:    server_structs.OriginType}
		mockServerAd3 := server_structs.ServerAd{
			Name:    "origin3",
			URL:     url.URL{Host: "example3.com", Scheme: "https"},
			AuthURL: url.URL{Host: "example3.com:8444", Scheme: "https"},
			Type:    server_structs.OriginType}
		mockServerAd4 := server_structs.ServerAd{
			Name:    "origin4",
			URL:     url.URL{Host: "example4.com", Scheme: "https"},
			AuthURL: url.URL{Host: "example4.com:8444", Scheme: "https"},
			Type:    server_structs.OriginType}
		mockServerAd5 := server_structs.ServerAd{
			Name:    "cache1",
			URL:     url.URL{Host: "cache1.com", Scheme: "https"},
			AuthURL: url.URL{Host: "cache1.com:8444", Scheme: "https"},
			Type:    server_structs.CacheType}
		mockNsAd0 := server_structs.NamespaceAdV2{Path: "/foo"}
		mockNsAd1 := server_structs.NamespaceAdV2{Path: "/foo/bar"}
		mockNsAd2 := server_structs.NamespaceAdV2{Path: "/foo/x"}
		mockNsAd3 := server_structs.NamespaceAdV2{Path: "/foo/bar/barz"}
		mockNsAd4 := server_structs.NamespaceAdV2{Path: "/unrelated"}
		mockNsAd5 := server_structs.NamespaceAdV2{Path: "/caches/hostname"}
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
	}

	cleanupMock := func() {
		statUtilsMutex.Lock()
		defer statUtilsMutex.Unlock()
		serverAds.DeleteAll()
		for sa := range statUtils {
			delete(statUtils, sa)
		}
	}

	initMockStatUtils := func() {
		statUtilsMutex.Lock()
		defer statUtilsMutex.Unlock()

		for _, key := range serverAds.Keys() {
			ctx, cancel := context.WithCancel(context.Background())
			statUtils[key] = serverStatUtil{
				Context:  ctx,
				Cancel:   cancel,
				Errgroup: &errgroup.Group{},
			}
		}
	}

	t.Cleanup(func() {
		cleanupMock()
		// Restore the old serverAds at the end of this test func
		serverAds = oldAds
		viper.Reset()
	})

	t.Run("empty-server-ads-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, queryNoPrefixMatchErr, result.ErrorType)
		assert.Nil(t, result.Objects)
	})

	t.Run("invalid-min-max", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 3, 1)

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

		result := stat.queryServersForObject(ctx, "/dne/random.txt", config.OriginType, 0, 0)

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

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

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

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Equal(t, 1, len(result.Objects))
		assert.True(t, result.Objects[0].URL.String() == "https://example2.com/foo/bar/test.txt" ||
			result.Objects[0].URL.String() == "https://example3.com/foo/bar/test.txt",
			"Return value is not expected:", result.Objects[0].URL.String())
	})

	t.Run("prefix-only-in-cache-return-nil-when-only-querying-origin", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", config.OriginType, 0, 0)

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

		result := stat.queryServersForObject(ctx, "/foo/bar/barz/test.txt", config.CacheType, 0, 0)

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

		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", config.CacheType, 0, 0)

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

		sType := config.CacheType
		sType.Set(config.OriginType)

		result := stat.queryServersForObject(ctx, "/foo/cache/only/test.txt", sType, 0, 0)

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

		mockCacheServer := []server_structs.ServerAd{{Name: "cache-overwrite", URL: url.URL{Host: "cache-overwrites.com", Scheme: "https"}}}

		statUtilsMutex.Lock()
		statUtils[mockCacheServer[0].URL.String()] = serverStatUtil{
			Context:  ctx,
			Cancel:   cancel,
			Errgroup: &errgroup.Group{},
		}
		statUtilsMutex.Unlock()

		result := stat.queryServersForObject(ctx, "/overwrites/test.txt", config.CacheType, 0, 0, withCacheAds(mockCacheServer))

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

		mockOrigin := []server_structs.ServerAd{{Name: "origin-overwrite", URL: url.URL{Host: "origin-overwrites.com", Scheme: "https"}}}

		statUtilsMutex.Lock()
		statUtils[mockOrigin[0].URL.String()] = serverStatUtil{
			Context:  ctx,
			Cancel:   cancel,
			Errgroup: &errgroup.Group{},
		}
		statUtilsMutex.Unlock()

		result := stat.queryServersForObject(ctx, "/overwrites/test.txt", config.OriginType, 0, 0, withOriginAds(mockOrigin))

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

		viper.Set("Director.MaxStatResponse", 2)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 2)
		assert.True(t, result.Objects[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://example3.com/foo/bar/test.txt")
		assert.True(t, result.Objects[1].URL.String() == "https://example2.com/foo/bar/test.txt" || result.Objects[1].URL.String() == "https://example3.com/foo/bar/test.txt")
	})

	t.Run("matched-prefixes-with-max-3-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MaxStatResponse", 3)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		// Response =2 < maxreq, so there won't be any message
		assert.Equal(t, "Stat finished with required number of responses.", result.Msg)
		require.Len(t, result.Objects, 2)
		assert.True(t, result.Objects[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://example3.com/foo/bar/test.txt")
		assert.True(t, result.Objects[1].URL.String() == "https://example2.com/foo/bar/test.txt" || result.Objects[1].URL.String() == "https://example3.com/foo/bar/test.txt")
	})

	t.Run("matched-prefixes-with-min-3-returns-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MinStatResponse", 3)
		viper.Set("Director.MaxStatResponse", 4)
		defer viper.Set("Director.MinStatResponse", 1)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, queryFailed, result.Status)
		require.NotEmpty(t, result.Msg)
		assert.Equal(t, "Number of success response: 2 is less than MinStatResponse (3) required.", result.Msg)
	})

	t.Run("param-overwrites-config", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MinStatResponse", 3)
		viper.Set("Director.MaxStatResponse", 4)
		defer viper.Set("Director.MinStatResponse", 1)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 1, 1)

		assert.Equal(t, querySuccessful, result.Status)
		assert.Empty(t, result.ErrorType)
		assert.Contains(t, result.Msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.Len(t, result.Objects, 1)
		assert.True(t, result.Objects[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result.Objects[0].URL.String() == "https://example3.com/foo/bar/test.txt")
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

		msgChan := make(chan string)

		go func() {
			result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)
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
			if dataUrl.Host == "example2.com" {
				return nil, headReqTimeoutErr{}
			}
			if dataUrl.Host == "example3.com" {
				return nil, headReqNotFoundErr{}
			}
			return nil, errors.New("Default error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result := stat.queryServersForObject(ctx, "/foo/bar/test.txt", config.OriginType, 0, 0)

		assert.Equal(t, queryFailed, result.Status)
		assert.Equal(t, "Number of success response: 0 is less than MinStatResponse (1) required.", result.Msg)
		assert.Nil(t, result.Objects)
	})
}

func TestSendHeadReq(t *testing.T) {
	viper.Reset()

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

	viper.Set("Server.ExternalWebUrl", server.URL)
	viper.Set("IssuerUrl", server.URL)
	realServerUrl, err := url.Parse(server.URL)
	require.NoError(t, err)

	mockOriginAd := server_structs.ServerAd{Type: server_structs.OriginType}
	mockOriginAd.URL = *realServerUrl

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

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
		_, ok := err.(headReqNotFoundErr)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReq(ctx, "/foo/bar/timeout.txt", mockOriginAd.URL, true, "", 200*time.Millisecond)
		require.Error(t, err)
		_, ok := err.(headReqTimeoutErr)
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
		_, ok := err.(headReqCancelledErr)
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
