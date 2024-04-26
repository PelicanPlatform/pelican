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
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestQueryOriginsForObject(t *testing.T) {
	viper.Reset()
	viper.Set("Director.MinStatResponse", 1)
	viper.Set("Director.MaxStatResponse", 1)
	viper.Set("Director.StatTimeout", time.Microsecond*200)

	// Preserve existing serverAds for other test funcs
	oldAds := serverAds

	stat := NewObjectStat()
	stat.ReqHandler = func(objectName string, dataUrl url.URL, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
		return &objectMetadata{URL: *dataUrl.JoinPath(objectName)}, nil
	}

	// The OnEviction function is added to serverAds, which will clear deleted cache item
	// but will have dead-lock for our test cases. Bypass the onEviction function
	// by re-init serverAds
	func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		serverAds = ttlcache.New[server_structs.ServerAd, []server_structs.NamespaceAdV2](ttlcache.WithTTL[server_structs.ServerAd, []server_structs.NamespaceAdV2](15 * time.Minute))
	}()

	mockTTLCache := func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		mockServerAd1 := server_structs.ServerAd{Name: "origin1", URL: url.URL{Host: "example1.com", Scheme: "https"}, Type: server_structs.OriginType}
		mockServerAd2 := server_structs.ServerAd{Name: "origin2", URL: url.URL{Host: "example2.com", Scheme: "https"}, Type: server_structs.OriginType}
		mockServerAd3 := server_structs.ServerAd{Name: "origin3", URL: url.URL{Host: "example3.com", Scheme: "https"}, Type: server_structs.OriginType}
		mockServerAd4 := server_structs.ServerAd{Name: "origin4", URL: url.URL{Host: "example4.com", Scheme: "https"}, Type: server_structs.OriginType}
		mockServerAd5 := server_structs.ServerAd{Name: "cache1", URL: url.URL{Host: "cache1.com", Scheme: "https"}, Type: server_structs.OriginType}
		mockNsAd0 := server_structs.NamespaceAdV2{Path: "/foo"}
		mockNsAd1 := server_structs.NamespaceAdV2{Path: "/foo/bar"}
		mockNsAd2 := server_structs.NamespaceAdV2{Path: "/foo/x"}
		mockNsAd3 := server_structs.NamespaceAdV2{Path: "/foo/bar/barz"}
		mockNsAd4 := server_structs.NamespaceAdV2{Path: "/unrelated"}
		mockNsAd5 := server_structs.NamespaceAdV2{Path: "/caches/hostname"}
		serverAds.Set(mockServerAd1, []server_structs.NamespaceAdV2{mockNsAd0}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd2, []server_structs.NamespaceAdV2{mockNsAd1}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd3, []server_structs.NamespaceAdV2{mockNsAd1, mockNsAd4}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd4, []server_structs.NamespaceAdV2{mockNsAd2, mockNsAd3}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd5, []server_structs.NamespaceAdV2{mockNsAd5}, ttlcache.DefaultTTL)
	}

	cleanupMock := func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		originStatUtilsMutex.Lock()
		defer originStatUtilsMutex.Unlock()
		serverAds.DeleteAll()
		for sa := range originStatUtils {
			delete(originStatUtils, sa)
		}
	}

	initMockStatUtils := func() {
		serverAdMutex.RLock()
		defer serverAdMutex.RUnlock()
		originStatUtilsMutex.Lock()
		defer originStatUtilsMutex.Unlock()

		for _, key := range serverAds.Keys() {
			ctx, cancel := context.WithCancel(context.Background())
			originStatUtils[key.URL] = originStatUtil{
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
	})

	t.Run("empty-server-ads-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, NoPrefixMatchError, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("invalid-min-max", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 3, 1)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, ParameterError, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("unmatched-prefix-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/dne/random.txt", ctx, 0, 0)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, NoPrefixMatchError, err)
		assert.Equal(t, 0, len(result))
	})

	t.Run("matched-prefixes-without-utils-returns-err", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.Error(t, err)
		assert.Contains(t, msg, "Number of success response: 0 is less than MinStatRespons")
		require.NotNil(t, result)
		require.Equal(t, 0, len(result))
	})

	t.Run("matched-prefixes-with-max-1-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.NoError(t, err)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Equal(t, 1, len(result))
		assert.True(t, result[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result[0].URL.String() == "https://example3.com/foo/bar/test.txt", "Return value is not expected:", result[0].URL.String())
	})

	t.Run("matched-prefixes-with-max-2-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MaxStatResponse", 2)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.NoError(t, err)
		assert.Contains(t, msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
		assert.True(t, result[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result[0].URL.String() == "https://example3.com/foo/bar/test.txt")
		assert.True(t, result[1].URL.String() == "https://example2.com/foo/bar/test.txt" || result[1].URL.String() == "https://example3.com/foo/bar/test.txt")
	})

	t.Run("matched-prefixes-with-max-3-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MaxStatResponse", 3)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.NoError(t, err)
		// Response =2 < maxreq, so there won't be any message
		assert.Empty(t, msg)
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
		assert.True(t, result[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result[0].URL.String() == "https://example3.com/foo/bar/test.txt")
		assert.True(t, result[1].URL.String() == "https://example2.com/foo/bar/test.txt" || result[1].URL.String() == "https://example3.com/foo/bar/test.txt")
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

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.Error(t, err)
		assert.Equal(t, "Number of success response: 2 is less than MinStatResponse (3) required.", msg)
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
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

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 1, 1)

		require.NoError(t, err)
		assert.Contains(t, msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Equal(t, 1, len(result))
		assert.True(t, result[0].URL.String() == "https://example2.com/foo/bar/test.txt" || result[0].URL.String() == "https://example3.com/foo/bar/test.txt")
	})

	t.Run("cancel-cancels-query", func(t *testing.T) {
		oldHandler := stat.ReqHandler
		defer func() {
			stat.ReqHandler = oldHandler
		}()

		stat.ReqHandler = func(objectName string, dataUrl url.URL, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
			time.Sleep(time.Second * 30)
			return &objectMetadata{URL: *dataUrl.JoinPath(objectName)}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		msgChan := make(chan string)

		go func() {
			_, msg, _ := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)
			msgChan <- msg
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

		stat.ReqHandler = func(objectName string, dataUrl url.URL, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
			if dataUrl.Host == "example2.com" {
				return nil, timeoutError{}
			}
			if dataUrl.Host == "example3.com" {
				return nil, notFoundError{}
			}
			return nil, errors.New("Default error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx, 0, 0)

		require.Error(t, err)
		assert.Equal(t, "Number of success response: 0 is less than MinStatResponse (1) required.", msg)
		require.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestSendHeadReqToOrigin(t *testing.T) {
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
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/test.txt", mockOriginAd.URL, time.Second, ctx)
		require.NoError(t, err)
		assert.NotNil(t, meta)
		assert.Equal(t, 1, meta.ContentLength)
		assert.Equal(t, "mockChecksum", meta.Checksum)
	})

	t.Run("404-input-gives-404-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/dne", mockOriginAd.URL, time.Second, ctx)
		require.Error(t, err)
		_, ok := err.(notFoundError)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/timeout.txt", mockOriginAd.URL, 200*time.Millisecond, ctx)
		require.Error(t, err)
		_, ok := err.(timeoutError)
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

		meta, err := stat.sendHeadReqToOrigin("/foo/bar/timeout.txt", mockOriginAd.URL, 5*time.Second, ctx)

		require.Error(t, err)
		_, ok := err.(cancelledError)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/error.txt", mockOriginAd.URL, 200*time.Millisecond, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Unknown origin response with status code 500")
		assert.Nil(t, meta)
	})
}
