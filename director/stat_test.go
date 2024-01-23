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
	"github.com/pelicanplatform/pelican/common"
	"github.com/pelicanplatform/pelican/config"
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
	stat.ReqHandler = func(objectName string, originAd common.ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
		return &objectMetadata{ServerAd: originAd}, nil
	}

	// The OnEviction function is added to serverAds, which will clear deleted cache item
	// but will have dead-lock for our test cases. Bypass the onEviction function
	// by re-init serverAds
	func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		serverAds = ttlcache.New[common.ServerAd, []common.NamespaceAd](ttlcache.WithTTL[common.ServerAd, []common.NamespaceAd](15 * time.Minute))
	}()

	mockTTLCache := func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		mockServerAd1 := common.ServerAd{Name: "origin1", URL: url.URL{Host: "example1.com"}, Type: common.OriginType}
		mockServerAd2 := common.ServerAd{Name: "origin2", URL: url.URL{Host: "example2.com"}, Type: common.OriginType}
		mockServerAd3 := common.ServerAd{Name: "origin3", URL: url.URL{Host: "example3.com"}, Type: common.OriginType}
		mockServerAd4 := common.ServerAd{Name: "origin4", URL: url.URL{Host: "example4.com"}, Type: common.OriginType}
		mockServerAd5 := common.ServerAd{Name: "cache1", URL: url.URL{Host: "cache1.com"}, Type: common.OriginType}
		mockNsAd0 := common.NamespaceAd{Path: "/foo"}
		mockNsAd1 := common.NamespaceAd{Path: "/foo/bar"}
		mockNsAd2 := common.NamespaceAd{Path: "/foo/x"}
		mockNsAd3 := common.NamespaceAd{Path: "/foo/bar/barz"}
		mockNsAd4 := common.NamespaceAd{Path: "/unrelated"}
		mockNsAd5 := common.NamespaceAd{Path: "/caches/hostname"}
		serverAds.Set(mockServerAd1, []common.NamespaceAd{mockNsAd0}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd2, []common.NamespaceAd{mockNsAd1}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd3, []common.NamespaceAd{mockNsAd1, mockNsAd4}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd4, []common.NamespaceAd{mockNsAd2, mockNsAd3}, ttlcache.DefaultTTL)
		serverAds.Set(mockServerAd5, []common.NamespaceAd{mockNsAd5}, ttlcache.DefaultTTL)
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
			originStatUtils[key] = originStatUtil{
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

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, "No namespace prefixes match found.", err.Error())
		assert.Equal(t, 0, len(result))
	})

	t.Run("unmatched-prefix-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/dne/random.txt", ctx)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, "No namespace prefixes match found.", err.Error())
		assert.Equal(t, 0, len(result))
	})

	t.Run("unmatched-prefix-returns", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/dne/random.txt", ctx)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Equal(t, "No namespace prefixes match found.", err.Error())
		assert.Equal(t, 0, len(result))
	})

	t.Run("matched-prefixes-without-utils-returns-err", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.Error(t, err)
		assert.Empty(t, msg)
		assert.Contains(t, err.Error(), "Number of success response: 0 is less than MinStatRespons")
		require.NotNil(t, result)
		require.Equal(t, 0, len(result))
	})

	t.Run("matched-prefixes-with-max-1-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.NoError(t, err)
		// By default maxReq is set to 1. Therefore, although there's 2 matched prefixes,
		// only one will be returned
		assert.Contains(t, msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Equal(t, 1, len(result))
		assert.True(t, result[0].ServerAd.Name == "origin2" || result[0].ServerAd.Name == "origin3")
	})

	t.Run("matched-prefixes-with-max-2-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MaxStatResponse", 2)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.NoError(t, err)
		assert.Contains(t, msg, "Maximum responses reached for stat. Return result and cancel ongoing requests.")
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
		assert.True(t, result[0].ServerAd.Name == "origin2" || result[0].ServerAd.Name == "origin3")
		assert.True(t, result[1].ServerAd.Name == "origin2" || result[1].ServerAd.Name == "origin3")
	})

	t.Run("matched-prefixes-with-max-3-returns-response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		viper.Set("Director.MaxStatResponse", 3)
		defer viper.Set("Director.MaxStatResponse", 1)

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.NoError(t, err)
		// Response =2 < maxreq, so there won't be any message
		assert.Empty(t, msg)
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
		assert.True(t, result[0].ServerAd.Name == "origin2" || result[0].ServerAd.Name == "origin3")
		assert.True(t, result[1].ServerAd.Name == "origin2" || result[1].ServerAd.Name == "origin3")
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

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.Error(t, err)
		assert.Equal(t, "Number of success response: 2 is less than MinStatResponse (3) required.", err.Error())
		assert.Empty(t, msg)
		require.NotNil(t, result)
		require.Equal(t, 2, len(result))
	})

	t.Run("cancel-cancels-query", func(t *testing.T) {
		oldHandler := stat.ReqHandler
		defer func() {
			stat.ReqHandler = oldHandler
		}()

		stat.ReqHandler = func(objectName string, originAd common.ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
			time.Sleep(time.Second * 30)
			return &objectMetadata{ServerAd: originAd}, nil
		}

		ctx, cancel := context.WithCancel(context.Background())

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		msgChan := make(chan string)

		go func() {
			_, msg, _ := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)
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
					assert.True(t, false, "queryOriginsForObject timeout for response")
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

		stat.ReqHandler = func(objectName string, originAd common.ServerAd, timeout time.Duration, maxCancelCtx context.Context) (*objectMetadata, error) {
			if originAd.Name == "origin2" {
				return nil, timeoutError{}
			}
			if originAd.Name == "origin3" {
				return nil, notFoundError{}
			}
			return nil, errors.New("Default error")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		mockTTLCache()
		initMockStatUtils()
		defer cleanupMock()

		result, msg, err := stat.queryOriginsForObject("/foo/bar/test.txt", ctx)

		require.Error(t, err)
		assert.Equal(t, "Number of success response: 0 is less than MinStatResponse (1) required.", err.Error())
		assert.Empty(t, msg)
		require.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestSendHeadReqToOrigin(t *testing.T) {
	viper.Reset()

	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method == "HEAD" && req.URL.String() == "/foo/bar/test.txt" {
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

	mockOriginAd := common.ServerAd{Type: common.OriginType}
	mockOriginAd.URL = *realServerUrl

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	config.InitConfig()

	t.Run("correct-input-gives-no-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/test.txt", mockOriginAd, time.Second, ctx)
		require.NoError(t, err)
		assert.NotNil(t, meta)
	})

	t.Run("404-input-gives-404-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/dne", mockOriginAd, time.Second, ctx)
		require.Error(t, err)
		_, ok := err.(notFoundError)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/timeout.txt", mockOriginAd, 200*time.Millisecond, ctx)
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

		meta, err := stat.sendHeadReqToOrigin("/foo/bar/timeout.txt", mockOriginAd, 5*time.Second, ctx)

		require.Error(t, err)
		_, ok := err.(cancelledError)
		assert.True(t, ok)
		assert.Nil(t, meta)
	})

	t.Run("timeout-server-gives-timeout-error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		stat := NewObjectStat()

		defer cancel()
		meta, err := stat.sendHeadReqToOrigin("/foo/bar/error.txt", mockOriginAd, 200*time.Millisecond, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Unknown origin response with status code 500")
		assert.Nil(t, meta)
	})
}
