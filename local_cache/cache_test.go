//go:build !windows

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

package local_cache_test

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/public-origin-cfg.yml
	pubOriginCfg string

	//go:embed resources/auth-origin-cfg.yml
	authOriginCfg string
)

// Setup a federation, invoke "get" through the local cache module
//
// The download is done twice -- once to verify functionality and once
// as a cache hit.
func TestFedPublicGet(t *testing.T) {
	viper.Reset()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	lc, err := local_cache.NewLocalCache(ft.Ctx, ft.Egrp)
	require.NoError(t, err)

	reader, err := lc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	// Query again -- cache hit case
	reader, err = lc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)

	assert.Equal(t, "*os.File", fmt.Sprintf("%T", reader))
	byteBuff, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
}

// Test the local cache library on an authenticated GET.
func TestFedAuthGet(t *testing.T) {
	viper.Reset()
	ft := fed_test_utils.NewFedTest(t, authOriginCfg)

	lc, err := local_cache.NewLocalCache(ft.Ctx, ft.Egrp)
	require.NoError(t, err)

	reader, err := lc.Get(context.Background(), "/test/hello_world.txt", ft.Token)
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Duration(time.Minute)
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/not_correct"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	_, err = lc.Get(context.Background(), "/test/hello_world.txt", token)
	assert.Error(t, err)
	assert.Equal(t, "authorization denied", err.Error())
}

// Test a raw HTTP request (no Pelican client) works with the local cache
func TestHttpReq(t *testing.T) {
	viper.Reset()
	ft := fed_test_utils.NewFedTest(t, authOriginCfg)

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}

	client := &http.Client{Transport: transport}
	req, err := http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+ft.Token)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(body))
}

// Test a raw HTTP request (no Pelican client) returns a 404 for an unknown object
func TestHttpFailures(t *testing.T) {
	viper.Reset()
	fed_test_utils.NewFedTest(t, authOriginCfg)

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Duration(time.Minute)
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/no_such_file"))
	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	client := &http.Client{Transport: transport}

	t.Run("Test404", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/no_such_file", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Test403", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/no_permission", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// Test that the client library (with authentication) works with the local cache
func TestClient(t *testing.T) {
	viper.Reset()
	ft := fed_test_utils.NewFedTest(t, authOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	cacheUrl2 := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	invalidCacheUrl := &url.URL{
		Scheme: "unix",
		Path:   "/this/path/does/not/exist/abc1234/foo/bar/baz",
	}

	t.Run("correct-auth", func(t *testing.T) {
		tmpDir := t.TempDir()
		tr, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
			filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken(ft.Token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(13), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)

		byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(byteBuff))

		// Assert our endpoint is the local cache (we should only have 1 transferResult and 1 attempt since only 1 cache listed)
		assert.Equal(t, tr[0].Attempts[0].Endpoint, cacheUrl.Host)
	})

	t.Run("incorrect-auth", func(t *testing.T) {
		tmpDir := t.TempDir()
		_, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
			filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken("badtoken"), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.Error(t, err)
		var sce *client.StatusCodeError
		assert.True(t, errors.As(err, &sce))
		if sce != nil {
			assert.Equal(t, int(*sce), http.StatusForbidden)
		}
	})

	// Test the local cache works with the client when multiple are specified
	t.Run("multi-caches", func(t *testing.T) {
		tmpDir := t.TempDir()
		cacheList := []*url.URL{cacheUrl, cacheUrl2}
		tr, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
			filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken(ft.Token), client.WithCaches(cacheList...), client.WithAcquireToken(false))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(13), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)

		byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(byteBuff))

		// Assert our endpoint is the local cache (we should only have 1 transferResult and 1 attempt since only 1 cache listed)
		assert.Equal(t, tr[0].Attempts[0].Endpoint, cacheUrl.Host)
	})

	// Test the local cache works with '+' specified (append normal list of caches as well) and that we match with the local cache
	t.Run("append-caches-hit-local-cache", func(t *testing.T) {
		tmpDir := t.TempDir()
		plusCache := &url.URL{Path: "+"}
		cacheList := []*url.URL{cacheUrl, plusCache}
		tr, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
			filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken(ft.Token), client.WithCaches(cacheList...), client.WithAcquireToken(false))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(13), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)

		byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(byteBuff))

		// Assert our endpoint is the local cache
		assert.Equal(t, tr[0].Attempts[0].Endpoint, cacheUrl.Host)
	})

	// Test the local cache works with '+' specified (append normal list of caches as well) and that we match with our fed cache when local cache fails
	t.Run("append-caches-hit-appended-cache", func(t *testing.T) {
		tmpDir := t.TempDir()
		plusCache := &url.URL{Path: "+"}
		cacheList := []*url.URL{invalidCacheUrl, plusCache}
		tr, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
			filepath.Join(tmpDir, "hello_world.txt"), false, client.WithToken(ft.Token), client.WithCaches(cacheList...), client.WithAcquireToken(false))
		assert.NoError(t, err)
		require.Equal(t, 1, len(tr))
		assert.Equal(t, int64(13), tr[0].TransferredBytes)
		assert.NoError(t, tr[0].Error)

		// Check that we still successfully downloaded the file
		byteBuff, err := os.ReadFile(filepath.Join(tmpDir, "hello_world.txt"))
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(byteBuff))

		// Check that the file was written to the fed cache by checking our endpoint
		hitAppendedCache := false
		cacheEndpointUrl, err := url.Parse(param.Cache_Url.GetString())
		require.NoError(t, err)
		cacheEndpoint := cacheEndpointUrl.Host

		// We will have multiple attempts since the first attempt towards local cache will fail
		for _, attempt := range tr[0].Attempts {
			// If the endpoint is our faulty cache, ensure we have an error
			if attempt.Endpoint == invalidCacheUrl.Host {
				assert.NotNil(t, attempt.Error)
			} else if attempt.Endpoint == cacheEndpoint {
				hitAppendedCache = true
				assert.Nil(t, attempt.Error)
			}
		}
		assert.True(t, hitAppendedCache)
	})

	t.Run("file-not-found", func(t *testing.T) {
		tmpDir := t.TempDir()
		issuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)
		tokConf := token.NewWLCGToken()

		tokConf.Lifetime = time.Duration(time.Minute)
		tokConf.Issuer = issuer
		tokConf.Subject = "test"
		tokConf.AddAudienceAny()
		tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/hello_world.txt.1"))

		token, err := tokConf.CreateToken()
		require.NoError(t, err)

		_, err = client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt.1",
			filepath.Join(tmpDir, "hello_world.txt.1"), false, client.WithToken(token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		assert.Error(t, err)
		assert.Equal(t, "failed download from local-cache: server returned 404 Not Found", err.Error())
	})
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// Test that HEAD requests to the local cache return the correct result
func TestStat(t *testing.T) {
	viper.Reset()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	lc, err := local_cache.NewLocalCache(ft.Ctx, ft.Egrp)
	require.NoError(t, err)

	size, err := lc.Stat("/test/hello_world.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(13), size)

	reader, err := lc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)
	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(byteBuff))

	size, err = lc.Stat("/test/hello_world.txt", "")
	assert.NoError(t, err)
	assert.Equal(t, uint64(13), size)
}

// Create a 100MB file in the origin.  Download it (slowly) via the local cache.
//
// This triggers multiple internal requests to wait on the slow download
func TestLargeFile(t *testing.T) {
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Client.MaximumDownloadSpeed", 40*1024*1024)
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, "hello_world.txt"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	require.NoError(t, err)
	size := test_utils.WriteBigBuffer(t, fp, 100)

	require.NoError(t, err)
	tr, err := client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt",
		filepath.Join(tmpDir, "hello_world.txt"), false, client.WithCaches(cacheUrl))
	assert.NoError(t, err)
	require.Equal(t, 1, len(tr))
	assert.Equal(t, int64(size), tr[0].TransferredBytes)
	assert.NoError(t, tr[0].Error)

	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})

}

// Create a federation then SIGSTOP the origin to prevent it from responding.
// Ensure the various client timeouts are reported correctly up to the user
func TestOriginUnresponsive(t *testing.T) {
	tmpDir := t.TempDir()

	viper.Reset()
	viper.Set("Transport.ResponseHeaderTimeout", "2s")
	viper.Set("Logging.Level", "debug")
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	cacheUrl := &url.URL{
		Scheme: "unix",
		Path:   param.LocalCache_Socket.GetString(),
	}

	// SIGSTOP the xrootd process so it doesn't respond to the client
	for _, pid := range ft.Pids {
		err := syscall.Kill(pid, syscall.SIGSTOP)
		require.NoError(t, err)
	}

	fp, err := os.OpenFile(filepath.Join(ft.Exports[0].StoragePrefix, "hello_world.txt"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	require.NoError(t, err)
	test_utils.WriteBigBuffer(t, fp, 1)

	downloadUrl := fmt.Sprintf("pelican://%s:%s%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
		ft.Exports[0].FederationPrefix, "hello_world.txt")

	tr, err := client.DoGet(ft.Ctx, downloadUrl, filepath.Join(tmpDir, "hello_world.txt"), false,
		client.WithCaches(cacheUrl))
	assert.Error(t, err)
	var sce *client.StatusCodeError
	assert.True(t, errors.As(err, &sce))
	if sce != nil {
		assert.Equal(t, int(*sce), 504)
	}
	require.Equal(t, 0, len(tr))
}
