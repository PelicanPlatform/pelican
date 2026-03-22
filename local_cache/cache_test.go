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
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
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

// Setup a federation, invoke "get" through the persistent cache module
//
// The download is done twice -- once to verify functionality and once
// as a cache hit.
func TestFedPublicGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	// Use a separate temp directory for the test cache to avoid conflict with the one
	// started by NewFedTest's LaunchModules
	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	reader, err := pc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
	reader.Close()

	// Query again -- cache hit case
	reader, err = pc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)

	byteBuff, err = io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
	reader.Close()
}

// Test the persistent cache library on an authenticated GET.
func TestFedAuthGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, authOriginCfg)

	// Use a separate temp directory for the test cache
	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	reader, err := pc.Get(context.Background(), "/test/hello_world.txt", ft.Token)
	require.NoError(t, err)

	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(byteBuff))
	reader.Close()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Duration(time.Minute)
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/not_correct"))

	token, err := tokConf.CreateToken()
	require.NoError(t, err)

	_, err = pc.Get(context.Background(), "/test/hello_world.txt", token)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authorization denied")
}

// Test a raw HTTP request (no Pelican client) works with the local cache
func TestHttpReq(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
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

// Test startup when the local cache socket wasn't cleaned up.
//
// Ensure that the cache.sock existing doesn't prevent the local cache
// from starting up.
func TestDirtyStartup(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	socketPath := filepath.Join(t.TempDir(), "lc.s")
	sock, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer func() {
		sock.Close()
		_ = os.Remove(socketPath)
	}()

	cfg := authOriginCfg
	cfg += "\n\nLocalCache:\n  Socket: \"" + socketPath + "\"\n"
	ft := fed_test_utils.NewFedTest(t, cfg)

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
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
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
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/no_such_file"))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
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
		var pde *client.PermissionDeniedError
		assert.True(t, errors.As(err, &pde))
		if pde != nil {
			assert.Contains(t, pde.Error(), "token could not be parsed")
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
		tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/hello_world.txt.1"))

		token, err := tokConf.CreateToken()
		require.NoError(t, err)

		_, err = client.DoGet(ctx, "pelican://"+param.Server_Hostname.GetString()+":"+strconv.Itoa(param.Server_WebPort.GetInt())+"/test/hello_world.txt.1",
			filepath.Join(tmpDir, "hello_world.txt.1"), false, client.WithToken(token), client.WithCaches(cacheUrl), client.WithAcquireToken(false))
		require.Error(t, err)
		// TODO (bbockelm, 10-Jan-2025): It's surprising that the `client.DoGet` above is querying the director then the local cache.
		// It seems like, in the local cache case, we should skip any director queries.
		// See description in https://github.com/PelicanPlatform/pelican/issues/1929
		assert.Contains(t, err.Error(), fmt.Sprintf("%d", http.StatusNotFound))
	})
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled && err != http.ErrServerClosed {
			require.NoError(t, err)
		}
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()
	})
}

// Test that HEAD requests to the persistent cache return the correct result
func TestStat(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	// Use a separate temp directory for the test cache
	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	size, err := pc.Stat("/test/hello_world.txt", "")
	require.NoError(t, err)
	assert.Equal(t, uint64(13), size)

	reader, err := pc.Get(context.Background(), "/test/hello_world.txt", "")
	require.NoError(t, err)
	byteBuff, err := io.ReadAll(reader)
	assert.NoError(t, err)
	assert.Equal(t, 13, len(byteBuff))
	reader.Close()

	size, err = pc.Stat("/test/hello_world.txt", "")
	assert.NoError(t, err)
	assert.Equal(t, uint64(13), size)
}

// Create a 100MB file in the origin.  Download it (slowly) via the local cache.
//
// This triggers multiple internal requests to wait on the slow download
func TestLargeFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tmpDir := t.TempDir()

	server_utils.ResetTestState()

	clientConfig := map[param.Param]any{
		param.Client_MaximumDownloadSpeed:     40 * 1024 * 1024,
		param.Transport_ResponseHeaderTimeout: "60s",
	}
	test_utils.InitClient(t, clientConfig)
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
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()
	})
}

// Test that Range: bytes=0-0 on a multi-block object downloads ONLY the
// first block, never completes the full file download, and therefore does
// NOT return an Age header (which requires Completed != zero).
func TestRangeZeroZero(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	// Create a multi-block file.  With BlockDataSize=4080, a 20 000-byte
	// file spans 5 blocks (well above InlineThreshold=4096), so the cache
	// will use disk storage.
	const fileSize = 20_000
	data := make([]byte, fileSize)
	for i := range data {
		data[i] = byte(i % 251) // deterministic, non-zero pattern
	}
	err := os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, "multiblock.bin"), data, 0644)
	require.NoError(t, err)

	// Build an HTTP client that talks to the local cache via its unix socket
	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	t.Run("FirstRequestNoAge", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/multiblock.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", "bytes=0-0")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusPartialContent, resp.StatusCode, "expected 206 Partial Content")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, 1, len(body), "expected exactly 1 byte")
		assert.Equal(t, data[0], body[0], "first byte should match source data")
		assert.Empty(t, resp.Header.Get("Age"), "Age must not be set when download is incomplete")
	})

	t.Run("SecondRequestStillNoAge", func(t *testing.T) {
		// This is a cache-hit for block 0, but the remaining blocks
		// were never fetched so Completed stays zero → no Age.
		req, err := http.NewRequest("GET", "http://localhost/test/multiblock.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", "bytes=0-0")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusPartialContent, resp.StatusCode, "expected 206 Partial Content")
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, 1, len(body), "expected exactly 1 byte")
		assert.Equal(t, data[0], body[0], "first byte should match source data")
		assert.Empty(t, resp.Header.Get("Age"), "Age must not be set on repeat range request for incomplete object")
	})
}

// TestFedConcurrentDownloadUsage starts 10 simultaneous downloads of 10
// different objects through the persistent cache v2 (Cache.EnableV2=true)
// using the pelican TransferClient API and verifies that the usage counters
// reflect the actual bytes stored — not an inflated value.
//
// This reproduces the production bug where concurrent downloads could
// inflate the usage counter to ~4.2 TB.
func TestFedConcurrentDownloadUsage(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	const numObjects = 10
	const objectSize = 2*1024*1024 + 37 // 2 MiB + 37 bytes (odd size)

	// Enable the persistent cache v2 so the cache module uses the new
	// Go implementation (BadgerDB) instead of XRootD.
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Pre-populate the origin with numObjects files before XRootD starts.
	names := make([]string, numObjects)
	for i := range names {
		names[i] = fmt.Sprintf("concurrent_%02d.bin", i)
	}
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg, func(storageDir string) {
		for _, name := range names {
			f, err := os.Create(filepath.Join(storageDir, name))
			require.NoError(t, err)
			buf := make([]byte, 128*1024)
			for j := range buf {
				buf[j] = byte(j % 251)
			}
			written := 0
			for written < objectSize {
				toWrite := len(buf)
				if written+toWrite > objectSize {
					toWrite = objectSize - written
				}
				n, err := f.Write(buf[:toWrite])
				require.NoError(t, err)
				written += n
			}
			require.NoError(t, f.Close())
		}
	})

	ctx := ft.Ctx

	// Create a single TransferEngine + TransferClient and submit all
	// jobs through it, matching how production submits concurrent work.
	te, err := client.NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
	}()

	tc, err := te.NewClient(client.WithAcquireToken(false))
	require.NoError(t, err)

	// Create and submit all transfer jobs before waiting for any results.
	// The director routes these to the persistent cache v2 automatically.
	tmpDir := t.TempDir()
	for _, name := range names {
		downloadUrl, err := url.Parse("pelican://" + param.Server_Hostname.GetString() + ":" +
			strconv.Itoa(param.Server_WebPort.GetInt()) + "/test/" + name)
		require.NoError(t, err)
		tj, err := tc.NewTransferJob(ctx, downloadUrl, filepath.Join(tmpDir, name), false, false)
		require.NoError(t, err)
		err = tc.Submit(tj)
		require.NoError(t, err)
	}

	// Wait for all jobs to complete
	results, err := tc.Shutdown()
	require.NoError(t, err)
	require.Equal(t, numObjects, len(results), "expected %d transfer results", numObjects)
	for _, r := range results {
		require.NoError(t, r.Error, "transfer failed")
		require.Equal(t, int64(objectSize), r.TransferredBytes, "wrong transferred size")
	}

	// Query cache stats via the HTTP API
	statsUrl := fmt.Sprintf("https://%s:%d/api/v1.0/cache/stats",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	transport := config.GetTransport().Clone()
	httpClient := &http.Client{Transport: transport}
	resp, err := httpClient.Get(statsUrl)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var stats local_cache.PersistentCacheStats
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(body, &stats)
	require.NoError(t, err)

	// Verify usage counters are NOT inflated.
	// Usage tracks actual on-disk bytes: content + 16-byte AES-GCM
	// authentication tag per 4080-byte payload block.
	expectedPerObject := local_cache.CalculateFileSize(int64(objectSize))
	expectedTotal := int64(numObjects) * expectedPerObject

	require.NotEmpty(t, stats.NamespaceUsage, "usage counters should not be empty")

	// Find the namespace entry for our test objects.  The director may
	// also cache a small health-test file under /pelican/monitoring,
	// which lives in a different namespace.  Select the entry whose
	// value matches the expected total for the /test namespace.
	var testNSUsage int64
	for _, v := range stats.NamespaceUsage {
		if v == expectedTotal {
			testNSUsage = v
			break
		}
	}
	assert.Equal(t, expectedTotal, testNSUsage,
		"usage for /test namespace should equal %d (got %d; ratio %.3fx)",
		expectedTotal, testNSUsage, float64(testNSUsage)/float64(expectedTotal))
}

// TestFedDiskUsageAccuracy downloads a 2MB+ file through the cache using a
// POSIX origin (xrootd, which always uses chunked encoding) and then verifies
// that the introspection API reports the correct on-disk size.  This catches
// bugs where usage counters drift (e.g. the SetUsage/AddUsage compounding
// issue) and ensures chunked-encoding downloads are tracked correctly.
func TestFedDiskUsageAccuracy(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	const testFileSize = 2*1024*1024 + 37 // 2 MiB + 37 bytes (odd size to exercise partial last block)
	const testFileName = "large_test_data.bin"

	// Create a 2MB+ file in the origin's storage directory before xrootd starts.
	ft := fed_test_utils.NewFedTest(t, pubOriginCfg, func(storageDir string) {
		f, err := os.Create(filepath.Join(storageDir, testFileName))
		require.NoError(t, err)
		defer f.Close()

		// Write deterministic data: repeating byte pattern
		buf := make([]byte, 32*1024)
		for i := range buf {
			buf[i] = byte(i % 251)
		}
		written := 0
		for written < testFileSize {
			toWrite := len(buf)
			if written+toWrite > testFileSize {
				toWrite = testFileSize - written
			}
			n, err := f.Write(buf[:toWrite])
			require.NoError(t, err)
			written += n
		}
	})

	// Use a separate temp directory for the test cache
	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	// Close before t.TempDir's cleanup removes the directory (defer runs
	// before t.Cleanup, so BadgerDB can flush while the dir still exists).
	defer pc.Close()

	// Download the file through the persistent cache
	reader, err := pc.Get(context.Background(), "/test/"+testFileName, "")
	require.NoError(t, err)

	// Read the full body to trigger all blocks to be downloaded and stored
	byteBuff, err := io.ReadAll(reader)
	require.NoError(t, err)
	reader.Close()
	require.Equal(t, testFileSize, len(byteBuff), "downloaded file size must match source")

	// Verify content integrity (spot-check first few bytes)
	for i := 0; i < 251 && i < len(byteBuff); i++ {
		require.Equal(t, byte(i%251), byteBuff[i], "content mismatch at byte %d", i)
	}

	// Query cache stats while the cache is still open
	stats, err := pc.GetCacheStats()
	require.NoError(t, err)

	// --- Verify metadata-based stats ---
	assert.Equal(t, int64(1), stats.TotalMetadataEntries, "should have exactly 1 cached object")
	assert.Equal(t, int64(testFileSize), stats.TotalBytesMetadata,
		"total bytes from metadata should equal the source file size")

	// The object is >4KB so it should be stored on disk, not inline
	assert.Equal(t, int64(0), stats.TotalInlineBytes, "no data should be inline for a 2MB object")

	// Check storage breakdown: should have exactly one storage dir with 1 on-disk object
	require.NotEmpty(t, stats.StorageBreakdown, "storage breakdown should not be empty")
	var foundDisk bool
	for _, ds := range stats.StorageBreakdown {
		if ds.OnDiskCount > 0 {
			foundDisk = true
			assert.Equal(t, int64(1), ds.OnDiskCount, "should have exactly 1 on-disk object")
			assert.Equal(t, local_cache.CalculateFileSize(int64(testFileSize)), ds.OnDiskBytes,
				"on-disk bytes should match the actual file size (content + MAC overhead)")
			assert.Equal(t, int64(0), ds.InlineCount, "no inline objects expected")
			assert.Equal(t, int64(0), ds.InlineBytes, "no inline bytes expected")
		}
	}
	assert.True(t, foundDisk, "should have at least one storage dir with on-disk data")

	// --- Verify usage counters ---
	// The usage counter for this storage+namespace should match the
	// actual on-disk size (content + per-block MAC overhead), NOT be
	// inflated to terabytes (which was the bug these fixes address).
	require.NotEmpty(t, stats.UsageCounters, "usage counters should not be empty")
	var totalUsage int64
	for _, v := range stats.UsageCounters {
		totalUsage += v
	}
	assert.Equal(t, local_cache.CalculateFileSize(int64(testFileSize)), totalUsage,
		"usage counter total should equal the on-disk file size")
}

// Create a federation then SIGSTOP the origin to prevent it from responding.
// Ensure the various client timeouts are reported correctly up to the user
func TestOriginUnresponsive(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tmpDir := t.TempDir()

	server_utils.ResetTestState()
	require.NoError(t, param.Transport_ResponseHeaderTimeout.SetString("5s"))
	require.NoError(t, param.Logging_Level.Set("debug"))
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
	// Check that it's a timeout error - can be either a PelicanError with timeout code
	// or a HeaderTimeoutError underneath
	var pe *error_codes.PelicanError
	var hte *client.HeaderTimeoutError
	isTimeout := errors.As(err, &pe) && (pe.Code() == 6004 || pe.Code() == 6003) || errors.As(err, &hte)
	assert.True(t, isTimeout, "expected a timeout error, got: %v", err)
	require.Equal(t, 0, len(tr))
}
