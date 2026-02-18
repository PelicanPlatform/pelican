//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestStatAPI tests the Stat/StatCachedOnly API methods on PersistentCache.
func TestStatAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	t.Run("stat-before-download-queries-origin", func(t *testing.T) {
		// Stat on an uncached object should query the origin and return the size
		size, err := pc.Stat("/test/hello_world.txt", "")
		require.NoError(t, err)
		assert.Equal(t, uint64(13), size) // "Hello, World!" is 13 bytes
	})

	t.Run("stat-cached-only-miss", func(t *testing.T) {
		// A new file that hasn't been downloaded yet
		require.NoError(t, os.WriteFile(
			filepath.Join(ft.Exports[0].StoragePrefix, "stat_miss.txt"),
			[]byte("uncached content"),
			0644,
		))

		_, err := pc.StatCachedOnly("/test/stat_miss.txt", "")
		assert.ErrorIs(t, err, local_cache.ErrNotCached)
	})

	t.Run("stat-after-download-uses-cache", func(t *testing.T) {
		// Download the object first
		reader, err := pc.Get(context.Background(), "/test/hello_world.txt", "")
		require.NoError(t, err)
		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		reader.Close()
		assert.Equal(t, "Hello, World!", string(data))

		// Now StatCachedOnly should find it
		size, err := pc.StatCachedOnly("/test/hello_world.txt", "")
		require.NoError(t, err)
		assert.Equal(t, uint64(13), size)
	})

	t.Run("stat-nonexistent-file", func(t *testing.T) {
		_, err := pc.Stat("/test/no_such_file_12345.txt", "")
		assert.Error(t, err)
	})
}

// TestStatHTTP tests HEAD requests to the cache's Unix socket listener.
func TestStatHTTP(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	t.Run("head-does-not-download", func(t *testing.T) {
		// A HEAD request should query the origin for metadata (size)
		// but must NOT trigger a download or cache the object.
		req, err := http.NewRequest("HEAD", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "13", resp.Header.Get("Content-Length"))
		assert.Contains(t, resp.Header.Get("Accept-Ranges"), "bytes")

		// Verify the object was NOT cached — only stat'd.
		testCacheDir := t.TempDir()
		pc, pcErr := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
			BaseDir: testCacheDir,
		})
		require.NoError(t, pcErr)
		defer pc.Close()

		_, statErr := pc.StatCachedOnly("/test/hello_world.txt", "")
		assert.ErrorIs(t, statErr, local_cache.ErrNotCached,
			"HEAD should not have cached the object")
	})

	t.Run("only-if-cached-head-miss", func(t *testing.T) {
		// Create a file at the origin but don't download it
		require.NoError(t, os.WriteFile(
			filepath.Join(ft.Exports[0].StoragePrefix, "head_miss.txt"),
			[]byte("not cached yet"),
			0644,
		))

		req, err := http.NewRequest("HEAD", "http://localhost/test/head_miss.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Cache-Control", "only-if-cached")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// RFC 7234 §5.2.1.7: 504 Gateway Timeout when not cached
		assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	})

	t.Run("only-if-cached-head-hit", func(t *testing.T) {
		// First, download the object via GET
		req, err := http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// HEAD with only-if-cached should hit the cache
		req, err = http.NewRequest("HEAD", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Cache-Control", "only-if-cached")

		resp, err = httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "13", resp.Header.Get("Content-Length"))
	})

	t.Run("only-if-cached-get-miss", func(t *testing.T) {
		// GET with only-if-cached for an uncached object returns 504
		req, err := http.NewRequest("GET", "http://localhost/test/head_miss.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Cache-Control", "only-if-cached")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	})

	t.Run("only-if-cached-get-hit", func(t *testing.T) {
		// hello_world.txt was cached by the head-hit subtest above;
		// GET with only-if-cached should return the cached data.
		req, err := http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Cache-Control", "only-if-cached")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(body))
	})

	t.Run("head-returns-cache-control", func(t *testing.T) {
		// HEAD response should include a Cache-Control header
		req, err := http.NewRequest("HEAD", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		// The cache always sets a Cache-Control header (either from origin or default)
		assert.NotEmpty(t, resp.Header.Get("Cache-Control"))
	})

	t.Run("age-header-increases-with-time", func(t *testing.T) {
		// hello_world.txt was cached by a previous subtest. We need the
		// Age header (integer seconds since caching) to become non-zero.
		// Wait just over 1 second — this is not an arbitrary sleep waiting
		// for an async condition; it is waiting for real time to elapse so
		// the Age measurement (whose granularity is 1 s) becomes non-zero.
		time.Sleep(1100 * time.Millisecond)

		// HEAD should now report Age ≥ 1
		req, err := http.NewRequest("HEAD", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		ageStr := resp.Header.Get("Age")
		require.NotEmpty(t, ageStr, "Age header must be present after data has aged")
		ageVal, convErr := strconv.Atoi(ageStr)
		require.NoError(t, convErr)
		assert.GreaterOrEqual(t, ageVal, 1, "Age should be at least 1 second")

		// GET should also carry the Age header
		req, err = http.NewRequest("GET", "http://localhost/test/hello_world.txt", nil)
		require.NoError(t, err)

		resp, err = httpClient.Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		ageStr = resp.Header.Get("Age")
		require.NotEmpty(t, ageStr, "GET response must include Age header")
		ageVal, convErr = strconv.Atoi(ageStr)
		require.NoError(t, convErr)
		assert.GreaterOrEqual(t, ageVal, 1, "GET Age should be at least 1 second")
	})
}

// pubOriginListingsCfg is like pubOriginCfg but adds the Listings capability
// so that PROPFIND requests can be served by the origin.
var pubOriginListingsCfg = `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "DirectReads", "Listings"]
`

// TestPropfindPassthrough tests that PROPFIND requests are proxied to the origin
// and that directory listings are NOT cached.
func TestPropfindPassthrough(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginListingsCfg)

	// Create some files at the origin for the directory listing
	require.NoError(t, os.WriteFile(
		filepath.Join(ft.Exports[0].StoragePrefix, "propfind_a.txt"),
		[]byte("file A"),
		0644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(ft.Exports[0].StoragePrefix, "propfind_b.txt"),
		[]byte("file B content"),
		0644,
	))

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	t.Run("propfind-returns-listing", func(t *testing.T) {
		req, err := http.NewRequest("PROPFIND", "http://localhost/test/", nil)
		require.NoError(t, err)
		req.Header.Set("Depth", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// PROPFIND should return 207 Multi-Status from the origin
		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// The listing should reference the files we created
		assert.True(t, strings.Contains(bodyStr, "hello_world.txt"),
			"listing should contain hello_world.txt, got: %s", bodyStr)
		assert.True(t, strings.Contains(bodyStr, "propfind_a.txt"),
			"listing should contain propfind_a.txt, got: %s", bodyStr)
		assert.True(t, strings.Contains(bodyStr, "propfind_b.txt"),
			"listing should contain propfind_b.txt, got: %s", bodyStr)
	})

	t.Run("propfind-not-cached", func(t *testing.T) {
		// After PROPFIND, the directory listing should NOT be in the cache.
		// HEAD with only-if-cached for the directory should return 504.
		req, err := http.NewRequest("HEAD", "http://localhost/test/", nil)
		require.NoError(t, err)
		req.Header.Set("Cache-Control", "only-if-cached")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Directories aren't cached objects → 504 per RFC 7234
		assert.Equal(t, http.StatusGatewayTimeout, resp.StatusCode)
	})

	t.Run("propfind-single-file", func(t *testing.T) {
		// PROPFIND on a single file (Depth: 0) should return that file's properties
		req, err := http.NewRequest("PROPFIND", "http://localhost/test/propfind_a.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Depth", "0")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// Should reference the file
		assert.True(t, strings.Contains(bodyStr, "propfind_a.txt"),
			"single-file PROPFIND should reference propfind_a.txt, got: %s", bodyStr)
	})

	t.Run("propfind-new-file-shows-immediately", func(t *testing.T) {
		// Create a new file at the origin
		require.NoError(t, os.WriteFile(
			filepath.Join(ft.Exports[0].StoragePrefix, "propfind_new.txt"),
			[]byte("brand new"),
			0644,
		))

		// PROPFIND should immediately show the new file because
		// listings are always proxied to the origin, never cached
		req, err := http.NewRequest("PROPFIND", "http://localhost/test/", nil)
		require.NoError(t, err)
		req.Header.Set("Depth", "1")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.True(t, strings.Contains(string(body), "propfind_new.txt"),
			"new file should appear in listing immediately")
	})
}

// TestStatLargeFile tests that Stat works correctly for a file larger than the
// inline threshold, which exercises the disk-mode storage path.
func TestStatLargeFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	// Create a 1 MB file
	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "stat_large.bin")
	fp, err := os.OpenFile(originPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	require.NoError(t, err)
	size := test_utils.WriteBigBuffer(t, fp, 1) // 1 MB

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	t.Run("stat-before-download", func(t *testing.T) {
		gotSize, err := pc.Stat("/test/stat_large.bin", "")
		require.NoError(t, err)
		assert.Equal(t, uint64(size), gotSize)
	})

	t.Run("stat-after-download", func(t *testing.T) {
		// Download the object via the HTTP handler (Unix socket) which
		// uses GetSeekableReader and handles on-demand block fetching.
		// The direct pc.Get() API for disk-mode files returns an
		// ObjectReader that expects all blocks already present.
		transport := config.GetTransport().Clone()
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", param.LocalCache_Socket.GetString())
		}
		httpClient := &http.Client{Transport: transport}

		req, err := http.NewRequest("GET", "http://localhost/test/stat_large.bin", nil)
		require.NoError(t, err)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		n, err := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, int64(size), n)

		gotSize, err := pc.Stat("/test/stat_large.bin", "")
		require.NoError(t, err)
		assert.Equal(t, uint64(size), gotSize)
	})

	t.Run("http-head-content-length", func(t *testing.T) {
		transport := config.GetTransport().Clone()
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", param.LocalCache_Socket.GetString())
		}
		httpClient := &http.Client{Transport: transport}

		req, err := http.NewRequest("HEAD", "http://localhost/test/stat_large.bin", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, strconv.Itoa(size), resp.Header.Get("Content-Length"))
	})
}
