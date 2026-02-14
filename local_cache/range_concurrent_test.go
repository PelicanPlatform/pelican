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
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	local_cache "github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestConcurrentRangeReads spawns many goroutines that each request a different
// byte range of the same large file via the cache's Unix socket.  This exercises
// concurrent block fetching, shared block state, and the on-demand fetch path.
func TestConcurrentRangeReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	// Create a 5 MB file at the origin (large enough for many blocks)
	const fileSize = 5 * 1024 * 1024
	originData := make([]byte, fileSize)
	_, err := rand.Read(originData)
	require.NoError(t, err)

	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "concurrent_range.bin")
	require.NoError(t, os.WriteFile(originPath, originData, 0644))

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	// Define diverse ranges: small, large, overlapping, suffix, open-ended
	type rangeSpec struct {
		name  string
		start int64
		end   int64
	}

	ranges := []rangeSpec{
		{"first-4k", 0, 4095},
		{"second-4k", 4096, 8191},
		{"cross-block-1", 4000, 8200},
		{"mid-64k", fileSize / 2, fileSize/2 + 65535},
		{"last-1k", fileSize - 1024, fileSize - 1},
		{"first-byte", 0, 0},
		{"last-byte", fileSize - 1, fileSize - 1},
		{"large-1mb", 1024 * 1024, 2*1024*1024 - 1},
		{"cross-block-2", 100000, 200000},
		{"near-end", fileSize - 65536, fileSize - 1},
	}

	const concurrency = 5 // Number of parallel goroutines per range

	var wg sync.WaitGroup
	errChan := make(chan error, len(ranges)*concurrency)

	for _, rs := range ranges {
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(rs rangeSpec, workerID int) {
				defer wg.Done()

				req, reqErr := http.NewRequest("GET", "http://localhost/test/concurrent_range.bin", nil)
				if reqErr != nil {
					errChan <- fmt.Errorf("[%s/%d] create request: %w", rs.name, workerID, reqErr)
					return
				}
				req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", rs.start, rs.end))

				resp, doErr := httpClient.Do(req)
				if doErr != nil {
					errChan <- fmt.Errorf("[%s/%d] do request: %w", rs.name, workerID, doErr)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusPartialContent {
					errChan <- fmt.Errorf("[%s/%d] expected 206, got %d", rs.name, workerID, resp.StatusCode)
					return
				}

				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					errChan <- fmt.Errorf("[%s/%d] read body: %w", rs.name, workerID, readErr)
					return
				}

				expected := originData[rs.start : rs.end+1]
				if len(body) != len(expected) {
					errChan <- fmt.Errorf("[%s/%d] length mismatch: got %d, want %d",
						rs.name, workerID, len(body), len(expected))
					return
				}

				for j := range body {
					if body[j] != expected[j] {
						errChan <- fmt.Errorf("[%s/%d] data mismatch at offset %d: got %02x, want %02x",
							rs.name, workerID, j, body[j], expected[j])
						return
					}
				}
			}(rs, i)
		}
	}

	wg.Wait()
	close(errChan)

	for e := range errChan {
		t.Error(e)
	}
}

// TestConcurrentFullAndRangeReads issues full-file GETs and range GETs simultaneously
// for the same object.  This stresses the interaction between the background download
// (full file) and on-demand block fetching (range readers).
func TestConcurrentFullAndRangeReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	const fileSize = 2 * 1024 * 1024
	originData := make([]byte, fileSize)
	_, err := rand.Read(originData)
	require.NoError(t, err)

	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "mixed_rw.bin")
	require.NoError(t, os.WriteFile(originPath, originData, 0644))

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	var wg sync.WaitGroup
	errChan := make(chan error, 20)

	// Spawn 3 full-file readers
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			req, reqErr := http.NewRequest("GET", "http://localhost/test/mixed_rw.bin", nil)
			if reqErr != nil {
				errChan <- fmt.Errorf("[full/%d] create request: %w", workerID, reqErr)
				return
			}

			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				errChan <- fmt.Errorf("[full/%d] do request: %w", workerID, doErr)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				errChan <- fmt.Errorf("[full/%d] expected 200, got %d", workerID, resp.StatusCode)
				return
			}

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				errChan <- fmt.Errorf("[full/%d] read body: %w", workerID, readErr)
				return
			}

			if len(body) != fileSize {
				errChan <- fmt.Errorf("[full/%d] length mismatch: got %d, want %d",
					workerID, len(body), fileSize)
				return
			}

			for j := range body {
				if body[j] != originData[j] {
					errChan <- fmt.Errorf("[full/%d] data mismatch at offset %d", workerID, j)
					return
				}
			}
		}(i)
	}

	// Spawn 5 range readers targeting scattered parts of the file
	rangeStarts := []int64{0, 100000, 500000, 1000000, fileSize - 8192}
	for i, start := range rangeStarts {
		wg.Add(1)
		go func(workerID int, start int64) {
			defer wg.Done()

			end := start + 8191
			if end >= fileSize {
				end = fileSize - 1
			}

			req, reqErr := http.NewRequest("GET", "http://localhost/test/mixed_rw.bin", nil)
			if reqErr != nil {
				errChan <- fmt.Errorf("[range/%d] create request: %w", workerID, reqErr)
				return
			}
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))

			resp, doErr := httpClient.Do(req)
			if doErr != nil {
				errChan <- fmt.Errorf("[range/%d] do request: %w", workerID, doErr)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusPartialContent {
				errChan <- fmt.Errorf("[range/%d] expected 206, got %d", workerID, resp.StatusCode)
				return
			}

			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				errChan <- fmt.Errorf("[range/%d] read body: %w", workerID, readErr)
				return
			}

			expected := originData[start : end+1]
			if len(body) != len(expected) {
				errChan <- fmt.Errorf("[range/%d] length mismatch: got %d, want %d",
					workerID, len(body), len(expected))
				return
			}

			for j := range body {
				if body[j] != expected[j] {
					errChan <- fmt.Errorf("[range/%d] data mismatch at offset %d", workerID, j)
					return
				}
			}
		}(i, start)
	}

	wg.Wait()
	close(errChan)

	for e := range errChan {
		t.Error(e)
	}
}

// TestConcurrentRangeViaAPI exercises the PersistentCache.GetRange API directly
// with many concurrent callers for the same object.
func TestConcurrentRangeViaAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	const fileSize = 3 * 1024 * 1024
	originData := make([]byte, fileSize)
	_, err := rand.Read(originData)
	require.NoError(t, err)

	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "api_range.bin")
	require.NoError(t, os.WriteFile(originPath, originData, 0644))

	testCacheDir := t.TempDir()
	pc, err := local_cache.NewPersistentCache(ft.Ctx, ft.Egrp, local_cache.PersistentCacheConfig{
		BaseDir: testCacheDir,
	})
	require.NoError(t, err)
	defer pc.Close()

	const workers = 10
	var wg sync.WaitGroup
	errChan := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			// Each worker requests a different 64KB chunk
			start := int64(workerID) * 65536
			end := start + 65535
			if end >= fileSize {
				end = fileSize - 1
			}

			rangeHeader := fmt.Sprintf("bytes=%d-%d", start, end)
			reader, getErr := pc.GetRange(context.Background(), "/test/api_range.bin", "", rangeHeader)
			if getErr != nil {
				errChan <- fmt.Errorf("[%d] GetRange: %w", workerID, getErr)
				return
			}
			defer reader.Close()

			body, readErr := io.ReadAll(reader)
			if readErr != nil {
				errChan <- fmt.Errorf("[%d] ReadAll: %w", workerID, readErr)
				return
			}

			expected := originData[start : end+1]
			if len(body) != len(expected) {
				errChan <- fmt.Errorf("[%d] length mismatch: got %d, want %d",
					workerID, len(body), len(expected))
				return
			}

			for j := range body {
				if body[j] != expected[j] {
					errChan <- fmt.Errorf("[%d] data mismatch at byte %d", workerID, j)
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	for e := range errChan {
		t.Error(e)
	}
}

// TestRangeHTTPHeaders verifies that the HTTP-level range response headers are correct
// (Content-Range, Content-Length, status 206) for various range patterns.
func TestRangeHTTPHeaders(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, pubOriginCfg)

	const fileSize = 100 * 1024 // 100 KB
	originData := make([]byte, fileSize)
	_, err := rand.Read(originData)
	require.NoError(t, err)

	originPath := filepath.Join(ft.Exports[0].StoragePrefix, "range_headers.bin")
	require.NoError(t, os.WriteFile(originPath, originData, 0644))

	transport := config.GetTransport().Clone()
	transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", param.LocalCache_Socket.GetString())
	}
	httpClient := &http.Client{Transport: transport}

	t.Run("explicit-range", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/range_headers.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", "bytes=0-99")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusPartialContent, resp.StatusCode)
		assert.Equal(t, "100", resp.Header.Get("Content-Length"))
		assert.Equal(t,
			fmt.Sprintf("bytes 0-99/%d", fileSize),
			resp.Header.Get("Content-Range"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, originData[:100], body)
	})

	t.Run("suffix-range", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/range_headers.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", "bytes=-256")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusPartialContent, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, originData[fileSize-256:], body)
	})

	t.Run("open-ended-range", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/range_headers.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", "bytes=1024-")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusPartialContent, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, originData[1024:], body)
	})

	t.Run("full-file-no-range", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/range_headers.bin", nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, strconv.Itoa(fileSize), resp.Header.Get("Content-Length"))
		assert.Empty(t, resp.Header.Get("Content-Range"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, originData, body)
	})

	t.Run("unsatisfiable-range", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost/test/range_headers.bin", nil)
		require.NoError(t, err)
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", fileSize+1, fileSize+100))

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusRequestedRangeNotSatisfiable, resp.StatusCode)
	})
}
