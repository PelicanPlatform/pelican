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

// Performance benchmarks for the persistent cache.
//
// Because the e2e test helpers (NewFedTest, getTempTokenForTest, etc.) all
// require *testing.T, these benchmarks are implemented as ordinary Test*
// functions that measure latency manually and report results via t.Logf.
// Run them with: go test -run "TestBench_" -v -count=1 -timeout 300s

package fed_tests

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// benchTestEnv holds a running federation and a token for issuing requests.
type benchTestEnv struct {
	ft       *fed_test_utils.FedTest
	token    string
	ctx      context.Context
	cacheURL string // populated after priming the cache
}

// setupBenchTestEnv spins up the federation, uploads a file of the
// requested size, and (optionally) primes the cache so cacheURL is ready.
func setupBenchTestEnv(t *testing.T, fileSize int, prime bool) *benchTestEnv {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	token := getTempTokenForTest(t)

	content := generateTestData(fileSize)
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "bench_file.bin")
	require.NoError(t, os.WriteFile(localFile, content, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/bench_file.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(token))
	require.NoError(t, err)

	env := &benchTestEnv{
		ft:    ft,
		token: token,
		ctx:   ft.Ctx,
	}

	if prime {
		downloadFile := filepath.Join(localTmpDir, "prime_download")
		_, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)

		env.cacheURL = getCacheRedirectURL(ft.Ctx, t, "/test/bench_file.bin", token)
	}

	return env
}

// httpGet performs a full GET against a URL and reads the body to completion.
func httpGet(ctx context.Context, url, token string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return len(body), nil
}

// httpRange performs a range GET and returns the body length and any error.
func httpRange(ctx context.Context, url, token, rangeHeader string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Range", rangeHeader)

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return len(body), nil
}

// reportThroughput logs a benchmark-style summary line.
func reportThroughput(t *testing.T, label string, iterations int, totalBytes int64, elapsed time.Duration) {
	t.Helper()
	perOp := elapsed / time.Duration(iterations)
	mbps := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("%-45s %5d ops  %10s/op  %8.1f MB/s  (total %s)",
		label, iterations, perOp.Round(time.Microsecond), mbps, elapsed.Round(time.Millisecond))
}

// ============================================================================
// Serial cache-hit benchmarks
// ============================================================================

func TestBench_CacheHit_Serial_FullRead(t *testing.T) {
	const fileSize = 64 * 1024
	const iterations = 50
	env := setupBenchTestEnv(t, fileSize, true)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(t, err)
		require.Equal(t, fileSize, n)
	}
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Serial/FullRead/64KB", iterations, int64(fileSize)*iterations, elapsed)
}

func TestBench_CacheHit_Serial_RangeRead(t *testing.T) {
	const fileSize = 64 * 1024
	const rangeSize = 4096
	const iterations = 50
	env := setupBenchTestEnv(t, fileSize, true)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		n, err := httpRange(env.ctx, env.cacheURL, env.token, "bytes=8192-12287")
		require.NoError(t, err)
		require.Equal(t, rangeSize, n)
	}
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Serial/RangeRead/4KB", iterations, int64(rangeSize)*iterations, elapsed)
}

func TestBench_CacheHit_Serial_SmallInline(t *testing.T) {
	const fileSize = 2048
	const iterations = 50
	env := setupBenchTestEnv(t, fileSize, true)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(t, err)
		require.Equal(t, fileSize, n)
	}
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Serial/Inline/2KB", iterations, int64(fileSize)*iterations, elapsed)
}

// ============================================================================
// Concurrent cache-hit benchmarks
// ============================================================================

func TestBench_CacheHit_Concurrent_FullRead(t *testing.T) {
	const fileSize = 64 * 1024
	const concurrency = 10
	const opsPerGoroutine = 10
	env := setupBenchTestEnv(t, fileSize, true)

	totalOps := concurrency * opsPerGoroutine
	var wg sync.WaitGroup
	start := time.Now()

	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				n, err := httpGet(env.ctx, env.cacheURL, env.token)
				if err != nil {
					t.Error(err)
					return
				}
				if n != fileSize {
					t.Errorf("expected %d bytes, got %d", fileSize, n)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Concurrent/FullRead/64KB", totalOps, int64(fileSize)*int64(totalOps), elapsed)
}

func TestBench_CacheHit_Concurrent_RangeRead(t *testing.T) {
	const fileSize = 64 * 1024
	const rangeSize = 4096
	const concurrency = 10
	const opsPerGoroutine = 10
	env := setupBenchTestEnv(t, fileSize, true)

	totalOps := concurrency * opsPerGoroutine
	var counter atomic.Int64
	var wg sync.WaitGroup

	start := time.Now()
	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				idx := counter.Add(1)
				offset := (idx % 15) * 4096
				rangeHdr := fmt.Sprintf("bytes=%d-%d", offset, offset+4095)
				n, err := httpRange(env.ctx, env.cacheURL, env.token, rangeHdr)
				if err != nil {
					t.Error(err)
					return
				}
				if n != rangeSize {
					t.Errorf("expected %d bytes, got %d", rangeSize, n)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Concurrent/RangeRead/4KB", totalOps, int64(rangeSize)*int64(totalOps), elapsed)
}

// ============================================================================
// Serial cache-miss benchmarks
// ============================================================================

func TestBench_CacheMiss_Serial_FullRead(t *testing.T) {
	const fileSize = 64 * 1024
	const iterations = 5
	env := setupBenchTestEnv(t, fileSize, false)

	var totalElapsed time.Duration
	for i := 0; i < iterations; i++ {
		// Upload a unique file for this iteration
		content := generateTestData(fileSize)
		localTmpDir := t.TempDir()
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("miss_%d.bin", i))
		require.NoError(t, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/miss_%d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(env.ctx, localFile, uploadURL, false, client.WithToken(env.token))
		require.NoError(t, err)

		cacheURL := getCacheRedirectURL(env.ctx, t, fmt.Sprintf("/test/miss_%d.bin", i), env.token)

		// Measure only the cache-miss read
		start := time.Now()
		n, err := httpGet(env.ctx, cacheURL, env.token)
		totalElapsed += time.Since(start)

		require.NoError(t, err)
		require.Equal(t, fileSize, n)
	}
	reportThroughput(t, "CacheMiss/Serial/FullRead/64KB", iterations, int64(fileSize)*iterations, totalElapsed)
}

// ============================================================================
// Concurrent cache-miss (stampede) benchmark
// ============================================================================

func TestBench_CacheMiss_Concurrent_Stampede(t *testing.T) {
	const fileSize = 64 * 1024
	const concurrency = 10
	const iterations = 3

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	token := getTempTokenForTest(t)

	var totalElapsed time.Duration
	for i := 0; i < iterations; i++ {
		content := generateTestData(fileSize)
		localTmpDir := t.TempDir()
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("stampede_%d.bin", i))
		require.NoError(t, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/stampede_%d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(token))
		require.NoError(t, err)

		cacheURL := getCacheRedirectURL(ft.Ctx, t, fmt.Sprintf("/test/stampede_%d.bin", i), token)

		start := time.Now()
		var wg sync.WaitGroup
		for g := 0; g < concurrency; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := httpGet(ft.Ctx, cacheURL, token)
				if err != nil {
					t.Error(err)
					return
				}
				if n != fileSize {
					t.Errorf("expected %d bytes, got %d", fileSize, n)
				}
			}()
		}
		wg.Wait()
		totalElapsed += time.Since(start)
	}
	totalOps := iterations * concurrency
	reportThroughput(t, "CacheMiss/Concurrent/Stampede/64KB", totalOps, int64(fileSize)*int64(totalOps), totalElapsed)
}

// ============================================================================
// Large-file benchmarks
// ============================================================================

func TestBench_CacheHit_Serial_LargeFile(t *testing.T) {
	const fileSize = 1024 * 1024
	const iterations = 10
	env := setupBenchTestEnv(t, fileSize, true)

	start := time.Now()
	for i := 0; i < iterations; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(t, err)
		require.Equal(t, fileSize, n)
	}
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Serial/FullRead/1MB", iterations, int64(fileSize)*iterations, elapsed)
}

func TestBench_CacheHit_Concurrent_LargeFile(t *testing.T) {
	const fileSize = 1024 * 1024
	const concurrency = 8
	const opsPerGoroutine = 3
	env := setupBenchTestEnv(t, fileSize, true)

	totalOps := concurrency * opsPerGoroutine
	var wg sync.WaitGroup

	start := time.Now()
	for g := 0; g < concurrency; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				n, err := httpGet(env.ctx, env.cacheURL, env.token)
				if err != nil {
					t.Error(err)
					return
				}
				if n != fileSize {
					t.Errorf("expected %d bytes, got %d", fileSize, n)
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	reportThroughput(t, "CacheHit/Concurrent/FullRead/1MB", totalOps, int64(fileSize)*int64(totalOps), elapsed)
}
