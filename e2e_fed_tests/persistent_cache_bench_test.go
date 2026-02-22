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
// Run them with: go test -run=^$ -bench "Benchmark" -benchtime=10x -count=1 -timeout 300s
//
// Because federation startup is expensive, each benchmark spins up the
// federation once (in an untimed setup phase) and then iterates b.N
// times over the hot path.

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
func setupBenchTestEnv(tb testing.TB, fileSize int, prime bool) *benchTestEnv {
	tb.Helper()
	tb.Cleanup(test_utils.SetupTestLogging(tb))
	server_utils.ResetTestState()
	tb.Cleanup(server_utils.ResetTestState)

	require.NoError(tb, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(tb, persistentCacheConfig)

	token := getTempTokenForTest(tb)

	content := generateTestData(fileSize)
	localTmpDir := tb.TempDir()
	localFile := filepath.Join(localTmpDir, "bench_file.bin")
	require.NoError(tb, os.WriteFile(localFile, content, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/bench_file.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(token))
	require.NoError(tb, err)

	env := &benchTestEnv{
		ft:    ft,
		token: token,
		ctx:   ft.Ctx,
	}

	if prime {
		downloadFile := filepath.Join(localTmpDir, "prime_download")
		_, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(tb, err)

		env.cacheURL = getCacheRedirectURL(ft.Ctx, tb, "/test/bench_file.bin", token)
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

// ============================================================================
// Serial cache-hit benchmarks
// ============================================================================

func BenchmarkCacheHit_Serial_FullRead(b *testing.B) {
	const fileSize = 64 * 1024
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(b, err)
		require.Equal(b, fileSize, n)
	}
}

func BenchmarkCacheHit_Serial_RangeRead(b *testing.B) {
	const fileSize = 64 * 1024
	const rangeSize = 4096
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(rangeSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := httpRange(env.ctx, env.cacheURL, env.token, "bytes=8192-12287")
		require.NoError(b, err)
		require.Equal(b, rangeSize, n)
	}
}

func BenchmarkCacheHit_Serial_SmallInline(b *testing.B) {
	const fileSize = 2048
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(b, err)
		require.Equal(b, fileSize, n)
	}
}

// ============================================================================
// Concurrent cache-hit benchmarks
// ============================================================================

func BenchmarkCacheHit_Concurrent_FullRead(b *testing.B) {
	const fileSize = 64 * 1024
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n, err := httpGet(env.ctx, env.cacheURL, env.token)
			if err != nil {
				b.Error(err)
				return
			}
			if n != fileSize {
				b.Errorf("expected %d bytes, got %d", fileSize, n)
				return
			}
		}
	})
}

func BenchmarkCacheHit_Concurrent_RangeRead(b *testing.B) {
	const fileSize = 64 * 1024
	const rangeSize = 4096
	env := setupBenchTestEnv(b, fileSize, true)

	var counter atomic.Int64

	b.SetBytes(int64(rangeSize))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			idx := counter.Add(1)
			offset := (idx % 15) * 4096
			rangeHdr := fmt.Sprintf("bytes=%d-%d", offset, offset+4095)
			n, err := httpRange(env.ctx, env.cacheURL, env.token, rangeHdr)
			if err != nil {
				b.Error(err)
				return
			}
			if n != rangeSize {
				b.Errorf("expected %d bytes, got %d", rangeSize, n)
				return
			}
		}
	})
}

// ============================================================================
// Serial cache-miss benchmarks
// ============================================================================

func BenchmarkCacheMiss_Serial_FullRead(b *testing.B) {
	const fileSize = 64 * 1024
	env := setupBenchTestEnv(b, fileSize, false)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Upload a unique file for this iteration
		content := generateTestData(fileSize)
		localTmpDir := b.TempDir()
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("miss_%d.bin", i))
		require.NoError(b, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/miss_%d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(env.ctx, localFile, uploadURL, false, client.WithToken(env.token))
		require.NoError(b, err)

		cacheURL := getCacheRedirectURL(env.ctx, b, fmt.Sprintf("/test/miss_%d.bin", i), env.token)
		b.StartTimer()

		n, err := httpGet(env.ctx, cacheURL, env.token)
		require.NoError(b, err)
		require.Equal(b, fileSize, n)
	}
}

// ============================================================================
// Concurrent cache-miss (stampede) benchmark
// ============================================================================

func BenchmarkCacheMiss_Concurrent_Stampede(b *testing.B) {
	const fileSize = 64 * 1024
	const concurrency = 10

	b.Cleanup(test_utils.SetupTestLogging(b))
	server_utils.ResetTestState()
	b.Cleanup(server_utils.ResetTestState)

	require.NoError(b, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(b, persistentCacheConfig)
	token := getTempTokenForTest(b)

	b.SetBytes(int64(fileSize) * int64(concurrency))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		content := generateTestData(fileSize)
		localTmpDir := b.TempDir()
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("stampede_%d.bin", i))
		require.NoError(b, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/stampede_%d.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(token))
		require.NoError(b, err)

		cacheURL := getCacheRedirectURL(ft.Ctx, b, fmt.Sprintf("/test/stampede_%d.bin", i), token)
		b.StartTimer()

		var wg sync.WaitGroup
		for g := 0; g < concurrency; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, err := httpGet(ft.Ctx, cacheURL, token)
				if err != nil {
					b.Error(err)
					return
				}
				if n != fileSize {
					b.Errorf("expected %d bytes, got %d", fileSize, n)
				}
			}()
		}
		wg.Wait()
	}
}

// ============================================================================
// Large-file benchmarks
// ============================================================================

func BenchmarkCacheHit_Serial_LargeFile(b *testing.B) {
	const fileSize = 1024 * 1024
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n, err := httpGet(env.ctx, env.cacheURL, env.token)
		require.NoError(b, err)
		require.Equal(b, fileSize, n)
	}
}

func BenchmarkCacheHit_Concurrent_LargeFile(b *testing.B) {
	const fileSize = 1024 * 1024
	env := setupBenchTestEnv(b, fileSize, true)

	b.SetBytes(int64(fileSize))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n, err := httpGet(env.ctx, env.cacheURL, env.token)
			if err != nil {
				b.Error(err)
				return
			}
			if n != fileSize {
				b.Errorf("expected %d bytes, got %d", fileSize, n)
				return
			}
		}
	})
}
