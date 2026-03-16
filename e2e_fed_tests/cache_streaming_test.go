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

// Tests for non-blocking / streaming cache behavior.
//
// These verify that the persistent cache starts streaming data back to
// the client before the entire origin-to-cache transfer has completed.
// We use a POSIXv2 origin with Origin.TransferRateLimit to simulate a
// slow backend.

package fed_tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// slowOriginConfig returns a YAML configuration snippet for a POSIXv2
// origin with a transfer rate limit to simulate a slow backend.
func slowOriginConfig(rateLimit string) string {
	return fmt.Sprintf(`Origin:
  StorageType: posixv2
  TransferRateLimit: %s
  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "DirectReads", "Listings"]
Director:
  CheckCachePresence: false
`, rateLimit)
}

// writeOriginFile creates a file in the origin's storage directory and
// returns the test content that was written.
func writeOriginFile(t *testing.T, ft *fed_test_utils.FedTest, name string, size int) []byte {
	t.Helper()
	content := generateTestData(size)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))
	return content
}

// waitForCacheRedirectURL polls the director until it redirects to a cache
// (i.e. the Location header contains "/api/v1.0/cache/data/"), then returns
// that redirect URL.  This is needed because the cache registers with the
// director asynchronously and may not be available immediately after
// NewFedTest returns.
func waitForCacheRedirectURL(t *testing.T, ft *fed_test_utils.FedTest, objectPath, token string) string {
	t.Helper()

	var cacheURL string
	require.Eventually(t, func() bool {
		directorURL := fmt.Sprintf("https://%s:%d%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)

		req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, directorURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+token)

		httpClient := &http.Client{
			Transport: config.GetTransport(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		_, _ = io.ReadAll(resp.Body)

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			return false
		}
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/api/v1.0/cache/data/") {
			cacheURL = loc
			return true
		}
		return false
	}, 15*time.Second, 500*time.Millisecond,
		"Director never redirected to cache for %s", objectPath)

	return cacheURL
}

// TestStreaming_FirstBytesArriveFast verifies that on a cache miss the
// persistent cache begins streaming data back to the client before the
// full origin-to-cache download completes.
//
// The origin is rate-limited to ~40 KB/s via Origin.TransferRateLimit.
// A 512 KB file at that rate takes ~13 seconds to transfer.
// If the cache buffered the full response, the client would hit the
// 5-second timeout before any bytes arrived.
func TestStreaming_FirstBytesArriveFast(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig("40KB/s"))
	token := getTempTokenForTest(t)

	const fileSize = 512 * 1024 // 512 KB
	content := writeOriginFile(t, ft, "stream_test.bin", fileSize)

	cacheURL := waitForCacheRedirectURL(t, ft, "/test/stream_test.bin", token)

	// Short timeout: at 40 KB/s the full 512 KB file takes ~13 seconds.
	// If the cache is truly streaming, the first 4 KB should arrive well
	// within the timeout.
	ctx, cancel := context.WithTimeout(ft.Ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")

	startTime := time.Now()
	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	firstChunk := make([]byte, 4096)
	n, err := io.ReadFull(resp.Body, firstChunk)
	firstByteLatency := time.Since(startTime)

	require.NoError(t, err)
	require.Equal(t, 4096, n)
	assert.Less(t, firstByteLatency, 5*time.Second,
		"First 4 KB should arrive before the short timeout (streaming)")
	assert.Equal(t, content[:4096], firstChunk)

	_ = resp.Body.Close() // Stop early to keep test fast
	if ctx.Err() != nil {
		require.NoError(t, ctx.Err(), "Streaming request should not timeout")
	}
}

// TestStreaming_RangeOnCacheMiss verifies that a range request on a cache miss
// returns the requested range correctly, that the range is cached for subsequent
// queries, and that the range request doesn't cause caching from the _beginning_
// of the object.
//
// Strategy: use a large file (2 MB) behind a slow origin (50 KB/s).
// Request bytes 1.5 MB–1.75 MB from the middle.  Because the cache uses a
// lightweight HEAD to initialise storage and then fetches only the needed
// blocks via an HTTP Range to the origin, the 256 KB range should arrive
// in roughly 256 KB / 50 KB/s ≈ 5 s — NOT the ~30 s it would take for a
// sequential download to reach offset 1.5 MB.  After that completes:
//   - Re-request the same range → must be a fast cache hit.
//   - Request bytes 0–4095 (the very beginning) with a short timeout → must
//     NOT be available quickly, proving the cache did not pre-fetch from offset 0.
func TestStreaming_RangeOnCacheMiss(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	// 50 KB/s: the full 2 MB file would take ~40 s to download sequentially.
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig("50KB/s"))
	token := getTempTokenForTest(t)

	const fileSize = 2 * 1024 * 1024 // 2 MB
	content := writeOriginFile(t, ft, "range_miss.bin", fileSize)

	cacheURL := waitForCacheRedirectURL(t, ft, "/test/range_miss.bin", token)

	// ---- Step 1: fetch a range in the middle (1.5 MB – 1.75 MB) ----------
	// At 50 KB/s a sequential download from byte 0 would need ~30 s to
	// reach offset 1.5 MB.  The range-on-miss fast path (HEAD + block
	// fetch) should deliver the 256 KB range in ≈5 s, so we use a 15 s
	// timeout — generous enough for CI, but well below the 30 s that a
	// sequential download would require.
	rangeStart := 1536 * 1024 // 1.5 MB
	rangeEnd := 1792*1024 - 1 // 1.75 MB - 1 (inclusive end)
	rangeHeader := fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd)

	rangeCtx, rangeCancel := context.WithTimeout(ft.Ctx, 15*time.Second)
	defer rangeCancel()

	startTime := time.Now()
	r := doRangeRead(rangeCtx, cacheURL, "", "", rangeHeader)
	fetchLatency := time.Since(startTime)
	require.NoError(t, r.err, "Range request from the middle should succeed within the timeout")

	expected := content[rangeStart : rangeEnd+1]
	assert.True(t, r.statusCode == http.StatusPartialContent || r.statusCode == http.StatusOK,
		"Should return 206 or 200, got %d", r.statusCode)
	assert.Equal(t, expected, r.body, "Range body should match expected content")
	assert.Equal(t, "200: OK", r.transferStatus)
	// 256 KB at 50 KB/s ≈ 5 s.  Assert a floor (proves we actually
	// fetched from the slow origin, not from a pre-filled cache) and a
	// ceiling (proves we didn't download sequentially from byte 0, which
	// would take ≥30 s to reach offset 1.5 MB).
	assert.Greater(t, fetchLatency, 2*time.Second,
		"256 KB at 50 KB/s should take several seconds — suspiciously fast")
	assert.Less(t, fetchLatency, 10*time.Second,
		"Range from the middle should arrive via on-demand block fetch, not a sequential download from byte 0")
	t.Logf("Step 1 latency: %v (256 KB from the middle at 50 KB/s)", fetchLatency)

	// ---- Step 2: re-read the same range → must be a fast cache hit -------
	startTime = time.Now()
	r2 := doRangeRead(ft.Ctx, cacheURL, "", "", rangeHeader)
	hitLatency := time.Since(startTime)

	require.NoError(t, r2.err)
	assert.True(t, r2.statusCode == http.StatusPartialContent || r2.statusCode == http.StatusOK,
		"Second range read: expected 206 or 200, got %d", r2.statusCode)
	assert.Equal(t, expected, r2.body, "Second range read should return identical data")
	// A cache hit should complete nearly instantly.
	assert.Less(t, hitLatency, 500*time.Millisecond,
		"Re-reading the same range should be a fast cache hit")
	t.Logf("Step 2 latency: %v (cache hit)", hitLatency)

	// ---- Step 3: request the beginning → must NOT be cached ----------------
	// Request 256 KB from the beginning.  At 50 KB/s this takes ~5 s from
	// the origin.  If the cache had pre-fetched from byte 0, the data would
	// already be on disk and would arrive nearly instantly.  We give the
	// request a 3 s timeout — long enough for a cache hit, but too short
	// for a fresh 256 KB fetch from the slow origin.
	beginCtx, beginCancel := context.WithTimeout(ft.Ctx, 3*time.Second)
	defer beginCancel()

	beginRange := fmt.Sprintf("bytes=0-%d", 256*1024-1)
	startTime = time.Now()
	r3 := doRangeRead(beginCtx, cacheURL, "", "", beginRange)
	beginLatency := time.Since(startTime)

	if r3.err != nil {
		// Timeout is the expected outcome: the beginning was not cached
		// and the slow origin couldn't deliver 256 KB within 3 s.
		assert.ErrorIs(t, beginCtx.Err(), context.DeadlineExceeded,
			"Request for the beginning should timeout (not pre-fetched)")
		t.Logf("Step 3: beginning range timed out as expected (%v)", beginLatency)
	} else {
		// If the request somehow succeeded, it must have taken close to
		// the full timeout — meaning the cache fetched it live from the
		// slow origin, NOT from a pre-fetched cache.  256 KB at 50 KB/s
		// takes ~5 s; anything under 2 s means it was pre-cached.
		assert.Greater(t, beginLatency, 2*time.Second,
			"If the beginning was returned, it should have been fetched live "+
				"from the slow origin (not pre-cached). Latency was suspiciously fast.")
		t.Logf("Step 3: beginning range succeeded in %v (fetched live, not pre-cached)", beginLatency)
	}
}

// TestStreaming_SecondReadIsCacheHit verifies that after a streaming cache miss,
// the second read of the same object is a cache hit (no origin round-trip).
func TestStreaming_SecondReadIsCacheHit(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	// Use 100 KB/s so the 256 KB file exceeds the rate limiter's burst
	// bucket (100 KB) and is genuinely throttled.  At 1 MB/s the burst
	// alone covers the whole file, letting it complete instantly.
	ft := fed_test_utils.NewFedTest(t, slowOriginConfig("100KB/s"))
	token := getTempTokenForTest(t)

	const fileSize = 256 * 1024 // 256 KB
	content := writeOriginFile(t, ft, "hit_test.bin", fileSize)

	cacheURL := waitForCacheRedirectURL(t, ft, "/test/hit_test.bin", token)

	// First read (cache miss -- downloads from origin at rate limit).
	// 256 KB at 100 KB/s ≈ 2.6 s (minus 100 KB burst ≈ 1.6 s minimum).
	firstStart := time.Now()
	r1 := doRangeRead(ft.Ctx, cacheURL, "", "", "")
	firstReadLatency := time.Since(firstStart)
	require.NoError(t, r1.err)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)
	assert.Equal(t, "200: OK", r1.transferStatus)
	assert.Greater(t, firstReadLatency, 500*time.Millisecond,
		"First read (cache miss) should take noticeable time from the slow origin")
	assert.Less(t, firstReadLatency, 10*time.Second,
		"First read should not take unreasonably long")

	// Second read (cache hit -- should be fast and return identical data)
	startTime := time.Now()
	r2 := doRangeRead(ft.Ctx, cacheURL, "", "", "")
	secondReadLatency := time.Since(startTime)

	require.NoError(t, r2.err)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)
	assert.Equal(t, "200: OK", r2.transferStatus)

	// The second read should be significantly faster since it's served from cache.
	// At 100 KB/s the origin would take ~2.6 s for 256 KB; a cache hit should be
	// near-instant.
	assert.Less(t, secondReadLatency, 500*time.Millisecond,
		"Second read should be fast (cache hit)")
}
