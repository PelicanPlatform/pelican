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
// the client before the entire origin→cache transfer has completed.
// We simulate a slow HTTP backend so buffering the full response would
// exceed a short client deadline.

package fed_tests

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

type slowOrigin struct {
	server      *httptest.Server
	bytesServed atomic.Int64
	content     []byte
	chunkSize   int
	chunkDelay  time.Duration
}

func newSlowOrigin(t *testing.T, content []byte, chunkSize int, chunkDelay time.Duration) *slowOrigin {
	t.Helper()

	so := &slowOrigin{
		content:    content,
		chunkSize:  chunkSize,
		chunkDelay: chunkDelay,
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(so.content)))
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusOK)
			return
		}

		start := 0
		end := len(so.content) - 1
		status := http.StatusOK

		if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
			parsedStart, parsedEnd, ok := parseRangeHeader(rangeHeader, len(so.content))
			if ok {
				start = parsedStart
				end = parsedEnd
				status = http.StatusPartialContent
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(so.content)))
			}
		}

		data := so.content[start : end+1]
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(status)

		for offset := 0; offset < len(data); {
			chunkEnd := offset + so.chunkSize
			if chunkEnd > len(data) {
				chunkEnd = len(data)
			}
			n, err := w.Write(data[offset:chunkEnd])
			if err != nil {
				return
			}
			so.bytesServed.Add(int64(n))
			offset += n
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if offset < len(data) {
				time.Sleep(so.chunkDelay)
			}
		}
	}

	so.server = httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(so.server.Close)
	return so
}

func parseRangeHeader(rangeHeader string, size int) (int, int, bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, false
	}

	parts := strings.SplitN(strings.TrimPrefix(rangeHeader, "bytes="), "-", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}

	start := 0
	end := size - 1

	if parts[0] != "" {
		_, err := fmt.Sscanf(parts[0], "%d", &start)
		if err != nil || start < 0 || start >= size {
			return 0, 0, false
		}
	}
	if parts[1] != "" {
		_, err := fmt.Sscanf(parts[1], "%d", &end)
		if err != nil || end < start {
			return 0, 0, false
		}
		if end >= size {
			end = size - 1
		}
	}

	return start, end, true
}

func httpOriginConfig(serviceURL string) string {
	return fmt.Sprintf(`Origin:
  StorageType: "https"
  HttpServiceUrl: %q
  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "DirectReads", "Listings"]
`, serviceURL)
}

func cacheObjectIsCached(ctx context.Context, cacheURL string) (bool, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, cacheURL, nil)
	if err != nil {
		return false, 0, err
	}
	req.Header.Set("X-Pelican-NoDownload", "true")

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	return resp.StatusCode == http.StatusOK, resp.StatusCode, nil
}

// waitForCacheRedirectURL polls the director until it redirects to a cache
// (i.e. the Location header contains "/api/v1.0/cache/data/"), then returns
// that redirect URL.  This is needed because the cache registers with the
// director asynchronously and may not be available immediately after
// NewFedTest returns.
func waitForCacheRedirectURL(ctx context.Context, t *testing.T, objectPath, token string) string {
	t.Helper()

	var cacheURL string
	require.Eventually(t, func() bool {
		directorURL := fmt.Sprintf("https://%s:%d%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, directorURL, nil)
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
// The origin is rate-limited; if the cache buffered the full response,
// the client would hit a short timeout before any bytes arrived.
func TestStreaming_FirstBytesArriveFast(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	const fileSize = 512 * 1024 // 512 KB
	content := generateTestData(fileSize)

	slowOrigin := newSlowOrigin(t, content, 8*1024, 200*time.Millisecond) // ~40 KB/s

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, httpOriginConfig(slowOrigin.server.URL))
	token := getTempTokenForTest(t)

	cacheURL := waitForCacheRedirectURL(ft.Ctx, t, "/test/stream_test.bin", token)

	// Verify cache miss before request
	cachedBefore, statusBefore, err := cacheObjectIsCached(ft.Ctx, cacheURL)
	require.NoError(t, err)
	assert.False(t, cachedBefore, "Object should not be cached before first read (status=%d)", statusBefore)

	// Short timeout: buffered responses would exceed this
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

	// Confirm the origin has NOT served the full object yet
	servedSoFar := slowOrigin.bytesServed.Load()
	assert.Less(t, servedSoFar, int64(fileSize),
		"Origin should not have served full object before first bytes arrived")

	_ = resp.Body.Close() // Stop early to keep test fast
	if ctx.Err() != nil {
		require.NoError(t, ctx.Err(), "Streaming request should not timeout")
	}
}

// TestStreaming_RangeOnCacheMiss verifies that a range request on a cache miss
// returns the requested range correctly and that the miss causes a full download
// from the origin backend.
func TestStreaming_RangeOnCacheMiss(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	const fileSize = 256 * 1024 // 256 KB
	content := generateTestData(fileSize)

	slowOrigin := newSlowOrigin(t, content, 8*1024, 150*time.Millisecond) // ~53 KB/s

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, httpOriginConfig(slowOrigin.server.URL))
	token := getTempTokenForTest(t)

	cacheURL := waitForCacheRedirectURL(ft.Ctx, t, "/test/range_miss.bin", token)

	// Verify cache miss before request
	cachedBefore, statusBefore, err := cacheObjectIsCached(ft.Ctx, cacheURL)
	require.NoError(t, err)
	assert.False(t, cachedBefore, "Object should not be cached before range read (status=%d)", statusBefore)

	// Request a range in the middle of the file
	r := doRangeRead(ft.Ctx, cacheURL, "", "bytes=100000-199999")
	require.NoError(t, r.err)

	expected := content[100000:200000]
	assert.True(t, r.statusCode == http.StatusPartialContent || r.statusCode == http.StatusOK,
		"Should return 206 or 200, got %d", r.statusCode)
	assert.Equal(t, expected, r.body)
	assert.Equal(t, "200: OK", r.transferStatus)

	// The cache miss should trigger a full origin download
	served := slowOrigin.bytesServed.Load()
	assert.GreaterOrEqual(t, served, int64(fileSize),
		"Origin should have served the full object on cache miss")

	// Verify object is cached after range read
	cachedAfter, statusAfter, err := cacheObjectIsCached(ft.Ctx, cacheURL)
	require.NoError(t, err)
	assert.True(t, cachedAfter, "Object should be cached after range read (status=%d)", statusAfter)
}

// TestStreaming_SecondReadIsCacheHit verifies that after a streaming cache miss,
// the second read of the same object is a cache hit (no origin round-trip).
func TestStreaming_SecondReadIsCacheHit(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	const fileSize = 256 * 1024 // 256 KB
	content := generateTestData(fileSize)

	slowOrigin := newSlowOrigin(t, content, 8*1024, 150*time.Millisecond) // ~53 KB/s

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, httpOriginConfig(slowOrigin.server.URL))
	token := getTempTokenForTest(t)

	cacheURL := waitForCacheRedirectURL(ft.Ctx, t, "/test/hit_test.bin", token)

	// Verify cache miss before request
	cachedBefore, statusBefore, err := cacheObjectIsCached(ft.Ctx, cacheURL)
	require.NoError(t, err)
	assert.False(t, cachedBefore, "Object should not be cached before first read (status=%d)", statusBefore)

	// First read (cache miss)
	r1 := doRangeRead(ft.Ctx, cacheURL, "", "")
	require.NoError(t, r1.err)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)
	assert.Equal(t, "200: OK", r1.transferStatus)

	servedAfterFirst := slowOrigin.bytesServed.Load()
	assert.GreaterOrEqual(t, servedAfterFirst, int64(fileSize),
		"Origin should have served the full object on first read")

	// Verify object is cached after first read
	cachedAfter, statusAfter, err := cacheObjectIsCached(ft.Ctx, cacheURL)
	require.NoError(t, err)
	assert.True(t, cachedAfter, "Object should be cached after first read (status=%d)", statusAfter)

	// Second read (cache hit) should not hit origin
	r2 := doRangeRead(ft.Ctx, cacheURL, "", "")
	require.NoError(t, r2.err)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)
	assert.Equal(t, "200: OK", r2.transferStatus)

	servedAfterSecond := slowOrigin.bytesServed.Load()
	assert.Equal(t, servedAfterFirst, servedAfterSecond,
		"Origin should not be contacted on cache hit")
}
