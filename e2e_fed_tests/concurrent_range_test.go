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

// This file contains high-concurrency range read tests for the persistent
// cache. These tests stress the block fetcher, bitmap merge operators, seekable
// reader, and active download deduplication under concurrent load.

package fed_tests

import (
	"context"
	"crypto/rand"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// ============================================================================
// Test helpers for concurrent range tests
// ============================================================================

// uploadTestFile creates a file with the given content and uploads it to the origin.
// Returns the cache URL for direct HTTP requests.
func uploadTestFile(ctx context.Context, t *testing.T, ft *fed_test_utils.FedTest, filename string, content []byte) string {
	t.Helper()

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, filename)
	require.NoError(t, os.WriteFile(localFile, content, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	return uploadURL
}

// primeCache downloads a file through the cache so it gets populated,
// and returns the direct cache URL for subsequent HTTP requests.
func primeCache(ctx context.Context, t *testing.T, ft *fed_test_utils.FedTest, pelicanURL, objectPath string) string {
	t.Helper()

	localTmpDir := t.TempDir()
	downloadFile := filepath.Join(localTmpDir, "prime_download")
	_, err := client.DoGet(ctx, pelicanURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	testToken := getTempTokenForTest(t)
	cacheURL := getCacheRedirectURL(ctx, t, objectPath, testToken)
	return cacheURL
}

// concurrentRangeRead performs a range read and reports the result.
type rangeResult struct {
	body           []byte
	statusCode     int
	transferStatus string // X-Transfer-Status trailer value, if any
	err            error
}

// doRangeRead performs a single HTTP request against the given URL.
// It requests X-Transfer-Status trailers so callers can detect mid-stream
// errors (e.g. failure from corrupted cache data) and error the transfer.
// If method is empty it defaults to GET.
func doRangeRead(ctx context.Context, url, token, method, rangeHeader string) rangeResult {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return rangeResult{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return rangeResult{err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return rangeResult{err: err, statusCode: resp.StatusCode}
	}

	xferStatus := resp.Trailer.Get("X-Transfer-Status")
	return rangeResult{body: body, statusCode: resp.StatusCode, transferStatus: xferStatus}
}

// generateTestData creates deterministic test data of the given size.
// Each byte position has a known value based on its index, making verification easy.
func generateTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251) // Use a prime to avoid alignment patterns
	}
	return data
}

// requireSuccessfulRead asserts that a rangeResult represents a fully
// successful HTTP response: no transport error, the expected status code,
// matching body content, and a "200: OK" X-Transfer-Status trailer (when
// the server sends one).  label is used in failure messages to identify
// the specific read.
func requireSuccessfulRead(t *testing.T, r rangeResult, expectedCode int, expectedBody []byte, label string) {
	t.Helper()
	require.NoError(t, r.err, "%s: should not error", label)
	require.Equal(t, expectedCode, r.statusCode, "%s: unexpected status code", label)
	assert.Equal(t, expectedBody, r.body, "%s: content mismatch", label)
	if r.transferStatus != "" {
		assert.Equal(t, "200: OK", r.transferStatus,
			"%s: X-Transfer-Status trailer indicates a mid-stream failure", label)
	}
}

// ============================================================================
// Concurrent full-read tests
// ============================================================================

// TestConcurrent_FullReads_SameObject tests many goroutines reading the same
// cached object simultaneously. This exercises the SeekableReader and
// http.ServeContent under contention.
func TestConcurrent_FullReads_SameObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Use a file larger than InlineThreshold (4096) so disk storage path is exercised
	content := generateTestData(16384) // 16KB = ~4 blocks
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_full.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_full.bin")

	testToken := getTempTokenForTest(t)
	const numReaders = 20

	var wg sync.WaitGroup
	results := make([]rangeResult, numReaders)

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", "")
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		requireSuccessfulRead(t, r, http.StatusOK, content, fmt.Sprintf("Reader %d", i))
	}
}

// ============================================================================
// Concurrent range-read tests
// ============================================================================

// TestConcurrent_RangeReads_DifferentRanges tests many goroutines requesting
// different byte ranges from the same cached object. This stresses the
// RangeReader's seek and block-read paths under contention.
func TestConcurrent_RangeReads_DifferentRanges(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Use a file large enough to have many blocks (each block is 4080 bytes data)
	content := generateTestData(32768) // 32KB = ~8 blocks
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_ranges.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_ranges.bin")

	testToken := getTempTokenForTest(t)

	// Define a variety of range requests spanning different blocks
	type rangeSpec struct {
		header string
		start  int
		end    int
	}
	ranges := []rangeSpec{
		{"bytes=0-99", 0, 99},
		{"bytes=100-4079", 100, 4079},       // Within first block
		{"bytes=4080-8159", 4080, 8159},     // Second block exactly
		{"bytes=4000-5000", 4000, 5000},     // Spans block boundary (block 0/1)
		{"bytes=0-0", 0, 0},                 // Single byte
		{"bytes=16000-16999", 16000, 16999}, // Middle of file
		{"bytes=32700-32767", 32700, 32767}, // End of file
		{"bytes=0-32767", 0, 32767},         // Entire file as range
		{"bytes=8000-12000", 8000, 12000},   // Spans blocks 1/2
		{"bytes=12000-24000", 12000, 24000}, // Spans multiple blocks
	}

	const repeats = 3 // Each range is read this many times concurrently
	totalReads := len(ranges) * repeats

	var wg sync.WaitGroup
	results := make([]rangeResult, totalReads)
	specs := make([]rangeSpec, totalReads)

	idx := 0
	for _, rs := range ranges {
		for r := 0; r < repeats; r++ {
			specs[idx] = rs
			wg.Add(1)
			go func(i int, spec rangeSpec) {
				defer wg.Done()
				results[i] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.header)
			}(idx, rs)
			idx++
		}
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Range %s (read %d)", spec.header, i))
	}
}

// TestConcurrent_RangeReads_BlockBoundaries focuses on ranges that straddle
// block boundaries to stress the RangeReader's cross-block read logic.
func TestConcurrent_RangeReads_BlockBoundaries(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// 5 blocks worth of data
	const blockDataSize = 4080
	content := generateTestData(blockDataSize * 5)
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_boundaries.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_boundaries.bin")

	testToken := getTempTokenForTest(t)

	// All ranges deliberately straddle block boundaries
	type rangeSpec struct {
		header string
		start  int
		end    int
	}
	ranges := []rangeSpec{
		// Straddle block 0/1 boundary
		{fmt.Sprintf("bytes=%d-%d", blockDataSize-10, blockDataSize+10), blockDataSize - 10, blockDataSize + 10},
		// Straddle block 1/2 boundary
		{fmt.Sprintf("bytes=%d-%d", 2*blockDataSize-1, 2*blockDataSize+1), 2*blockDataSize - 1, 2*blockDataSize + 1},
		// Straddle block 2/3 boundary
		{fmt.Sprintf("bytes=%d-%d", 3*blockDataSize-50, 3*blockDataSize+50), 3*blockDataSize - 50, 3*blockDataSize + 50},
		// Span 3 blocks (block 1 through block 3)
		{fmt.Sprintf("bytes=%d-%d", blockDataSize+100, 3*blockDataSize+100), blockDataSize + 100, 3*blockDataSize + 100},
		// Span all blocks
		{fmt.Sprintf("bytes=0-%d", 5*blockDataSize-1), 0, 5*blockDataSize - 1},
	}

	const numReaders = 5
	totalReads := len(ranges) * numReaders

	var wg sync.WaitGroup
	results := make([]rangeResult, totalReads)
	specs := make([]rangeSpec, totalReads)

	idx := 0
	for _, rs := range ranges {
		for r := 0; r < numReaders; r++ {
			specs[idx] = rs
			wg.Add(1)
			go func(i int, spec rangeSpec) {
				defer wg.Done()
				results[i] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.header)
			}(idx, rs)
			idx++
		}
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Boundary range %s (read %d)", spec.header, i))
	}
}

// ============================================================================
// Concurrent cache-miss tests (download deduplication)
// ============================================================================

// TestConcurrent_CacheMiss_SameObject tests that many concurrent requests for
// the same uncached object are properly deduplicated — only one download should
// happen, and all waiters should get correct data.
func TestConcurrent_CacheMiss_SameObject(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Upload but do NOT prime the cache — all readers will hit a cache miss
	content := generateTestData(20000) // ~5 blocks, forces disk storage
	uploadTestFile(ft.Ctx, t, ft, "concurrent_miss.bin", content)

	// Get the cache URL without priming
	testToken := getTempTokenForTest(t)
	cacheURL := getCacheRedirectURL(ft.Ctx, t, "/test/concurrent_miss.bin", testToken)

	const numReaders = 15

	var wg sync.WaitGroup
	results := make([]rangeResult, numReaders)

	// All readers fire simultaneously — the first will trigger a download,
	// the rest should either wait for that download or get it once complete.
	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", "")
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		requireSuccessfulRead(t, r, http.StatusOK, content,
			fmt.Sprintf("Cache-miss reader %d", i))
	}
}

// TestConcurrent_CacheMiss_RangeReads tests concurrent range reads on an
// object that is not yet cached. The first request triggers a download;
// subsequent range requests should wait for it and return correct slices.
func TestConcurrent_CacheMiss_RangeReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(24000) // ~6 blocks
	uploadTestFile(ft.Ctx, t, ft, "concurrent_miss_range.bin", content)

	testToken := getTempTokenForTest(t)
	cacheURL := getCacheRedirectURL(ft.Ctx, t, "/test/concurrent_miss_range.bin", testToken)

	type rangeSpec struct {
		header string
		start  int
		end    int
	}
	ranges := []rangeSpec{
		{"bytes=0-999", 0, 999},
		{"bytes=5000-9999", 5000, 9999},
		{"bytes=15000-19999", 15000, 19999},
		{"bytes=20000-23999", 20000, 23999},
		{"", 0, len(content) - 1}, // Full read too
	}

	var wg sync.WaitGroup
	results := make([]rangeResult, len(ranges))
	specs := make([]rangeSpec, len(ranges))

	for i, rs := range ranges {
		specs[i] = rs
		wg.Add(1)
		go func(idx int, spec rangeSpec) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.header)
		}(i, rs)
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		expectedCode := http.StatusPartialContent
		if spec.header == "" {
			expectedCode = http.StatusOK
		}
		requireSuccessfulRead(t, r, expectedCode, expected,
			fmt.Sprintf("Range %s (read %d)", spec.header, i))
	}
}

// ============================================================================
// Concurrent multi-object tests
// ============================================================================

// TestConcurrent_MultipleObjects tests concurrent reads across several different
// objects. This exercises multiple independent download paths and ensures the
// active download map handles multiple keys correctly.
func TestConcurrent_MultipleObjects(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	const numObjects = 5
	const numReadersPerObject = 4

	// Create distinct objects of varying sizes
	objects := make([]struct {
		content  []byte
		cacheURL string
	}, numObjects)

	testToken := getTempTokenForTest(t)

	for i := 0; i < numObjects; i++ {
		// Vary sizes: some inline (<4KB), some disk-backed
		size := 1000 + i*5000 // 1KB, 6KB, 11KB, 16KB, 21KB
		content := generateTestData(size)
		filename := fmt.Sprintf("concurrent_multi_%d.bin", i)
		pelicanURL := uploadTestFile(ft.Ctx, t, ft, filename, content)
		objectPath := fmt.Sprintf("/test/%s", filename)

		cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, objectPath)

		objects[i].content = content
		objects[i].cacheURL = cacheURL
	}

	var wg sync.WaitGroup
	totalReads := numObjects * numReadersPerObject
	results := make([]rangeResult, totalReads)
	objectIndices := make([]int, totalReads)

	idx := 0
	for objIdx := 0; objIdx < numObjects; objIdx++ {
		for r := 0; r < numReadersPerObject; r++ {
			objectIndices[idx] = objIdx
			wg.Add(1)
			go func(i, oi int) {
				defer wg.Done()
				results[i] = doRangeRead(ft.Ctx, objects[oi].cacheURL, testToken, "", "")
			}(idx, objIdx)
			idx++
		}
	}
	wg.Wait()

	for i, r := range results {
		oi := objectIndices[i]
		requireSuccessfulRead(t, r, http.StatusOK, objects[oi].content,
			fmt.Sprintf("Object %d reader %d", oi, i))
	}
}

// ============================================================================
// Concurrent mixed full + range read tests
// ============================================================================

// TestConcurrent_MixedFullAndRangeReads interleaves full and partial reads
// on the same object to exercise the cache serving both code paths simultaneously.
func TestConcurrent_MixedFullAndRangeReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(24576) // 24KB = 6 blocks
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_mixed.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_mixed.bin")

	testToken := getTempTokenForTest(t)

	type readSpec struct {
		rangeHeader string // empty = full read
		start       int
		end         int
		expectCode  int
	}
	specs := []readSpec{
		// Full reads
		{"", 0, len(content) - 1, http.StatusOK},
		{"", 0, len(content) - 1, http.StatusOK},
		// Range reads
		{"bytes=0-4079", 0, 4079, http.StatusPartialContent},
		{"bytes=4080-8159", 4080, 8159, http.StatusPartialContent},
		{"bytes=8160-12239", 8160, 12239, http.StatusPartialContent},
		{"bytes=12240-16319", 12240, 16319, http.StatusPartialContent},
		{"bytes=100-200", 100, 200, http.StatusPartialContent},
		{"bytes=20000-24575", 20000, 24575, http.StatusPartialContent},
		// More full reads mixed in
		{"", 0, len(content) - 1, http.StatusOK},
		{"", 0, len(content) - 1, http.StatusOK},
	}

	var wg sync.WaitGroup
	results := make([]rangeResult, len(specs))

	for i, s := range specs {
		wg.Add(1)
		go func(idx int, spec readSpec) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.rangeHeader)
		}(i, s)
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, spec.expectCode, expected,
			fmt.Sprintf("Mixed read %d (%s)", i, spec.rangeHeader))
	}
}

// ============================================================================
// Large file concurrent range tests
// ============================================================================

// TestConcurrent_LargeFile_ManySmallRanges tests many small range reads on a
// large file. This exercises the block bitmap, decryption, and seek paths at
// scale with many concurrent goroutines.
func TestConcurrent_LargeFile_ManySmallRanges(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// 256KB file = ~62 blocks — large enough to stress multiple blocks
	const fileSize = 256 * 1024
	content := generateTestData(fileSize)
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_large.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_large.bin")

	testToken := getTempTokenForTest(t)

	// Generate 50 random 1KB range reads spread across the file
	const numRanges = 50
	const rangeSize = 1024

	type rangeSpec struct {
		header string
		start  int
		end    int
	}
	ranges := make([]rangeSpec, numRanges)
	for i := 0; i < numRanges; i++ {
		// Deterministic but well-distributed start positions
		start := (i * (fileSize - rangeSize)) / numRanges
		end := start + rangeSize - 1
		ranges[i] = rangeSpec{
			header: fmt.Sprintf("bytes=%d-%d", start, end),
			start:  start,
			end:    end,
		}
	}

	var wg sync.WaitGroup
	results := make([]rangeResult, numRanges)

	for i, rs := range ranges {
		wg.Add(1)
		go func(idx int, spec rangeSpec) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.header)
		}(i, rs)
	}
	wg.Wait()

	for i, r := range results {
		spec := ranges[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Large file range %d (%s)", i, spec.header))
	}
}

// ============================================================================
// Inline storage concurrent test
// ============================================================================

// TestConcurrent_InlineStorage_Reads tests concurrent reads on a small file
// that uses inline storage (stored directly in BadgerDB, not on disk).
// This exercises a different code path than the disk-based tests above.
func TestConcurrent_InlineStorage_Reads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Small file — below InlineThreshold (4096), stored inline in BadgerDB
	content := []byte("This is a small file for inline storage concurrent testing. It must be less than 4096 bytes.")
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_inline.txt", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_inline.txt")

	testToken := getTempTokenForTest(t)
	const numReaders = 20

	var wg sync.WaitGroup
	results := make([]rangeResult, numReaders)

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", "")
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		requireSuccessfulRead(t, r, http.StatusOK, content,
			fmt.Sprintf("Inline reader %d", i))
	}
}

// ============================================================================
// Random data integrity test
// ============================================================================

// TestConcurrent_RandomData_Integrity uses random data to ensure
// round-trips correctly under concurrent access for data without any patterns.
func TestConcurrent_RandomData_Integrity(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// 50KB of random data — avoid any potential pattern matching in simpler tests
	const fileSize = 50 * 1024
	content := make([]byte, fileSize)
	_, err := rand.Read(content)
	require.NoError(t, err)

	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_random.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_random.bin")

	testToken := getTempTokenForTest(t)

	// Mix of full reads and range reads
	type readSpec struct {
		rangeHeader string
		start       int
		end         int
		expectCode  int
	}
	specs := []readSpec{
		{"", 0, fileSize - 1, http.StatusOK},
		{"", 0, fileSize - 1, http.StatusOK},
		{"bytes=0-4079", 0, 4079, http.StatusPartialContent},
		{"bytes=4080-8159", 4080, 8159, http.StatusPartialContent},
		{"bytes=0-0", 0, 0, http.StatusPartialContent},
		{fmt.Sprintf("bytes=%d-%d", fileSize-1, fileSize-1), fileSize - 1, fileSize - 1, http.StatusPartialContent},
		{fmt.Sprintf("bytes=%d-%d", fileSize-100, fileSize-1), fileSize - 100, fileSize - 1, http.StatusPartialContent},
		{"bytes=10000-30000", 10000, 30000, http.StatusPartialContent},
		{"", 0, fileSize - 1, http.StatusOK},
		{"bytes=3000-5000", 3000, 5000, http.StatusPartialContent}, // Cross block boundary
	}

	var wg sync.WaitGroup
	results := make([]rangeResult, len(specs))

	for i, s := range specs {
		wg.Add(1)
		go func(idx int, spec readSpec) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.rangeHeader)
		}(i, s)
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, spec.expectCode, expected,
			fmt.Sprintf("Random data read %d (%s)", i, spec.rangeHeader))
	}
}

// ============================================================================
// Suffix range and edge case tests
// ============================================================================

// TestConcurrent_SuffixRange tests concurrent suffix range requests (bytes=-N),
// which request the last N bytes of a file.
func TestConcurrent_SuffixRange(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(16384) // 16KB
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_suffix.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_suffix.bin")

	testToken := getTempTokenForTest(t)
	fileSize := len(content)

	type rangeSpec struct {
		header string
		start  int
		end    int
	}
	ranges := []rangeSpec{
		{"bytes=-100", fileSize - 100, fileSize - 1},
		{"bytes=-1", fileSize - 1, fileSize - 1},
		{"bytes=-4080", fileSize - 4080, fileSize - 1},
		{"bytes=-8000", fileSize - 8000, fileSize - 1},
	}

	const repeats = 3
	totalReads := len(ranges) * repeats

	var wg sync.WaitGroup
	results := make([]rangeResult, totalReads)
	specs := make([]rangeSpec, totalReads)

	idx := 0
	for _, rs := range ranges {
		for r := 0; r < repeats; r++ {
			specs[idx] = rs
			wg.Add(1)
			go func(i int, spec rangeSpec) {
				defer wg.Done()
				results[i] = doRangeRead(ft.Ctx, cacheURL, testToken, "", spec.header)
			}(idx, rs)
			idx++
		}
	}
	wg.Wait()

	for i, r := range results {
		spec := specs[i]
		expected := content[spec.start : spec.end+1]
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Suffix range %s (read %d)", spec.header, i))
	}
}

// TestConcurrent_HeadAndGet tests concurrent HEAD and GET requests on the same
// object to verify that HEAD requests don't interfere with GET requests.
func TestConcurrent_HeadAndGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(12000) // ~3 blocks
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_head_get.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_head_get.bin")

	testToken := getTempTokenForTest(t)

	type requestSpec struct {
		method      string
		rangeHeader string
	}
	reqs := []requestSpec{
		{"GET", ""},
		{"HEAD", ""},
		{"GET", "bytes=0-999"},
		{"HEAD", ""},
		{"GET", "bytes=5000-5999"},
		{"HEAD", ""},
		{"GET", ""},
		{"HEAD", ""},
		{"GET", "bytes=10000-11999"},
		{"GET", ""},
	}

	var wg sync.WaitGroup

	type result struct {
		statusCode    int
		body          []byte
		contentLength string
		err           error
	}
	results := make([]result, len(reqs))

	for i, r := range reqs {
		wg.Add(1)
		go func(idx int, spec requestSpec) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ft.Ctx, spec.method, cacheURL, nil)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			if spec.rangeHeader != "" {
				req.Header.Set("Range", spec.rangeHeader)
			}

			httpClient := &http.Client{Transport: config.GetTransport()}
			resp, err := httpClient.Do(req)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[idx] = result{
				statusCode:    resp.StatusCode,
				body:          body,
				contentLength: resp.Header.Get("Content-Length"),
			}
		}(i, r)
	}
	wg.Wait()

	for i, r := range results {
		spec := reqs[i]
		require.NoError(t, r.err, "Request %d (%s %s) should not error", i, spec.method, spec.rangeHeader)

		if spec.method == "HEAD" {
			assert.True(t, r.statusCode == http.StatusOK || r.statusCode == http.StatusPartialContent,
				"HEAD request %d should return 200 or 206, got %d", i, r.statusCode)
			// HEAD should have Content-Length but empty body
			assert.Empty(t, r.body, "HEAD request %d should have empty body", i)
			assert.NotEmpty(t, r.contentLength, "HEAD request %d should have Content-Length", i)
		} else {
			// GET requests
			if spec.rangeHeader != "" {
				assert.Equal(t, http.StatusPartialContent, r.statusCode,
					"GET range request %d should return 206", i)
			} else {
				assert.Equal(t, http.StatusOK, r.statusCode,
					"GET full request %d should return 200", i)
				assert.Equal(t, content, r.body,
					"GET full request %d content mismatch", i)
			}
		}
	}
}

// ============================================================================
// Conditional request under concurrency
// ============================================================================

// TestConcurrent_ConditionalAndFullReads tests that conditional requests
// (If-None-Match) work correctly when mixed with full reads under concurrency.
func TestConcurrent_ConditionalAndFullReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(8192) // 8KB
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "concurrent_conditional.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/concurrent_conditional.bin")

	testToken := getTempTokenForTest(t)

	// Get the ETag from an initial request
	initialResult := doRangeRead(ft.Ctx, cacheURL, testToken, "", "")
	require.NoError(t, initialResult.err)

	// We need to get the ETag from the response headers - do a manual request
	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Skip("Cache did not return ETag; skipping conditional concurrency test")
	}

	type requestSpec struct {
		ifNoneMatch string // empty = unconditional GET
	}
	reqs := []requestSpec{
		{""}, {etag}, {""}, {etag}, {etag},
		{""}, {""}, {etag}, {""}, {etag},
	}

	var wg sync.WaitGroup
	type result struct {
		statusCode int
		body       []byte
		err        error
	}
	results := make([]result, len(reqs))

	for i, r := range reqs {
		wg.Add(1)
		go func(idx int, spec requestSpec) {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheURL, nil)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			if spec.ifNoneMatch != "" {
				req.Header.Set("If-None-Match", spec.ifNoneMatch)
			}

			resp, err := httpClient.Do(req)
			if err != nil {
				results[idx] = result{err: err}
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			results[idx] = result{statusCode: resp.StatusCode, body: body}
		}(i, r)
	}
	wg.Wait()

	for i, r := range results {
		spec := reqs[i]
		require.NoError(t, r.err, "Concurrent conditional/full read %d should not error", i)

		if spec.ifNoneMatch != "" {
			assert.Equal(t, http.StatusNotModified, r.statusCode,
				"Conditional request %d with matching ETag should return 304", i)
		} else {
			assert.Equal(t, http.StatusOK, r.statusCode,
				"Unconditional request %d should return 200", i)
			assert.Equal(t, content, r.body,
				"Unconditional request %d content mismatch", i)
		}
	}
}

// ============================================================================
// Thundering herd tests — same range from many goroutines
// ============================================================================

// TestConcurrent_ThunderingHerd_SameRange_CacheHit fires many simultaneous
// requests for the exact same byte range on a fully cached object.  This
// stresses the SeekableReader's shared state and verifies that no data
// corruption occurs when many goroutines read the same blocks at once.
func TestConcurrent_ThunderingHerd_SameRange_CacheHit(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(32768) // 32KB = ~8 blocks
	pelicanURL := uploadTestFile(ft.Ctx, t, ft, "herd_hit.bin", content)
	cacheURL := primeCache(ft.Ctx, t, ft, pelicanURL, "/test/herd_hit.bin")

	testToken := getTempTokenForTest(t)

	// All goroutines request the exact same range that spans two blocks.
	const rangeStart = 4000
	const rangeEnd = 8200
	rangeHeader := fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd)
	expected := content[rangeStart : rangeEnd+1]

	const numReaders = 30

	var wg sync.WaitGroup
	results := make([]rangeResult, numReaders)

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", rangeHeader)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Herd hit reader %d", i))
	}
}

// TestConcurrent_ThunderingHerd_SameRange_CacheMiss fires many simultaneous
// requests for the exact same byte range on an object that is NOT yet cached.
// The first request triggers a download from origin; all others must wait for
// (or join) that download and return the correct data.  This is the classic
// "thundering herd" scenario for a cache miss.
func TestConcurrent_ThunderingHerd_SameRange_CacheMiss(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	content := generateTestData(32768) // 32KB = ~8 blocks
	// Upload but do NOT prime the cache — all readers hit a miss.
	uploadTestFile(ft.Ctx, t, ft, "herd_miss.bin", content)

	testToken := getTempTokenForTest(t)
	cacheURL := getCacheRedirectURL(ft.Ctx, t, "/test/herd_miss.bin", testToken)

	const rangeStart = 4000
	const rangeEnd = 8200
	rangeHeader := fmt.Sprintf("bytes=%d-%d", rangeStart, rangeEnd)
	expected := content[rangeStart : rangeEnd+1]

	const numReaders = 30

	var wg sync.WaitGroup
	results := make([]rangeResult, numReaders)

	for i := 0; i < numReaders; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = doRangeRead(ft.Ctx, cacheURL, testToken, "", rangeHeader)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		requireSuccessfulRead(t, r, http.StatusPartialContent, expected,
			fmt.Sprintf("Herd miss reader %d", i))
	}
}
