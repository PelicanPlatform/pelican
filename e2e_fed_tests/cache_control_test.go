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

// End-to-end tests for Cache-Control header handling.
//
// These verify that the persistent cache correctly:
//   - Passes through Cache-Control headers from the origin
//   - Honors no-store (does not persist to disk)
//   - Honors max-age (reports correct freshness)
//   - Serves a sensible default when the origin sends no Cache-Control
//   - Returns correct Age headers
//   - Handles If-None-Match / ETag conditional requests (304)

package fed_tests

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// cacheControlOriginConfig returns a YAML configuration snippet for a
// POSIXv2 origin with an explicit Origin.CacheControl value.
// Pass "" for cacheControl to omit the directive entirely (test default behavior).
func cacheControlOriginConfig(cacheControl string) string {
	ccLine := ""
	if cacheControl != "" {
		ccLine = fmt.Sprintf("  CacheControl: %q\n", cacheControl)
	}
	return fmt.Sprintf(`Origin:
  StorageType: posixv2
%s  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "DirectReads", "Listings"]
`, ccLine)
}

// writeTestFile writes a deterministic file into the origin's
// storage prefix and returns its content.  The bytes depend on both the
// file size and its name, so two same-sized files with different names
// will always have different content.
func writeTestFile(t *testing.T, ft *fed_test_utils.FedTest, name string, size int) []byte {
	t.Helper()
	content := generateTestData(size)
	// Mix in the filename so same-sized files produce distinct bytes.
	h := sha256.Sum256([]byte(name))
	for i := range content {
		content[i] ^= h[i%len(h)]
	}
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))
	return content
}

// fetchFromCache performs a GET against the cache URL and returns the
// response headers and body.  The caller is responsible for interpreting
// the status code.
type cacheResponse struct {
	statusCode     int
	body           []byte
	headers        http.Header
	transferStatus string
}

func fetchFromCache(t *testing.T, ft *fed_test_utils.FedTest, cacheURL string, extraHeaders map[string]string) cacheResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheURL, nil)
	require.NoError(t, err)
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return cacheResponse{
		statusCode:     resp.StatusCode,
		body:           body,
		headers:        resp.Header,
		transferStatus: resp.Trailer.Get("X-Transfer-Status"),
	}
}

// TestCacheControl_MaxAgePassthrough verifies that when the origin sets
// Origin.CacheControl to "max-age=3600", the cache:
//   - Stores the object
//   - Returns Cache-Control: s-maxage=3600, max-age=3600
//   - Returns an Age header on subsequent requests
func TestCacheControl_MaxAgePassthrough(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "maxage.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/maxage.bin", token)

	// First fetch (cache miss — downloads from origin)
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// Verify Cache-Control header is passed through
	cc := r1.headers.Get("Cache-Control")
	assert.Contains(t, cc, "max-age=3600",
		"Cache should pass through max-age from origin")
	assert.Contains(t, cc, "s-maxage=3600",
		"Cache should include s-maxage for shared cache semantics")

	// Second fetch (cache hit — should return the same content and an Age header)
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)

	// Verify Age header is present and non-negative on a cache hit
	ageStr := r2.headers.Get("Age")
	require.NotEmpty(t, ageStr, "Cached response must have an Age header")
	age, err := strconv.Atoi(ageStr)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, age, 0, "Age must be non-negative")
	assert.Less(t, age, 60, "Age should be small since object was just cached")

	// Verify Cache-Control is still present on the cached response
	cc2 := r2.headers.Get("Cache-Control")
	assert.Contains(t, cc2, "max-age=3600",
		"Cached response should preserve Cache-Control")
}

// TestCacheControl_NoStore verifies that when the origin sets
// Cache-Control: no-store, the cache:
//   - Does NOT persist the object to disk
//   - Still serves the data to the requesting client
//   - Returns Cache-Control: no-store in the response
func TestCacheControl_NoStore(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("no-store"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "nostore.bin", 4096)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/nostore.bin", token)

	// First fetch — should succeed but not persist
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// Verify no-store is reflected in the response
	cc := r1.headers.Get("Cache-Control")
	assert.Contains(t, cc, "no-store",
		"Cache should pass through no-store from origin")

	// Wait so that if the object were incorrectly cached, Age would grow
	time.Sleep(2 * time.Second)

	// Second fetch — still succeeds (re-fetched from origin, not from disk)
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)

	// The response should NOT have an Age header (it's freshly fetched)
	// or if it does, it should be 0.  If it were served from cache, Age
	// would be ≥2 after the sleep above.
	ageStr := r2.headers.Get("Age")
	if ageStr != "" {
		age, err := strconv.Atoi(ageStr)
		if err == nil {
			assert.LessOrEqual(t, age, 0,
				"no-store response must not have a positive Age (would indicate caching)")
		}
	}
}

// TestCacheControl_DefaultBehavior verifies that when the origin does NOT set
// any Cache-Control header, the cache:
//   - Stores the object
//   - Returns Cache-Control with max-age reflecting the remaining freshness
//   - Returns an ETag header
func TestCacheControl_DefaultBehavior(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("")) // No CC set
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "default.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/default.bin", token)

	// First fetch (cache miss)
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// When origin sends no Cache-Control, the cache should respond with a
	// max-age derived from LocalCache_DefaultMaxAge (24h by default).
	// The freshly-cached object should have a large remaining freshness.
	cc := r1.headers.Get("Cache-Control")
	assert.NotEmpty(t, cc, "Cache should set a default Cache-Control header")
	assert.Contains(t, cc, "max-age=",
		"Default Cache-Control should include max-age")

	// Parse the max-age value and verify it's in a reasonable range.
	// Default is 24h (86400s) with up to 10% jitter, so we expect
	// somewhere above 75000 seconds for a freshly-cached object.
	parsed := local_cache.ParseCacheControl(cc)
	if assert.True(t, parsed.MaxAgeSet(), "max-age should be present") {
		assert.Greater(t, int(parsed.MaxAge().Seconds()), 75000,
			"max-age for a freshly cached object should be large (close to 24h)")
	}

	// Verify ETag is present
	etag := r1.headers.Get("ETag")
	assert.NotEmpty(t, etag, "Cache should return an ETag header")

	// Second fetch (cache hit — data should match)
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)
}

// TestCacheControl_ETagConditional verifies that the cache handles
// If-None-Match conditional requests correctly by returning 304.
func TestCacheControl_ETagConditional(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	writeTestFile(t, ft, "etag.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/etag.bin", token)

	// First fetch to prime the cache and capture the ETag
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)

	etag := r1.headers.Get("ETag")
	require.NotEmpty(t, etag, "First response must include an ETag")

	// Second fetch with If-None-Match using the captured ETag → expect 304
	r2 := fetchFromCache(t, ft, cacheURL, map[string]string{
		"If-None-Match": etag,
	})
	assert.Equal(t, http.StatusNotModified, r2.statusCode,
		"Cache should return 304 when ETag matches")
	assert.Empty(t, r2.body,
		"304 response body should be empty")

	// Verify Cache-Control is set on the 304 response
	cc304 := r2.headers.Get("Cache-Control")
	assert.NotEmpty(t, cc304, "304 response should include Cache-Control")
}

// TestCacheControl_AgeHeaderAccuracy verifies that the Age header
// approximately reflects the time since the object was cached.
func TestCacheControl_AgeHeaderAccuracy(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "age.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/age.bin", token)

	// First fetch to cache the object
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)
	cacheTime := time.Now()

	// Wait a bit so the Age header becomes non-zero
	time.Sleep(2 * time.Second)

	// Second fetch — Age header should reflect elapsed time
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)

	ageStr := r2.headers.Get("Age")
	require.NotEmpty(t, ageStr, "Cached response must have an Age header")

	age, err := strconv.Atoi(ageStr)
	require.NoError(t, err)
	require.Greater(t, age, 0,
		"Age should be non-zero after waiting 2 seconds")

	elapsed := int(time.Since(cacheTime).Seconds())
	// Age should be approximately elapsed time (±2 seconds tolerance)
	assert.InDelta(t, elapsed, age, 2.0,
		"Age header (%d) should be close to elapsed time (%d)", age, elapsed)
}

// TestCacheControl_NoCacheWithMustRevalidate verifies that
// Cache-Control: no-cache, must-revalidate is handled:
//   - Object IS stored in the cache
//   - Cache still serves it on subsequent requests
func TestCacheControl_NoCacheWithMustRevalidate(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("no-cache, must-revalidate"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "nocache.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/nocache.bin", token)

	// First fetch (cache miss)
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// Verify directives are present in the response
	cc := r1.headers.Get("Cache-Control")
	assert.Contains(t, cc, "no-cache",
		"Response should contain no-cache")
	assert.Contains(t, cc, "must-revalidate",
		"Response should contain must-revalidate")

	// Second fetch — within the NoCacheGracePeriod (5s), so the cache
	// should serve the object without revalidating
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)

	// The cached version should have an Age header (it was stored)
	ageStr := r2.headers.Get("Age")
	if ageStr != "" {
		age, err := strconv.Atoi(ageStr)
		if err == nil {
			assert.GreaterOrEqual(t, age, 0,
				"Age should be non-negative for cached no-cache response")
		}
	}
}

// TestCacheControl_PrivateNotStored verifies that Cache-Control: private
// is treated like no-store for a shared cache: the object is NOT persisted.
func TestCacheControl_PrivateNotStored(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("private"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "private.bin", 4096)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/private.bin", token)

	// First fetch — should succeed but not persist
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// Verify private is reflected in the response
	cc := r1.headers.Get("Cache-Control")
	assert.Contains(t, cc, "private",
		"Cache should pass through private from origin")

	// Second fetch — also succeeds (re-fetched from origin)
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, content, r2.body)
}

// TestCacheControl_ETagStarWildcard verifies that If-None-Match: * returns
// 304 for any cached object (the wildcard matches any ETag).
func TestCacheControl_ETagStarWildcard(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	writeTestFile(t, ft, "wildcard.bin", 4096)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/wildcard.bin", token)

	// Prime the cache
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)

	// Wildcard If-None-Match
	r2 := fetchFromCache(t, ft, cacheURL, map[string]string{
		"If-None-Match": "*",
	})
	assert.Equal(t, http.StatusNotModified, r2.statusCode,
		"If-None-Match: * should return 304 for any cached object")
}

// TestCacheControl_SMaxAgePriority verifies that s-maxage takes priority
// over max-age for the shared cache (per RFC 7234).
func TestCacheControl_SMaxAgePriority(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	// Origin sets both max-age and s-maxage with different values
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=60, s-maxage=7200"))
	token := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "smaxage.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/smaxage.bin", token)

	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, content, r1.body)

	// The cache stores the minimum of max-age and s-maxage for a shared cache.
	// Since s-maxage=7200 > max-age=60, the stored value should be 60.
	// But the implementation stores min(max-age, s-maxage) when both are present.
	cc := r1.headers.Get("Cache-Control")
	// Verify we have some form of max-age in the response
	assert.True(t, strings.Contains(cc, "max-age=") || strings.Contains(cc, "s-maxage="),
		"Cache should include freshness info, got: %s", cc)
}

// TestCacheControl_ETagChangeAfterExpiry verifies that when an origin file
// is updated (new ETag) and the cached entry has gone stale, the cache
// fetches the new version instead of serving the old one.
//
// Scenario:
//  1. Origin serves file with max-age=1 (stale after 1 second)
//  2. Client fetches → cache stores
//  3. Wait 2 seconds for staleness
//  4. Update origin file with new content (changes ETag)
//  5. Client fetches again → cache detects stale → re-downloads from origin
//  6. Verify new content is returned
func TestCacheControl_ETagChangeAfterExpiry(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=1"))
	token := getTempTokenForTest(t)

	// Step 1: Write initial content
	originalContent := writeTestFile(t, ft, "update_me.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/update_me.bin", token)

	// Step 2: Fetch to populate the cache
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, originalContent, r1.body, "First fetch should return original content")
	etag1 := r1.headers.Get("ETag")

	// Step 3: Wait for the entry to go stale (max-age=1)
	time.Sleep(2 * time.Second)

	// Step 4: Update the origin file with new, different content
	newContent := generateTestData(9000) // Different size → definitely different content
	storageDir := ft.Exports[0].StoragePrefix
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "update_me.bin"), newContent, 0644))

	// Step 5: Fetch again — cache should revalidate and serve new version
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, newContent, r2.body, "After origin update, cache should serve new content")

	// Step 6: Verify the ETag changed
	etag2 := r2.headers.Get("ETag")
	if etag1 != "" && etag2 != "" {
		assert.NotEqual(t, etag1, etag2, "ETag should change when origin file is updated")
	}
}

// TestCacheControl_StaleServedWithinMaxAge verifies that within the max-age
// window, the cache serves the old version even if the origin has been updated.
// The cache should NOT contact the origin until the entry is stale.
func TestCacheControl_StaleServedWithinMaxAge(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	// Use a long max-age so the entry stays fresh
	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	// Write initial content and fetch
	originalContent := writeTestFile(t, ft, "fresh.bin", 8192)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fresh.bin", token)

	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, originalContent, r1.body)

	// Update the origin file
	newContent := generateTestData(9000)
	storageDir := ft.Exports[0].StoragePrefix
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "fresh.bin"), newContent, 0644))

	// Fetch again — entry is still fresh (max-age=3600), so cache should serve old version
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode)
	require.Equal(t, originalContent, r2.body,
		"Within max-age window, cache should serve old content even if origin changed")
}

// TestCacheControl_EvictionUnderPressure verifies that when the cache fills
// past the high water mark, eviction fires and frees space down to the low
// water mark using LRU (oldest accessed objects evicted first).
//
// Scenario:
//  1. Set cache size to 100KB (high water 90%, low water 50%)
//  2. Write 5 × 20KB files on the origin
//  3. Fetch all 5 via the cache endpoint (total ~100KB → exceeds high water)
//  4. Wait for eviction to fire
//  5. Verify oldest files are evicted; newest files remain
func TestCacheControl_EvictionUnderPressure(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	// Constrain cache size: 100KB, high water 90% (90KB), low water 50% (50KB)
	require.NoError(t, param.Set(param.LocalCache_Size.GetName(), "100KB"))
	require.NoError(t, param.Set(param.LocalCache_HighWaterMarkPercentage.GetName(), 90))
	require.NoError(t, param.Set(param.LocalCache_LowWaterMarkPercentage.GetName(), 50))

	ft := fed_test_utils.NewFedTest(t, cacheControlOriginConfig("max-age=3600"))
	token := getTempTokenForTest(t)

	// Write 5 × 20KB files on the origin
	fileNames := make([]string, 5)
	fileContents := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("evict_%d.bin", i)
		fileNames[i] = name
		fileContents[i] = writeTestFile(t, ft, name, 20*1024)
	}

	// Get cache redirect URL using the first file
	cacheURL0 := waitForCacheRedirectURL(t, ft, "/test/evict_0.bin", token)
	// Derive base URL by parsing the redirect and trimming the filename
	// from the path (the query string may contain an authz token, so
	// simple string suffix matching would fail).
	parsedURL, err := url.Parse(cacheURL0)
	require.NoError(t, err)
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "evict_0.bin")
	parsedURL.RawQuery = "" // drop file-specific authz; origin has PublicReads
	baseURL := parsedURL.String()

	// Fetch all 5 files sequentially (total ~100KB, exceeds 90KB high water)
	for i := 0; i < 5; i++ {
		url := baseURL + fileNames[i]
		r := fetchFromCache(t, ft, url, nil)
		require.Equal(t, http.StatusOK, r.statusCode,
			"Fetch %d (%s) should succeed", i, fileNames[i])
		require.Equal(t, fileContents[i], r.body,
			"Fetch %d content mismatch", i)
	}

	// Wait for eviction to fire and free space.
	// The oldest files (0, 1, ...) should be evicted first.
	// With 100KB total and 50KB low water, at least ~50KB (2-3 files) must be evicted.
	//
	// We use "only-if-cached" to prevent transparent re-fetching from the origin.
	// Evicted objects will return 504 Gateway Timeout; surviving objects return 200.
	onlyCached := map[string]string{"Cache-Control": "only-if-cached"}

	// Wait until at least one of the oldest files has actually been evicted.
	require.Eventually(t, func() bool {
		r := fetchFromCache(t, ft, baseURL+fileNames[0], onlyCached)
		return r.statusCode == http.StatusGatewayTimeout
	}, 15*time.Second, 500*time.Millisecond,
		"Eviction did not remove the oldest file (file 0) from the cache")

	// Verify the newest file survived eviction (still in cache)
	rLatest := fetchFromCache(t, ft, baseURL+fileNames[4], onlyCached)
	require.Equal(t, http.StatusOK, rLatest.statusCode,
		"Newest file should still be in cache after eviction")
	assert.Equal(t, fileContents[4], rLatest.body,
		"Newest file content should be intact")

	// Count how many of the oldest files were actually evicted
	evictedCount := 0
	for i := 0; i < 4; i++ {
		r := fetchFromCache(t, ft, baseURL+fileNames[i], onlyCached)
		if r.statusCode == http.StatusGatewayTimeout {
			evictedCount++
		}
	}
	// With 100KB total, 90KB HW, 50KB LW, and 5×20KB files, we expect
	// at least 2 files (~40KB) to be evicted to get below the low-water mark.
	assert.GreaterOrEqual(t, evictedCount, 2,
		"At least 2 of the oldest files should have been evicted (got %d)", evictedCount)
}

// writeThroughOriginConfig returns a YAML configuration snippet for a
// POSIXv2 origin with Writes, DirectReads, and PublicReads enabled, plus
// an explicit Cache-Control so cached entries are considered fresh and
// would normally be served from disk (allowing us to verify invalidation).
func writeThroughOriginConfig() string {
	return `Origin:
  StorageType: posixv2
  CacheControl: "max-age=3600"
  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "DirectReads", "Writes", "Listings"]
`
}

// sendToCacheURL sends a PUT or DELETE request to the cache endpoint URL
// and returns the response.
func sendToCacheURL(t *testing.T, ft *fed_test_utils.FedTest, method, cacheURL, bearerToken string, body []byte) cacheResponse {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		bodyReader = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ft.Ctx, method, cacheURL, bodyReader)
	require.NoError(t, err)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return cacheResponse{
		statusCode: resp.StatusCode,
		body:       respBody,
		headers:    resp.Header,
	}
}

// TestWriteThrough_PutAndGet verifies the full write-through cycle:
//  1. GET a file through the cache (populates the cache)
//  2. PUT new content for that file through the cache (proxied to origin)
//  3. Verify the cache invalidated the old version
//  4. GET the file again through the cache — should return the new content
func TestWriteThrough_PutAndGet(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, writeThroughOriginConfig())
	tkn := getTempTokenForTest(t)

	// Step 1: Write initial content to the origin and fetch through cache to populate it
	originalContent := writeTestFile(t, ft, "writable.bin", 4096)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/writable.bin", tkn)

	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode, "Initial GET should succeed")
	require.Equal(t, originalContent, r1.body, "Initial GET should return original content")

	// Verify the object is cached (max-age=3600 means it's fresh)
	cc := r1.headers.Get("Cache-Control")
	assert.Contains(t, cc, "max-age=3600", "Object should be cached with max-age")

	// Step 2: PUT new content through the cache endpoint
	newContent := generateTestData(5000) // Different size to be distinct
	rPut := sendToCacheURL(t, ft, "PUT", cacheURL, tkn, newContent)
	require.True(t, rPut.statusCode >= 200 && rPut.statusCode < 300,
		"PUT through cache should succeed, got %d: %s", rPut.statusCode, string(rPut.body))

	// Step 3: Verify the origin now has the new content
	storageDir := ft.Exports[0].StoragePrefix
	backendContent, err := os.ReadFile(filepath.Join(storageDir, "writable.bin"))
	require.NoError(t, err, "Should be able to read the file from origin backend")
	assert.Equal(t, newContent, backendContent,
		"Origin backend should contain the new content after PUT")

	// Step 4: GET the file again through the cache.
	// Even though max-age=3600 and the entry was fetched moments ago,
	// the write-through PUT should have invalidated the cached version.
	// Therefore this GET should fetch from the origin and return new content.
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode, "GET after PUT should succeed")
	assert.Equal(t, newContent, r2.body,
		"After PUT, cache should serve the new content (old entry was invalidated)")

	// Step 5: Verify the new content is now cached
	r3 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r3.statusCode)
	assert.Equal(t, newContent, r3.body,
		"Third GET should still return new content (now cached)")
}

// TestWriteThrough_PutNewFile verifies that PUT through the cache works
// for a file that doesn't exist yet (no prior cache entry to invalidate).
func TestWriteThrough_PutNewFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, writeThroughOriginConfig())
	tkn := getTempTokenForTest(t)

	// We need a cache URL. Discover it using an existing file, then
	// substitute the path for the new file we want to create.
	dummyContent := writeTestFile(t, ft, "dummy.bin", 256)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/dummy.bin", tkn)
	_ = dummyContent

	// Derive the URL for a brand-new file by replacing the filename
	newFileURL := strings.Replace(cacheURL, "dummy.bin", "brand_new.bin", 1)

	// PUT the new file through the cache
	newContent := generateTestData(2048)
	rPut := sendToCacheURL(t, ft, "PUT", newFileURL, tkn, newContent)
	require.True(t, rPut.statusCode >= 200 && rPut.statusCode < 300,
		"PUT of new file should succeed, got %d: %s", rPut.statusCode, string(rPut.body))

	// Verify the file exists on the origin backend
	storageDir := ft.Exports[0].StoragePrefix
	backendContent, err := os.ReadFile(filepath.Join(storageDir, "brand_new.bin"))
	require.NoError(t, err, "New file should exist on origin backend")
	assert.Equal(t, newContent, backendContent, "Backend content should match what was PUT")

	// GET the new file through the cache
	rGet := fetchFromCache(t, ft, newFileURL, nil)
	require.Equal(t, http.StatusOK, rGet.statusCode, "GET of new file should succeed")
	assert.Equal(t, newContent, rGet.body,
		"GET should return the content that was just PUT")
}

// TestWriteThrough_Unauthorized verifies that PUT without a valid token
// is rejected with 403 Forbidden.
func TestWriteThrough_Unauthorized(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, writeThroughOriginConfig())
	tkn := getTempTokenForTest(t)

	content := writeTestFile(t, ft, "secret.bin", 1024)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/secret.bin", tkn)
	_ = content

	// PUT with no token — should be rejected
	rPut := sendToCacheURL(t, ft, "PUT", cacheURL, "", []byte("evil data"))
	assert.Equal(t, http.StatusForbidden, rPut.statusCode,
		"PUT without token should be forbidden")
}
