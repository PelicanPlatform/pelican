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

// Package fed_tests contains comprehensive tests for HTTP conditional requests
// (If-None-Match, If-Modified-Since) and Cache-Control behavior. These tests
// verify RFC 7232 compliance for the POSIXv2 origin backend and persistent cache.

package fed_tests

import (
	"context"
	_ "embed"
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

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// getOriginURL returns the direct URL to the origin server for an object
func getOriginURL(t *testing.T, objectPath string) string {
	return fmt.Sprintf("https://%s:%d/api/v1.0/origin/data%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)
}

// setupTestFileOnOrigin creates and uploads a test file, returning the content and URL
func setupTestFileOnOrigin(ctx context.Context, t *testing.T, ft *fed_test_utils.FedTest, filename, content string) (string, string) {
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, filename)
	// Ensure parent directory exists for files in subdirectories
	require.NoError(t, os.MkdirAll(filepath.Dir(localFile), 0755))
	require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	return content, fmt.Sprintf("/test/%s", filename)
}

// makeRequest makes an HTTP request to the origin with optional conditional headers
func makeRequest(ctx context.Context, t *testing.T, url string, headers map[string]string) *http.Response {
	testToken := getTempTokenForTest(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

// ============================================================================
// If-None-Match Tests (ETag-based conditional requests)
// ============================================================================

// TestConditionalRequests runs each case below against one shared federation. Starting a
// federation (five services plus XRootD) dominates the run time of these
// cases, so they share one and keep their object names distinct instead.
func TestConditionalRequests(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Cache_EnableV2.Set(true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Origin_IfNoneMatch_MatchingETag tests that origin returns 304 when ETag matches
	t.Run("Origin_IfNoneMatch_MatchingETag", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_none_match_test.txt", "Test content for If-None-Match")
		originURL := getOriginURL(t, objectPath)

		// First request - get the ETag
		resp1 := makeRequest(ft.Ctx, t, originURL, nil)
		defer resp1.Body.Close()
		require.Equal(t, http.StatusOK, resp1.StatusCode)

		etag := resp1.Header.Get("ETag")
		require.NotEmpty(t, etag, "Origin should return ETag header")

		body1, _ := io.ReadAll(resp1.Body)
		assert.Equal(t, content, string(body1))

		// Second request - with matching If-None-Match
		resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": etag,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Origin should return 304 Not Modified for matching ETag")

		// Body should be empty for 304
		body2, _ := io.ReadAll(resp2.Body)
		assert.Empty(t, body2, "304 response should have empty body")

		// ETag header should still be present in 304 response
		assert.Equal(t, etag, resp2.Header.Get("ETag"), "304 response should include ETag")
	})

	// Origin_IfNoneMatch_NonMatchingETag tests that origin returns 200 when ETag doesn't match
	t.Run("Origin_IfNoneMatch_NonMatchingETag", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_none_match_nonmatch_test.txt", "Test content for non-matching ETag")
		originURL := getOriginURL(t, objectPath)

		// Request with non-matching ETag
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": `"definitely-wrong-etag"`,
		})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Origin should return 200 OK for non-matching ETag")

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, content, string(body))
	})

	// Origin_IfNoneMatch_MultipleETags tests If-None-Match with multiple ETags
	t.Run("Origin_IfNoneMatch_MultipleETags", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_none_match_multi_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Get the actual ETag
		resp1 := makeRequest(ft.Ctx, t, originURL, nil)
		etag := resp1.Header.Get("ETag")
		resp1.Body.Close()
		require.NotEmpty(t, etag)

		// Test with multiple ETags (matching one in the middle)
		resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": `"wrong1", ` + etag + `, "wrong2"`,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Origin should return 304 when one of multiple ETags matches")
	})

	// Origin_IfNoneMatch_Wildcard tests If-None-Match with wildcard (*)
	t.Run("Origin_IfNoneMatch_Wildcard", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_none_match_wildcard_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Request with wildcard If-None-Match
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": "*",
		})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp.StatusCode,
			"Origin should return 304 for If-None-Match: * on existing resource")
	})

	// Origin_IfNoneMatch_WeakETag tests weak ETag comparison
	t.Run("Origin_IfNoneMatch_WeakETag", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_none_match_weak_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Get the actual ETag
		resp1 := makeRequest(ft.Ctx, t, originURL, nil)
		etag := resp1.Header.Get("ETag")
		resp1.Body.Close()
		require.NotEmpty(t, etag)

		// Test with weak ETag prefix (W/...)
		// Per RFC 7232, weak comparison for GET should match
		weakETag := "W/" + etag
		resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": weakETag,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Origin should use weak comparison for GET requests with W/ prefix")
	})

	// Origin_IfModifiedSince_NotModified tests that origin returns 304 when file hasn't changed
	t.Run("Origin_IfModifiedSince_NotModified", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_modified_since_test.txt", "Test content for If-Modified-Since")
		originURL := getOriginURL(t, objectPath)

		// First request - get Last-Modified
		resp1 := makeRequest(ft.Ctx, t, originURL, nil)
		defer resp1.Body.Close()
		require.Equal(t, http.StatusOK, resp1.StatusCode)

		lastModified := resp1.Header.Get("Last-Modified")
		require.NotEmpty(t, lastModified, "Origin should return Last-Modified header")
		_, _ = io.ReadAll(resp1.Body)

		// Second request - with If-Modified-Since (using same time - should return 304)
		resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-Modified-Since": lastModified,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Origin should return 304 when file hasn't been modified since the given time")
	})

	// Origin_IfModifiedSince_Modified tests that origin returns 200 when file is newer
	t.Run("Origin_IfModifiedSince_Modified", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_modified_since_modified_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Request with old If-Modified-Since (file should be newer)
		oldTime := time.Now().Add(-24 * time.Hour).UTC().Format(http.TimeFormat)
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-Modified-Since": oldTime,
		})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Origin should return 200 when file has been modified since the given time")

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, content, string(body))
	})

	// Origin_IfModifiedSince_FutureDate tests If-Modified-Since with a future date
	t.Run("Origin_IfModifiedSince_FutureDate", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_modified_since_future_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Request with future If-Modified-Since (should return 304)
		futureTime := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-Modified-Since": futureTime,
		})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp.StatusCode,
			"Origin should return 304 when If-Modified-Since is in the future")
	})

	// Origin_IfModifiedSince_InvalidDate tests that invalid dates are ignored
	t.Run("Origin_IfModifiedSince_InvalidDate", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "if_modified_since_invalid_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Request with invalid date format
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-Modified-Since": "not-a-valid-date",
		})
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"Origin should ignore invalid If-Modified-Since and return 200")

		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, content, string(body))
	})

	// Origin_CombinedHeaders_IfNoneMatchTakesPrecedence tests RFC 7232 precedence rules
	t.Run("Origin_CombinedHeaders_IfNoneMatchTakesPrecedence", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "combined_headers_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		// Get ETag
		resp1 := makeRequest(ft.Ctx, t, originURL, nil)
		etag := resp1.Header.Get("ETag")
		resp1.Body.Close()
		require.NotEmpty(t, etag)

		// Test: If-None-Match matches, If-Modified-Since doesn't matter (should be 304)
		oldTime := time.Now().Add(-24 * time.Hour).UTC().Format(http.TimeFormat)
		resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match":     etag,
			"If-Modified-Since": oldTime, // This would normally return 200 alone
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"If-None-Match should take precedence per RFC 7232")

		// Test: If-None-Match doesn't match - should return 200 regardless of If-Modified-Since
		futureTime := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
		resp3 := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match":     `"wrong-etag"`,
			"If-Modified-Since": futureTime, // This would return 304 alone
		})
		defer resp3.Body.Close()

		assert.Equal(t, http.StatusOK, resp3.StatusCode,
			"Non-matching If-None-Match should return 200, ignoring If-Modified-Since")

		body, _ := io.ReadAll(resp3.Body)
		assert.Equal(t, content, string(body))
	})

	// Cache_IfNoneMatch_CachedContent tests that cache returns 304 for matching ETag
	t.Run("Cache_IfNoneMatch_CachedContent", func(t *testing.T) {
		// Setup test file
		content, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "cache_if_none_match_test.txt", "Test content for cache conditional request")

		// Populate cache through Pelican client
		localTmpDir := t.TempDir()
		uploadURL := fmt.Sprintf("pelican://%s:%d%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)
		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)

		// Get cache URL
		testToken := getTempTokenForTest(t)
		cacheURL := getCacheRedirectURL(ft.Ctx, t, objectPath, testToken)

		// First request to cache - get ETag
		resp1 := makeRequest(ft.Ctx, t, cacheURL, nil)
		defer resp1.Body.Close()
		require.Equal(t, http.StatusOK, resp1.StatusCode)

		etag := resp1.Header.Get("ETag")
		require.NotEmpty(t, etag, "Cache should return ETag header")

		body1, _ := io.ReadAll(resp1.Body)
		assert.Equal(t, content, string(body1))

		// Second request with matching If-None-Match
		resp2 := makeRequest(ft.Ctx, t, cacheURL, map[string]string{
			"If-None-Match": etag,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Cache should return 304 Not Modified for matching ETag")
	})

	// Cache_IfModifiedSince_CachedContent tests that cache returns 304 for If-Modified-Since
	t.Run("Cache_IfModifiedSince_CachedContent", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "cache_if_modified_since_test.txt", "Test content")

		// Populate cache
		localTmpDir := t.TempDir()
		uploadURL := fmt.Sprintf("pelican://%s:%d%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)
		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)

		// Get cache URL
		testToken := getTempTokenForTest(t)
		cacheURL := getCacheRedirectURL(ft.Ctx, t, objectPath, testToken)

		// Get Last-Modified from cache
		resp1 := makeRequest(ft.Ctx, t, cacheURL, nil)
		lastModified := resp1.Header.Get("Last-Modified")
		resp1.Body.Close()
		require.NotEmpty(t, lastModified, "Cache should return Last-Modified header")

		// Request with matching If-Modified-Since
		resp2 := makeRequest(ft.Ctx, t, cacheURL, map[string]string{
			"If-Modified-Since": lastModified,
		})
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
			"Cache should return 304 when content hasn't been modified")
	})

	// Origin_ETagFormat tests that ETag format is valid and consistent
	t.Run("Origin_ETagFormat", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "etag_format_test.txt", "Test content for ETag format")
		originURL := getOriginURL(t, objectPath)

		// Make multiple requests and verify ETag format and consistency
		var previousETag string
		for i := 0; i < 3; i++ {
			resp := makeRequest(ft.Ctx, t, originURL, nil)
			etag := resp.Header.Get("ETag")
			resp.Body.Close()

			require.NotEmpty(t, etag, "ETag should be present")

			// Verify ETag format: should be quoted string (strong) or W/"..." (weak)
			isStrong := strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`)
			isWeak := strings.HasPrefix(etag, `W/"`) && strings.HasSuffix(etag, `"`)
			assert.True(t, isStrong || isWeak, "ETag should be properly quoted: %s", etag)

			// Verify consistency
			if previousETag != "" {
				assert.Equal(t, previousETag, etag, "ETag should be consistent across requests")
			}
			previousETag = etag
		}
	})

	// Origin_LastModifiedFormat tests that Last-Modified header format is valid
	t.Run("Origin_LastModifiedFormat", func(t *testing.T) {
		// Setup test file
		_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "last_modified_format_test.txt", "Test content")
		originURL := getOriginURL(t, objectPath)

		resp := makeRequest(ft.Ctx, t, originURL, nil)
		defer resp.Body.Close()

		lastModified := resp.Header.Get("Last-Modified")
		require.NotEmpty(t, lastModified, "Last-Modified should be present")

		// Verify it can be parsed as HTTP date
		parsedTime, err := http.ParseTime(lastModified)
		require.NoError(t, err, "Last-Modified should be a valid HTTP date format")

		// Should be in the past or very recent
		assert.True(t, parsedTime.Before(time.Now().Add(time.Minute)),
			"Last-Modified should be in the past or very recent")
	})

	// Origin_ConditionalRequest_NonExistentFile tests conditional request for missing file
	t.Run("Origin_ConditionalRequest_NonExistentFile", func(t *testing.T) {
		originURL := getOriginURL(t, "/test/nonexistent_file.txt")

		// Request with If-None-Match for non-existent file
		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": `"some-etag"`,
		})
		defer resp.Body.Close()

		// Should return 404, not 304
		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"Non-existent file should return 404 even with conditional headers")
	})

	// Origin_ConditionalRequest_Directory tests conditional request for directory
	t.Run("Origin_ConditionalRequest_Directory", func(t *testing.T) {
		// Create a file in a subdirectory to ensure the directory exists
		_, _ = setupTestFileOnOrigin(ft.Ctx, t, ft, "subdir/file.txt", "Test content")

		// Request the directory (not the file)
		originURL := getOriginURL(t, "/test/subdir/")

		resp := makeRequest(ft.Ctx, t, originURL, map[string]string{
			"If-None-Match": `"some-etag"`,
		})
		defer resp.Body.Close()

		// Directory requests shouldn't get 304 for ETags (ETags are for files)
		// Response could be various things depending on WebDAV config, but not 304
		assert.NotEqual(t, http.StatusNotModified, resp.StatusCode,
			"Directory listing shouldn't return 304 for If-None-Match")
	})
}

// TestOrigin_CacheControlHeader tests that Cache-Control header is set appropriately
func TestOrigin_CacheControlHeader(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Origin_CacheControl.Set("no-cache, must-revalidate"))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	// Setup test file
	_, objectPath := setupTestFileOnOrigin(ft.Ctx, t, ft, "cache_control_test.txt", "Test content")
	originURL := getOriginURL(t, objectPath)

	// Test 200 response includes Cache-Control: no-cache, must-revalidate
	resp1 := makeRequest(ft.Ctx, t, originURL, nil)
	resp1.Body.Close()

	require.Equal(t, http.StatusOK, resp1.StatusCode)
	cacheControl := resp1.Header.Get("Cache-Control")
	t.Logf("Normal request Cache-Control: %q", cacheControl)
	assert.Equal(t, "no-cache, must-revalidate", cacheControl,
		"200 response should include Cache-Control: no-cache, must-revalidate")

	// Test 304 response also includes Cache-Control: no-cache, must-revalidate
	etag := resp1.Header.Get("ETag")
	require.NotEmpty(t, etag, "ETag should be present on 200 response")

	resp2 := makeRequest(ft.Ctx, t, originURL, map[string]string{
		"If-None-Match": etag,
	})
	defer resp2.Body.Close()

	require.Equal(t, http.StatusNotModified, resp2.StatusCode)
	cacheControl304 := resp2.Header.Get("Cache-Control")
	t.Logf("304 response Cache-Control: %q", cacheControl304)
	assert.Equal(t, "no-cache, must-revalidate", cacheControl304,
		"304 response should include Cache-Control: no-cache, must-revalidate")
}
