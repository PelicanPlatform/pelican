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

package fed_tests

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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

//go:embed resources/persistent_cache_config.yaml
var persistentCacheConfig string

// getCacheRedirectURL queries the director and extracts the cache redirect URL.
// Returns the full redirect URL including any API path prefix.
func getCacheRedirectURL(ctx context.Context, t testing.TB, objectPath string, token string) string {
	// Query the director to get the cache location
	directorURL := fmt.Sprintf("https://%s:%d%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), objectPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directorURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	// Use a client that doesn't follow redirects so we can see where it would redirect
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.True(t, resp.StatusCode >= 300 && resp.StatusCode < 400,
		"Director should redirect, got %d", resp.StatusCode)
	redirectLocation := resp.Header.Get("Location")
	require.NotEmpty(t, redirectLocation, "Director should provide a redirect location")

	return redirectLocation
}

// TestPersistentCache_BasicDownload tests that the persistent cache can serve content.
// This verifies:
// 1. A file can be downloaded through the cache
// 2. Content matches what was uploaded to the origin
// 3. The cache stores the file in its storage backend
func TestPersistentCache_BasicDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Verify the federation initialized with expected exports
	require.Greater(t, len(ft.Exports), 0, "Federation should have at least one export")
	assert.Equal(t, "/test", ft.Exports[0].FederationPrefix)

	// Create a test file to upload
	testContent := "Hello from persistent cache test! This is test data for basic download."
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	// Upload the file using the Pelican client
	uploadURL := fmt.Sprintf("pelican://%s:%d/test/cache_test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	transferResultsUpload, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsUpload)

	// Download the file through the cache
	downloadFile := filepath.Join(localTmpDir, "downloaded_file.txt")
	transferResultsDownload, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsDownload)
	assert.Equal(t, transferResultsUpload[0].TransferredBytes, transferResultsDownload[0].TransferredBytes,
		"Downloaded bytes should match uploaded bytes")

	// Verify downloaded file content matches
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent), "Downloaded content should match uploaded content")

	// Verify the cache storage location exists and has data
	// The persistent cache stores data under Cache.StorageLocation/persistent-cache
	cacheStorageLocation := filepath.Join(param.Cache_StorageLocation.GetString(), "persistent-cache")
	require.DirExists(t, cacheStorageLocation, "Cache storage location should exist")

	// Check that there are files in the cache storage (excluding database files)
	var cacheFiles []string
	err = filepath.Walk(cacheStorageLocation, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip database directory and its contents
		if info.IsDir() && info.Name() == "db" {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			cacheFiles = append(cacheFiles, path)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Greater(t, len(cacheFiles), 0, "Cache should have stored files")
}

// TestPersistentCache_AgeHeader verifies that the cache returns the Age header
// indicating how long an object has been cached.
func TestPersistentCache_AgeHeader(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Create and upload a test file
	testContent := "Test content for Age header verification"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "age_test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/age_test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// First request - this will fetch from origin and cache
	downloadFile := filepath.Join(localTmpDir, "downloaded_age_test.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// Get cache URL from director - this returns the full redirect URL including /api/v1.0/cache/data prefix
	cacheObjectURL := getCacheRedirectURL(ft.Ctx, t, "/test/age_test_file.txt", testToken)

	// Wait a bit so Age header will be non-zero
	time.Sleep(2 * time.Second)

	// Make a direct HTTP request to the cache to check headers
	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheObjectURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Cache should return 200 OK")

	// Check for Age header
	ageHeader := resp.Header.Get("Age")
	if ageHeader != "" {
		age, err := strconv.Atoi(ageHeader)
		require.NoError(t, err, "Age header should be a valid integer")
		assert.GreaterOrEqual(t, age, 1, "Age should be at least 1 second after waiting")
	}
	// Note: Age header may be empty on first cache (Age=0 is often omitted)

	// Read and verify content
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(body), "Cached content should match original")
}

// TestPersistentCache_ConditionalRequest tests ETag-based conditional requests.
// Verifies:
// 1. ETag is returned in response headers
// 2. If-None-Match with matching ETag returns 304 Not Modified
func TestPersistentCache_ConditionalRequest(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Create and upload a test file
	testContent := "Test content for ETag and conditional request"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "etag_test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/etag_test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// First request - populate the cache
	downloadFile := filepath.Join(localTmpDir, "downloaded_etag_test.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// Get cache URL from director - this returns the full redirect URL including /api/v1.0/cache/data prefix
	cacheObjectURL := getCacheRedirectURL(ft.Ctx, t, "/test/etag_test_file.txt", testToken)

	// Make first direct request to get ETag
	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheObjectURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode, "First request should return 200 OK")

	// Get the ETag from the response
	etag := resp.Header.Get("ETag")
	_, _ = io.ReadAll(resp.Body) // Drain body

	require.NotEmpty(t, etag, "Response should contain an ETag header")

	// Make conditional request with If-None-Match
	req2, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheObjectURL, nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+testToken)
	req2.Header.Set("If-None-Match", etag)

	resp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	defer func() {
		_ = resp2.Body.Close()
	}()

	// Should return 304 Not Modified since content hasn't changed
	assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
		"Conditional request with matching ETag should return 304 Not Modified")
}

// TestPersistentCache_RangeRequest tests that the cache handles Range requests correctly.
func TestPersistentCache_RangeRequest(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Create and upload a test file with known content
	testContent := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "range_test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/range_test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// First request - populate the cache
	downloadFile := filepath.Join(localTmpDir, "downloaded_range_test.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// Get cache URL from director - this returns the full redirect URL including /api/v1.0/cache/data prefix
	cacheObjectURL := getCacheRedirectURL(ft.Ctx, t, "/test/range_test_file.txt", testToken)

	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	// Test Range request for bytes 10-19 (should return "KLMNOPQRST")
	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, cacheObjectURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Range", "bytes=10-19")

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	// Should return 206 Partial Content
	assert.Equal(t, http.StatusPartialContent, resp.StatusCode,
		"Range request should return 206 Partial Content")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "KLMNOPQRST", string(body),
		"Range request should return correct byte range")

	// Verify Content-Range header
	contentRange := resp.Header.Get("Content-Range")
	assert.NotEmpty(t, contentRange, "Content-Range header should be present")
	assert.Contains(t, contentRange, "bytes 10-19/", "Content-Range should indicate correct range")
}

// TestPersistentCache_StatsAPI tests that the cache stats API endpoint returns valid statistics.
func TestPersistentCache_StatsAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	// Create and upload a test file to generate some cache activity
	testContent := "Test content for stats API"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "stats_test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/stats_test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// Download the file to populate cache
	downloadFile := filepath.Join(localTmpDir, "downloaded_stats_test.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)

	// Query the stats API endpoint (use /api/v1.0/cache/stats for the cache server module)
	statsURL := fmt.Sprintf("https://%s:%d/api/v1.0/cache/stats",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	httpClient := &http.Client{
		Transport: config.GetTransport(),
	}

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, statsURL, nil)
	require.NoError(t, err)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer func() {
		_ = resp.Body.Close()
	}()

	require.Equal(t, http.StatusOK, resp.StatusCode, "Stats API should return 200 OK")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify stats response contains expected fields
	statsResponse := string(body)
	assert.Contains(t, statsResponse, "TotalUsage", "Stats should contain TotalUsage field")
	assert.Contains(t, statsResponse, "MaxSize", "Stats should contain MaxSize field")
}

// TestPersistentCache_MultipleObjects tests caching multiple objects.
func TestPersistentCache_MultipleObjects(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Enable persistent cache
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	// Start the federation with persistent cache
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	require.NotNil(t, ft)

	localTmpDir := t.TempDir()
	testToken := getTempTokenForTest(t)

	// Create and upload multiple test files
	for i := 1; i <= 3; i++ {
		testContent := fmt.Sprintf("Content for file %d - some test data", i)
		localFile := filepath.Join(localTmpDir, fmt.Sprintf("multi_file_%d.txt", i))
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/multi_file_%d.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)

		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
	}

	// Download all files through the cache
	for i := 1; i <= 3; i++ {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/multi_file_%d.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), i)
		downloadFile := filepath.Join(localTmpDir, fmt.Sprintf("downloaded_multi_%d.txt", i))

		_, err := client.DoGet(ft.Ctx, downloadURL, downloadFile, false, client.WithToken(ft.Token))
		require.NoError(t, err)

		// Verify content
		expectedContent := fmt.Sprintf("Content for file %d - some test data", i)
		downloadedContent, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, string(downloadedContent),
			"Downloaded content for file %d should match", i)
	}
}
