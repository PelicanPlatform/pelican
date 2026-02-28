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

// End-to-end tests for federation token handling.
//
// These verify that the persistent cache correctly includes the
// federation token when fetching data from origins that have
// Origin.DisableDirectClients enabled.  Such origins reject
// requests that lack a token issued by the federation.

package fed_tests

import (
	_ "embed"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

//go:embed resources/fed_token_posixv2_public.yaml
var fedTokenPosixv2PublicConfig string

//go:embed resources/fed_token_posix_public.yaml
var fedTokenPosixPublicConfig string

//go:embed resources/fed_token_posixv2_reads.yaml
var fedTokenPosixv2ReadsConfig string

// TestFedToken_DisableDirectClients verifies end-to-end that the
// persistent cache can serve objects from a POSIXv2 origin with
// Origin.DisableDirectClients enabled.
//
// When DisableDirectClients is true the origin's auth middleware
// rejects every request that does not carry a federation-issued token.
// The persistent cache must:
//  1. Receive the federation token in-memory from LaunchFedTokManager.
//  2. Combine it with the user's bearer token in the Authorization header.
//  3. Route the request through /api/v1.0/director/origin/ (not ?directread)
//     because the origin cannot advertise DirectReads.
//
// A successful 200 response proves all three steps work correctly.
func TestFedToken_DisableDirectClients(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, fedTokenPosixv2PublicConfig)

	content := generateTestData(8192)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, "fed_token_test.bin")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))

	// The origin has PublicReads so we don't need a user token for read
	// authorization on the origin side.  The cache still requires one for
	// its own auth check, and it must also present the federation token
	// to the origin.
	token := getTempTokenForTest(t)

	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fed_token_test.bin", token)

	resp := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, resp.statusCode,
		"Cache should successfully fetch from origin with DisableDirectClients; "+
			"non-200 indicates the federation token was not sent or the routing was wrong")
	assert.Equal(t, content, resp.body,
		"Content returned through cache should match what was written to origin")
}

// TestFedToken_DisableDirectClients_SecondFetch verifies that a second
// fetch (cache hit) also succeeds and returns the correct data.
// This ensures that metadata and storage were persisted correctly on the
// first fetch despite the DisableDirectClients routing change.
func TestFedToken_DisableDirectClients_SecondFetch(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, fedTokenPosixv2PublicConfig)

	content := generateTestData(16384)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, "fed_token_second.bin")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))

	token := getTempTokenForTest(t)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fed_token_second.bin", token)

	// First fetch — cache miss, downloads from origin
	r1 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r1.statusCode, "First fetch (cache miss) should succeed")
	require.Equal(t, content, r1.body)

	// Second fetch — cache hit, served from disk
	r2 := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, r2.statusCode, "Second fetch (cache hit) should succeed")
	assert.Equal(t, content, r2.body, "Cached content should match original")

	// Verify this was actually a cache hit by checking the Age header.
	// On a hit the cache returns the time elapsed since the object was
	// stored; on a miss the object has just been fetched so Age is 0.
	ageStr := r2.headers.Get("Age")
	require.NotEmpty(t, ageStr, "Second fetch should include an Age header (cache hit)")
	age, err := strconv.Atoi(ageStr)
	require.NoError(t, err, "Age header should be a valid integer")
	assert.GreaterOrEqual(t, age, 0, "Age must be non-negative")
}

// TestFedToken_DirectFetchWithoutFedToken verifies that a direct
// request to the origin (bypassing the cache) is rejected when
// DisableDirectClients is enabled and no federation token is provided.
// This confirms that the guard is active and the test is meaningful.
func TestFedToken_DirectFetchWithoutFedToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, fedTokenPosixv2PublicConfig)

	content := generateTestData(4096)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, "fed_token_direct.bin")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))

	// Build a direct URL to the origin's data endpoint (no federation token).
	originURL := param.Origin_Url.GetString()
	require.NotEmpty(t, originURL, "Origin URL should be set")
	directURL := originURL + "/api/v1.0/origin/data/test/fed_token_direct.bin"

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, directURL, nil)
	require.NoError(t, err)
	// Deliberately do NOT set a federation token — only a regular user token.
	token := getTempTokenForTest(t)
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"Direct request without federation token should be rejected (401)")
}

// TestFedToken_PosixOrigin verifies that the federation token flow
// works with a POSIX (XRootD-based) origin, not just the native
// POSIXv2 handler.  This ensures cross-compatibility between the
// two storage backends.
func TestFedToken_PosixOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, fedTokenPosixPublicConfig)

	content := generateTestData(8192)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, "fed_token_posix.bin")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))

	token := getTempTokenForTest(t)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fed_token_posix.bin", token)

	resp := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, resp.statusCode,
		"Cache should successfully fetch from XRootD origin with DisableDirectClients")
	assert.Equal(t, content, resp.body,
		"Content returned through cache should match what was written to origin")
}

// TestFedToken_NonPublicReads verifies that DisableDirectClients works
// with a non-public (Reads-only) namespace, where the origin requires
// both a user token and a federation token.  This exercises the
// two-token authorization path in authMiddleware.
func TestFedToken_NonPublicReads(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, fedTokenPosixv2ReadsConfig)

	content := generateTestData(8192)
	storageDir := ft.Exports[0].StoragePrefix
	filePath := filepath.Join(storageDir, "fed_token_reads.bin")
	require.NoError(t, os.MkdirAll(filepath.Dir(filePath), 0755))
	require.NoError(t, os.WriteFile(filePath, content, 0644))

	// For a non-public namespace the cache must present both a user
	// token (for storage.read authorization) and a federation token
	// (to satisfy DisableDirectClients).
	token := getTempTokenForTest(t)
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fed_token_reads.bin", token)

	resp := fetchFromCache(t, ft, cacheURL, nil)
	require.Equal(t, http.StatusOK, resp.statusCode,
		"Cache should successfully fetch from non-public origin with DisableDirectClients; "+
			"non-200 indicates the user token or federation token was missing")
	assert.Equal(t, content, resp.body,
		"Content returned through cache should match what was written to origin")

	// Negative case: a direct request to the origin with only a user
	// token (no federation token) should be rejected.  This proves the
	// DisableDirectClients guard is active for non-public namespaces.
	originURL := param.Origin_Url.GetString()
	require.NotEmpty(t, originURL, "Origin URL should be set")
	directURL := originURL + "/api/v1.0/origin/data/test/fed_token_reads.bin"

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, directURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	httpClient := &http.Client{Transport: config.GetTransport()}
	directResp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer directResp.Body.Close()
	_, _ = io.ReadAll(directResp.Body)

	assert.Equal(t, http.StatusUnauthorized, directResp.StatusCode,
		"Direct request to non-public origin without federation token should be rejected (401)")
}
