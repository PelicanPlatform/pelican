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
	"io"
	"net/http"
	"os"
	"path/filepath"
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

// disableDirectClientsOriginConfig returns a YAML configuration for a
// POSIXv2 origin that does NOT have DirectReads (incompatible with
// DisableDirectClients) but does have PublicReads and Listings.
// The Origin.DisableDirectClients flag itself is set via param.Set
// before calling NewFedTest, because InitializeHandlers validates the
// combination at startup.
func disableDirectClientsOriginConfig() string {
	return `Origin:
  StorageType: posixv2
  Exports:
    - StoragePrefix: "/"
      FederationPrefix: "/test"
      Capabilities: ["PublicReads", "Listings"]
`
}

// TestFedToken_DisableDirectClients verifies end-to-end that the
// persistent cache can serve objects from an origin with
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

	// Enable v2 persistent cache and DisableDirectClients BEFORE NewFedTest
	// so that InitializeHandlers sees the flag at startup.
	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	require.NoError(t, param.Set(param.Origin_DisableDirectClients.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, disableDirectClientsOriginConfig())

	// Write a test file into the origin's storage directory.
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

	// Wait until the director starts redirecting to the cache.
	cacheURL := waitForCacheRedirectURL(t, ft, "/test/fed_token_test.bin", token)

	// Fetch through the cache.  If the federation token is missing or the
	// routing uses ?directread (which requires DirectReads), the origin
	// will return 401 and the cache will propagate a non-200 error.
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
	require.NoError(t, param.Set(param.Origin_DisableDirectClients.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, disableDirectClientsOriginConfig())

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
	require.NoError(t, param.Set(param.Origin_DisableDirectClients.GetName(), true))

	ft := fed_test_utils.NewFedTest(t, disableDirectClientsOriginConfig())

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
