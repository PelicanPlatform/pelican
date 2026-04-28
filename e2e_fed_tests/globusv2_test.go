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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/origin"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const testCollectionID = "e2e-test-collection-00000001"

// ---------------------------------------------------------------------------
// Mock Globus servers
// ---------------------------------------------------------------------------

// mockGlobusOIDC serves the OIDC discovery document.
// GET /.well-known/openid-configuration → returns token_endpoint, etc.
func mockGlobusOIDC(tokenEndpointURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		resp := map[string]interface{}{
			"issuer":                        "https://mock-globus-auth.test/",
			"authorization_endpoint":        "https://mock-globus-auth.test/v2/oauth2/authorize",
			"token_endpoint":                tokenEndpointURL,
			"device_authorization_endpoint": "https://mock-globus-auth.test/v2/oauth2/device/authorize",
			"scopes_supported":              []string{"openid", "email", "profile"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// mockGlobusTokenServer serves the OAuth2 token endpoint.
// POST /v2/oauth2/token → returns access/refresh tokens.
// Also tracks how many refresh requests have been made.
func mockGlobusTokenServer(refreshCount *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/oauth2/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		grantType := r.FormValue("grant_type")
		if grantType == "refresh_token" {
			refreshCount.Add(1)
		}

		// Return a new access token with short expiry
		resp := map[string]interface{}{
			"access_token":  fmt.Sprintf("mock-access-token-%d", time.Now().UnixNano()),
			"refresh_token": "mock-refresh-token-stable",
			"expires_in":    3600,
			"token_type":    "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// mockGlobusTransferAPI serves the Globus Transfer API.
// GET /v0.10/endpoint/{cid} → returns collection HTTPS URL.
func mockGlobusTransferAPI(httpsServerURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/v0.10/endpoint/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		resp := map[string]interface{}{
			"DATA_TYPE":    "endpoint",
			"id":           strings.TrimPrefix(r.URL.Path, prefix),
			"display_name": "Mock Test Collection",
			"https_server": httpsServerURL,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// startMockGlobusServers starts all mock Globus services and returns:
//   - oidcURL: the base URL for OIDC discovery
//   - tokenURL: the token endpoint URL
//   - transferAPIBaseURL: the Transfer API base URL (with trailing slash)
//   - refreshCount: an atomic counter for token refresh requests
func startMockGlobusServers(t *testing.T, webdavURL string) (oidcURL, tokenURL, transferAPIBaseURL string, refreshCount *atomic.Int64) {
	t.Helper()
	refreshCount = &atomic.Int64{}

	// Token server
	tokenSrv := httptest.NewServer(mockGlobusTokenServer(refreshCount))
	t.Cleanup(tokenSrv.Close)
	tokenURL = tokenSrv.URL + "/v2/oauth2/token"

	// OIDC discovery server
	oidcSrv := httptest.NewServer(mockGlobusOIDC(tokenURL))
	t.Cleanup(oidcSrv.Close)
	oidcURL = oidcSrv.URL + "/"

	// Transfer API server
	transferSrv := httptest.NewServer(mockGlobusTransferAPI(webdavURL))
	t.Cleanup(transferSrv.Close)
	transferAPIBaseURL = transferSrv.URL + "/v0.10/"

	return
}

// globusv2OriginConfig returns a YAML origin config for the Globus v2 E2E test.
func globusv2OriginConfig(collectionID, collectionName string) string {
	return fmt.Sprintf(`
Origin:
  StorageType: globusv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: "/"
      GlobusCollectionID: "%s"
      GlobusCollectionName: "%s"
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, collectionID, collectionName)
}

// getGlobusv2Token creates a federation token for the test.
func getGlobusv2Token(t *testing.T) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// ---------------------------------------------------------------------------
// TestGlobusv2Origin — E2E test with mocked Globus API
// ---------------------------------------------------------------------------

func TestGlobusv2Origin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Reset the Globus OAuth config singleton so it can pick up our mock endpoints
	origin.ResetGlobusOAuthCfg()
	t.Cleanup(origin.ResetGlobusOAuthCfg)

	// Start a WebDAV server as the "Globus collection HTTPS endpoint".
	// This is what the real Globus HTTPS endpoint exposes: a WebDAV-capable
	// HTTP server that accepts GET, PUT, MKCOL, PROPFIND, etc.
	webdavRoot := t.TempDir()
	webdavURL := startWebDAVServer(t, webdavRoot)

	// Start mock Globus API servers
	oidcURL, tokenURL, transferAPIBaseURL, refreshCount := startMockGlobusServers(t, webdavURL)

	// Create Globus client credential files
	tmpDir := t.TempDir()
	clientIDFile := filepath.Join(tmpDir, "globus-client-id")
	clientSecretFile := filepath.Join(tmpDir, "globus-client-secret")
	require.NoError(t, os.WriteFile(clientIDFile, []byte("test-globus-client-id"), 0600))
	require.NoError(t, os.WriteFile(clientSecretFile, []byte("test-globus-client-secret"), 0600))

	// Configure Globus hidden params to point at mock servers
	require.NoError(t, param.Set(param.Origin_GlobusIssuerURL, oidcURL))
	require.NoError(t, param.Set(param.Origin_GlobusTransferAPIBaseUrl, transferAPIBaseURL))
	require.NoError(t, param.Set(param.Origin_GlobusClientIDFile, clientIDFile))
	require.NoError(t, param.Set(param.Origin_GlobusClientSecretFile, clientSecretFile))
	// Set a short refresh interval so we can verify token refresh in the test
	require.NoError(t, param.Set(param.Origin_Globusv2TokenRefreshInterval, "2s"))

	originConfig := globusv2OriginConfig(testCollectionID, "Mock Test Collection")

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// NewFedTest overrides StoragePrefix to a random temp path. The Globus
	// backend was created with an empty HTTPSServer and not activated (because
	// InitGlobusBackend found no DB records to load).
	// Activate the backend directly with mock tokens pointing at the WebDAV server.
	storagePrefix := ft.Exports[0].StoragePrefix

	// Create the directory structure that the WebDAV server needs.
	// The origin will send requests to <webdavURL>/<storagePrefix>/...; the
	// WebDAV server maps that to <webdavRoot>/<storagePrefix>/...
	webdavDataDir := filepath.Join(webdavRoot, storagePrefix)
	require.NoError(t, os.MkdirAll(webdavDataDir, 0755))

	// Copy the hello_world.txt that NewFedTest created
	hwSrc := filepath.Join(storagePrefix, "hello_world.txt")
	hwDst := filepath.Join(webdavDataDir, "hello_world.txt")
	if data, err := os.ReadFile(hwSrc); err == nil {
		require.NoError(t, os.WriteFile(hwDst, data, 0644))
	}

	// Activate the Globus backend with mock tokens
	gBackends := origin_serve.GetGlobusBackends()
	require.Contains(t, gBackends, testCollectionID, "Globus backend for %s should exist", testCollectionID)
	gb := gBackends[testCollectionID]

	collectionToken := &oauth2.Token{
		AccessToken:  "mock-collection-access-token",
		RefreshToken: "mock-collection-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
		TokenType:    "Bearer",
	}
	transferToken := &oauth2.Token{
		AccessToken:  "mock-transfer-access-token",
		RefreshToken: "mock-transfer-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
		TokenType:    "Bearer",
	}

	// Create an OAuth2 config pointing at the mock token endpoint for refresh
	mockOAuth2Cfg := &oauth2.Config{
		ClientID:     "test-globus-client-id",
		ClientSecret: "test-globus-client-secret",
		Endpoint: oauth2.Endpoint{
			TokenURL:  tokenURL,
			AuthStyle: oauth2.AuthStyleInHeader,
		},
	}

	gb.Activate(collectionToken, transferToken, webdavURL, mockOAuth2Cfg)

	testToken := getGlobusv2Token(t)
	localTmpDir := t.TempDir()

	t.Run("UploadAndDownload", func(t *testing.T) {
		testContent := "Hello from the Globus v2 E2E federation test!"
		localFile := filepath.Join(localTmpDir, "globus_test.txt")
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/globus_test.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, uploadResults)
		assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))

		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, downloadResults)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))
	})

	t.Run("RecursiveUploadDownload", func(t *testing.T) {
		sourceDir := t.TempDir()
		sourceSubdir := filepath.Join(sourceDir, "subdir")
		sourceDeepdir := filepath.Join(sourceSubdir, "deepdir")
		require.NoError(t, os.MkdirAll(sourceDeepdir, 0755))

		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("globus-content1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "file2.txt"), []byte("globus-content2"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceSubdir, "file3.txt"), []byte("globus-content3"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(sourceDeepdir, "file4.txt"), []byte("globus-content4"), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/recursive/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoPut(ft.Ctx, sourceDir, uploadURL, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive upload should succeed")

		downloadDir := t.TempDir()
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadDir, true, client.WithToken(testToken))
		require.NoError(t, err, "recursive download should succeed")

		testCases := []struct {
			relativePath    string
			expectedContent string
		}{
			{"file1.txt", "globus-content1"},
			{"file2.txt", "globus-content2"},
			{filepath.Join("subdir", "file3.txt"), "globus-content3"},
			{filepath.Join("subdir", "deepdir", "file4.txt"), "globus-content4"},
		}
		for _, tc := range testCases {
			downloadedPath := filepath.Join(downloadDir, tc.relativePath)
			content, err := os.ReadFile(downloadedPath)
			require.NoError(t, err, "should be able to read %s", tc.relativePath)
			assert.Equal(t, tc.expectedContent, string(content), "content of %s should match", tc.relativePath)
		}
	})

	t.Run("Listing", func(t *testing.T) {
		files := []string{"list_a.txt", "list_b.txt", "list_c.txt"}
		for _, name := range files {
			localFile := filepath.Join(localTmpDir, name)
			require.NoError(t, os.WriteFile(localFile, []byte("globus-list-"+name), 0644))

			uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
			_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
			require.NoError(t, err, "failed to upload %s", name)
		}

		listURL := fmt.Sprintf("pelican://%s:%d/test/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		nameSet := make(map[string]bool)
		for _, e := range entries {
			nameSet[e.Name] = true
		}
		for _, name := range files {
			found := false
			for key := range nameSet {
				if strings.Contains(key, name) {
					found = true
					break
				}
			}
			assert.True(t, found, "listing should contain %s", name)
		}
	})

	t.Run("TokenRefresh", func(t *testing.T) {
		// The token refresh interval is set to 2s. Give short-lived tokens
		// so the refresher actually hits the mock token endpoint.
		shortCollectionToken := &oauth2.Token{
			AccessToken:  "short-lived-collection-token",
			RefreshToken: "mock-collection-refresh-token",
			Expiry:       time.Now().Add(30 * time.Second), // expiring soon (within 10min threshold)
			TokenType:    "Bearer",
		}
		shortTransferToken := &oauth2.Token{
			AccessToken:  "short-lived-transfer-token",
			RefreshToken: "mock-transfer-refresh-token",
			Expiry:       time.Now().Add(30 * time.Second),
			TokenType:    "Bearer",
		}
		gb.Activate(shortCollectionToken, shortTransferToken, webdavURL, mockOAuth2Cfg)

		initialRefreshes := refreshCount.Load()
		// Wait for the periodic refresh (interval = 2s) to trigger
		require.Eventually(t, func() bool {
			return refreshCount.Load() > initialRefreshes
		}, 10*time.Second, 500*time.Millisecond, "expected at least one token refresh to occur")

		t.Logf("Token refresh count increased from %d to %d", initialRefreshes, refreshCount.Load())

		// Verify the backend is still activated after refresh
		assert.True(t, gb.IsActivated(), "backend should remain activated after token refresh")

		// Verify file operations still work after token refresh
		testContent := "post-refresh content"
		localFile := filepath.Join(localTmpDir, "post_refresh.txt")
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/post_refresh.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err, "upload should succeed after token refresh")

		downloadFile := filepath.Join(localTmpDir, "post_refresh_download.txt")
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err, "download should succeed after token refresh")

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))
	})
}
