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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

//go:embed resources/single-private-full.yml
var singlePrivateFullOrigin string

// TestCacheScitokensConfigOverride tests that Xrootd.ScitokensConfig works for caches
// to serve cached objects during origin downtime. This test:
// 1. Sets up a full federation with private reads and pulls a file through the cache
// 2. Simulates origin downtime by POSTing a new origin ad without the /test namespace
// 3. Triggers cache authz refresh by overwriting Xrootd.ScitokensConfig with unrelated issuer
// 4. Verifies data is no longer accessible through the cache (authorization removed)
// 5. Triggers another authz refresh with proper authorization for the test prefix
// 6. Verifies cached object is now accessible even with origin "offline"
func TestCacheScitokensConfigOverride(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
		server_utils.ResetTestState()
	})

	// Create test directories and file
	tmpDir := t.TempDir()
	testFileContent := "test file content for cache scitokens override test"
	testFileName := "test_file.txt"
	testFilePath := filepath.Join(tmpDir, testFileName)
	err := os.WriteFile(testFilePath, []byte(testFileContent), 0644)
	require.NoError(t, err)

	// Set up Xrootd.ScitokensConfig location
	scitokensConfigPath := filepath.Join(tmpDir, "scitokens.cfg")
	require.NoError(t, param.Set(param.Xrootd_ScitokensConfig.GetName(), scitokensConfigPath))

	// Set floor to 0 to allow immediate director refreshes when scitokens config changes
	require.NoError(t, param.Set(param.Cache_MinDirectorRefreshInterval.GetName(), "0s"))

	// Use long-lived ads so they don't expire during test
	require.NoError(t, param.Set(param.Server_AdLifetime.GetName(), "1h"))

	// Set up the federation with embedded config
	_ = fed_test_utils.NewFedTest(t, singlePrivateFullOrigin)

	// Get the server issuer URL for creating tokens
	serverIssuerUrl, err := config.GetServerIssuerURL()
	require.NoError(t, err, "Failed to get server issuer URL")

	// Create a token for accessing the object
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = 30 * time.Minute
	tokenConfig.Issuer = serverIssuerUrl
	tokenConfig.Subject = "test-subject"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)

	tok, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	// Construct pelican URL for file operations
	pelicanUrl := fmt.Sprintf("pelican://%s:%d/test/%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), testFileName)

	// Upload the test file to the origin
	_, err = client.DoPut(ctx, testFilePath, pelicanUrl, false, client.WithToken(tok))
	require.NoError(t, err, "Should be able to upload file to origin")

	// Step 1: Download through the federation to populate the cache
	destPath1 := filepath.Join(tmpDir, "downloaded1.txt")
	transferResults, err := client.DoGet(ctx, pelicanUrl, destPath1, false, client.WithToken(tok))
	require.NoError(t, err, "Should be able to download file through federation")
	require.Equal(t, int64(len(testFileContent)), transferResults[0].TransferredBytes)

	content1, err := os.ReadFile(destPath1)
	require.NoError(t, err)
	require.Equal(t, testFileContent, string(content1), "Downloaded content should match original")

	// Step 2: Simulate origin downtime by POSTing new origin ad without /test namespace
	metadata, err := server_utils.GetServerMetadata(ctx, server_structs.OriginType)
	require.NoError(t, err)

	issuerUrlStr, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	issuerUrl, err := url.Parse(issuerUrlStr)
	require.NoError(t, err)

	// Create advertisement with empty namespace list
	emptyAd := server_structs.OriginAdvertiseV2{
		ServerID:   metadata.ID,
		DataURL:    param.Origin_Url.GetString(),
		WebURL:     param.Server_ExternalWebUrl.GetString(),
		Namespaces: []server_structs.NamespaceAdV2{},
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: *issuerUrl,
		}},
		StorageType: server_structs.OriginStoragePosix,
	}
	emptyAd.Initialize(metadata.Name)
	emptyAd.Now = time.Now()

	body, err := json.Marshal(emptyAd)
	require.NoError(t, err)

	directorUrlStr := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/director/registerOrigin"
	directorUrl, err := url.Parse(directorUrlStr)
	require.NoError(t, err)

	// Create advertisement token
	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = issuerUrlStr
	advTokenCfg.AddAudienceAny()
	advTokenCfg.Subject = param.Server_Hostname.GetString()
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)
	advTok, err := advTokenCfg.CreateToken()
	require.NoError(t, err)

	// POST the empty advertisement
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, directorUrl.String(), bytes.NewBuffer(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+advTok)
	req.Header.Set("User-Agent", "pelican-test/"+config.GetVersion())

	tr := config.GetTransport()
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Failed to register empty origin advertisement")

	// Wait for director to process the empty advertisement and remove /test namespace
	namespacesUrl := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/director/listNamespaces"
	require.Eventually(t, func() bool {
		resp, err := httpClient.Get(namespacesUrl)
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		var namespaces []server_structs.NamespaceAdV2
		if err := json.NewDecoder(resp.Body).Decode(&namespaces); err != nil {
			return false
		}

		// Check that /test namespace is no longer present
		for _, ns := range namespaces {
			if ns.Path == "/test" {
				return false
			}
		}
		return true
	}, 20*time.Second, 100*time.Millisecond, "Director should remove /test namespace after processing empty advertisement")

	// Step 3: Trigger cache authz refresh by overwriting Xrootd.ScitokensConfig with an unrelated issuer
	// The file watcher will detect this change and call EmitScitokensConfig, which uses cached namespace ads
	// from the cache's last GetNamespaceAdsFromDirector() call (which gets data from the director).
	// Since we just updated the director to remove /test, the cache's cached ads should now reflect that.
	unrelatedConfig := `
[Global]
audience = https://wlcg.cern.ch/jwt/v1/any

[Issuer UnrelatedIssuer]
issuer = https://unrelated-issuer.example.com
base_path = /unrelated/path
default_user = xrootd
`
	err = os.WriteFile(scitokensConfigPath, []byte(unrelatedConfig), 0644)
	require.NoError(t, err)

	// Wait for the background cache process to emit the config with /unrelated/path
	generatedConfigPath := filepath.Join(param.Cache_RunLocation.GetString(), "scitokens-cache-generated.cfg")
	require.Eventually(t, func() bool {
		generatedContent, err := os.ReadFile(generatedConfigPath)
		if err != nil {
			return false
		}
		contentStr := string(generatedContent)
		// Check that the unrelated issuer override is present and /test is gone
		return len(contentStr) > 0 &&
			strings.Contains(contentStr, "unrelated-issuer.example.com") &&
			strings.Contains(contentStr, "/unrelated/path") &&
			!strings.Contains(contentStr, "/test")
	}, 20*time.Second, 100*time.Millisecond, "Generated config should contain unrelated issuer override and not /test")

	// Step 4: Verify data is no longer accessible through the cache
	// Try to download directly from cache - should fail because authorization is missing
	destPath2 := filepath.Join(tmpDir, "downloaded2.txt")
	cacheUrl := param.Cache_Url.GetString()
	cacheUrlParsed, err := url.Parse(cacheUrl)
	require.NoError(t, err)
	testUrl, err := url.Parse(cacheUrlParsed.Scheme + "://" + cacheUrlParsed.Host)
	require.NoError(t, err)
	testUrl.Path = filepath.Join("/test", testFileName)
	_, err = client.DoGet(ctx, testUrl.String(), destPath2, false, client.WithToken(tok))
	require.Error(t, err, "Should not be able to access cached data without proper authorization")

	// Step 5: Trigger another cache authz refresh with proper authorization for /test
	properConfig := `
[Global]
audience = https://wlcg.cern.ch/jwt/v1/any

[Issuer TestIssuer]
issuer = ` + serverIssuerUrl + `
base_path = /test
default_user = xrootd
`
	err = os.WriteFile(scitokensConfigPath, []byte(properConfig), 0644)
	require.NoError(t, err)

	// Wait for the background cache process to emit the updated config with /test
	require.Eventually(t, func() bool {
		generatedContent, err := os.ReadFile(generatedConfigPath)
		if err != nil {
			return false
		}
		contentStr := string(generatedContent)
		// Check that the unrelated issuer is gone and our server issuer is present
		return len(contentStr) > 0 &&
			!strings.Contains(contentStr, "unrelated-issuer.example.com") &&
			strings.Contains(contentStr, serverIssuerUrl) &&
			strings.Contains(contentStr, "TestIssuer")
	}, 20*time.Second, 100*time.Millisecond, "Generated config should contain server issuer and not unrelated issuer")

	// Step 6: Verify cached object is accessible with proper auth, even with origin "offline"
	// Use client.DoGet with WithCaches to force use of specific cache
	destPath3 := filepath.Join(tmpDir, "downloaded3.txt")
	transferResults, err = client.DoGet(ctx, pelicanUrl, destPath3, false, client.WithToken(tok), client.WithCaches(cacheUrlParsed))
	require.NoError(t, err, "Should be able to access cached data with proper authorization")
	require.Equal(t, int64(len(testFileContent)), transferResults[0].TransferredBytes)

	content3, err := os.ReadFile(destPath3)
	require.NoError(t, err)
	require.Equal(t, testFileContent, string(content3), "Content from cache should match original")
}
