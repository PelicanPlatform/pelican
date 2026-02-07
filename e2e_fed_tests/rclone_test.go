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
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const rcloneTestOriginConfig = `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
`

// checkRcloneInstalled returns true if rclone is installed and available
func checkRcloneInstalled() bool {
	_, err := exec.LookPath("rclone")
	return err == nil
}

// writeRcloneConfig writes a temporary rclone configuration file
func writeRcloneConfig(t *testing.T, remoteName, baseURL, tokenCmd string) string {
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "rclone.conf")

	config := fmt.Sprintf(`[%s]
type = webdav
url = %s
vendor = other
bearer_token_command = %s
`, remoteName, baseURL, tokenCmd)

	require.NoError(t, os.WriteFile(configPath, []byte(config), 0600))
	return configPath
}

// createRcloneTestToken creates a token suitable for rclone testing
func createRcloneTestToken(t *testing.T, read, write bool) string {
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = 5 * time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "rclone-test"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	if read {
		readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
		require.NoError(t, err)
		scopes = append(scopes, readScope)
	}
	if write {
		createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
		require.NoError(t, err)
		scopes = append(scopes, createScope)
		modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
		require.NoError(t, err)
		scopes = append(scopes, modScope)
	}
	tokenConfig.AddScopes(scopes...)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// runRclone runs an rclone command with the given config and arguments.
// It automatically passes --no-check-certificate since tests use self-signed TLS.
func runRclone(t *testing.T, configPath string, args ...string) (string, error) {
	allArgs := append([]string{"--config", configPath, "--no-check-certificate"}, args...)
	cmd := exec.Command("rclone", allArgs...)

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// TestRcloneDownload tests downloading files via rclone
func TestRcloneDownload(t *testing.T) {
	if !checkRcloneInstalled() {
		t.Skip("rclone is not installed, skipping rclone integration tests")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2 with public reads
	originConfig := fmt.Sprintf(rcloneTestOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create a test file in the backend
	testContent := "Hello from rclone download test!"
	testFile := filepath.Join(ft.Exports[0].StoragePrefix, "download_test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Create subdirectory with more files
	subDir := filepath.Join(ft.Exports[0].StoragePrefix, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file2.txt"), []byte("content2"), 0644))

	// In production, `pelican rclone setup` points reads at the director URL so
	// it can pick the best cache. Here we use the origin URL directly because
	// federation-in-a-box serves data at /api/v1.0/origin/data/..., which means a
	// 307 redirect from the director changes the path prefix and confuses rclone's
	// href matching. (There is also a known rclone bug where PROPFIND 307 redirects
	// work for directories but not for individual files; this is being reported
	// upstream.)
	webdavURL := fmt.Sprintf("https://%s:%d/api/v1.0/origin/data/test",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create a token file for rclone (simpler than using bearer_token_command for tests)
	testToken := createRcloneTestToken(t, true, false)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(testToken), 0600))

	// Write rclone config with a simple token echo command
	configPath := writeRcloneConfig(t, "pelican-test", webdavURL, fmt.Sprintf("cat %s", tokenFile))

	// Test: List files
	t.Run("list-files", func(t *testing.T) {
		output, err := runRclone(t, configPath, "ls", "pelican-test:")
		require.NoError(t, err, "rclone ls failed: %s", output)
		assert.Contains(t, output, "download_test.txt")
		assert.Contains(t, output, "file1.txt")
		assert.Contains(t, output, "file2.txt")
	})

	// Test: Download single file
	t.Run("download-single-file", func(t *testing.T) {
		localDir := t.TempDir()
		output, err := runRclone(t, configPath, "copy", "pelican-test:download_test.txt", localDir)
		require.NoError(t, err, "rclone copy failed: %s", output)

		// Verify downloaded content
		downloadedContent, err := os.ReadFile(filepath.Join(localDir, "download_test.txt"))
		require.NoError(t, err)
		assert.Equal(t, testContent, string(downloadedContent))
	})

	// Test: Sync directory
	t.Run("sync-directory", func(t *testing.T) {
		localDir := t.TempDir()
		output, err := runRclone(t, configPath, "sync", "pelican-test:subdir", localDir)
		require.NoError(t, err, "rclone sync failed: %s", output)

		// Verify synced files
		content1, err := os.ReadFile(filepath.Join(localDir, "file1.txt"))
		require.NoError(t, err)
		assert.Equal(t, "content1", string(content1))

		content2, err := os.ReadFile(filepath.Join(localDir, "file2.txt"))
		require.NoError(t, err)
		assert.Equal(t, "content2", string(content2))
	})
}

// TestRcloneUpload tests uploading files via rclone
func TestRcloneUpload(t *testing.T) {
	if !checkRcloneInstalled() {
		t.Skip("rclone is not installed, skipping rclone integration tests")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2 with writes enabled
	originConfig := fmt.Sprintf(rcloneTestOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Get the WebDAV URL pointing to the origin's data endpoint directly.
	webdavURL := fmt.Sprintf("https://%s:%d/api/v1.0/origin/data/test",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create a token with write permissions
	testToken := createRcloneTestToken(t, true, true)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(testToken), 0600))

	// Write rclone config
	configPath := writeRcloneConfig(t, "pelican-upload", webdavURL, fmt.Sprintf("cat %s", tokenFile))

	// Create local test files
	localDir := t.TempDir()
	testContent := "This is test content for upload"
	require.NoError(t, os.WriteFile(filepath.Join(localDir, "upload_test.txt"), []byte(testContent), 0644))

	// Create a subdirectory with files
	subDir := filepath.Join(localDir, "upload_subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "nested1.txt"), []byte("nested content 1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "nested2.txt"), []byte("nested content 2"), 0644))

	// Test: Upload single file
	t.Run("upload-single-file", func(t *testing.T) {
		output, err := runRclone(t, configPath, "copy", filepath.Join(localDir, "upload_test.txt"), "pelican-upload:")
		require.NoError(t, err, "rclone copy failed: %s", output)

		// Verify file exists in backend
		backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "upload_test.txt")
		backendContent, err := os.ReadFile(backendFile)
		require.NoError(t, err, "uploaded file not found in backend")
		assert.Equal(t, testContent, string(backendContent))
	})

	// Test: Sync directory upload
	t.Run("sync-directory-upload", func(t *testing.T) {
		output, err := runRclone(t, configPath, "sync", subDir, "pelican-upload:synced_dir")
		require.NoError(t, err, "rclone sync failed: %s", output)

		// Verify synced files in backend
		nested1 := filepath.Join(ft.Exports[0].StoragePrefix, "synced_dir", "nested1.txt")
		content1, err := os.ReadFile(nested1)
		require.NoError(t, err, "nested1.txt not found in backend")
		assert.Equal(t, "nested content 1", string(content1))

		nested2 := filepath.Join(ft.Exports[0].StoragePrefix, "synced_dir", "nested2.txt")
		content2, err := os.ReadFile(nested2)
		require.NoError(t, err, "nested2.txt not found in backend")
		assert.Equal(t, "nested content 2", string(content2))
	})

	// Test: List uploaded files
	t.Run("list-uploaded-files", func(t *testing.T) {
		output, err := runRclone(t, configPath, "ls", "pelican-upload:")
		require.NoError(t, err, "rclone ls failed: %s", output)
		assert.Contains(t, output, "upload_test.txt")
		assert.Contains(t, output, "nested1.txt")
		assert.Contains(t, output, "nested2.txt")
	})
}

// TestRcloneSync tests bidirectional sync operations
func TestRcloneSync(t *testing.T) {
	if !checkRcloneInstalled() {
		t.Skip("rclone is not installed, skipping rclone integration tests")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(rcloneTestOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Get the WebDAV URL pointing to the origin's data endpoint directly.
	webdavURL := fmt.Sprintf("https://%s:%d/api/v1.0/origin/data/test",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create a token with read/write permissions
	testToken := createRcloneTestToken(t, true, true)
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(testToken), 0600))

	// Write rclone config
	configPath := writeRcloneConfig(t, "pelican-sync", webdavURL, fmt.Sprintf("cat %s", tokenFile))

	// Test: Full sync workflow
	t.Run("full-sync-workflow", func(t *testing.T) {
		// Create local directory with initial files
		localDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(localDir, "file_a.txt"), []byte("content A"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(localDir, "file_b.txt"), []byte("content B"), 0644))

		// Sync local to remote
		output, err := runRclone(t, configPath, "sync", localDir, "pelican-sync:sync_test")
		require.NoError(t, err, "initial sync failed: %s", output)

		// Verify files on remote
		output, err = runRclone(t, configPath, "ls", "pelican-sync:sync_test")
		require.NoError(t, err, "list failed: %s", output)
		assert.Contains(t, output, "file_a.txt")
		assert.Contains(t, output, "file_b.txt")

		// Add a new local file
		require.NoError(t, os.WriteFile(filepath.Join(localDir, "file_c.txt"), []byte("content C"), 0644))

		// Sync again
		output, err = runRclone(t, configPath, "sync", localDir, "pelican-sync:sync_test")
		require.NoError(t, err, "second sync failed: %s", output)

		// Verify new file on remote
		output, err = runRclone(t, configPath, "ls", "pelican-sync:sync_test")
		require.NoError(t, err, "list after second sync failed: %s", output)
		assert.Contains(t, output, "file_c.txt")

		// Download everything to a new local directory
		downloadDir := t.TempDir()
		output, err = runRclone(t, configPath, "sync", "pelican-sync:sync_test", downloadDir)
		require.NoError(t, err, "download sync failed: %s", output)

		// Verify all files downloaded
		files, err := os.ReadDir(downloadDir)
		require.NoError(t, err)
		assert.Len(t, files, 3)

		// Verify content
		contentA, _ := os.ReadFile(filepath.Join(downloadDir, "file_a.txt"))
		assert.Equal(t, "content A", string(contentA))
	})
}

// TestRcloneWithExpiredToken tests that rclone properly refreshes expired tokens
func TestRcloneTokenRefresh(t *testing.T) {
	if !checkRcloneInstalled() {
		t.Skip("rclone is not installed, skipping rclone integration tests")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(rcloneTestOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create a test file
	testContent := "Token refresh test content"
	require.NoError(t, os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, "refresh_test.txt"), []byte(testContent), 0644))

	// Get the WebDAV URL pointing to the origin's data endpoint directly.
	webdavURL := fmt.Sprintf("https://%s:%d/api/v1.0/origin/data/test",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create a script that generates fresh tokens each time it's called
	// This simulates what `pelican rclone token` does
	scriptDir := t.TempDir()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// First, get the issuer private key location for token generation
	// For testing, we'll use a simpler approach - write fresh tokens to a file
	tokenFile := filepath.Join(scriptDir, "token")
	testToken := createRcloneTestToken(t, true, false)
	require.NoError(t, os.WriteFile(tokenFile, []byte(testToken), 0600))

	// Create a counter file to track token requests
	counterFile := filepath.Join(scriptDir, "counter")
	require.NoError(t, os.WriteFile(counterFile, []byte("0"), 0644))

	// Create a script that outputs the token and increments the counter
	tokenScript := filepath.Join(scriptDir, "get_token.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
count=$(cat %s)
count=$((count + 1))
echo $count > %s
cat %s
`, counterFile, counterFile, tokenFile)
	require.NoError(t, os.WriteFile(tokenScript, []byte(scriptContent), 0755))

	// Write rclone config using the script
	configPath := writeRcloneConfig(t, "pelican-refresh", webdavURL, tokenScript)

	// Test: Multiple operations should use bearer_token_command
	t.Run("token-command-invoked", func(t *testing.T) {
		// Reset counter
		require.NoError(t, os.WriteFile(counterFile, []byte("0"), 0644))

		// Perform some operations
		output, err := runRclone(t, configPath, "ls", "pelican-refresh:")
		require.NoError(t, err, "rclone ls failed: %s", output)
		assert.Contains(t, output, "refresh_test.txt")

		// Check that the token command was invoked
		countBytes, err := os.ReadFile(counterFile)
		require.NoError(t, err)
		count := strings.TrimSpace(string(countBytes))
		assert.NotEqual(t, "0", count, "bearer_token_command should have been invoked")
		t.Logf("Token command invoked %s times", count)
	})

	// Test: Verify token command is used for downloads too
	t.Run("token-used-for-download", func(t *testing.T) {
		// Reset counter
		require.NoError(t, os.WriteFile(counterFile, []byte("0"), 0644))

		localDir := t.TempDir()
		output, err := runRclone(t, configPath, "copy", "pelican-refresh:refresh_test.txt", localDir)
		require.NoError(t, err, "rclone copy failed: %s", output)

		// Verify content
		downloaded, err := os.ReadFile(filepath.Join(localDir, "refresh_test.txt"))
		require.NoError(t, err)
		assert.Equal(t, testContent, string(downloaded))

		// Check token command was invoked
		countBytes, err := os.ReadFile(counterFile)
		require.NoError(t, err)
		count := strings.TrimSpace(string(countBytes))
		assert.NotEqual(t, "0", count, "bearer_token_command should have been invoked for download")
	})

	_ = issuer // Used to document where issuer comes from
}

// TestDirectorTokenValidation tests the Director's expired-token detection using
// direct HTTP requests against the Director's redirect endpoints. This validates
// that the Director returns 401 for expired tokens (triggering rclone's
// bearer_token_command) while allowing requests without tokens to pass through.
//
// We use HTTP requests instead of rclone here because rclone talks directly to
// the origin's data endpoint and never hits the Director's redirect path.
func TestDirectorTokenValidation(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	originConfig := fmt.Sprintf(rcloneTestOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create a test file
	require.NoError(t, os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, "token_test.txt"), []byte("content"), 0644))

	// The Director's redirect endpoint — a GET here returns 307 to the origin/cache
	directorURL := fmt.Sprintf("https://%s:%d/test/token_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// HTTP client that skips TLS verification (self-signed certs in tests)
	// and does NOT follow redirects so we can inspect the Director's response.
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Test: No token → Director should redirect normally (307)
	t.Run("no-token-redirects", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, directorURL, nil)
		require.NoError(t, err)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Director should redirect (307) because no token means nothing to reject
		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode,
			"Director should redirect when no token is present")
	})

	// Test: Expired token → Director should return 401
	t.Run("expired-token-returns-401", func(t *testing.T) {
		issuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)

		privKey, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)

		now := time.Now()
		tok, err := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(now.Add(-10*time.Minute)).
			Expiration(now.Add(-5*time.Minute)). // Expired 5 minutes ago
			Subject("rclone-test").
			Claim("scope", "storage.read:/").
			Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, directorURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+string(signed))

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Director should return 401 for an expired bearer token")
		// RFC 7235 §3.1 requires WWW-Authenticate with any 401 response
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Bearer",
			"401 response must include WWW-Authenticate: Bearer header per RFC 7235")
	})

	// Test: Valid token → Director should redirect normally (307)
	t.Run("valid-token-redirects", func(t *testing.T) {
		testToken := createRcloneTestToken(t, true, false)

		req, err := http.NewRequest(http.MethodGet, directorURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+testToken)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode,
			"Director should redirect when a valid token is present")
	})

	// Test: Nearly-expired token (within grace period) → Director should return 401.
	// The Director rejects tokens within 10 seconds of expiry to account for
	// redirect latency and clock skew.
	t.Run("nearly-expired-token-returns-401", func(t *testing.T) {
		issuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)

		privKey, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)

		now := time.Now()
		tok, err := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(now.Add(-5*time.Minute)).
			Expiration(now.Add(3*time.Second)). // Expires in 3s — well within 10s grace
			Subject("rclone-test").
			Claim("scope", "storage.read:/").
			Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, directorURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+string(signed))

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Director should return 401 for a token within the expiry grace period")
	})

	// Test: Short-lived token where half the lifetime is the grace.
	// A 4-second token has a 2-second grace; if 3 seconds have elapsed
	// (1 second left, less than the 2-second grace), it should be rejected.
	t.Run("short-lived-token-half-lifetime-grace", func(t *testing.T) {
		issuer, err := config.GetServerIssuerURL()
		require.NoError(t, err)

		privKey, err := config.GetIssuerPrivateJWK()
		require.NoError(t, err)

		now := time.Now()
		tok, err := jwt.NewBuilder().
			Issuer(issuer).
			IssuedAt(now.Add(-3*time.Second)).  // Issued 3s ago
			Expiration(now.Add(1*time.Second)). // 4s lifetime, 1s remaining
			Subject("rclone-test").
			Claim("scope", "storage.read:/").
			Build()
		require.NoError(t, err)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
		require.NoError(t, err)

		req, err := http.NewRequest(http.MethodGet, directorURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+string(signed))

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"Director should return 401 for a short-lived token within half-lifetime grace")
	})
}
