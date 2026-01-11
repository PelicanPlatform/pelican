//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/studio-b12/gowebdav"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const posixv2OriginConfig = `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

// simpleTokenAuth implements gowebdav.Auth for bearer token authentication
type simpleTokenAuth struct {
	token string
}

func (a *simpleTokenAuth) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &simpleTokenAuthenticator{token: a.token}, body
}

func (a *simpleTokenAuth) AddAuthenticator(key string, fn gowebdav.AuthFactory) {
	// Not needed for bearer auth
}

type simpleTokenAuthenticator struct {
	token string
}

func (a *simpleTokenAuthenticator) Authorize(c *http.Client, rq *http.Request, path string) error {
	rq.Header.Set("Authorization", "Bearer "+a.token)
	return nil
}

func (a *simpleTokenAuthenticator) Clone() gowebdav.Authenticator {
	return &simpleTokenAuthenticator{token: a.token}
}

func (a *simpleTokenAuthenticator) Close() error {
	return nil
}

func (a *simpleTokenAuthenticator) Verify(c *http.Client, rs *http.Response, path string) (redo bool, err error) {
	return false, nil
}

// Helper function to get a token with write permissions for testing
func getTempTokenForTest(t *testing.T) string {
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir()))

	// Get the server issuer URL (same as FedTest uses)
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, readScope)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, createScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	return tkn
}

// Test POSIXv2 origin upload and download with the Pelican client
func TestPosixv2OriginUploadDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(posixv2OriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Verify the federation initialized with POSIXv2 exports
	require.Greater(t, len(ft.Exports), 0, "Federation should have at least one export")
	assert.Equal(t, "/test", ft.Exports[0].FederationPrefix)
	assert.True(t, ft.Exports[0].Capabilities.PublicReads, "Export should allow public reads")
	assert.True(t, ft.Exports[0].Capabilities.Writes, "Export should allow writes")

	// Create a test file to upload
	testContent := "Hello from POSIXv2 origin! This is test data."
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	// Upload the file using the Pelican client
	uploadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	transferResultsUpload, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsUpload)
	assert.Greater(t, transferResultsUpload[0].TransferredBytes, int64(0), "Should have transferred bytes")

	// Download the file using the Pelican client with federation discovery
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

	// Verify the file also exists in the backend storage
	// Use the actual StoragePrefix from the export (may differ from tmpDir after federation setup)
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "test_file.txt")
	backendContent, err := os.ReadFile(backendFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(backendContent), "Backend content should match uploaded content")
}

// Test POSIXv2 origin stat with checksum verification
func TestPosixv2OriginStat(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(posixv2OriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create a test file directly in the backend using the actual StoragePrefix
	testContent := []byte("Test content for stat and checksum verification")
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "stat_test.txt")
	require.NoError(t, os.WriteFile(backendFile, testContent, 0644))

	// Stat the file using the Pelican client
	statURL := fmt.Sprintf("pelican://%s:%d/test/stat_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Stat without checksum
	testToken := getTempTokenForTest(t)
	statInfo, err := client.DoStat(ft.Ctx, statURL, client.WithToken(testToken))
	require.NoError(t, err)
	assert.Equal(t, int64(len(testContent)), statInfo.Size, "File size should match")
	assert.Equal(t, "/test/stat_test.txt", statInfo.Name, "File name should match")
	assert.Nil(t, statInfo.Checksums, "Checksums should be nil when not requested")

	// Stat with checksum request
	statInfo, err = client.DoStat(ft.Ctx, statURL, client.WithToken(ft.Token),
		client.WithRequestChecksums([]client.ChecksumType{client.AlgCRC32C}))
	require.NoError(t, err)
	assert.Equal(t, int64(len(testContent)), statInfo.Size, "File size should match")
	assert.NotNil(t, statInfo.Checksums, "Checksums should be present")
	_, ok := statInfo.Checksums["crc32c"]
	assert.True(t, ok, "CRC32C checksum should be present")
}

// Test POSIXv2 origin with multiple file uploads
func TestPosixv2OriginMultipleFiles(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(posixv2OriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create multiple test files with different content
	testFiles := map[string]string{
		"file1.txt": "Content of file 1 - This is the first test file",
		"file2.txt": "Content of file 2 - This is the second test file",
		"file3.txt": "Content of file 3 - This is the third test file",
	}

	localTmpDir := t.TempDir()
	testToken := getTempTokenForTest(t)

	// Upload all files using the Pelican client
	for filename, content := range testFiles {
		localFile := filepath.Join(localTmpDir, filename)
		require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

		transferResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err, "Failed to upload %s", filename)
		require.NotEmpty(t, transferResults)
		assert.Greater(t, transferResults[0].TransferredBytes, int64(0), "Should have transferred bytes for %s", filename)
	}

	// Download and verify all files
	for filename, expectedContent := range testFiles {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)
		downloadFile := filepath.Join(localTmpDir, "downloaded_"+filename)

		transferResults, err := client.DoGet(ft.Ctx, downloadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err, "Failed to download %s", filename)
		require.NotEmpty(t, transferResults)

		// Verify content
		content, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, string(content), "Content of %s should match", filename)

		// Verify file exists in backend storage (use actual StoragePrefix)
		backendFile := filepath.Join(ft.Exports[0].StoragePrefix, filename)
		backendContent, err := os.ReadFile(backendFile)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, string(backendContent), "Backend content of %s should match", filename)
	}
}

// Test POSIXv2 origin with large file transfer
func TestPosixv2OriginLargeFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(posixv2OriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create a large test file (10MB)
	largeContent := make([]byte, 10*1024*1024) // 10MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "large_file.bin")
	require.NoError(t, os.WriteFile(localFile, largeContent, 0644))

	// Calculate hash of original file
	originalHash := fmt.Sprintf("%x", md5.Sum(largeContent))

	// Upload the large file using the Pelican client
	uploadURL := fmt.Sprintf("pelican://%s:%d/test/large_file.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)

	transferResultsUpload, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsUpload)
	assert.Equal(t, int64(len(largeContent)), transferResultsUpload[0].TransferredBytes,
		"Should have transferred all bytes")

	// Download the large file
	downloadFile := filepath.Join(localTmpDir, "downloaded_large_file.bin")
	transferResultsDownload, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsDownload)
	assert.Equal(t, transferResultsUpload[0].TransferredBytes, transferResultsDownload[0].TransferredBytes,
		"Downloaded bytes should match uploaded bytes")

	// Verify downloaded file content hash
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	downloadedHash := fmt.Sprintf("%x", md5.Sum(downloadedContent))
	assert.Equal(t, originalHash, downloadedHash, "Downloaded file hash should match original")

	// Verify backend storage file (use actual StoragePrefix)
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "large_file.bin")
	backendContent, err := os.ReadFile(backendFile)
	require.NoError(t, err)
	backendHash := fmt.Sprintf("%x", md5.Sum(backendContent))
	assert.Equal(t, originalHash, backendHash, "Backend file hash should match original")
}

// Test POSIXv2 origin directory listing with director
func TestPosixv2OriginListingWithDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin to use POSIXv2 (without specifying storage, NewFedTest will create it)
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Now create test files in the actual storage directory that NewFedTest created
	storageDir := ft.Exports[0].StoragePrefix
	subdir := filepath.Join(storageDir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0755))

	// Create some test files
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "file3.txt"), []byte("content3"), 0644))

	testToken := getTempTokenForTest(t)

	// Test listing root directory
	listURL := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list root directory")
	require.NotEmpty(t, entries, "Should have entries in root directory")

	// Verify we have both files and directory
	var hasFile1, hasFile2, hasSubdir bool
	for _, entry := range entries {
		// Entry names include the full path
		if strings.Contains(entry.Name, "file1.txt") && !entry.IsCollection {
			hasFile1 = true
		} else if strings.Contains(entry.Name, "file2.txt") && !entry.IsCollection {
			hasFile2 = true
		} else if strings.Contains(entry.Name, "subdir") && entry.IsCollection {
			hasSubdir = true
		}
	}

	assert.True(t, hasFile1, "Should list file1.txt")
	assert.True(t, hasFile2, "Should list file2.txt")
	assert.True(t, hasSubdir, "Should list subdir directory")

	// Test listing subdirectory
	subdirURL := fmt.Sprintf("pelican://%s:%d/test/subdir/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	subEntries, err := client.DoList(ft.Ctx, subdirURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list subdirectory")
	require.NotEmpty(t, subEntries, "Should have entries in subdirectory")

	// Verify subdirectory contains file3.txt
	var hasFile3 bool
	for _, entry := range subEntries {
		// Entry names include the full path
		if strings.Contains(entry.Name, "file3.txt") && !entry.IsCollection {
			hasFile3 = true
		}
	}

	assert.True(t, hasFile3, "Should list file3.txt in subdirectory")
}

// Test cache proxying of directory listings
func TestCacheProxyDirectoryListing(t *testing.T) {
	t.Skip("This test exposed bugs in xrdcl-pelican; see https://github.com/PelicanPlatform/xrdcl-pelican/pull/103.  Skip can be removed for the 1.6.2 release.")

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin to use POSIXv2
	originConfig := `
Logging:
  Cache:
    PssSetOpt: trace
    Pfc: debug
    Pss: debug
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create test files in the origin storage directory
	storageDir := ft.Exports[0].StoragePrefix
	subdir := filepath.Join(storageDir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "file3.txt"), []byte("content3"), 0644))

	// Get token
	testToken := getTempTokenForTest(t)

	// Query the director to get the cache location
	// The director defaults to routing to cache (via DefaultResponse: cache)
	directorURL := fmt.Sprintf("https://%s:%d/test/file1.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	req, err := http.NewRequestWithContext(ft.Ctx, http.MethodGet, directorURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

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

	// The director should redirect us to a cache server
	require.True(t, resp.StatusCode >= 300 && resp.StatusCode < 400, "Director should redirect, got %d", resp.StatusCode)
	redirectLocation := resp.Header.Get("Location")
	require.NotEmpty(t, redirectLocation, "Director should provide a redirect location")

	// Extract the base URL from the redirect (e.g., https://hostname:port)
	redirectURL, err := url.Parse(redirectLocation)
	require.NoError(t, err)
	cacheBaseURL := fmt.Sprintf("https://%s", redirectURL.Host)

	// Verify the cache is on a different port than the director/origin
	directorURL2 := fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	require.NotEqual(t, directorURL2, cacheBaseURL, "Cache should be on a different port than director")

	// Test cache by listing directories through it using gowebdav
	// The cache should proxy WebDAV requests to the origin
	auth := &simpleTokenAuth{token: testToken}
	cacheWebDAVURL := cacheBaseURL + "/test/"
	cacheWebdavClient := gowebdav.NewAuthClient(cacheWebDAVURL, auth)
	cacheWebdavClient.SetTransport(config.GetTransport())

	// List root directory via cache
	cacheInfos, err := cacheWebdavClient.ReadDir("/")
	require.NoError(t, err, "gowebdav should be able to list root directory through cache")
	require.NotEmpty(t, cacheInfos, "Cache should proxy directory listing from origin")

	// Verify we have the expected entries from cache
	var cacheFoundFile1, cacheFoundFile2, cacheFoundSubdir bool
	for _, info := range cacheInfos {
		if info.Name() == "file1.txt" {
			cacheFoundFile1 = true
			assert.False(t, info.IsDir(), "file1.txt should not be a directory")
		} else if info.Name() == "file2.txt" {
			cacheFoundFile2 = true
			assert.False(t, info.IsDir(), "file2.txt should not be a directory")
		} else if info.Name() == "subdir" {
			cacheFoundSubdir = true
			assert.True(t, info.IsDir(), "subdir should be a directory")
		}
	}

	require.True(t, cacheFoundFile1, "Cache should list file1.txt from origin")
	require.True(t, cacheFoundFile2, "Cache should list file2.txt from origin")
	require.True(t, cacheFoundSubdir, "Cache should list subdir from origin")

	// Test listing subdirectory through cache
	cacheSubdirInfos, err := cacheWebdavClient.ReadDir("/subdir/")
	require.NoError(t, err, "gowebdav should be able to list subdirectory through cache")
	require.NotEmpty(t, cacheSubdirInfos, "Cache should proxy subdirectory listing from origin")

	var cacheFoundFile3 bool
	for _, info := range cacheSubdirInfos {
		if info.Name() == "file3.txt" {
			cacheFoundFile3 = true
			assert.False(t, info.IsDir(), "file3.txt should not be a directory")
		}
	}

	require.True(t, cacheFoundFile3, "Cache should list file3.txt in subdirectory from origin")
}

// Test gowebdav compatibility with the cache directly
func TestGoWebDAVCompatibility(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin to use POSIXv2
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create nested directory structure
	storageDir := ft.Exports[0].StoragePrefix
	level1 := filepath.Join(storageDir, "level1")
	level2 := filepath.Join(level1, "level2")
	require.NoError(t, os.MkdirAll(level2, 0755))

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "root_file.txt"), []byte("root"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(level1, "level1_file.txt"), []byte("level1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(level2, "level2_file.txt"), []byte("level2"), 0644))

	// Get token
	testToken := getTempTokenForTest(t)

	// Construct the WebDAV URL for the origin server directly
	// WebDAV handlers are registered at /api/v1.0/origin/data/<prefix>
	originWebDAVURL := fmt.Sprintf("https://%s:%d/api/v1.0/origin/data/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Create gowebdav client with bearer token authentication
	auth := &simpleTokenAuth{token: testToken}
	webdavClient := gowebdav.NewAuthClient(originWebDAVURL, auth)
	webdavClient.SetTransport(config.GetTransport())

	// Test listing root directory via PROPFIND
	infos, err := webdavClient.ReadDir("/")
	require.NoError(t, err, "gowebdav should be able to read root directory via PROPFIND")
	require.NotEmpty(t, infos, "Should have entries in root")

	// Verify root entries
	var foundRootFile, foundLevel1 bool
	for _, info := range infos {
		if info.Name() == "root_file.txt" {
			foundRootFile = true
			assert.False(t, info.IsDir(), "root_file.txt should not be a directory")
			assert.Greater(t, info.Size(), int64(0), "File should have non-zero size")
		} else if info.Name() == "level1" {
			foundLevel1 = true
			assert.True(t, info.IsDir(), "level1 should be a directory")
		}
	}
	require.True(t, foundRootFile, "Should find root_file.txt via PROPFIND")
	require.True(t, foundLevel1, "Should find level1 directory via PROPFIND")

	// Test listing nested directory via PROPFIND
	level1Infos, err := webdavClient.ReadDir("/level1/")
	require.NoError(t, err, "gowebdav should be able to read nested directory via PROPFIND")
	require.NotEmpty(t, level1Infos, "Should have entries in level1")

	var foundLevel1File, foundLevel2 bool
	for _, info := range level1Infos {
		if info.Name() == "level1_file.txt" {
			foundLevel1File = true
			assert.False(t, info.IsDir(), "level1_file.txt should not be a directory")
		} else if info.Name() == "level2" {
			foundLevel2 = true
			assert.True(t, info.IsDir(), "level2 should be a directory")
		}
	}
	require.True(t, foundLevel1File, "Should find level1_file.txt via PROPFIND")
	require.True(t, foundLevel2, "Should find level2 directory via PROPFIND")

	// Test listing deep nested directory via PROPFIND
	level2Infos, err := webdavClient.ReadDir("/level1/level2/")
	require.NoError(t, err, "gowebdav should be able to read deep nested directory via PROPFIND")
	require.NotEmpty(t, level2Infos, "Should have entries in level2")

	var foundLevel2File bool
	for _, info := range level2Infos {
		if info.Name() == "level2_file.txt" {
			foundLevel2File = true
			assert.False(t, info.IsDir(), "level2_file.txt should not be a directory")
			assert.Greater(t, info.Size(), int64(0), "File should have non-zero size")
		}
	}
	require.True(t, foundLevel2File, "Should find level2_file.txt via PROPFIND")
}

// Test recursive downloads using the Pelican client
func TestRecursiveDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin to use POSIXv2
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Create nested directory structure
	storageDir := ft.Exports[0].StoragePrefix
	subdir := filepath.Join(storageDir, "subdir")
	deepdir := filepath.Join(subdir, "deepdir")
	require.NoError(t, os.MkdirAll(deepdir, 0755))

	// Create test files
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "file3.txt"), []byte("content3"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(deepdir, "file4.txt"), []byte("content4"), 0644))

	// Get token
	testToken := getTempTokenForTest(t)

	// Create a local directory for downloads
	downloadDir := t.TempDir()

	// Test recursive download of directory
	dirURL := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// List root directory
	entries, err := client.DoList(ft.Ctx, dirURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list root directory")
	require.NotEmpty(t, entries, "Should have entries in root")

	// Verify root entries
	var hasFile1, hasSubdir bool
	for _, entry := range entries {
		if strings.Contains(entry.Name, "file1.txt") && !entry.IsCollection {
			hasFile1 = true
		} else if strings.Contains(entry.Name, "subdir") && entry.IsCollection {
			hasSubdir = true
		}
	}

	require.True(t, hasFile1, "Should find file1.txt at root level")
	require.True(t, hasSubdir, "Should find subdir directory")

	// List subdir
	subdirURL := fmt.Sprintf("pelican://%s:%d/test/subdir/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	subdirEntries, err := client.DoList(ft.Ctx, subdirURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list subdir")
	require.NotEmpty(t, subdirEntries, "Should have entries in subdir")

	var hasFile3, hasDeepdir bool
	for _, entry := range subdirEntries {
		if strings.Contains(entry.Name, "file3.txt") && !entry.IsCollection {
			hasFile3 = true
		} else if strings.Contains(entry.Name, "deepdir") && entry.IsCollection {
			hasDeepdir = true
		}
	}

	require.True(t, hasFile3, "Should find file3.txt in subdir")
	require.True(t, hasDeepdir, "Should find deepdir in subdir")

	// List deepdir
	deepdirURL := fmt.Sprintf("pelican://%s:%d/test/subdir/deepdir/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	deepdirEntries, err := client.DoList(ft.Ctx, deepdirURL, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to list deepdir")
	require.NotEmpty(t, deepdirEntries, "Should have entries in deepdir")

	var hasFile4 bool
	for _, entry := range deepdirEntries {
		if strings.Contains(entry.Name, "file4.txt") && !entry.IsCollection {
			hasFile4 = true
		}
	}

	require.True(t, hasFile4, "Should find file4.txt in deepdir")

	// Download individual files to verify content
	file1URL := fmt.Sprintf("pelican://%s:%d/test/file1.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	localFile1 := filepath.Join(downloadDir, "file1.txt")
	_, err = client.DoGet(ft.Ctx, file1URL, localFile1, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to download file1.txt")

	content1, err := os.ReadFile(localFile1)
	require.NoError(t, err, "Should be able to read downloaded file")
	require.Equal(t, "content1", string(content1), "Downloaded file should have correct content")

	// Download file from subdirectory
	file3URL := fmt.Sprintf("pelican://%s:%d/test/subdir/file3.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	localFile3 := filepath.Join(downloadDir, "file3.txt")
	_, err = client.DoGet(ft.Ctx, file3URL, localFile3, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to download file3.txt from subdir")

	content3, err := os.ReadFile(localFile3)
	require.NoError(t, err, "Should be able to read downloaded file")
	require.Equal(t, "content3", string(content3), "Downloaded file should have correct content")

	// Download file from deep subdirectory
	file4URL := fmt.Sprintf("pelican://%s:%d/test/subdir/deepdir/file4.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	localFile4 := filepath.Join(downloadDir, "file4.txt")
	_, err = client.DoGet(ft.Ctx, file4URL, localFile4, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to download file4.txt from deep subdir")

	content4, err := os.ReadFile(localFile4)
	require.NoError(t, err, "Should be able to read downloaded file")
	require.Equal(t, "content4", string(content4), "Downloaded file should have correct content")
}
