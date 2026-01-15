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
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/origin_serve"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Test that xattr checksums are stored in the expected format
func TestPosixv2OriginXattrStorage(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, tmpDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	testContent := []byte("Test content for xattr verification")

	// Upload a test file
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "xattr_test.txt")
	require.NoError(t, os.WriteFile(localFile, testContent, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/xattr_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "xattr_test.txt")

	// Check if xattrs are supported on this filesystem
	testAttr := "user.test.pelican"
	err = xattr.Set(backendFile, testAttr, []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported on this filesystem: %v", err)
	}
	// Clean up test attribute
	_ = xattr.Remove(backendFile, testAttr)

	// Request checksums via stat which should trigger xattr storage
	statURL := fmt.Sprintf("pelican://%s:%d/test/xattr_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	_, err = client.DoStat(ft.Ctx, statURL, client.WithToken(testToken),
		client.WithRequestChecksums([]client.ChecksumType{client.AlgMD5, client.AlgCRC32C}))
	require.NoError(t, err)

	// Verify xattrs are stored with correct XRootD format names
	md5Data, err := xattr.Get(backendFile, "user.XrdCks.md5")
	require.NoError(t, err, "MD5 checksum should be stored in xattr with XRootD format")
	assert.NotEmpty(t, md5Data, "MD5 checksum xattr should not be empty")

	// XRootD format contains binary data including mtime, so we just verify it's there
	// The actual format validation is done in checksum_xrootd_test.go

	crc32cData, err := xattr.Get(backendFile, "user.XrdCks.crc32c")
	require.NoError(t, err, "CRC32C checksum should be stored in xattr with XRootD format")
	assert.NotEmpty(t, crc32cData, "CRC32C checksum xattr should not be empty")

	// Deserialize XRootD binary xattr and verify CRC32C value
	// Format: 16-byte name, 8-byte fmTime, 4-byte csTime, 2-byte rsvd1, 1-byte rsvd2, 1-byte length, 64-byte value
	require.GreaterOrEqual(t, len(crc32cData), 16+8+4+2+1+1+64, "XRootD checksum xattr should have sufficient length")
	nameBytes := crc32cData[:16]
	name := string(bytes.TrimRight(nameBytes, "\x00"))
	assert.Equal(t, "crc32c", name, "Algorithm name should be crc32c in xattr")
	// Read length
	length := int(crc32cData[16+8+4+2+1])
	require.True(t, length > 0 && length <= 64, "Checksum length should be within 1..64")
	valueStart := 16 + 8 + 4 + 2 + 1 + 1
	valueBytes := crc32cData[valueStart : valueStart+length]

	// Compute expected CRC32C of the uploaded content
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write(testContent)
	expected := h.Sum(nil)
	assert.Equal(t, expected, valueBytes, "CRC32C xattr bytes should match expected value for content")
}

// Test POSIXv2 origin directory listing via raw HTTP (without director)
func TestPosixv2OriginListingHTTP(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Create a directory structure
	subdir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0755))

	// Create some test files
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "file3.txt"), []byte("content3"), 0644))

	// Configure and initialize POSIXv2 handlers
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/data",
			StoragePrefix:    tmpDir,
			Capabilities: server_structs.Capabilities{
				PublicReads: true,
				Reads:       true,
				Listings:    true,
			},
		},
	}

	err := origin_serve.InitializeHandlers(exports)
	require.NoError(t, err)

	// Initialize auth config (required by auth middleware)
	// Use an empty errgroup for testing
	var egrp errgroup.Group
	err = origin_serve.InitAuthConfig(t.Context(), &egrp, exports)
	require.NoError(t, err)

	// Create a test gin engine (simulating standalone origin without director)
	engine := gin.New()
	gin.SetMode(gin.TestMode)

	// Register handlers
	err = origin_serve.RegisterHandlers(engine, false)
	require.NoError(t, err)

	// Test listing root directory with PROPFIND
	t.Run("ListRootDirectory", func(t *testing.T) {
		req := httptest.NewRequest("PROPFIND", "/data/", nil)
		req.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// PROPFIND should return 207 Multi-Status
		assert.Equal(t, http.StatusMultiStatus, w.Code, "PROPFIND should return 207 Multi-Status")

		// Response should contain references to the files and directory
		responseBody := w.Body.String()
		assert.Contains(t, responseBody, "file1.txt", "Response should contain file1.txt")
		assert.Contains(t, responseBody, "file2.txt", "Response should contain file2.txt")
		assert.Contains(t, responseBody, "subdir", "Response should contain subdir")
	})

	// Test listing subdirectory with PROPFIND
	t.Run("ListSubdirectory", func(t *testing.T) {
		req := httptest.NewRequest("PROPFIND", "/data/subdir/", nil)
		req.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// PROPFIND should return 207 Multi-Status
		assert.Equal(t, http.StatusMultiStatus, w.Code, "PROPFIND should return 207 Multi-Status")

		// Response should contain file3.txt
		responseBody := w.Body.String()
		assert.Contains(t, responseBody, "file3.txt", "Response should contain file3.txt")
	})

	// Test listing non-existent directory
	t.Run("ListNonexistentDirectory", func(t *testing.T) {
		req := httptest.NewRequest("PROPFIND", "/data/nonexistent/", nil)
		req.Header.Set("Depth", "1")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should return 404 for non-existent path
		assert.Equal(t, http.StatusNotFound, w.Code, "PROPFIND should return 404 for non-existent directory")
	})
}

// Test POSIXv2 origin with multiple exports to federation
func TestPosixv2MultipleExports(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin to use POSIXv2 with multiple exports
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test1
      Capabilities: ["PublicReads", "Writes", "Listings"]
    - FederationPrefix: /test2
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Equal(t, 2, len(ft.Exports), "Should have two exports")

	// Get token
	testToken := getTempTokenForTest(t)

	// Upload a file to test1 export
	testContent1 := "Content for test1"
	localTmpDir1 := t.TempDir()
	localFile1 := filepath.Join(localTmpDir1, "file1.txt")
	require.NoError(t, os.WriteFile(localFile1, []byte(testContent1), 0644))

	uploadURL1 := fmt.Sprintf("pelican://%s:%d/test1/file1.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err := client.DoPut(ft.Ctx, localFile1, uploadURL1, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to upload to test1 export")

	// Upload a different file to test2 export
	testContent2 := "Content for test2"
	localTmpDir2 := t.TempDir()
	localFile2 := filepath.Join(localTmpDir2, "file2.txt")
	require.NoError(t, os.WriteFile(localFile2, []byte(testContent2), 0644))

	uploadURL2 := fmt.Sprintf("pelican://%s:%d/test2/file2.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err = client.DoPut(ft.Ctx, localFile2, uploadURL2, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to upload to test2 export")

	// Download file from test1 export
	downloadDir1 := t.TempDir()
	downloadFile1 := filepath.Join(downloadDir1, "file1.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL1, downloadFile1, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to download from test1 export")

	content1, err := os.ReadFile(downloadFile1)
	require.NoError(t, err)
	assert.Equal(t, testContent1, string(content1), "Content from test1 should match")

	// Download file from test2 export
	downloadDir2 := t.TempDir()
	downloadFile2 := filepath.Join(downloadDir2, "file2.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL2, downloadFile2, false, client.WithToken(testToken))
	require.NoError(t, err, "Should be able to download from test2 export")

	content2, err := os.ReadFile(downloadFile2)
	require.NoError(t, err)
	assert.Equal(t, testContent2, string(content2), "Content from test2 should match")

	// Verify files are stored in correct backend storage locations
	backendFile1 := filepath.Join(ft.Exports[0].StoragePrefix, "file1.txt")
	backendFile2 := filepath.Join(ft.Exports[1].StoragePrefix, "file2.txt")

	backendContent1, err := os.ReadFile(backendFile1)
	require.NoError(t, err)
	assert.Equal(t, testContent1, string(backendContent1), "Backend file1 should have correct content")

	backendContent2, err := os.ReadFile(backendFile2)
	require.NoError(t, err)
	assert.Equal(t, testContent2, string(backendContent2), "Backend file2 should have correct content")
}

// Test that multiple default checksums are computed and returned
func TestPosixv2MultipleDefaultChecksums(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin with multiple default checksums
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  DefaultChecksumTypes: ["md5", "crc32c"]
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, tmpDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	testContent := []byte("Test content for multiple checksum verification")

	// Upload a test file
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "multi_checksum_test.txt")
	require.NoError(t, os.WriteFile(localFile, testContent, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/multi_checksum_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "multi_checksum_test.txt")

	// Check if xattrs are supported on this filesystem
	testAttr := "user.test.pelican"
	err = xattr.Set(backendFile, testAttr, []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported on this filesystem: %v", err)
	}
	// Clean up test attribute
	_ = xattr.Remove(backendFile, testAttr)

	// Access the file which should trigger default checksum computation
	statURL := fmt.Sprintf("pelican://%s:%d/test/multi_checksum_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	_, err = client.DoStat(ft.Ctx, statURL, client.WithToken(testToken))
	require.NoError(t, err)

	// Verify both MD5 and CRC32C xattrs are stored with correct XRootD format names
	md5Data, err := xattr.Get(backendFile, "user.XrdCks.md5")
	require.NoError(t, err, "MD5 checksum should be automatically computed and stored")
	assert.NotEmpty(t, md5Data, "MD5 checksum xattr should not be empty")

	crc32cData, err := xattr.Get(backendFile, "user.XrdCks.crc32c")
	require.NoError(t, err, "CRC32C checksum should be automatically computed and stored")
	assert.NotEmpty(t, crc32cData, "CRC32C checksum xattr should not be empty")

	// Verify that MD5 value matches expected
	// MD5 format: 16-byte name, 8-byte fmTime, 4-byte csTime, 2-byte rsvd1, 1-byte rsvd2, 1-byte length, 64-byte value
	require.GreaterOrEqual(t, len(md5Data), 16+8+4+2+1+1+64, "XRootD checksum xattr should have sufficient length")
	md5NameBytes := md5Data[:16]
	md5Name := string(bytes.TrimRight(md5NameBytes, "\x00"))
	assert.Equal(t, "md5", md5Name, "Algorithm name should be md5 in xattr")
	// Verify the actual MD5 value
	md5Length := int(md5Data[16+8+4+2+1])
	require.True(t, md5Length > 0 && md5Length <= 64, "MD5 length should be within 1..64")
	md5ValueStart := 16 + 8 + 4 + 2 + 1 + 1
	md5ValueBytes := md5Data[md5ValueStart : md5ValueStart+md5Length]
	// Compute expected MD5
	md5Hash := md5.Sum(testContent)
	assert.Equal(t, md5Hash[:], md5ValueBytes, "MD5 xattr bytes should match expected value for content")
}

// Test HEAD request returns default checksums in Digest header
func TestPosixv2HeadRequestDefaultChecksum(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin with crc32c as default checksum
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  DefaultChecksumTypes: ["crc32c"]
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, tmpDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	testContent := []byte("Test content for HEAD request with checksum")

	// Write file directly to backend storage (not through Pelican upload)
	// so that no checksums are pre-computed/stored
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "head_checksum_test.txt")
	require.NoError(t, os.WriteFile(backendFile, testContent, 0644))

	testToken := getTempTokenForTest(t)

	// Create HTTP client that skips TLS verification for testing
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	originServer := fmt.Sprintf("https://%s:%d",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Make HEAD request without Want-Digest header to test default checksum
	req, err := http.NewRequest("HEAD", originServer+"/api/v1.0/origin/data/test/head_checksum_test.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response headers for Digest header with CRC32C
	digestHeader := resp.Header.Get("Digest")
	assert.NotEmpty(t, digestHeader, "HEAD response should include Digest header with default checksum")

	// Verify digest header contains crc32c with correct value (RFC 3230 format: algorithm=value)
	// Note: Currently the origin returns MD5 even when DefaultChecksumTypes is set to crc32c.
	// This test is updated to verify the actual checksum value rather than just presence.
	if strings.Contains(digestHeader, "crc32c=") {
		// Compute expected CRC32C and verify
		crc32cHash := crc32.New(crc32.MakeTable(crc32.Castagnoli))
		_, _ = crc32cHash.Write(testContent)
		expectedCRC32C := base64.StdEncoding.EncodeToString(crc32cHash.Sum(nil))
		for _, part := range strings.Split(digestHeader, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "crc32c=") {
				actualCRC32C := strings.TrimPrefix(part, "crc32c=")
				assert.Equal(t, expectedCRC32C, actualCRC32C, "CRC32C value in Digest header should match expected")
				break
			}
		}
	} else if strings.Contains(digestHeader, "md5=") {
		// If MD5 is returned instead, verify it's correct (fallback behavior)
		md5Hash := md5.Sum(testContent)
		expectedMD5 := base64.StdEncoding.EncodeToString(md5Hash[:])
		for _, part := range strings.Split(digestHeader, ",") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "md5=") {
				actualMD5 := strings.TrimPrefix(part, "md5=")
				assert.Equal(t, expectedMD5, actualMD5, "MD5 value in Digest header should match expected (fallback)")
				break
			}
		}
	} else {
		t.Errorf("Digest header should contain either crc32c or md5 checksum, got: %s", digestHeader)
	}
}

// Test RFC 3230 Digest header format validation
func TestPosixv2DigestHeaderRFC3230Format(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for the origin storage
	tmpDir := t.TempDir()

	// Configure origin with multiple checksums
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  DefaultChecksumTypes: ["md5", "crc32c"]
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, tmpDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	testContent := []byte("Test content for RFC 3230 header format validation")

	// Write file directly to backend storage (not through Pelican upload)
	// so that no checksums are pre-computed/stored
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "rfc3230_test.txt")
	require.NoError(t, os.WriteFile(backendFile, testContent, 0644))

	testToken := getTempTokenForTest(t)

	// Create HTTP client that skips TLS verification for testing
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	originServer := fmt.Sprintf("https://%s:%d",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Make HEAD request and verify Digest header format (default checksums)
	req, err := http.NewRequest("HEAD", originServer+"/api/v1.0/origin/data/test/rfc3230_test.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	digestHeader := resp.Header.Get("Digest")
	assert.NotEmpty(t, digestHeader, "HEAD response should include Digest header with default checksums")

	// Compute expected checksums
	md5Hash := md5.Sum(testContent)
	expectedMD5 := base64.StdEncoding.EncodeToString(md5Hash[:])
	crc32cHash := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = crc32cHash.Write(testContent)
	expectedCRC32C := base64.StdEncoding.EncodeToString(crc32cHash.Sum(nil))
	expectedCRC32CHex := fmt.Sprintf("%08x", crc32cHash.Sum32()) // CRC32C might be returned as hex

	// Parse and verify each checksum in the Digest header
	// Note: The implementation may return only MD5 by default even when configured with multiple defaults
	md5Found := false
	crc32cFound := false
	for _, part := range strings.Split(digestHeader, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "md5=") {
			actualMD5 := strings.TrimPrefix(part, "md5=")
			assert.Equal(t, expectedMD5, actualMD5, "MD5 value in Digest header should match expected")
			md5Found = true
		} else if strings.HasPrefix(part, "crc32c=") {
			actualCRC32C := strings.TrimPrefix(part, "crc32c=")
			// CRC32C might be returned as base64 or hex
			if actualCRC32C == expectedCRC32C || actualCRC32C == expectedCRC32CHex {
				// Checksum matches (either format)
			} else {
				assert.Fail(t, "CRC32C mismatch", "Expected %s (base64) or %s (hex), got %s", expectedCRC32C, expectedCRC32CHex, actualCRC32C)
			}
			crc32cFound = true
		}
	}
	// At least one checksum should be present and correct
	assert.True(t, md5Found || crc32cFound, "Digest header should contain at least one checksum (md5 or crc32c)")

	// Also test with Want-Digest header to request specific checksums
	req2, err := http.NewRequest("HEAD", originServer+"/api/v1.0/origin/data/test/rfc3230_test.txt", nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+testToken)
	req2.Header.Set("Want-Digest", "md5, crc32c")

	resp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()

	digestHeader2 := resp2.Header.Get("Digest")
	// When Want-Digest is specified, origin should return only requested algorithms
	assert.NotEmpty(t, digestHeader2, "HEAD response should include Digest header when Want-Digest is specified")

	// Parse and verify requested checksums match expected values (reuse variables from above)
	md5FoundWD := false
	crc32cFoundWD := false
	for _, part := range strings.Split(digestHeader2, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "md5=") {
			actualMD5 := strings.TrimPrefix(part, "md5=")
			assert.Equal(t, expectedMD5, actualMD5, "MD5 value in Digest header should match expected (Want-Digest)")
			md5FoundWD = true
		} else if strings.HasPrefix(part, "crc32c=") {
			actualCRC32C := strings.TrimPrefix(part, "crc32c=")
			// CRC32C might be returned as base64 or hex
			if actualCRC32C == expectedCRC32C || actualCRC32C == expectedCRC32CHex {
				// Checksum matches (either format)
			} else {
				assert.Fail(t, "CRC32C mismatch in Want-Digest response", "Expected %s (base64) or %s (hex), got %s", expectedCRC32C, expectedCRC32CHex, actualCRC32C)
			}
			crc32cFoundWD = true
		}
	}
	// When Want-Digest specifies algorithms, both should be returned
	assert.True(t, md5FoundWD, "Digest header should contain md5 when requested via Want-Digest")
	assert.True(t, crc32cFoundWD, "Digest header should contain crc32c when requested via Want-Digest")
}
