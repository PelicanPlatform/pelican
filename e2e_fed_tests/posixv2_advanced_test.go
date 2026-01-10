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
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	// Verify xattrs are stored with correct names
	md5Data, err := xattr.Get(backendFile, "user.checksum.md5")
	require.NoError(t, err, "MD5 checksum should be stored in xattr")
	assert.NotEmpty(t, md5Data, "MD5 checksum xattr should not be empty")

	// Verify MD5 format (base64 encoded)
	md5Str := string(md5Data)
	_, err = base64.StdEncoding.DecodeString(md5Str)
	assert.NoError(t, err, "MD5 checksum should be valid base64")

	crc32cData, err := xattr.Get(backendFile, "user.checksum.crc32c")
	require.NoError(t, err, "CRC32C checksum should be stored in xattr")
	assert.NotEmpty(t, crc32cData, "CRC32C checksum xattr should not be empty")

	// Verify CRC32C format (hex encoded)
	crc32cStr := string(crc32cData)
	assert.Len(t, crc32cStr, 8, "CRC32C checksum should be 8 hex characters")
	_, err = fmt.Sscanf(crc32cStr, "%x", new(uint32))
	assert.NoError(t, err, "CRC32C checksum should be valid hex")

	// Verify mtime xattrs are also stored
	_, err = xattr.Get(backendFile, "user.checksum.md5.mtime")
	assert.NoError(t, err, "MD5 mtime should be stored")

	_, err = xattr.Get(backendFile, "user.checksum.crc32c.mtime")
	assert.NoError(t, err, "CRC32C mtime should be stored")
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
