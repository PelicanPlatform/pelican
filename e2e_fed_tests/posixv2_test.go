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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
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

	transferResultsUpload, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsUpload)
	assert.Greater(t, transferResultsUpload[0].TransferredBytes, int64(0), "Should have transferred bytes")

	// Download the file using the Pelican client
	downloadFile := filepath.Join(localTmpDir, "downloaded_file.txt")
	transferResultsDownload, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsDownload)
	assert.Equal(t, transferResultsUpload[0].TransferredBytes, transferResultsDownload[0].TransferredBytes,
		"Downloaded bytes should match uploaded bytes")

	// Verify downloaded file content matches
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent), "Downloaded content should match uploaded content")

	// Verify the file also exists in the backend storage
	backendFile := filepath.Join(tmpDir, "test_file.txt")
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

	// Create a test file directly in the backend
	testContent := []byte("Test content for stat and checksum verification")
	backendFile := filepath.Join(tmpDir, "stat_test.txt")
	require.NoError(t, os.WriteFile(backendFile, testContent, 0644))

	// Configure origin to use POSIXv2
	originConfig := fmt.Sprintf(posixv2OriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// Stat the file using the Pelican client
	statURL := fmt.Sprintf("pelican://%s:%d/test/stat_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Stat without checksum
	statInfo, err := client.DoStat(ft.Ctx, statURL, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	assert.Equal(t, int64(len(testContent)), statInfo.Size, "File size should match")
	assert.Equal(t, "/test/stat_test.txt", statInfo.Name, "File name should match")
	assert.Nil(t, statInfo.Checksums, "Checksums should be nil when not requested")

	// Stat with checksum request
	statInfo, err = client.DoStat(ft.Ctx, statURL, client.WithTokenLocation(ft.Token),
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

	// Upload all files using the Pelican client
	for filename, content := range testFiles {
		localFile := filepath.Join(localTmpDir, filename)
		require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

		transferResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithTokenLocation(ft.Token))
		require.NoError(t, err, "Failed to upload %s", filename)
		require.NotEmpty(t, transferResults)
		assert.Greater(t, transferResults[0].TransferredBytes, int64(0), "Should have transferred bytes for %s", filename)
	}

	// Download and verify all files
	for filename, expectedContent := range testFiles {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)
		downloadFile := filepath.Join(localTmpDir, "downloaded_"+filename)

		transferResults, err := client.DoGet(ft.Ctx, downloadURL, downloadFile, false, client.WithTokenLocation(ft.Token))
		require.NoError(t, err, "Failed to download %s", filename)
		require.NotEmpty(t, transferResults)

		// Verify content
		content, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, string(content), "Content of %s should match", filename)

		// Verify file exists in backend storage
		backendFile := filepath.Join(tmpDir, filename)
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

	transferResultsUpload, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsUpload)
	assert.Equal(t, int64(len(largeContent)), transferResultsUpload[0].TransferredBytes,
		"Should have transferred all bytes")

	// Download the large file
	downloadFile := filepath.Join(localTmpDir, "downloaded_large_file.bin")
	transferResultsDownload, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferResultsDownload)
	assert.Equal(t, transferResultsUpload[0].TransferredBytes, transferResultsDownload[0].TransferredBytes,
		"Downloaded bytes should match uploaded bytes")

	// Verify downloaded file content hash
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	downloadedHash := fmt.Sprintf("%x", md5.Sum(downloadedContent))
	assert.Equal(t, originalHash, downloadedHash, "Downloaded file hash should match original")

	// Verify backend storage file
	backendFile := filepath.Join(tmpDir, "large_file.bin")
	backendContent, err := os.ReadFile(backendFile)
	require.NoError(t, err)
	backendHash := fmt.Sprintf("%x", md5.Sum(backendContent))
	assert.Equal(t, originalHash, backendHash, "Backend file hash should match original")
}
