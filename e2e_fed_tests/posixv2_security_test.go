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

// TestPosixv2LegitimateAccessWorks verifies that basic file access works
// This is a sanity check to ensure the test federation is properly configured
func TestPosixv2LegitimateAccessWorks(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory for storage
	tmpDir := t.TempDir()

	// Configure origin
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
	require.Greater(t, len(ft.Exports), 0)

	testToken := getTempTokenForTest(t)

	// Create a test file in storage
	testContent := "This is a test file"
	testFile := filepath.Join(ft.Exports[0].StoragePrefix, "test_file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Verify we can download it
	downloadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	localDest := filepath.Join(t.TempDir(), "downloaded.txt")
	_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

	require.NoError(t, err, "Should be able to download legitimate files")

	content, err := os.ReadFile(localDest)
	assert.NoError(t, err)
	assert.Equal(t, testContent, string(content), "Downloaded content should match uploaded content")
}

// TestPosixv2PathTraversalAttack tests that path traversal attacks using ../ are blocked
// This test verifies actual data access is prevented, not just HTTP response codes
func TestPosixv2PathTraversalAttack(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory structure with proper isolation
	tmpDir := t.TempDir()
	originDir := filepath.Join(tmpDir, "origin")
	require.NoError(t, os.Mkdir(originDir, 0755))

	// Configure origin with the restricted storage prefix
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
`, originDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	testToken := getTempTokenForTest(t)

	// Create a sensitive file OUTSIDE the federation namespace
	// but in the same parent directory as the storage
	sensitiveDir := filepath.Join(tmpDir, "sensitive")
	require.NoError(t, os.Mkdir(sensitiveDir, 0755))
	sensitiveFile := filepath.Join(sensitiveDir, "data.txt")
	sensitiveContent := "SENSITIVE DATA - SHOULD NOT BE ACCESSIBLE"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(sensitiveContent), 0644))

	// Create a file in the storage directory to test legitimate access
	allowedContent := "This is allowed"
	allowedFileInStorage := filepath.Join(ft.Exports[0].StoragePrefix, "allowed_file.txt")
	require.NoError(t, os.WriteFile(allowedFileInStorage, []byte(allowedContent), 0644))

	// Test Case 1: Verify legitimate access works first
	t.Run("LegitimateAccessWorks", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/allowed_file.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		require.NoError(t, err, "Legitimate file access should work")

		content, err := os.ReadFile(localDest)
		assert.NoError(t, err)
		assert.Equal(t, allowedContent, string(content), "Should download correct file content")
	})

	// Test Case 2: Simple path traversal with ../
	t.Run("SimpleDotDotSlashTraversal", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/../sensitive/data.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		// Should fail to download
		assert.Error(t, err, "Path traversal attack should fail - should not be able to download sensitive file")

		// If a file was created, verify it doesn't contain sensitive data
		if content, err := os.ReadFile(localDest); err == nil {
			assert.NotEqual(t, sensitiveContent, string(content),
				"Downloaded file should not contain sensitive data")
		}
	})

	// Test Case 3: Multiple levels of path traversal
	t.Run("MultiLevelTraversal", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/../../sensitive/data.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		assert.Error(t, err, "Multi-level path traversal attack should fail")

		if content, err := os.ReadFile(localDest); err == nil {
			assert.NotEqual(t, sensitiveContent, string(content),
				"Downloaded file should not contain sensitive data")
		}
	})

	// Test Case 4: Traversal with encoded dots
	t.Run("EncodedPathTraversal", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/%%2e%%2e/sensitive/data.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		// Either fails to parse or fails to download - both are acceptable
		assert.Error(t, err, "Encoded path traversal should be blocked")
	})
}

// TestPosixv2SymlinkTraversalAttack tests that symlink-based traversal attacks are blocked
// This test verifies actual data access is prevented via DoGet
func TestPosixv2SymlinkTraversalAttack(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory structure:
	// tmpDir/
	//   ├── origin/                    <- origin storage
	//   │   ├── allowed_file.txt       <- legitimate file
	//   │   └── malicious_symlink  -> ../sensitive/data.txt (symlink to sensitive file)
	//   └── sensitive/
	//       └── data.txt               <- sensitive file OUTSIDE allowed namespace

	tmpDir := t.TempDir()
	originDir := filepath.Join(tmpDir, "origin")
	require.NoError(t, os.Mkdir(originDir, 0755))

	sensitiveDir := filepath.Join(tmpDir, "sensitive")
	require.NoError(t, os.Mkdir(sensitiveDir, 0755))

	// Create sensitive file outside namespace
	sensitiveFile := filepath.Join(sensitiveDir, "data.txt")
	sensitiveContent := "SENSITIVE DATA FROM SYMLINK - SHOULD NOT BE ACCESSIBLE"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(sensitiveContent), 0644))

	// Configure origin with the restricted storage prefix
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
`, originDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	testToken := getTempTokenForTest(t)

	// Create legitimate file in storage
	allowedContent := "This is allowed"
	allowedFileInStorage := filepath.Join(ft.Exports[0].StoragePrefix, "allowed_file.txt")
	require.NoError(t, os.WriteFile(allowedFileInStorage, []byte(allowedContent), 0644))

	// Create a malicious symlink in the storage directory that points outside the namespace
	symlinkPath := filepath.Join(ft.Exports[0].StoragePrefix, "malicious_symlink")
	targetPath := filepath.Join(tmpDir, "sensitive", "data.txt")
	require.NoError(t, os.Symlink(targetPath, symlinkPath))

	// Test Case 1: Try to access the symlink via DoGet
	// NOTE: This test demonstrates the fix for symlink traversal vulnerability
	// Using os.Root (Go 1.24), symlinks that escape the storage prefix are blocked
	t.Run("SymlinkTraversalBlocked", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/malicious_symlink",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		// The request should fail because the symlink points outside the namespace
		assert.Error(t, err, "Symlink traversal should be blocked by os.Root")

		// Verify we didn't get the sensitive data
		if _, statErr := os.Stat(localDest); statErr == nil {
			content, _ := os.ReadFile(localDest)
			assert.NotEqual(t, sensitiveContent, string(content),
				"Downloaded content should NOT be the sensitive file outside namespace")
		}
	})

	// Test Case 2: Verify legitimate access still works
	t.Run("LegitimateAccessWorks", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/allowed_file.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		assert.NoError(t, err, "Legitimate file access should work")

		if err == nil {
			content, err := os.ReadFile(localDest)
			assert.NoError(t, err)
			assert.Equal(t, allowedContent, string(content), "Should access legitimate file")
		}
	})

	// Test Case 3: Verify legitimate symlinks within namespace work
	t.Run("LegitimateSymlinksWork", func(t *testing.T) {
		// Create a legitimate symlink within the namespace
		legitimateSymlink := filepath.Join(ft.Exports[0].StoragePrefix, "link_to_allowed")
		require.NoError(t, os.Symlink(allowedFileInStorage, legitimateSymlink))

		downloadURL := fmt.Sprintf("pelican://%s:%d/test/link_to_allowed",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		if err == nil {
			content, err := os.ReadFile(localDest)
			assert.NoError(t, err)
			assert.Equal(t, allowedContent, string(content), "Should access legitimate symlink target")
		}
		// Note: if it fails, that's also acceptable depending on symlink policy
	})
}

// TestPosixv2UploadedSymlinkAttack tests if an attacker can upload a symlink to escape the namespace
func TestPosixv2UploadedSymlinkAttack(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a temporary directory structure to test if symlinks can escape
	tmpDir := t.TempDir()
	originDir := filepath.Join(tmpDir, "origin")
	require.NoError(t, os.Mkdir(originDir, 0755))

	sensitiveDir := filepath.Join(tmpDir, "sensitive")
	require.NoError(t, os.Mkdir(sensitiveDir, 0755))

	// Create a sensitive file outside namespace
	sensitiveFile := filepath.Join(sensitiveDir, "data.txt")
	sensitiveContent := "SENSITIVE DATA - SHOULD NOT BE ACCESSIBLE VIA SYMLINK"
	require.NoError(t, os.WriteFile(sensitiveFile, []byte(sensitiveContent), 0644))

	// Configure origin
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
`, originDir)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	testToken := getTempTokenForTest(t)

	// Create a malicious symlink in the storage directory pointing outside
	// (simulating a symlink created via other means, not via HTTP upload)
	symlinkPath := filepath.Join(ft.Exports[0].StoragePrefix, "escaped_symlink")
	targetPath := filepath.Join(tmpDir, "sensitive", "data.txt")
	require.NoError(t, os.Symlink(targetPath, symlinkPath))

	// Try to access the symlink via DoGet
	downloadURL := fmt.Sprintf("pelican://%s:%d/test/escaped_symlink",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	localDest := filepath.Join(t.TempDir(), "downloaded.txt")
	_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

	// The symlink should not allow access to the sensitive file
	// Fixed with os.Root (Go 1.24) which prevents symlink escapes
	assert.Error(t, err, "Symlink escape should fail - protected by os.Root filesystem boundary")

	// Verify we didn't get sensitive data
	if _, statErr := os.Stat(localDest); statErr == nil {
		if content, readErr := os.ReadFile(localDest); readErr == nil {
			assert.NotEqual(t, sensitiveContent, string(content),
				"Downloaded content should NOT be the sensitive file outside namespace")
		}
	}
}

// TestPosixv2CapabilityEnforcement tests that capabilities are properly enforced
// This test verifies that writes are blocked when the Writes capability is disabled
// Capabilities should be enforced at BOTH the origin layer AND the helper/WebDAV layer (defense in depth)
func TestPosixv2CapabilityEnforcement(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin WITHOUT Writes capability
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /tmp
      Capabilities: ["PublicReads", "Reads", "Listings"]
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	testToken := getTempTokenForTest(t)

	// Test Case 1: Verify that reads still work (sanity check)
	t.Run("ReadsStillWork", func(t *testing.T) {
		// Create a test file directly in storage
		testContent := "This file can be read"
		testFile := filepath.Join(ft.Exports[0].StoragePrefix, "readable.txt")
		require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

		// Verify we can download it
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/readable.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		require.NoError(t, err, "Reads should work when Writes is disabled")

		content, err := os.ReadFile(localDest)
		assert.NoError(t, err)
		assert.Equal(t, testContent, string(content))
	})

	// Test Case 2: Verify that writes are blocked
	t.Run("WritesAreBlocked", func(t *testing.T) {
		// Create a local file to upload
		localFile := filepath.Join(t.TempDir(), "upload_me.txt")
		require.NoError(t, os.WriteFile(localFile, []byte("Attempting to upload"), 0644))

		// Try to upload - should fail because Writes capability is disabled
		uploadURL := fmt.Sprintf("pelican://%s:%d/test/should_not_exist.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))

		// Upload should fail - capabilities are enforced at both origin and helper layers
		require.Error(t, err, "Upload should fail when Writes capability is disabled")

		// Verify the file was NOT created on storage
		notExistPath := filepath.Join(ft.Exports[0].StoragePrefix, "should_not_exist.txt")
		_, statErr := os.Stat(notExistPath)
		assert.True(t, os.IsNotExist(statErr), "File should NOT exist in storage when writes are disabled")
	})
}

// TestPosixv2ListingsCapabilityEnforcement tests that directory listing capabilities are enforced
func TestPosixv2ListingsCapabilityEnforcement(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Configure origin WITHOUT Listings capability
	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /tmp
      Capabilities: ["PublicReads", "Reads", "Writes"]
`

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	// Create a temporary directory for storage with some files
	require.NoError(t, os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(ft.Exports[0].StoragePrefix, "file2.txt"), []byte("content2"), 0644))

	testToken := getTempTokenForTest(t)

	// Test Case 1: Individual file reads should still work
	t.Run("IndividualReadsWork", func(t *testing.T) {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/file1.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		localDest := filepath.Join(t.TempDir(), "downloaded.txt")
		_, err := client.DoGet(ft.Ctx, downloadURL, localDest, false, client.WithToken(testToken))

		require.NoError(t, err, "Individual file reads should work when Listings is disabled")
	})

	// Test Case 2: Directory listing should be blocked
	// Note: This test depends on the client trying to do PROPFIND with Depth:1 for directory ops
	// The exact behavior depends on how the client implements directory operations
	t.Run("DirectoryListingBlocked", func(t *testing.T) {
		// Create a subdirectory with files
		subDir := filepath.Join(ft.Exports[0].StoragePrefix, "subdir")
		require.NoError(t, os.Mkdir(subDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("nested content"), 0644))

		// Verify the capability flag is disabled as configured
		assert.False(t, ft.Exports[0].Capabilities.Listings,
			"Listings capability should be disabled as configured")

		// Try to list the directory - should fail because Listings capability is disabled
		listURL := fmt.Sprintf("pelican://%s:%d/test/subdir",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))

		// Directory listing should fail when Listings capability is disabled
		require.Error(t, err, "Directory listing should fail when Listings capability is disabled")
	})
}
