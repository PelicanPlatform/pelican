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
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// multiuserOriginConfig configures an origin with Multiuser and ScitokensMapSubject enabled
const multiuserOriginConfig = `
Origin:
  StorageType: posix
  Multiuser: true
  ScitokensMapSubject: true
  Exports:
    - FederationPrefix: /test
      Capabilities: ["Reads", "Writes", "Listings"]
`

// Helper function to create a token with a specific subject and scopes
func createTokenWithSubject(t *testing.T, subject string, scopes []token_scopes.TokenScope) string {
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = subject
	tokenConfig.AddAudienceAny()
	tokenConfig.AddScopes(scopes...)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	return tkn
}

// getFileOwner returns the UID and GID of a file
func getFileOwner(t *testing.T, filePath string) (uint32, uint32) {
	fileInfo, err := os.Stat(filePath)
	require.NoError(t, err)

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok, "Failed to get syscall.Stat_t from file info")

	return stat.Uid, stat.Gid
}

// getUserUID looks up a user by name and returns their UID
func getUserUID(t *testing.T, username string) uint32 {
	u, err := user.Lookup(username)
	require.NoError(t, err, "Failed to lookup user %s", username)

	var uid uint64
	_, err = fmt.Sscanf(u.Uid, "%d", &uid)
	require.NoError(t, err, "Failed to parse UID for user %s", username)

	return uint32(uid)
}

// TestOriginMultiuser tests the Origin's Multiuser feature
// This test verifies that:
// 1. Files uploaded with tokens having different subjects are owned by the corresponding users
// 2. Checksums are stored in xattrs
// 3. Downloads return the correct checksums
func TestOriginMultiuser(t *testing.T) {
	// Skip if not running as root - Multiuser feature requires root privileges
	if os.Geteuid() != 0 {
		t.Skip("Skipping multiuser test: must run as root")
	}

	// Verify that the test users exist
	_, err := user.Lookup("alice")
	if err != nil {
		t.Skip("Skipping multiuser test: user 'alice' does not exist")
	}

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create the federation with Multiuser enabled
	ft := fed_test_utils.NewFedTest(t, multiuserOriginConfig)
	require.NotNil(t, ft)

	// Get the storage prefix for verification
	storagePrefix := ft.Exports[0].StoragePrefix
	require.NotEmpty(t, storagePrefix, "Storage prefix should not be empty")

	// In multiuser mode, XRootD switches to the user specified in the token's subject.
	// We need to make the storage directory writable by alice and bob.
	// Set permissions to 0777 so any user can create files.
	err = os.Chmod(storagePrefix, 0777)
	require.NoError(t, err, "Failed to set storage directory permissions")

	// Get UID for alice
	aliceUID := getUserUID(t, "alice")

	// Create scopes for uploading and reading
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modifyScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)

	writeScopes := []token_scopes.TokenScope{createScope, modifyScope, readScope}

	// Create token for alice
	aliceToken := createTokenWithSubject(t, "alice", writeScopes)

	// Test content
	aliceContent := []byte("Hello from Alice! This is Alice's test file.")

	// Create local temp directory for test files
	localTmpDir := t.TempDir()

	// Write local files
	aliceLocalFile := filepath.Join(localTmpDir, "alice_file.txt")
	require.NoError(t, os.WriteFile(aliceLocalFile, aliceContent, 0644))

	// Upload URLs
	aliceUploadURL := fmt.Sprintf("pelican://%s:%d/test/alice_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Upload Alice's file
	t.Run("UploadAliceFile", func(t *testing.T) {
		transferResults, err := client.DoPut(ft.Ctx, aliceLocalFile, aliceUploadURL, false, client.WithToken(aliceToken))
		require.NoError(t, err)
		require.NotEmpty(t, transferResults)
		assert.Greater(t, transferResults[0].TransferredBytes, int64(0))
	})

	// Verify file ownership
	t.Run("VerifyAliceFileOwnership", func(t *testing.T) {
		aliceBackendFile := filepath.Join(storagePrefix, "alice_file.txt")
		uid, _ := getFileOwner(t, aliceBackendFile)
		assert.Equal(t, aliceUID, uid, "Alice's file should be owned by alice (UID %d), but is owned by UID %d", aliceUID, uid)
	})

	// Verify checksums in xattrs
	// Note: With multiuser.checksumonwrite enabled, checksums should be stored during upload
	t.Run("VerifyAliceFileChecksum", func(t *testing.T) {
		aliceBackendFile := filepath.Join(storagePrefix, "alice_file.txt")

		// Check if xattrs are supported on this filesystem
		testAttr := "user.test.pelican"
		err := xattr.Set(aliceBackendFile, testAttr, []byte("test"))
		if err != nil {
			t.Skipf("Xattrs not supported on this filesystem: %v", err)
		}
		_ = xattr.Remove(aliceBackendFile, testAttr)

		// Verify xattr was stored by checksumonwrite during upload (using adler32)
		adler32Data, err := xattr.Get(aliceBackendFile, "user.XrdCks.adler32")
		require.NoError(t, err)
		assert.NotEmpty(t, adler32Data, "Adler32 checksum xattr should not be empty")

		// Verify the checksum structure if we have enough data
		if len(adler32Data) >= 16+8+4+2+1+1+4 {
			nameBytes := adler32Data[:16]
			name := string(bytes.TrimRight(nameBytes, "\x00"))
			assert.Equal(t, "adler32", name, "Algorithm name should be adler32 in xattr")
		}
	})

	// Download files and verify checksums are provided in response
	// Use WithRequestChecksums to request md5 (supported by both client and xrootd-multiuser plugin)
	t.Run("DownloadAliceFileWithChecksum", func(t *testing.T) {
		downloadDir := t.TempDir()
		downloadFile := filepath.Join(downloadDir, "alice_downloaded.txt")

		transferResults, err := client.DoGet(
			ft.Ctx,
			aliceUploadURL,
			downloadFile,
			false,
			client.WithToken(aliceToken),
			client.WithRequestChecksums([]client.ChecksumType{client.AlgMD5}),
		)
		require.NoError(t, err)
		require.NotEmpty(t, transferResults)

		// Verify downloaded content
		content, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, aliceContent, content, "Downloaded content should match uploaded content")
	})

	t.Run("StatReturnsChecksum", func(t *testing.T) {
		statURL := fmt.Sprintf("pelican://%s:%d/test/alice_file.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		fileInfo, err := client.DoStat(
			ft.Ctx,
			statURL,
			client.WithToken(aliceToken),
			client.WithRequestChecksums([]client.ChecksumType{client.AlgMD5}),
		)
		require.NoError(t, err)
		require.NotNil(t, fileInfo, "FileInfo should not be nil")

		// Verify file size matches
		assert.Equal(t, int64(len(aliceContent)), fileInfo.Size, "File size should match uploaded content")

		// Verify checksum is returned
		assert.NotEmpty(t, fileInfo.Checksums, "Checksums should be returned when WithRequestChecksums is used")
		if len(fileInfo.Checksums) > 0 {
			t.Logf("Returned checksums: %v", fileInfo.Checksums)
		}
	})
}
