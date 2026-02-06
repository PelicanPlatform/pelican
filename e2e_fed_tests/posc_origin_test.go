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
	"context"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

/*
TestPOSCOrigin_CancelUpload Does the following:
- Create a large file (500MB) and begin an upload to the origin
- During the upload, a temporary is created under the in-progress/anonymous/ directory
- During the upload, verify that we can't pelican object stat the temporary file
- After verifying that the temporary file is present, kill the upload
- Verify that the temporary file is deleted
- Verify that the attempted uploaded file is not present under the storage prefix
- Assert that a pelican object stat for the attempted uploaded file fails with a 404 error
*/
func TestPOSCOrigin_CancelUpload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	originConfig := `
Origin:
  StorageType: "posix"
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: /test-namespace
      Capabilities: ["PublicReads", "Reads", "Writes", "DirectReads", "Listings"]
`
	ft := fed_test_utils.NewFedTest(t, originConfig)

	// Get the storage prefix from the export (this is the actual filesystem location)
	storagePrefix := ft.Exports[0].StoragePrefix
	federationPrefix := ft.Exports[0].FederationPrefix

	// The POSC plugin creates temp files under the configured Origin.InProgressLocation.
	// For unauthenticated uploads, files go under the "anonymous" subdirectory.
	// Get the actual in-progress location from the running configuration.
	inProgressLocation := param.Origin_InProgressLocation.GetString()
	require.NotEmpty(t, inProgressLocation, "Origin.InProgressLocation should be set")
	inProgressDir := filepath.Join(inProgressLocation, "anonymous")

	t.Logf("In-progress directory: %s", inProgressDir)
	t.Logf("Storage prefix: %s", storagePrefix)

	// Create a large file with random content (1GB to ensure upload takes long enough to observe)
	fileContent := make([]byte, 1024*1024*1024)
	for i := range fileContent {
		fileContent[i] = byte(rand.Intn(256))
	}

	// Write the file to a temporary directory
	localFilePath := filepath.Join(t.TempDir(), "large_file.bin")
	require.NoError(t, os.WriteFile(localFilePath, fileContent, 0644))

	// Get the discovery URL for constructing pelican URLs
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	// The remote path where we're trying to upload
	remoteFileName := "upload_test_file.bin"
	uploadUrl := fmt.Sprintf("pelican://%s%s/%s", discoveryUrl.Host, federationPrefix, remoteFileName)
	finalFilePath := filepath.Join(storagePrefix, remoteFileName)

	// Create a cancellable context for the upload
	uploadCtx, uploadCancel := context.WithCancel(ft.Ctx)

	// Channel to signal when upload completes (or errors)
	uploadDone := make(chan error, 1)

	// Start the upload in a goroutine
	go func() {
		_, err := client.DoPut(uploadCtx, localFilePath, uploadUrl, false, client.WithTokenLocation(""))
		uploadDone <- err
	}()

	// Wait for a temporary file to appear in the in-progress directory
	// The POSC plugin creates temp files here during uploads.
	// Note: The anonymous directory is created lazily when the first upload starts.
	var tempFilePath string
	foundTempFile := assert.Eventually(t, func() bool {
		// First check if the in-progress location directory exists
		if _, err := os.Stat(inProgressLocation); os.IsNotExist(err) {
			t.Logf("In-progress location does not exist yet: %s", inProgressLocation)
			return false
		}

		// Check for files in the anonymous subdirectory
		entries, err := os.ReadDir(inProgressDir)
		if err != nil {
			// Directory might not exist yet - this is expected initially
			if !os.IsNotExist(err) {
				t.Logf("Error reading in-progress dir: %v", err)
			}
			return false
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				tempFilePath = filepath.Join(inProgressDir, entry.Name())
				t.Logf("Found temp file: %s", tempFilePath)
				return true
			}
		}
		return false
	}, 60*time.Second, 100*time.Millisecond, "Temporary file never appeared in in-progress directory")

	if !foundTempFile {
		// Log diagnostic information before failing
		t.Logf("Diagnostic: checking in-progress location contents")
		if entries, err := os.ReadDir(inProgressLocation); err == nil {
			for _, e := range entries {
				t.Logf("  Found in in-progress location: %s (dir=%v)", e.Name(), e.IsDir())
			}
		} else {
			t.Logf("  Could not read in-progress location: %v", err)
		}
		uploadCancel()
		t.Fatal("Test failed: temporary file was never created during upload")
	}

	t.Logf("Found temporary file during upload: %s", tempFilePath)

	// Verify that the temporary file exists on disk
	_, err = os.Stat(tempFilePath)
	require.NoError(t, err, "Temporary file should exist on disk")

	// Verify that we can't stat the temporary file via pelican
	// The in-progress directory should not be accessible via the federation namespace
	inProgressStatUrl := fmt.Sprintf("pelican://%s%s/in-progress/anonymous/%s",
		discoveryUrl.Host, federationPrefix, filepath.Base(tempFilePath))
	_, err = client.DoStat(ft.Ctx, inProgressStatUrl, client.WithTokenLocation(""))
	require.Error(t, err, "Should not be able to stat the temporary in-progress file via pelican")
	var pe *error_codes.PelicanError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "Specification.FileNotFound", pe.ErrorType())

	// Also verify that the final file doesn't exist yet (upload is still in progress)
	_, err = os.Stat(finalFilePath)
	assert.True(t, os.IsNotExist(err), "Final file should not exist yet during upload")

	// Cancel the upload context to kill the upload
	t.Log("Cancelling upload...")
	uploadCancel()

	// Wait for the upload goroutine to finish
	select {
	case uploadErr := <-uploadDone:
		// We expect an error since we cancelled the upload
		t.Logf("Upload finished with error (expected due to cancellation): %v", uploadErr)
		require.ErrorAs(t, uploadErr, &context.Canceled)
	case <-time.After(30 * time.Second):
		t.Fatal("Upload did not finish within timeout after cancellation")
	}

	// Verify that the temporary file is deleted after the upload is cancelled
	assert.Eventually(t, func() bool {
		_, err := os.Stat(tempFilePath)
		return os.IsNotExist(err)
	}, 30*time.Second, 100*time.Millisecond, "Temporary file was not cleaned up after upload cancellation")

	// Verify that the final file was not created (upload was cancelled before completion)
	_, err = os.Stat(finalFilePath)
	assert.True(t, os.IsNotExist(err), "Final file should not exist after cancelled upload")

	// Assert that a pelican object stat for the attempted uploaded file fails with a 404 error
	_, err = client.DoStat(ft.Ctx, uploadUrl, client.WithTokenLocation(""))
	require.Error(t, err, "Stat for cancelled upload file should return an error")
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "Specification.FileNotFound", pe.ErrorType())

	t.Log("POSC origin test passed: temporary files are properly managed during upload cancellation")
}
