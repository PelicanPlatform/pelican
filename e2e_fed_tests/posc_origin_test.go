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

const (
	// Size of the large file used to keep the upload in progress long enough to observe POSC temp files
	largeFileSize = 1024 * 1024 * 1024 // 1 GiB
	// Buffer size for writing the file in chunks to avoid holding 1 GiB in memory
	writeBufferSize = 512 * 1024 // 512 KiB
)

/*
TestPOSCOrigin_CancelUpload does the following:
  - Create a large file (1 GiB) and begin an upload to the origin
  - During the upload, a temporary file is created under the in-progress/anonymous/ directory
  - During the upload, verify that we can't pelican object stat the temporary file
  - After verifying that the temporary file is present, kill the upload
  - Verify that the temporary file is deleted
  - Verify that the attempted uploaded file is not present under the storage prefix
  - Assert that a pelican object stat for the attempted uploaded file fails with a 404 error
*/
func TestPOSCOrigin_CancelUpload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

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

	// The POSC plugin creates temp files under the configured Origin.UploadTempLocation.
	// For unauthenticated uploads, files go under the "anonymous" subdirectory.
	// Get the actual upload temp location from the running configuration.
	uploadTempLocation := param.Origin_UploadTempLocation.GetString()
	require.NotEmpty(t, uploadTempLocation, "Origin.UploadTempLocation should be set")
	uploadTempDir := filepath.Join(uploadTempLocation, "anonymous")

	t.Logf("Upload temp directory: %s", uploadTempDir)
	t.Logf("Storage prefix: %s", storagePrefix)

	// Create a large file with random content (1GB to ensure upload takes long enough to observe).
	// Write in a buffered loop so we don't hold 1 GiB in memory.
	localFilePath := filepath.Join(t.TempDir(), "large_file.bin")
	f, err := os.Create(localFilePath)
	require.NoError(t, err)
	buf := make([]byte, writeBufferSize)
	for written := int64(0); written < largeFileSize; {
		n := int64(len(buf))
		if remaining := largeFileSize - written; n > remaining {
			n = remaining
		}
		// Fill buffer with random data (only the slice we'll write)
		for i := int64(0); i < n; i++ {
			buf[i] = byte(rand.Intn(256))
		}
		nw, writeErr := f.Write(buf[:n])
		require.NoError(t, writeErr)
		written += int64(nw)
	}
	require.NoError(t, f.Sync())
	require.NoError(t, f.Close())

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

	// Wait for a temporary file to appear in the upload temp directory.
	// The POSC plugin creates temp files here during uploads.
	// Note: The anonymous directory is created lazily when the first upload starts.
	var tempFilePath string
	foundTempFile := assert.Eventually(t, func() bool {
		// First check if the upload temp location directory exists
		if _, err := os.Stat(uploadTempLocation); os.IsNotExist(err) {
			t.Logf("Upload temp location does not exist yet: %s", uploadTempLocation)
			return false
		}

		// Check for files in the anonymous subdirectory
		entries, err := os.ReadDir(uploadTempDir)
		if err != nil {
			// Directory might not exist yet - this is expected initially
			if !os.IsNotExist(err) {
				t.Logf("Error reading upload temp dir: %v", err)
			}
			return false
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				tempFilePath = filepath.Join(uploadTempDir, entry.Name())
				t.Logf("Found temp file: %s", tempFilePath)
				return true
			}
		}
		return false
	}, 60*time.Second, 100*time.Millisecond, "Temporary file never appeared in upload temp directory")

	if !foundTempFile {
		// Log diagnostic information before failing
		t.Logf("Diagnostic: checking upload temp location contents")
		if entries, err := os.ReadDir(uploadTempLocation); err == nil {
			for _, e := range entries {
				t.Logf("  Found in upload temp location: %s (dir=%v)", e.Name(), e.IsDir())
			}
		} else {
			t.Logf("  Could not read upload temp location: %v", err)
		}
		uploadCancel()
		t.Fatal("Test failed: temporary file was never created during upload")
	}

	t.Logf("Found temporary file during upload: %s", tempFilePath)

	// Verify that the temporary file exists on disk
	_, err = os.Stat(tempFilePath)
	require.NoError(t, err, "Temporary file should exist on disk")

	// Verify the file hasn't been committed to its final federation path yet.
	// The POSC plugin holds writes in a temp location and only renames to the final
	// path on a successful close(), so a stat on the upload URL should fail while
	// the upload is still in flight.
	var pe *error_codes.PelicanError
	_, err = client.DoStat(ft.Ctx, uploadUrl, client.WithTokenLocation(""))
	require.Error(t, err, "Should not be able to stat the upload URL while the upload is still in progress")
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "Specification.FileNotFound", pe.ErrorType())

	// Also verify that the final file doesn't exist yet (upload is still in progress).
	// This assumes the 1 GiB upload hasn't completed by the time we reach this point. Given
	// the file size and the fact that the upload goes through the full Pelican stack (client ->
	// director -> origin -> POSC plugin -> disk), this should hold on any reasonable hardware.
	// If this assertion ever fails, the file size (largeFileSize) should be increased.
	_, err = os.Stat(finalFilePath)
	require.True(t, os.IsNotExist(err), "Final file should not exist yet during upload; "+
		"if the upload completed before cancellation, consider increasing largeFileSize")

	// Cancel the upload context to kill the upload
	t.Log("Cancelling upload...")
	uploadCancel()

	// Wait for the cancellation to propagate and the upload goroutine to exit
	select {
	case uploadErr := <-uploadDone:
		t.Logf("Upload goroutine exited with error (expected due to cancellation): %v", uploadErr)
		require.ErrorAs(t, uploadErr, &context.Canceled)
	case <-time.After(30 * time.Second):
		t.Fatal("Context cancellation did not propagate to the upload goroutine within 30 seconds")
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

}
