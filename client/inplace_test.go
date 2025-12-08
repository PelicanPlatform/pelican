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

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestInPlaceDefault tests that downloads use temporary files by default
func TestInPlaceDefault(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "test file content for inplace default"
	var tempFileSeen bool

	// Create a mock server that simulates a slow download
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
		w.WriteHeader(http.StatusOK)

		// Write content slowly to allow us to check for temp file
		for i := 0; i < len(testContent); i++ {
			_, _ = w.Write([]byte{testContent[i]})
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// Start download in a goroutine
	doneChan := make(chan error, 1)
	go func() {
		transfer := &transferFile{
			xferType: transferTypeDownload,
			ctx:      context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   serverURL.Host,
					Path:   "/test.txt",
				},
				inPlace: false, // Use temp files (default)
			},
			localPath: finalPath,
			remoteURL: serverURL,
			attempts: []transferAttemptDetails{
				{Url: serverURL},
			},
		}
		transferResult, err := downloadObject(transfer)
		if err != nil {
			doneChan <- err
		} else {
			doneChan <- transferResult.Error
		}
	}()

	// Give download time to start
	time.Sleep(50 * time.Millisecond)

	// Check for temporary file (should exist during download)
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".testfile.txt.") {
			tempFileSeen = true
			// Verify temp file has expected format: .basename.XXXXXX
			assert.Regexp(t, `^\.testfile\.txt\.[a-zA-Z0-9]{6}$`, file.Name())
			break
		}
	}

	// Wait for download to complete
	err = <-doneChan
	require.NoError(t, err)

	// Verify temp file was used
	assert.True(t, tempFileSeen, "Temporary file should have been created during download")

	// Verify final file exists and has correct content
	content, err := os.ReadFile(finalPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))

	// Verify temp file was cleaned up
	files, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	for _, file := range files {
		assert.False(t, strings.HasPrefix(file.Name(), ".testfile.txt."),
			"Temporary file should have been cleaned up after successful download")
	}
}

// TestInPlaceFlag tests that --inplace flag bypasses temporary files
func TestInPlaceFlag(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "test file content for inplace flag"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
		w.WriteHeader(http.StatusOK)

		// Write slowly
		for i := 0; i < len(testContent); i++ {
			_, _ = w.Write([]byte{testContent[i]})
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// Start download with inPlace=true
	doneChan := make(chan error, 1)
	go func() {
		transfer := &transferFile{
			xferType: transferTypeDownload,
			ctx:      context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   serverURL.Host,
					Path:   "/test.txt",
				},
				inPlace: true, // Write directly, no temp files
			},
			localPath: finalPath,
			remoteURL: serverURL,
			attempts: []transferAttemptDetails{
				{Url: serverURL},
			},
		}
		transferResult, err := downloadObject(transfer)
		if err != nil {
			doneChan <- err
		} else {
			doneChan <- transferResult.Error
		}
	}()

	// Give download time to start
	time.Sleep(50 * time.Millisecond)

	// Check that NO temporary file exists
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	var tempFileFound bool
	for _, file := range files {
		if strings.HasPrefix(file.Name(), ".testfile.txt.") {
			tempFileFound = true
		}
	}
	assert.False(t, tempFileFound, "Temporary file should NOT be created with inPlace=true")

	// Wait for download to complete
	err = <-doneChan
	require.NoError(t, err)

	// Verify final file exists and has correct content
	content, err := os.ReadFile(finalPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))
}

// TestTempFileCleanupOnFailure tests that temp files are cleaned up on download failure
func TestTempFileCleanupOnFailure(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "partial content"

	// Create a server that fails mid-transfer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000") // Lie about content length
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testContent))
		// Connection "drops" here - don't send rest of content
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// Attempt download (should fail)
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test.txt",
			},
			inPlace: false, // Use temp files
		},
		localPath: finalPath,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	transferResult, err := downloadObject(transfer)
	// Download should fail due to incomplete transfer
	if err == nil {
		err = transferResult.Error
	}
	assert.Error(t, err, "Download should fail due to incomplete transfer")

	// Verify temp file was cleaned up
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	for _, file := range files {
		assert.False(t, strings.HasPrefix(file.Name(), ".testfile.txt."),
			"Temporary file should have been cleaned up after failed download")
	}

	// Verify final file doesn't exist
	_, err = os.Stat(finalPath)
	assert.True(t, os.IsNotExist(err), "Final file should not exist after failed download")
}

// TestInPlaceSyncPreservesFileOnFailure tests the critical sync scenario: when inPlace=true,
// a file already exists, and the download fails, the file should NOT be deleted.
// This is essential for sync operations - we don't want to lose existing data on transient failures.
func TestInPlaceSyncPreservesFileOnFailure(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	oldContent := "original file content before sync"
	partialContent := "partial"

	// Create a server that fails mid-transfer
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000") // Lie about content length
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partialContent))
		// Connection "drops" here
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// CRITICAL: Create existing file first (simulating a sync scenario)
	err = os.WriteFile(finalPath, []byte(oldContent), 0644)
	require.NoError(t, err)

	// Attempt sync download with inPlace=true (should fail)
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test.txt",
			},
			inPlace: true, // Write directly (sync mode)
		},
		localPath: finalPath,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	transferResult, err := downloadObject(transfer)
	if err == nil {
		err = transferResult.Error
	}
	assert.Error(t, err, "Download should fail due to incomplete transfer")

	// CRITICAL: The file should still exist (not deleted) even though download failed
	// This is the key sync behavior - preserve data on failure
	fileContent, err := os.ReadFile(finalPath)
	require.NoError(t, err, "File should still exist after failed sync download (not deleted)")

	// The file was opened with O_TRUNC, so it contains the partial content
	assert.Equal(t, partialContent, string(fileContent),
		"File should contain partial content, demonstrating it wasn't deleted")
}

// TestDevNullSpecialCase tests that os.DevNull never uses temp files
func TestDevNullSpecialCase(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "test content for dev null"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testContent))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Download to os.DevNull (should not create temp file)
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test.txt",
			},
			inPlace: false, // Even with temp files, os.DevNull should be special-cased
		},
		localPath: os.DevNull,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	transferResult, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, transferResult.Error)

	// Verify os.DevNull is still a character device (not corrupted)
	info, err := os.Stat(os.DevNull)
	require.NoError(t, err)
	assert.Equal(t, os.ModeDevice|os.ModeCharDevice, info.Mode()&(os.ModeDevice|os.ModeCharDevice),
		"os.DevNull should still be a character device")
}

// TestContextCancellationCleanup tests that temp files are cleaned up on context cancellation
func TestContextCancellationCleanup(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "test content that will be interrupted"

	// Create a server with slow response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)*100))
		w.WriteHeader(http.StatusOK)

		// Write slowly
		for i := 0; i < len(testContent); i++ {
			select {
			case <-r.Context().Done():
				return
			default:
				_, _ = w.Write([]byte{testContent[i]})
				if flusher, ok := w.(http.Flusher); ok {
					flusher.Flush()
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())

	// Start download
	doneChan := make(chan error, 1)
	go func() {
		transfer := &transferFile{
			xferType: transferTypeDownload,
			ctx:      ctx,
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   serverURL.Host,
					Path:   "/test.txt",
				},
				inPlace: false,
			},
			localPath: finalPath,
			remoteURL: serverURL,
			attempts: []transferAttemptDetails{
				{Url: serverURL},
			},
		}
		transferResult, err := downloadObject(transfer)
		if err != nil {
			doneChan <- err
		} else {
			doneChan <- transferResult.Error
		}
	}()

	// Give download time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Wait for download to finish
	err = <-doneChan
	assert.Error(t, err, "Download should fail due to context cancellation")

	// Give cleanup time to happen
	time.Sleep(100 * time.Millisecond)

	// Verify temp file was cleaned up
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	for _, file := range files {
		assert.False(t, strings.HasPrefix(file.Name(), ".testfile.txt."),
			"Temporary file should have been cleaned up after context cancellation")
	}
}

// TestExistingFileOverwrite tests that existing files are properly overwritten
func TestExistingFileOverwrite(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	oldContent := "old content that should be replaced"
	newContent := "new content from server"

	tempDir := t.TempDir()
	finalPath := filepath.Join(tempDir, "testfile.txt")

	// Create existing file
	err := os.WriteFile(finalPath, []byte(oldContent), 0644)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(newContent)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(newContent))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Download (should overwrite existing file)
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test.txt",
			},
			inPlace: false,
		},
		localPath: finalPath,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	transferResult, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, transferResult.Error)

	// Verify file has new content
	content, err := os.ReadFile(finalPath)
	require.NoError(t, err)
	assert.Equal(t, newContent, string(content))
}

// TestDirectoryDestination tests downloads to directory destinations
func TestDirectoryDestination(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	testContent := "test content for directory destination"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(testContent))
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()

	// Download to directory (filename will be extracted from path)
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/testfile.txt",
			},
			inPlace: false,
		},
		localPath: tempDir,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	transferResult, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, transferResult.Error)

	// Verify file was created in directory
	finalPath := filepath.Join(tempDir, "testfile.txt")
	content, err := os.ReadFile(finalPath)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(content))

	// Verify no temp files remain
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)

	for _, file := range files {
		if file.Name() != "testfile.txt" {
			assert.False(t, strings.HasPrefix(file.Name(), "."),
				"No temporary files should remain")
		}
	}
}
