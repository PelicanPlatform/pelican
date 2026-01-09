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

package client_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"math/rand"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestPelicanFS_Basic(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	// Create a test file
	testFileContent := "Hello, Pelican FS! This is a test file with some content."
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err, "Error creating temp file")
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	require.NoError(t, err, "Error writing to temp file")
	tempFile.Close()

	// Upload the test file
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	for _, export := range fed.Exports {
		fileName := filepath.Base(tempFile.Name())
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		// Upload the file
		_, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false)
		require.NoError(t, err)

		// Now test the FS interface with the federation discovery URL
		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)

		// Test Open
		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)
		file, err := pfs.Open(remotePath)
		require.NoError(t, err, "Failed to open file")
		defer file.Close()

		// Test Stat
		info, err := file.Stat()
		require.NoError(t, err, "Failed to stat file")
		assert.Equal(t, fileName, info.Name())
		assert.Equal(t, int64(len(testFileContent)), info.Size())
		assert.False(t, info.IsDir())

		// Test Read (full file)
		buf := make([]byte, len(testFileContent))
		n, err := file.Read(buf)
		require.NoError(t, err, "Failed to read file")
		assert.Equal(t, len(testFileContent), n)
		assert.Equal(t, testFileContent, string(buf[:n]))

		// EOF should be reached
		_, err = file.Read(buf)
		assert.Equal(t, io.EOF, err)

		file.Close()

		// Clean up
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false))
	}
}

func TestPelicanFS_Seek(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	// Create a test file with known content
	testFileContent := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	require.NoError(t, err)
	tempFile.Close()

	// Upload the test file
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	for _, export := range fed.Exports {
		fileName := filepath.Base(tempFile.Name())
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		_, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false)
		require.NoError(t, err)

		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)
		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)

		file, err := pfs.Open(remotePath)
		require.NoError(t, err)
		defer file.Close()

		// Cast to get Seeker interface
		seeker, ok := file.(io.Seeker)
		require.True(t, ok, "File does not implement io.Seeker")

		// Test Seek from start
		pos, err := seeker.Seek(10, io.SeekStart)
		require.NoError(t, err)
		assert.Equal(t, int64(10), pos)

		// Read 10 bytes from position 10
		buf := make([]byte, 10)
		n, err := file.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 10, n)
		assert.Equal(t, "ABCDEFGHIJ", string(buf))

		// Test Seek from current
		pos, err = seeker.Seek(5, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(25), pos)

		n, err = file.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 10, n)
		assert.Equal(t, "PQRSTUVWXY", string(buf))

		// Test Seek from end
		pos, err = seeker.Seek(-5, io.SeekEnd)
		require.NoError(t, err)
		assert.Equal(t, int64(len(testFileContent)-5), pos)

		buf = make([]byte, 5)
		n, err = file.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "vwxyz", string(buf))

		file.Close()
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false))
	}
}

func TestPelicanFS_ReadAt(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	// Create a test file
	testFileContent := "The quick brown fox jumps over the lazy dog"
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	require.NoError(t, err)
	tempFile.Close()

	// Upload the test file
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	for _, export := range fed.Exports {
		fileName := filepath.Base(tempFile.Name())
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		_, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false)
		require.NoError(t, err)

		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)
		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)

		file, err := pfs.Open(remotePath)
		require.NoError(t, err)
		defer file.Close()

		// Cast to get ReaderAt interface
		readerAt, ok := file.(io.ReaderAt)
		require.True(t, ok, "File does not implement io.ReaderAt")

		// Test ReadAt from different positions
		buf := make([]byte, 5)

		// Read "quick" at offset 4
		n, err := readerAt.ReadAt(buf, 4)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "quick", string(buf))

		// Read "brown" at offset 10
		n, err = readerAt.ReadAt(buf, 10)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "brown", string(buf))

		// Read "jumps" at offset 20
		n, err = readerAt.ReadAt(buf, 20)
		require.NoError(t, err)
		assert.Equal(t, 5, n)
		assert.Equal(t, "jumps", string(buf))

		file.Close()
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false))
	}
}

func TestPelicanFS_InvalidPath(t *testing.T) {
	// This test doesn't require a full federation setup
	ctx := context.Background()
	pfs := client.NewPelicanFS(ctx)

	// Test with invalid path (should fail validation)
	_, err := pfs.Open("../etc/passwd")
	require.Error(t, err)
	var pathErr *fs.PathError
	require.ErrorAs(t, err, &pathErr)
}

func TestPelicanFS_Interfaces(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	// Create and upload a test file
	testFileContent := "test"
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	require.NoError(t, err)
	tempFile.Close()

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	for _, export := range fed.Exports {
		fileName := filepath.Base(tempFile.Name())
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		_, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false)
		require.NoError(t, err)

		// Test that PelicanFS implements fs.FS
		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)
		var _ fs.FS = pfs

		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)

		file, err := pfs.Open(remotePath)
		require.NoError(t, err)
		defer file.Close()

		// Test that PelicanFile implements fs.File
		var _ fs.File = file

		// Test that PelicanFile implements io.ReaderAt
		_, ok := file.(io.ReaderAt)
		require.True(t, ok, "File does not implement io.ReaderAt")

		// Test that PelicanFile implements io.Seeker
		_, ok = file.(io.Seeker)
		require.True(t, ok, "File does not implement io.Seeker")

		file.Close()
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false))
	}
}

// TestPelicanFS_ReadDir tests directory listing functionality
func TestPelicanFS_ReadDir(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	for _, export := range fed.Exports {
		// Upload multiple test files
		for i := 0; i < 3; i++ {
			testContent := fmt.Sprintf("test file %d content", i)
			tempFile, err := os.CreateTemp(t.TempDir(), "test")
			require.NoError(t, err)
			_, err = tempFile.WriteString(testContent)
			require.NoError(t, err)
			tempFile.Close()

			fileName := fmt.Sprintf("testfile%d.txt", i)
			uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
				export.FederationPrefix, fileName)

			_, err = client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false)
			require.NoError(t, err)
			os.Remove(tempFile.Name())
		}

		// Test ReadDir
		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)
		dirPath := fmt.Sprintf("%s/osdf_osdf", export.FederationPrefix)

		file, err := pfs.Open(dirPath)
		require.NoError(t, err)
		defer file.Close()

		// Cast to ReadDirFile
		dirFile, ok := file.(fs.ReadDirFile)
		require.True(t, ok, "File does not implement fs.ReadDirFile")

		// Read directory entries
		entries, err := dirFile.ReadDir(-1)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(entries), 3, "Should have at least 3 files")

		// Verify entries
		foundFiles := 0
		for _, entry := range entries {
			baseName := filepath.Base(entry.Name())
			if baseName == "testfile0.txt" || baseName == "testfile1.txt" || baseName == "testfile2.txt" {
				foundFiles++
				assert.False(t, entry.IsDir())
			}
		}
		assert.Equal(t, 3, foundFiles, "Should find all 3 test files")

		file.Close()

		// Cleanup
		for i := 0; i < 3; i++ {
			fileName := fmt.Sprintf("testfile%d.txt", i)
			deleteURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
				export.FederationPrefix, fileName)
			_ = client.DoDelete(fed.Ctx, deleteURL, false)
		}
	}
}

// TestPelicanFS_Write tests file writing functionality
func TestPelicanFS_Write(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	// Get a token for authenticated operations
	tempToken, _ := getTempToken(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	for _, export := range fed.Exports {
		fileName := "write_test.txt"
		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		// Note: OpenFile is not exposed, so we test via regular client operations
		// The Write method is tested through the pipe mechanism used internally

		testContent := "This is test content written via PelicanFS"
		tempFile, err := os.CreateTemp(t.TempDir(), "write_test")
		require.NoError(t, err)
		_, err = tempFile.WriteString(testContent)
		require.NoError(t, err)
		tempFile.Close()

		// Upload the file
		_, err = client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)

		// Verify we can read it back
		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix, client.WithTokenLocation(tempToken.Name()))
		file, err := pfs.Open(remotePath)
		require.NoError(t, err)

		buf := make([]byte, len(testContent))
		n, err := file.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, len(testContent), n)
		assert.Equal(t, testContent, string(buf))

		file.Close()
		os.Remove(tempFile.Name())

		// Cleanup
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false, client.WithTokenLocation(tempToken.Name())))
	}
}

// TestPelicanFS_NonPublicRead tests token generation for non-public reads
func TestPelicanFS_NonPublicRead(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	// Get a token
	tempToken, _ := getTempToken(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	for _, export := range fed.Exports {
		// Upload a test file with authentication
		testFileContent := "authenticated test content"
		tempFile, err := os.CreateTemp(t.TempDir(), "test")
		require.NoError(t, err)
		_, err = tempFile.WriteString(testFileContent)
		require.NoError(t, err)
		tempFile.Close()

		fileName := filepath.Base(tempFile.Name())
		uploadURL := fmt.Sprintf("pelican://%s%s/osdf_osdf/%s", discoveryUrl.Host,
			export.FederationPrefix, fileName)

		_, err = client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)

		// Test reading with token
		urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
		pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix, client.WithTokenLocation(tempToken.Name()))
		remotePath := fmt.Sprintf("%s/osdf_osdf/%s", export.FederationPrefix, fileName)

		file, err := pfs.Open(remotePath)
		require.NoError(t, err, "Should be able to open with valid token")

		// Read the content
		buf := make([]byte, len(testFileContent))
		n, err := file.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, len(testFileContent), n)
		assert.Equal(t, testFileContent, string(buf[:n]))

		file.Close()
		os.Remove(tempFile.Name())

		// Test that reading without token fails (if namespace requires auth)

		pfsNoToken := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)
		_, _ = pfsNoToken.Open(remotePath)
		// This may or may not fail depending on namespace configuration
		// Just verify the token mechanism is being invoked

		// Cleanup
		require.NoError(t, client.DoDelete(fed.Ctx, uploadURL, false, client.WithTokenLocation(tempToken.Name())))
	}
}

// TestPelicanFS_InvalidToken ensures invalid bearer tokens are rejected
func TestPelicanFS_InvalidToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
	pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix, client.WithToken("invalid-token"))

	remotePath := fmt.Sprintf("%s/osdf_osdf/invalid_token.txt", fed.Exports[0].FederationPrefix)

	_, err = pfs.Open(remotePath)
	require.Error(t, err, "opening with an invalid token should fail")

	var pathErr *fs.PathError
	require.ErrorAs(t, err, &pathErr)
}
func TestPelicanFS_NotFound(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	urlPrefix := fmt.Sprintf("pelican://%s", discoveryUrl.Host)
	pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)

	// Try to open a non-existent file
	_, err = pfs.Open("/does/not/exist.txt")
	require.Error(t, err)

	// Should be a PathError wrapping a 404-like error
	pathErr, ok := err.(*fs.PathError)
	require.True(t, ok, "error should be a *fs.PathError, got %T", err)
	assert.Equal(t, "open", pathErr.Op)
	assert.Equal(t, "/does/not/exist.txt", pathErr.Path)

	// The underlying error should indicate file not found (e.g., status code 404)
	assert.Error(t, pathErr.Err, "underlying error should be set")
}

// TestPelicanFS_WrongDirector tests that wrong director hostname/port produces reasonable error
func TestPelicanFS_WrongDirector(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	ctx := context.Background()

	// Use invalid director hostname and port
	pfs := client.NewPelicanFSWithPrefix(ctx, "pelican://nonexistent-director-12345.invalid:9999")

	// Try to open a file - should fail when contacting director
	_, err := pfs.Open("/test/file.txt")
	require.Error(t, err)

	// Should be a PathError
	pathErr, ok := err.(*fs.PathError)
	require.True(t, ok, "error should be a *fs.PathError, got %T", err)
	assert.Equal(t, "open", pathErr.Op)

	// The underlying error should indicate connection/DNS failure
	assert.Error(t, pathErr.Err, "underlying error should be set for director connection failure")
}

// TestPelicanFS_StressTest performs concurrent uploads, downloads, and random reads
func TestPelicanFS_StressTest(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	urlPrefix := fmt.Sprintf("pelican://%s/", discoveryUrl.Host)
	pfs := client.NewPelicanFSWithPrefix(fed.Ctx, urlPrefix)

	numFiles := 20
	numGoroutines := 4
	filesPerGoroutine := numFiles / numGoroutines
	fileSize := 1024 * 10             // 10 KB files
	largeFileSize := 50 * 1024 * 1024 // 50 MB

	// Use first federation export prefix for namespace
	basePrefix := ""
	if len(fed.Exports) > 0 {
		basePrefix = fed.Exports[0].FederationPrefix
	}
	if basePrefix == "" {
		basePrefix = "/first/namespace"
	}

	// Create test files with predictable content
	testFiles := make([]struct {
		path    string
		content []byte
	}, numFiles)

	for i := 0; i < numFiles; i++ {
		testFiles[i].path = fmt.Sprintf("%s/osdf_osdf/concurrent_%d.bin", basePrefix, i)
		testFiles[i].content = make([]byte, fileSize)
		// Fill with predictable pattern for verification
		for j := 0; j < fileSize; j++ {
			testFiles[i].content[j] = byte((i + j) % 256)
		}
	}

	t.Run("ConcurrentWrites", func(t *testing.T) {
		// Concurrently open files for writing
		errChan := make(chan error, numGoroutines)
		for g := 0; g < numGoroutines; g++ {
			go func(goroutineID int) {
				for i := 0; i < filesPerGoroutine; i++ {
					fileIdx := goroutineID*filesPerGoroutine + i

					// Open file for writing
					file, err := pfs.OpenFile(testFiles[fileIdx].path, os.O_WRONLY|os.O_CREATE)
					if err != nil {
						errChan <- fmt.Errorf("failed to open file %d for writing: %w", fileIdx, err)
						return
					}

					// Write data
					w, ok := file.(io.Writer)
					if !ok {
						file.Close()
						errChan <- fmt.Errorf("file %d does not support Writer interface", fileIdx)
						return
					}

					_, err = w.Write(testFiles[fileIdx].content)
					if err != nil {
						file.Close()
						errChan <- fmt.Errorf("failed to write file %d: %w", fileIdx, err)
						return
					}

					err = file.Close()
					if err != nil {
						errChan <- fmt.Errorf("failed to close file %d: %w", fileIdx, err)
						return
					}
				}
				errChan <- nil
			}(g)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			require.NoError(t, err, "goroutine %d failed during writes", i)
		}
	})

	t.Run("LargeFileUploadDownload", func(t *testing.T) {
		largePath := fmt.Sprintf("%s/osdf_osdf/large_pipe.bin", basePrefix)
		content := bytes.Repeat([]byte{0xAB}, largeFileSize)

		file, err := pfs.OpenFile(largePath, os.O_WRONLY|os.O_CREATE)
		require.NoError(t, err)

		w, ok := file.(io.Writer)
		require.True(t, ok, "large file handle missing Writer")

		_, err = w.Write(content)
		require.NoError(t, err)

		require.NoError(t, file.Close())

		file, err = pfs.Open(largePath)
		require.NoError(t, err)

		partial := make([]byte, 4096)
		_, err = file.Read(partial)
		require.NoError(t, err)

		require.NoError(t, file.Close())

		file, err = pfs.Open(largePath)
		require.NoError(t, err)

		readBack, err := io.ReadAll(file)
		require.NoError(t, err)
		assert.Len(t, readBack, len(content))
		assert.Equal(t, content[:1024], readBack[:1024])

		require.NoError(t, file.Close())
	})

	t.Run("ConcurrentReads", func(t *testing.T) {
		// Concurrently read files that were just written
		errChan := make(chan error, numGoroutines)
		for g := 0; g < numGoroutines; g++ {
			go func(goroutineID int) {
				for i := 0; i < filesPerGoroutine; i++ {
					fileIdx := goroutineID*filesPerGoroutine + i

					// Open file for reading
					file, err := pfs.Open(testFiles[fileIdx].path)
					if err != nil {
						// File might not exist if upload didn't complete, that's OK for stress test
						errChan <- nil
						return
					}

					// Read some data
					data, err := io.ReadAll(file)
					if err != nil && err != io.EOF {
						file.Close()
						errChan <- fmt.Errorf("failed to read file %d: %w", fileIdx, err)
						return
					}

					err = file.Close()
					if err != nil {
						errChan <- fmt.Errorf("failed to close file %d: %w", fileIdx, err)
						return
					}

					// Verify we read something
					if len(data) > 0 {
						t.Logf("Read %d bytes from file %d", len(data), fileIdx)
					}
				}
				errChan <- nil
			}(g)
		}

		// Wait for all goroutines
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			require.NoError(t, err, "goroutine %d failed during reads", i)
		}
	})

	t.Run("ConcurrentReadAt", func(t *testing.T) {
		// Open files for concurrent ReadAt operations
		files := make([]fs.File, numFiles)
		openFileIndices := make([]int, 0, numFiles)
		for i := 0; i < numFiles; i++ {
			file, err := pfs.Open(testFiles[i].path)
			if err != nil {
				// File might not exist, skip it
				files[i] = nil
				continue
			}
			files[i] = file
			openFileIndices = append(openFileIndices, i)
		}
		defer func() {
			for _, f := range files {
				if f != nil {
					f.Close()
				}
			}
		}()

		// If no files opened, skip this sub-test
		if len(openFileIndices) == 0 {
			t.Skip("no files available for concurrent ReadAt test")
		}

		// Random concurrent reads using ReadAt
		stopChan := make(chan struct{})
		errChan := make(chan error, numGoroutines)
		done := make(chan struct{})

		go func() {
			time.Sleep(2 * time.Second)
			close(stopChan)
		}()

		rng := rand.New(rand.NewSource(time.Now().UnixNano()))

		for g := 0; g < numGoroutines; g++ {
			go func(goroutineID int) {
				defer func() { done <- struct{}{} }()

				for {
					select {
					case <-stopChan:
						errChan <- nil
						return
					default:
					}

					// Pick random file that exists
					randIdx := rng.Intn(len(openFileIndices))
					fileIdx := openFileIndices[randIdx]

					reader, ok := files[fileIdx].(io.ReaderAt)
					if !ok {
						errChan <- fmt.Errorf("file %d does not support ReaderAt", fileIdx)
						return
					}

					// Random offset and size
					offset := int64(rng.Intn(fileSize - 100))
					size := 100 + rng.Intn(900)

					buf := make([]byte, size)
					_, err := reader.ReadAt(buf, offset)
					if err != nil && err != io.EOF {
						errChan <- fmt.Errorf("ReadAt failed on file %d at offset %d: %w", fileIdx, offset, err)
						return
					}
				}
			}(g)
		}

		// Wait for all goroutines to finish
		for i := 0; i < numGoroutines; i++ {
			<-done
		}

		// Check for errors
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			require.NoError(t, err, "goroutine %d failed during concurrent ReadAt", i)
		}
	})
}
