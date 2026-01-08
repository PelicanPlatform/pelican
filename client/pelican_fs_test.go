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

package client_test

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/url"
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

		// Now test the FS interface
		pfs := client.NewPelicanFS(fed.Ctx)

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

		pfs := client.NewPelicanFS(fed.Ctx)
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
		assert.Equal(t, "PQRSTUVWXYa", string(buf)[:10])

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

		pfs := client.NewPelicanFS(fed.Ctx)
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
		pfs := client.NewPelicanFS(fed.Ctx)
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
