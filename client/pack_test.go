//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Morgridge Institute for Research
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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestDirectory(t *testing.T, path string) {
	subdirPath := filepath.Join(path, "subdir1")
	siblingPath := filepath.Join(path, "foo.txt")
	childPath := filepath.Join(path, "subdir1", "bar.txt")
	err := os.Mkdir(subdirPath, 0750)
	require.NoError(t, err)
	err = os.WriteFile(siblingPath, []byte("foo"), 0640)
	require.NoError(t, err)
	err = os.WriteFile(childPath, []byte("bar"), 0440)
	require.NoError(t, err)
}

func verifyTestDirectory(t *testing.T, testDirectory string) {
	entryCount := 0
	err := filepath.WalkDir(testDirectory, func(path string, dent fs.DirEntry, err error) error {
		// Skip the top-level directory itself.
		if len(testDirectory) >= len(path) {
			return nil
		}
		switch path[len(testDirectory)+1:] {
		case "subdir1":
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsDir())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0750))
		case "foo.txt":
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsRegular())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0640))
			buffer, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, string(buffer), "foo")
		case filepath.Join("subdir1", "bar.txt"):
			fi, err := dent.Info()
			require.NoError(t, err)
			assert.True(t, fi.Mode().IsRegular())
			assert.Equal(t, fi.Mode()&fs.ModePerm, fs.FileMode(0440))
			buffer, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, string(buffer), "bar")
		default:
			assert.Failf(t, "Unknown file encountered in directory", path)
		}
		entryCount += 1
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, entryCount, 3)
}

func verifyTarball(t *testing.T, reader io.Reader) {
	tr := tar.NewReader(reader)
	entryCount := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		entryCount += 1
		switch hdr.Name {
		case "subdir1":
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeDir))
			assert.Equal(t, hdr.Mode, int64(0750))
		case "foo.txt":
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeReg))
			assert.Equal(t, hdr.Mode, int64(0640))
			buffer := new(bytes.Buffer)
			_, err := io.Copy(buffer, tr)
			require.NoError(t, err)
			assert.Equal(t, buffer.String(), string([]byte("foo")))
		case filepath.Join("subdir1", "bar.txt"):
			assert.Equal(t, hdr.Typeflag, uint8(tar.TypeReg))
			assert.Equal(t, hdr.Mode, int64(0440))
			buffer := new(bytes.Buffer)
			_, err := io.Copy(buffer, tr)
			require.NoError(t, err)
			assert.True(t, bytes.Equal(buffer.Bytes(), []byte("bar")))
		default:
			assert.Failf(t, "Unknown file encountered in tarball", hdr.Name)
		}
	}
	assert.Equal(t, entryCount, 3)
}

func TestAutoPacker(t *testing.T) {
	t.Parallel()

	t.Run("create-tarfile", func(t *testing.T) {
		dirname := t.TempDir()

		createTestDirectory(t, dirname)
		ap := newAutoPacker(dirname, tarBehavior)
		verifyTarball(t, ap)

		// Unwrap the GZIP stream, pass to the tarball verifier
		ap = newAutoPacker(dirname, tarGZBehavior)
		gzReader, err := gzip.NewReader(ap)
		require.NoError(t, err)
		verifyTarball(t, gzReader)

		// Default behavior should be the same as the tar.gz
		ap = newAutoPacker(dirname, autoBehavior)
		gzReader, err = gzip.NewReader(ap)
		require.NoError(t, err)
		verifyTarball(t, gzReader)
	})

	t.Run("unpack-tarfile", func(t *testing.T) {
		dirnameSource := t.TempDir()
		dirnameDest := t.TempDir()

		createTestDirectory(t, dirnameSource)
		ap := newAutoPacker(dirnameSource, tarGZBehavior)

		aup := newAutoUnpacker(dirnameDest, autoBehavior)
		_, err := io.Copy(aup, ap)
		require.NoError(t, err)

		require.NoError(t, aup.Error())
		verifyTestDirectory(t, dirnameDest)
	})
}
