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

package utils

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// onlyFile asserts that dir holds exactly one entry, named name: no temporary
// file was left behind.
func onlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{name}, names)
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "link")

	require.NoError(t, WriteFileAtomic(path, []byte("first\n"), 0640))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "first\n", string(contents))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0640), info.Mode().Perm(), "the mode is applied exactly, regardless of umask")
	}

	require.NoError(t, WriteFileAtomic(path, []byte("second\n"), 0640))
	contents, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "second\n", string(contents))
	onlyFile(t, dir, "link")

	assert.Error(t, WriteFileAtomic(filepath.Join(dir, "missing", "link"), []byte("x"), 0600),
		"a missing parent directory is reported")
}

func TestWriteFileAtomicFromFailureLeavesFileUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(path, []byte("good"), 0600))

	boom := errors.New("template failed halfway")
	err := WriteFileAtomicFrom(path, 0600, func(w io.Writer) error {
		_, _ = w.Write([]byte("half-wri"))
		return boom
	})
	require.ErrorIs(t, err, boom)

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "good", string(contents))
	onlyFile(t, dir, "config")
}

func TestWriteFileAtomicWithOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file ownership cannot be set on Windows")
	}
	path := filepath.Join(t.TempDir(), "token")
	// Chown to our own ids is always permitted, so this exercises the option
	// without needing privileges.
	require.NoError(t, WriteFileAtomic(path, []byte("tok"), 0600, WithOwner(os.Getuid(), os.Getgid())))
	require.NoError(t, WriteFileAtomic(path, []byte("tok"), 0600, WithOwner(-1, os.Getgid())))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "tok", string(contents))
}

// A reader racing a writer must only ever see one complete version of the file.
func TestWriteFileAtomicConcurrentReader(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("on Windows the rename fails while a reader holds the file open")
	}
	path := filepath.Join(t.TempDir(), "link")
	versions := [][]byte{bytes.Repeat([]byte("a"), 64*1024), bytes.Repeat([]byte("b"), 64*1024)}
	require.NoError(t, WriteFileAtomic(path, versions[0], 0600))

	writerDone := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			if err := WriteFileAtomic(path, versions[i%2], 0600); err != nil {
				writerDone <- err
				return
			}
		}
		writerDone <- nil
	}()

	for {
		contents, err := os.ReadFile(path)
		require.NoError(t, err)
		if !bytes.Equal(contents, versions[0]) && !bytes.Equal(contents, versions[1]) {
			t.Fatalf("reader saw a partial file of %d bytes", len(contents))
		}
		select {
		case err := <-writerDone:
			require.NoError(t, err)
			return
		default:
		}
	}
}

// Every step after the directory is opened is relative to that directory, so
// moving it mid-write cannot split the temporary file from its rename target.
func TestWriteFileAtomicStaysInOpenedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow renaming a directory that has open handles")
	}
	parent := t.TempDir()
	dir := filepath.Join(parent, "dir")
	moved := filepath.Join(parent, "moved")
	require.NoError(t, os.Mkdir(dir, 0700))

	err := WriteFileAtomicFrom(filepath.Join(dir, "file"), 0600, func(w io.Writer) error {
		if err := os.Rename(dir, moved); err != nil {
			return err
		}
		// Something new now sits at the old path; it must not receive the file.
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		_, err := w.Write([]byte("contents"))
		return err
	})
	require.NoError(t, err)

	contents, err := os.ReadFile(filepath.Join(moved, "file"))
	require.NoError(t, err)
	assert.Equal(t, "contents", string(contents))
	onlyFile(t, moved, "file")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing may land in the directory that replaced the original")
}
