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

package ssh_posixv2

import (
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// helperAutoCreateDirFs wraps an afero.Fs to automatically create parent directories
// when opening a file for writing
type helperAutoCreateDirFs struct {
	afero.Fs
}

// newHelperAutoCreateDirFs creates a new filesystem that auto-creates parent directories
func newHelperAutoCreateDirFs(fs afero.Fs) afero.Fs {
	return &helperAutoCreateDirFs{Fs: fs}
}

// OpenFile wraps the underlying OpenFile and auto-creates parent directories if needed
func (fs *helperAutoCreateDirFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	file, err := fs.Fs.OpenFile(name, flag, perm)
	// If opening for write failed with "no such file or directory", create parent dirs and retry
	if err != nil && os.IsNotExist(err) && (flag&os.O_CREATE != 0 || flag&os.O_WRONLY != 0 || flag&os.O_RDWR != 0) {
		dir := filepath.Dir(name)
		if dir != "" && dir != "." && dir != "/" {
			if mkdirErr := fs.Fs.MkdirAll(dir, 0755); mkdirErr == nil {
				// Retry opening the file after creating parent directories
				file, err = fs.Fs.OpenFile(name, flag, perm)
			}
		}
	}
	return file, err
}

// helperAferoFileSystem wraps an afero.Fs to implement webdav.FileSystem
type helperAferoFileSystem struct {
	fs     afero.Fs
	prefix string
	logger func(*http.Request, error)
}

// Mkdir creates a directory
func (afs *helperAferoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	fullPath := path.Join(afs.prefix, name)
	return afs.fs.MkdirAll(fullPath, perm)
}

// OpenFile opens a file for reading/writing
func (afs *helperAferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath := path.Join(afs.prefix, name)
	// Open the file
	f, err := afs.fs.OpenFile(fullPath, flag, perm)
	if err != nil {
		return nil, err
	}
	return &helperAferoFile{File: f, fs: afs.fs, name: fullPath}, nil
}

// RemoveAll removes a file or directory
func (afs *helperAferoFileSystem) RemoveAll(ctx context.Context, name string) error {
	fullPath := path.Join(afs.prefix, name)
	return afs.fs.RemoveAll(fullPath)
}

// Rename renames a file or directory
func (afs *helperAferoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := path.Join(afs.prefix, oldName)
	newPath := path.Join(afs.prefix, newName)
	return afs.fs.Rename(oldPath, newPath)
}

// Stat returns file info
func (afs *helperAferoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fullPath := path.Join(afs.prefix, name)
	return afs.fs.Stat(fullPath)
}

// helperAferoFile wraps an afero.File to implement webdav.File
type helperAferoFile struct {
	afero.File
	fs   afero.Fs
	name string
}

// Readdir reads directory entries
func (f *helperAferoFile) Readdir(count int) ([]os.FileInfo, error) {
	return f.File.Readdir(count)
}

// Seek seeks to a position in the file
func (f *helperAferoFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.Seek(offset, whence)
}

// Stat returns file info
func (f *helperAferoFile) Stat() (os.FileInfo, error) {
	return f.File.Stat()
}

// Write writes data to the file
func (f *helperAferoFile) Write(p []byte) (n int, err error) {
	return f.File.Write(p)
}

// Read reads data from the file
func (f *helperAferoFile) Read(p []byte) (n int, err error) {
	return f.File.Read(p)
}

// Close closes the file
func (f *helperAferoFile) Close() error {
	return f.File.Close()
}

// ReadAt reads at a specific offset (implements io.ReaderAt if needed)
func (f *helperAferoFile) ReadAt(p []byte, off int64) (n int, err error) {
	// Seek to position
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return f.Read(p)
}

// WriteAt writes at a specific offset (implements io.WriterAt if needed)
func (f *helperAferoFile) WriteAt(p []byte, off int64) (n int, err error) {
	// Seek to position
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return 0, err
	}
	return f.Write(p)
}
