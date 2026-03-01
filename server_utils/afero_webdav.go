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

package server_utils

import (
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
)

// AutoCreateDirFs wraps an afero.Fs to automatically create parent directories
// when opening a file for writing
type AutoCreateDirFs struct {
	afero.Fs
}

// NewAutoCreateDirFs creates a new filesystem that auto-creates parent directories
func NewAutoCreateDirFs(fs afero.Fs) afero.Fs {
	return &AutoCreateDirFs{Fs: fs}
}

// OpenFile wraps the underlying OpenFile and auto-creates parent directories if needed
func (fs *AutoCreateDirFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
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

// AferoFileSystem wraps an afero.Fs to implement webdav.FileSystem
type AferoFileSystem struct {
	Fs     afero.Fs
	Prefix string
	Logger func(*http.Request, error)
}

// NewAferoFileSystem creates a new AferoFileSystem
func NewAferoFileSystem(fs afero.Fs, prefix string, logger func(*http.Request, error)) *AferoFileSystem {
	return &AferoFileSystem{
		Fs:     fs,
		Prefix: prefix,
		Logger: logger,
	}
}

// Mkdir implements webdav.FileSystem
func (afs *AferoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	fullPath := afs.FullPath(name)
	return afs.Fs.MkdirAll(fullPath, perm)
}

// OpenFile implements webdav.FileSystem
func (afs *AferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath := afs.FullPath(name)

	// WORKAROUND: When attempting to upload a file to a path that is actually a directory/collection,
	// the underlying filesystem will correctly return EISDIR (syscall.EISDIR on Unix).
	// However, the golang.org/x/net/webdav handler has the following error handling logic:
	//
	//   if os.IsNotExist(err) {
	//       return http.StatusConflict, err  // 409
	//   }
	//   return http.StatusNotFound, err      // 404
	//
	// This means EISDIR gets mapped to 404 Not Found instead of 409 Conflict, which is incorrect
	// per WebDAV RFC 4918. When a client attempts to PUT a file to a URL that represents a collection,
	// the server should return 409 Conflict, not 404 Not Found.
	//
	// To work around this handler limitation, we check if the target is a directory before attempting
	// to open it with write flags (O_WRONLY, O_RDWR, O_CREATE, O_TRUNC). If so, we return an error
	// that satisfies os.IsNotExist() so the handler returns the correct 409 status code.
	//
	// This is semantically incorrect (the directory DOES exist), but necessary because the webdav
	// handler doesn't distinguish between "path doesn't exist" and "path is wrong type" errors.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		info, statErr := afs.Fs.Stat(fullPath)
		if statErr == nil && info.IsDir() {
			// Return a "not exist" error instead of "is a directory" error to trigger
			// the webdav handler's 409 Conflict response instead of 404 Not Found
			return nil, os.ErrNotExist
		}
	}

	file, err := afs.Fs.OpenFile(fullPath, flag, perm)
	if err != nil {
		return nil, err
	}

	return &AferoFile{
		File:   file,
		Fs:     afs.Fs,
		Name:   fullPath,
		Logger: afs.Logger,
	}, nil
}

// RemoveAll implements webdav.FileSystem
func (afs *AferoFileSystem) RemoveAll(ctx context.Context, name string) error {
	fullPath := afs.FullPath(name)
	return afs.Fs.RemoveAll(fullPath)
}

// Rename implements webdav.FileSystem
func (afs *AferoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := afs.FullPath(oldName)
	newPath := afs.FullPath(newName)
	return afs.Fs.Rename(oldPath, newPath)
}

// Stat implements webdav.FileSystem
func (afs *AferoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fullPath := afs.FullPath(name)
	return afs.Fs.Stat(fullPath)
}

// FullPath converts a webdav path to a full filesystem path
func (afs *AferoFileSystem) FullPath(name string) string {
	if afs.Prefix == "" {
		return name
	}
	return path.Join(afs.Prefix, name)
}

// AferoFile wraps an afero.File to implement webdav.File
type AferoFile struct {
	afero.File
	Fs         afero.Fs
	Name       string
	DirEntries []os.FileInfo              // Cached directory entries for pagination
	DirOffset  int                        // Current offset in directory entries
	DirMutex   sync.Mutex                 // Mutex for concurrent access
	Logger     func(*http.Request, error) // WebDAV logger
}

// Readdir implements webdav.File
func (af *AferoFile) Readdir(count int) ([]os.FileInfo, error) {
	af.DirMutex.Lock()
	defer af.DirMutex.Unlock()

	// On first call or when count <= 0, read all entries
	if af.DirEntries == nil {
		entries, err := afero.ReadDir(af.Fs, af.Name)
		if err != nil {
			return nil, err
		}
		af.DirEntries = entries
		af.DirOffset = 0
	}

	// If count <= 0, return all remaining entries and reset
	if count <= 0 {
		result := af.DirEntries[af.DirOffset:]
		af.DirOffset = len(af.DirEntries)
		return result, nil
	}

	// Return up to count entries from current offset
	remaining := len(af.DirEntries) - af.DirOffset
	if remaining == 0 {
		// No more entries, return io.EOF
		return nil, io.EOF
	}

	if count > remaining {
		count = remaining
	}

	result := af.DirEntries[af.DirOffset : af.DirOffset+count]
	af.DirOffset += count

	return result, nil
}

// Stat implements webdav.File
func (af *AferoFile) Stat() (os.FileInfo, error) {
	return af.File.Stat()
}
