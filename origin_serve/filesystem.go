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

package origin_serve

import (
	"context"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
	"golang.org/x/time/rate"
)

// rateLimitedFs wraps an afero.Fs to rate-limit read operations
type rateLimitedFs struct {
	afero.Fs
	limiter *rate.Limiter
}

// rateLimitedFile wraps an afero.File to rate-limit reads
type rateLimitedFile struct {
	afero.File
	limiter *rate.Limiter
}

// newRateLimitedFs creates a filesystem with rate-limited reads
// bytesPerSec is the maximum read rate in bytes per second (0 = unlimited)
func newRateLimitedFs(fs afero.Fs, bytesPerSec int) afero.Fs {
	if bytesPerSec <= 0 {
		return fs
	}
	// Use a modest burst to allow reasonable read sizes without
	// excessive bursting above the configured rate
	burstSize := bytesPerSec / 2
	if burstSize < 32768 {
		burstSize = 32768 // Minimum 32KB burst
	}
	return &rateLimitedFs{
		Fs:      fs,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burstSize),
	}
}

// Open wraps files with rate limiting
func (fs *rateLimitedFs) Open(name string) (afero.File, error) {
	f, err := fs.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return &rateLimitedFile{File: f, limiter: fs.limiter}, nil
}

// OpenFile wraps files with rate limiting
func (fs *rateLimitedFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := fs.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &rateLimitedFile{File: f, limiter: fs.limiter}, nil
}

// Read applies rate limiting to reads
func (f *rateLimitedFile) Read(p []byte) (n int, err error) {
	// Limit individual read size to avoid excessive waiting
	// This ensures reads complete in reasonable time even with rate limiting
	maxReadSize := f.limiter.Burst()
	toRead := len(p)
	if toRead > maxReadSize {
		toRead = maxReadSize
	}

	// Try to do a non-blocking read with available tokens
	// If requested size isn't available, try progressively smaller reads
	// This allows short reads when tokens are limited, avoiding long waits
	readSize := toRead
	for readSize >= 1024 { // Don't try reads smaller than 1KB
		if f.limiter.AllowN(time.Now(), readSize) {
			// Sufficient tokens available, do the read immediately
			return f.File.Read(p[:readSize])
		}
		// Try half the size for a short read
		readSize = readSize / 2
	}

	// No tokens available for even small reads; wait for a minimal amount
	// Use 1KB minimum to make reasonable progress
	minRead := 1024
	if minRead > toRead {
		minRead = toRead
	}
	if minRead > 0 {
		if err := f.limiter.WaitN(context.Background(), minRead); err != nil {
			return 0, err
		}
		return f.File.Read(p[:minRead])
	}

	// Edge case: zero-length read
	return f.File.Read(p[:0])
}

// autoCreateDirFs wraps an afero.Fs to automatically create parent directories
// when opening a file for writing
type autoCreateDirFs struct {
	afero.Fs
}

// newAutoCreateDirFs creates a new filesystem that auto-creates parent directories
func newAutoCreateDirFs(fs afero.Fs) afero.Fs {
	return &autoCreateDirFs{Fs: fs}
}

// OpenFile wraps the underlying OpenFile and auto-creates parent directories if needed
func (fs *autoCreateDirFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
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

type (
	// contextKey is used to store user/group info in the context
	contextKey int

	// userInfo contains information about the authenticated user
	userInfo struct {
		User   string
		Groups []string
	}
)

const (
	userInfoKey contextKey = iota
)

// setUserInfo stores user info in context
func setUserInfo(ctx context.Context, ui *userInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, ui)
}

// getUserInfo retrieves user info from context
func getUserInfo(ctx context.Context) *userInfo {
	ui, ok := ctx.Value(userInfoKey).(*userInfo)
	if !ok {
		return nil
	}
	return ui
}

// aferoFileSystem wraps an afero.Fs to implement webdav.FileSystem
type aferoFileSystem struct {
	fs     afero.Fs
	prefix string
	logger func(*http.Request, error)
}

// newAferoFileSystem creates a new aferoFileSystem
func newAferoFileSystem(fs afero.Fs, prefix string, logger func(*http.Request, error)) *aferoFileSystem {
	return &aferoFileSystem{
		fs:     fs,
		prefix: prefix,
		logger: logger,
	}
}

// Mkdir implements webdav.FileSystem
func (afs *aferoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	fullPath := afs.fullPath(name)
	// Use webdav logger if available
	return afs.fs.MkdirAll(fullPath, perm)
}

// OpenFile implements webdav.FileSystem
func (afs *aferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath := afs.fullPath(name)
	if afs.logger != nil {
		afs.logger(nil, nil) // Use the logger provided by webdav
	}

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
		info, statErr := afs.fs.Stat(fullPath)
		if statErr == nil && info.IsDir() {
			// Return a "not exist" error instead of "is a directory" error to trigger
			// the webdav handler's 409 Conflict response instead of 404 Not Found
			return nil, os.ErrNotExist
		}
	}

	file, err := afs.fs.OpenFile(fullPath, flag, perm)
	if err != nil {
		return nil, err
	}

	return &aferoFile{
		File:   file,
		fs:     afs.fs,
		name:   fullPath,
		logger: afs.logger,
	}, nil
}

// RemoveAll implements webdav.FileSystem
func (afs *aferoFileSystem) RemoveAll(ctx context.Context, name string) error {
	fullPath := afs.fullPath(name)
	return afs.fs.RemoveAll(fullPath)
}

// Rename implements webdav.FileSystem
func (afs *aferoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := afs.fullPath(oldName)
	newPath := afs.fullPath(newName)
	return afs.fs.Rename(oldPath, newPath)
}

// Stat implements webdav.FileSystem
func (afs *aferoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fullPath := afs.fullPath(name)
	return afs.fs.Stat(fullPath)
}

// fullPath converts a webdav path to a full filesystem path
func (afs *aferoFileSystem) fullPath(name string) string {
	if afs.prefix == "" {
		return name
	}
	return path.Join(afs.prefix, name)
}

// aferoFile wraps an afero.File to implement webdav.File
type aferoFile struct {
	afero.File
	fs         afero.Fs
	name       string
	dirEntries []os.FileInfo              // Cached directory entries for pagination
	dirOffset  int                        // Current offset in directory entries
	dirMutex   sync.Mutex                 // Mutex for concurrent access
	logger     func(*http.Request, error) // WebDAV logger
}

// Readdir implements webdav.File
func (af *aferoFile) Readdir(count int) ([]os.FileInfo, error) {
	af.dirMutex.Lock()
	defer af.dirMutex.Unlock()

	// On first call or when count <= 0, read all entries
	if af.dirEntries == nil {
		entries, err := afero.ReadDir(af.fs, af.name)
		if err != nil {
			return nil, err
		}
		af.dirEntries = entries
		af.dirOffset = 0
	}

	// If count <= 0, return all remaining entries and reset
	if count <= 0 {
		result := af.dirEntries[af.dirOffset:]
		af.dirOffset = len(af.dirEntries)
		return result, nil
	}

	// Return up to count entries from current offset
	remaining := len(af.dirEntries) - af.dirOffset
	if remaining == 0 {
		// No more entries, return io.EOF
		return nil, io.EOF
	}

	if count > remaining {
		count = remaining
	}

	result := af.dirEntries[af.dirOffset : af.dirOffset+count]
	af.dirOffset += count

	return result, nil
}

// Stat implements webdav.File
func (af *aferoFile) Stat() (os.FileInfo, error) {
	return af.File.Stat()
}
