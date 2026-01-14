//go:build go1.25 && !windows

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
	"io"
	"os"
	"time"

	"github.com/spf13/afero"
)

// OsRootFs is a filesystem implementation using os.Root (Go 1.24+)
// to prevent symlink traversal attacks. It wraps all filesystem operations
// to ensure they stay within a designated root directory.
type OsRootFs struct {
	root *os.Root
}

// NewOsRootFs creates a new OsRootFs with the given root directory
func NewOsRootFs(rootDir string) (*OsRootFs, error) {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	return &OsRootFs{root: root}, nil
}

// Name returns the name of the filesystem
func (ofs *OsRootFs) Name() string {
	return "OsRootFs"
}

// normalizePath removes leading slashes from paths for os.Root compatibility
func (ofs *OsRootFs) normalizePath(name string) string {
	if len(name) > 0 && name[0] == '/' {
		return name[1:]
	}
	return name
}

// Create creates or truncates the named file.
func (ofs *OsRootFs) Create(name string) (afero.File, error) {
	f, err := ofs.root.Create(ofs.normalizePath(name))
	if f == nil {
		return nil, err
	}
	return &OsRootFile{f}, err
}

// Open opens the named file for reading.
func (ofs *OsRootFs) Open(name string) (afero.File, error) {
	f, err := ofs.root.Open(ofs.normalizePath(name))
	if f == nil {
		return nil, err
	}
	return &OsRootFile{f}, err
}

// OpenFile opens the named file with specified flags and permissions
func (ofs *OsRootFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	f, err := ofs.root.OpenFile(ofs.normalizePath(name), flag, perm)
	if f == nil {
		return nil, err
	}
	return &OsRootFile{f}, err
}

// Remove removes the named file or directory
func (ofs *OsRootFs) Remove(name string) error {
	return ofs.root.Remove(ofs.normalizePath(name))
}

// RemoveAll removes the named file or directory and all its contents
func (ofs *OsRootFs) RemoveAll(path string) error {
	return ofs.root.RemoveAll(ofs.normalizePath(path))
}

// Rename renames the file or directory
func (ofs *OsRootFs) Rename(oldname, newname string) error {
	return ofs.root.Rename(ofs.normalizePath(oldname), ofs.normalizePath(newname))
}

// Mkdir creates a new directory
func (ofs *OsRootFs) Mkdir(name string, perm os.FileMode) error {
	return ofs.root.Mkdir(ofs.normalizePath(name), perm)
}

// MkdirAll creates a directory along with any necessary parents
func (ofs *OsRootFs) MkdirAll(path string, perm os.FileMode) error {
	return ofs.root.MkdirAll(ofs.normalizePath(path), perm)
}

// Stat returns file information
func (ofs *OsRootFs) Stat(name string) (os.FileInfo, error) {
	return ofs.root.Stat(ofs.normalizePath(name))
}

// Chmod changes file permissions
func (ofs *OsRootFs) Chmod(name string, mode os.FileMode) error {
	return ofs.root.Chmod(ofs.normalizePath(name), mode)
}

// Chown changes file ownership
func (ofs *OsRootFs) Chown(name string, uid, gid int) error {
	return ofs.root.Chown(ofs.normalizePath(name), uid, gid)
}

// Chtimes changes file access and modification times
func (ofs *OsRootFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return ofs.root.Chtimes(ofs.normalizePath(name), atime, mtime)
}

// Lstat returns file info without following symlinks
// Since os.Root prevents escaping via symlinks, this is safe
func (ofs *OsRootFs) Lstat(name string) (os.FileInfo, error) {
	return ofs.root.Lstat(ofs.normalizePath(name))
}

// LstatIfPossible returns file info without following symlinks if possible
func (ofs *OsRootFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	fi, err := ofs.root.Lstat(ofs.normalizePath(name))
	return fi, true, err
}

// Readlink returns the target of a symlink
func (ofs *OsRootFs) Readlink(name string) (string, error) {
	return ofs.root.Readlink(ofs.normalizePath(name))
}

// ReadlinkIfPossible returns the target of a symlink if possible
func (ofs *OsRootFs) ReadlinkIfPossible(name string) (string, error) {
	return ofs.root.Readlink(ofs.normalizePath(name))
}

// Symlink creates a symlink
func (ofs *OsRootFs) Symlink(oldname, newname string) error {
	return ofs.root.Symlink(ofs.normalizePath(oldname), ofs.normalizePath(newname))
}

// SymlinkIfPossible creates a symlink if possible
func (ofs *OsRootFs) SymlinkIfPossible(oldname, newname string) error {
	return ofs.root.Symlink(ofs.normalizePath(oldname), ofs.normalizePath(newname))
}

// OsRootFile wraps os.File to implement afero.File interface
type OsRootFile struct {
	*os.File
}

// ReadAt reads from the file at offset
func (f *OsRootFile) ReadAt(b []byte, off int64) (n int, err error) {
	return f.File.ReadAt(b, off)
}

// WriteAt writes to the file at offset
func (f *OsRootFile) WriteAt(b []byte, off int64) (n int, err error) {
	return f.File.WriteAt(b, off)
}

// Read reads from the file
func (f *OsRootFile) Read(b []byte) (n int, err error) {
	return f.File.Read(b)
}

// ReadFrom implements io.ReaderFrom
func (f *OsRootFile) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(f.File, r)
}

// Seek seeks to position in file
func (f *OsRootFile) Seek(offset int64, whence int) (int64, error) {
	return f.File.Seek(offset, whence)
}

// Write writes to the file
func (f *OsRootFile) Write(b []byte) (n int, err error) {
	return f.File.Write(b)
}

// WriteTo implements io.WriterTo
func (f *OsRootFile) WriteTo(w io.Writer) (n int64, err error) {
	return io.Copy(w, f.File)
}

// Name returns the filename
func (f *OsRootFile) Name() string {
	return f.File.Name()
}

// Readdir reads directory entries
func (f *OsRootFile) Readdir(count int) ([]os.FileInfo, error) {
	return f.File.Readdir(count)
}

// Readdirnames reads directory entry names
func (f *OsRootFile) Readdirnames(n int) ([]string, error) {
	return f.File.Readdirnames(n)
}

// Stat returns file info
func (f *OsRootFile) Stat() (os.FileInfo, error) {
	return f.File.Stat()
}

// Sync syncs file to disk
func (f *OsRootFile) Sync() error {
	return f.File.Sync()
}

// Truncate truncates the file
func (f *OsRootFile) Truncate(size int64) error {
	return f.File.Truncate(size)
}

// WriteString writes a string to the file
func (f *OsRootFile) WriteString(s string) (ret int, err error) {
	return f.File.WriteString(s)
}

// Close closes the file
func (f *OsRootFile) Close() error {
	return f.File.Close()
}
