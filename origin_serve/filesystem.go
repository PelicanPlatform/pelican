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

package origin_serve

import (
	"context"
	"os"
	"path"

	"github.com/spf13/afero"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
)

type (
	// contextKey is used to store user/group info in the context
	contextKey int

	// UserInfo contains information about the authenticated user
	UserInfo struct {
		User   string
		Groups []string
	}
)

const (
	userInfoKey contextKey = iota
)

// GetUserInfo retrieves user info from context
func GetUserInfo(ctx context.Context) *UserInfo {
	if userInfo, ok := ctx.Value(userInfoKey).(*UserInfo); ok {
		return userInfo
	}
	return nil
}

// SetUserInfo stores user info in context
func SetUserInfo(ctx context.Context, userInfo *UserInfo) context.Context {
	return context.WithValue(ctx, userInfoKey, userInfo)
}

// aferoFileSystem wraps an afero.Fs to implement webdav.FileSystem
type aferoFileSystem struct {
	fs     afero.Fs
	prefix string
}

// newAferoFileSystem creates a new aferoFileSystem
func newAferoFileSystem(fs afero.Fs, prefix string) *aferoFileSystem {
	return &aferoFileSystem{
		fs:     fs,
		prefix: prefix,
	}
}

// Mkdir implements webdav.FileSystem
func (afs *aferoFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	fullPath := afs.fullPath(name)
	log.Debugf("Mkdir: %s (perm: %v)", fullPath, perm)
	return afs.fs.MkdirAll(fullPath, perm)
}

// OpenFile implements webdav.FileSystem
func (afs *aferoFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	fullPath := afs.fullPath(name)
	log.Debugf("OpenFile: %s (flag: %d, perm: %v)", fullPath, flag, perm)
	
	file, err := afs.fs.OpenFile(fullPath, flag, perm)
	if err != nil {
		return nil, err
	}
	
	return &aferoFile{File: file, fs: afs.fs, name: fullPath}, nil
}

// RemoveAll implements webdav.FileSystem
func (afs *aferoFileSystem) RemoveAll(ctx context.Context, name string) error {
	fullPath := afs.fullPath(name)
	log.Debugf("RemoveAll: %s", fullPath)
	return afs.fs.RemoveAll(fullPath)
}

// Rename implements webdav.FileSystem
func (afs *aferoFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	oldPath := afs.fullPath(oldName)
	newPath := afs.fullPath(newName)
	log.Debugf("Rename: %s -> %s", oldPath, newPath)
	return afs.fs.Rename(oldPath, newPath)
}

// Stat implements webdav.FileSystem
func (afs *aferoFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	fullPath := afs.fullPath(name)
	log.Debugf("Stat: %s", fullPath)
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
	fs   afero.Fs
	name string
}

// Readdir implements webdav.File
func (af *aferoFile) Readdir(count int) ([]os.FileInfo, error) {
	// For directories, read and return directory entries
	entries, err := afero.ReadDir(af.fs, af.name)
	if err != nil {
		return nil, err
	}
	
	if count <= 0 {
		return entries, nil
	}
	
	if count > len(entries) {
		count = len(entries)
	}
	return entries[:count], nil
}

// Stat implements webdav.File
func (af *aferoFile) Stat() (os.FileInfo, error) {
	return af.File.Stat()
}
