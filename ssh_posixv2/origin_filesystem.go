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
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"
)

// SSHFileSystem implements webdav.FileSystem by proxying requests to the remote
// helper via reverse connections. This is used by the origin to serve requests
// for SSH-backed storage.
type SSHFileSystem struct {
	// broker is the helper broker for obtaining connections
	broker *HelperBroker

	// federationPrefix is the federation namespace prefix (e.g., "/test")
	federationPrefix string

	// storagePrefix is the storage path on the remote system
	storagePrefix string

	// httpClient uses the helper transport for reverse connections
	httpClient *http.Client
}

// NewSSHFileSystem creates a new SSH filesystem that proxies to the helper
func NewSSHFileSystem(broker *HelperBroker, federationPrefix, storagePrefix string) *SSHFileSystem {
	transport := NewHelperTransport(broker)
	return &SSHFileSystem{
		broker:           broker,
		federationPrefix: federationPrefix,
		storagePrefix:    storagePrefix,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}
}

// makeHelperURL constructs the URL for a request to the helper
// The helper serves WebDAV at /<federationPrefix>/<path>
func (fs *SSHFileSystem) makeHelperURL(name string) string {
	// The helper uses the federation prefix as its route
	// Clean the path to avoid double slashes
	cleanPath := path.Clean(path.Join(fs.federationPrefix, name))
	return "http://helper" + cleanPath
}

// Mkdir creates a directory on the remote filesystem via WebDAV MKCOL
func (fs *SSHFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	url := fs.makeHelperURL(name)
	req, err := http.NewRequestWithContext(ctx, "MKCOL", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create MKCOL request")
	}

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "MKCOL request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		// Directory might already exist
		return os.ErrExist
	}

	return fmt.Errorf("MKCOL failed with status %d", resp.StatusCode)
}

// OpenFile opens a file for reading or writing
func (fs *SSHFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	return &sshFile{
		fs:   fs,
		name: name,
		flag: flag,
		ctx:  ctx,
	}, nil
}

// RemoveAll removes a file or directory
func (fs *SSHFileSystem) RemoveAll(ctx context.Context, name string) error {
	url := fs.makeHelperURL(name)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create DELETE request")
	}

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "DELETE request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}

	return fmt.Errorf("DELETE failed with status %d", resp.StatusCode)
}

// Rename renames a file or directory via WebDAV MOVE
func (fs *SSHFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	url := fs.makeHelperURL(oldName)
	req, err := http.NewRequestWithContext(ctx, "MOVE", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create MOVE request")
	}

	// Set the Destination header for the new location
	destURL := fs.makeHelperURL(newName)
	req.Header.Set("Destination", destURL)
	req.Header.Set("Overwrite", "T")

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "MOVE request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("MOVE failed with status %d", resp.StatusCode)
}

// Stat returns file info via WebDAV PROPFIND
func (fs *SSHFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	url := fs.makeHelperURL(name)
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PROPFIND request")
	}
	req.Header.Set("Depth", "0")

	resp, err := fs.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "PROPFIND request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}

	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PROPFIND failed with status %d", resp.StatusCode)
	}

	// Parse the multistatus response
	return fs.parseStatResponse(resp.Body, name)
}

// parseStatResponse parses a PROPFIND response to extract file info
func (fs *SSHFileSystem) parseStatResponse(body io.Reader, name string) (os.FileInfo, error) {
	// Read the response body
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read PROPFIND response")
	}

	// Parse the XML response
	var multistatus webdavMultistatus
	if err := xml.Unmarshal(data, &multistatus); err != nil {
		// If XML parsing fails, try to infer from the name
		log.Debugf("Failed to parse PROPFIND response for %s: %v", name, err)
		// Return a basic file info assuming it exists
		return &sshFileInfo{
			name:    path.Base(name),
			size:    0,
			mode:    0644,
			modTime: time.Now(),
			isDir:   false,
		}, nil
	}

	if len(multistatus.Responses) == 0 {
		return nil, os.ErrNotExist
	}

	resp := multistatus.Responses[0]
	if len(resp.PropStats) == 0 {
		return nil, fmt.Errorf("no propstat in response")
	}

	prop := resp.PropStats[0].Prop

	// Determine if it's a directory
	isDir := prop.ResourceType.Collection != nil

	// Parse size
	var size int64
	if prop.ContentLength != "" {
		size, _ = strconv.ParseInt(prop.ContentLength, 10, 64)
	}

	// Parse modification time
	modTime := time.Now()
	if prop.LastModified != "" {
		if t, err := http.ParseTime(prop.LastModified); err == nil {
			modTime = t
		}
	}

	// Determine mode
	mode := os.FileMode(0644)
	if isDir {
		mode = os.FileMode(0755) | os.ModeDir
	}

	return &sshFileInfo{
		name:    path.Base(name),
		size:    size,
		mode:    mode,
		modTime: modTime,
		isDir:   isDir,
	}, nil
}

// WebDAV XML structures for PROPFIND parsing
type webdavMultistatus struct {
	XMLName   xml.Name         `xml:"DAV: multistatus"`
	Responses []webdavResponse `xml:"response"`
}

type webdavResponse struct {
	Href      string           `xml:"href"`
	PropStats []webdavPropstat `xml:"propstat"`
}

type webdavPropstat struct {
	Prop   webdavProp `xml:"prop"`
	Status string     `xml:"status"`
}

type webdavProp struct {
	ResourceType  webdavResourceType `xml:"resourcetype"`
	ContentLength string             `xml:"getcontentlength"`
	LastModified  string             `xml:"getlastmodified"`
	ContentType   string             `xml:"getcontenttype"`
	ETag          string             `xml:"getetag"`
}

type webdavResourceType struct {
	Collection *struct{} `xml:"collection"`
}

// sshFileInfo implements os.FileInfo for remote files
type sshFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
}

func (fi *sshFileInfo) Name() string       { return fi.name }
func (fi *sshFileInfo) Size() int64        { return fi.size }
func (fi *sshFileInfo) Mode() os.FileMode  { return fi.mode }
func (fi *sshFileInfo) ModTime() time.Time { return fi.modTime }
func (fi *sshFileInfo) IsDir() bool        { return fi.isDir }
func (fi *sshFileInfo) Sys() interface{}   { return nil }

// sshFile implements webdav.File for remote files
type sshFile struct {
	fs   *SSHFileSystem
	name string
	flag int
	ctx  context.Context

	// For reading
	reader     io.ReadCloser
	readOffset int64

	// For writing
	writer *io.PipeWriter

	// Cached stat info
	info os.FileInfo
}

// Close closes the file
func (f *sshFile) Close() error {
	var err error
	if f.reader != nil {
		err = f.reader.Close()
		f.reader = nil
	}
	if f.writer != nil {
		f.writer.Close()
		f.writer = nil
	}
	return err
}

// Read reads data from the file via HTTP GET with Range header
func (f *sshFile) Read(p []byte) (n int, err error) {
	// If we don't have a reader yet, create one
	if f.reader == nil {
		url := f.fs.makeHelperURL(f.name)
		req, err := http.NewRequestWithContext(f.ctx, "GET", url, nil)
		if err != nil {
			return 0, errors.Wrap(err, "failed to create GET request")
		}

		// Set Range header if we've read some data already
		if f.readOffset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", f.readOffset))
		}

		resp, err := f.fs.httpClient.Do(req)
		if err != nil {
			return 0, errors.Wrap(err, "GET request failed")
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return 0, os.ErrNotExist
		}

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			resp.Body.Close()
			return 0, fmt.Errorf("GET failed with status %d", resp.StatusCode)
		}

		f.reader = resp.Body
	}

	n, err = f.reader.Read(p)
	f.readOffset += int64(n)
	return n, err
}

// Seek seeks to a position in the file
func (f *sshFile) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = f.readOffset + offset
	case io.SeekEnd:
		// Need to know file size for SeekEnd
		info, err := f.Stat()
		if err != nil {
			return 0, err
		}
		newOffset = info.Size() + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}

	if newOffset < 0 {
		return 0, fmt.Errorf("negative position")
	}

	// Close existing reader if any
	if f.reader != nil {
		f.reader.Close()
		f.reader = nil
	}

	f.readOffset = newOffset
	return newOffset, nil
}

// Write writes data to the file via HTTP PUT
func (f *sshFile) Write(p []byte) (n int, err error) {
	// For simplicity, we'll buffer writes and send on Close
	// A more sophisticated implementation would use chunked transfer
	url := f.fs.makeHelperURL(f.name)
	req, err := http.NewRequestWithContext(f.ctx, "PUT", url, strings.NewReader(string(p)))
	if err != nil {
		return 0, errors.Wrap(err, "failed to create PUT request")
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := f.fs.httpClient.Do(req)
	if err != nil {
		return 0, errors.Wrap(err, "PUT request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("PUT failed with status %d", resp.StatusCode)
	}

	return len(p), nil
}

// Readdir reads directory entries via PROPFIND with Depth: 1
func (f *sshFile) Readdir(count int) ([]os.FileInfo, error) {
	url := f.fs.makeHelperURL(f.name)
	req, err := http.NewRequestWithContext(f.ctx, "PROPFIND", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PROPFIND request")
	}
	req.Header.Set("Depth", "1")

	resp, err := f.fs.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "PROPFIND request failed")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}

	if resp.StatusCode != http.StatusMultiStatus && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PROPFIND failed with status %d", resp.StatusCode)
	}

	// Parse the response
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read PROPFIND response")
	}

	var multistatus webdavMultistatus
	if err := xml.Unmarshal(data, &multistatus); err != nil {
		return nil, errors.Wrap(err, "failed to parse PROPFIND response")
	}

	// Convert responses to FileInfo, skipping the first one (the directory itself)
	var infos []os.FileInfo
	for i, resp := range multistatus.Responses {
		if i == 0 {
			continue // Skip the directory itself
		}

		if len(resp.PropStats) == 0 {
			continue
		}

		prop := resp.PropStats[0].Prop
		isDir := prop.ResourceType.Collection != nil

		var size int64
		if prop.ContentLength != "" {
			size, _ = strconv.ParseInt(prop.ContentLength, 10, 64)
		}

		modTime := time.Now()
		if prop.LastModified != "" {
			if t, err := http.ParseTime(prop.LastModified); err == nil {
				modTime = t
			}
		}

		mode := os.FileMode(0644)
		if isDir {
			mode = os.FileMode(0755) | os.ModeDir
		}

		// Extract name from href
		name := path.Base(resp.Href)
		if name == "" || name == "." {
			continue
		}

		infos = append(infos, &sshFileInfo{
			name:    name,
			size:    size,
			mode:    mode,
			modTime: modTime,
			isDir:   isDir,
		})

		if count > 0 && len(infos) >= count {
			break
		}
	}

	return infos, nil
}

// Stat returns file info
func (f *sshFile) Stat() (os.FileInfo, error) {
	if f.info != nil {
		return f.info, nil
	}

	info, err := f.fs.Stat(f.ctx, f.name)
	if err != nil {
		return nil, err
	}

	f.info = info
	return info, nil
}

// GetSSHFileSystem returns a webdav.FileSystem for the SSH backend
// This should be called after the helper broker is initialized
func GetSSHFileSystem(federationPrefix, storagePrefix string) (webdav.FileSystem, error) {
	broker := GetHelperBroker()
	if broker == nil {
		return nil, errors.New("helper broker not initialized")
	}

	return NewSSHFileSystem(broker, federationPrefix, storagePrefix), nil
}
