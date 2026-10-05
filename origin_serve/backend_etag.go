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

// File backend_etag.go declares the contract: the *backend* (the
// layer that produced an os.FileInfo) is responsible for telling
// callers what its ETag is. Higher-level code — the metadata
// publisher in particular — must not synthesize an ETag of its own;
// it should ask the FileInfo and accept whatever the backend says.
//
// For the V2 POSIXv2 backend (aferoFileSystem), we attach an ETag
// implementation by wrapping every *os.FileInfo* returned through
// the webdav layer with `etagFileInfo`. Future S3/SSH backends that
// add POSC support are expected to do the same — wrap their
// FileInfo with whatever string the upstream protocol gave them, so
// the metadata layer round-trips it unchanged.

package origin_serve

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/pelicanplatform/pelican/utils"
)

// BackendETager is the optional interface a FileInfo (or its
// underlying value) implements to supply a backend-supplied ETag.
// The contract matches golang.org/x/net/webdav's internal ETager:
// return the bare ETag string, including any quotes the wire
// format demands.
type BackendETager interface {
	ETag(ctx context.Context) (string, error)
}

// BackendETag asks `info` for its ETag. Returns the empty string if
// info is nil or the FileInfo's backend declined / errored. The
// metadata publish path treats an empty ETag as "no etag known" and
// emits the field anyway (with that empty value); operators who care
// about a non-empty ETag in their webhook should ensure their backend
// implements BackendETager.
//
// IMPORTANT: this function deliberately does NOT synthesize an ETag.
// "How is an ETag computed?" is a backend question; centralizing the
// answer here would tie this layer to a particular convention (e.g.
// `<size>-<mtime>`), and that convention is wrong on every backend
// that has its own canonical ETag (S3, anything object-store-shaped).
func BackendETag(info os.FileInfo) string {
	if info == nil {
		return ""
	}
	if e, ok := info.(BackendETager); ok {
		if et, err := e.ETag(context.Background()); err == nil {
			return et
		}
	}
	return ""
}

// etagFileInfo wraps an os.FileInfo with the POSIXv2 backend's ETag, so that
// every path that asks the backend -- WebDAV PROPFIND and HEAD, preconditions,
// the object-metadata layer and its webhooks -- gets the same ETag the GET and
// PUT handlers send (computeETag).  This is the *backend*'s answer for
// POSIXv2, not a generic synthesis.
type etagFileInfo struct {
	os.FileInfo
}

// ETag implements BackendETager; see computeETag.
func (e etagFileInfo) ETag(_ context.Context) (string, error) {
	if e.FileInfo == nil {
		return "", nil
	}
	return computeETag(e.FileInfo), nil
}

// computeETag generates an opaque, quoted ETag string that uniquely identifies
// a specific instance of a file on disk.
//
// The ETag is the first 8 bytes of SHA-256 over (dev, inode, size, mtime),
// rendered as 16 hex characters. The (dev, inode) pair is a VFS-level file
// identifier: inodes alone are only unique within a single filesystem, so
// including the device id keeps the ETag distinct when an origin exports
// multiple volumes (separate disks, bind mounts, etc.) that happen to reuse
// the same inode number. mtime ensures the ETag changes when a file is
// rewritten in place. Size is folded in for cheap collision insurance.
//
// On platforms that don't expose a stable VFS id (Windows, or synthesized
// FileInfo values such as afero's in-memory FS), the dev/inode portion is
// omitted and only (size, mtime) feed the hash. The output width and shape
// are unchanged in that case.
//
// The previous format -- size and mtime concatenated as a single hex blob --
// matched the golang.org/x/net/webdav default but caused two different files
// with the same size and mtime (common for empty/freshly-created files on
// filesystems with second-precision mtime, or batches of fixed-size records)
// to receive identical ETags. Mixing in the VFS id and running the tuple
// through a hash fixes that.
func computeETag(info os.FileInfo) string {
	h := sha256.New()
	var buf [8]byte
	if dev, ino, ok := utils.FileVFSID(info); ok {
		binary.BigEndian.PutUint64(buf[:], dev)
		h.Write(buf[:])
		binary.BigEndian.PutUint64(buf[:], ino)
		h.Write(buf[:])
	}
	binary.BigEndian.PutUint64(buf[:], uint64(info.Size()))
	h.Write(buf[:])
	binary.BigEndian.PutUint64(buf[:], uint64(info.ModTime().UnixNano()))
	h.Write(buf[:])
	sum := h.Sum(nil)
	return fmt.Sprintf(`"%x"`, sum[:8])
}

// withBackendETag returns its argument wrapped with the POSIXv2
// backend's ETag policy unless it already carries an ETag (e.g. an
// upstream S3 backend that already supplied one).
func withBackendETag(info os.FileInfo) os.FileInfo {
	if info == nil {
		return nil
	}
	if _, ok := info.(BackendETager); ok {
		return info
	}
	return etagFileInfo{FileInfo: info}
}

// (compile-time assert)
var _ BackendETager = etagFileInfo{}
var _ os.FileInfo = etagFileInfo{}

// (declared but unused at the package level; keeps the deps tidy
// against future drift)
var _ = time.Time{}
