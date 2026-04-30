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
	"fmt"
	"os"
	"time"
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

// etagFileInfo wraps an os.FileInfo with a BackendETag implementation
// suitable for the POSIXv2 backend. The format mirrors the default
// used by golang.org/x/net/webdav so a receiver who saw the object
// via GET sees the same ETag in the commit webhook. This is the
// *backend*'s answer for the POSIXv2 backend, not a generic synthesis.
type etagFileInfo struct {
	os.FileInfo
}

// ETag implements BackendETager. The format is `"<hex(mtime)><hex(size)>"`,
// matching the stdlib webdav default.
func (e etagFileInfo) ETag(_ context.Context) (string, error) {
	if e.FileInfo == nil {
		return "", nil
	}
	mt := e.ModTime()
	if mt.IsZero() {
		return fmt.Sprintf(`"%x"`, e.Size()), nil
	}
	return fmt.Sprintf(`"%x%x"`, mt.UnixNano(), e.Size()), nil
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
