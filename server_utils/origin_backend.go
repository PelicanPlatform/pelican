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

package server_utils

import (
	"context"
	"net/http"

	"golang.org/x/net/webdav"
)

// OriginBackend abstracts a storage backend for the origin server.
// Every export is backed by exactly one OriginBackend, which supplies
// the WebDAV filesystem, availability status, and optional checksum
// support.
//
// Backends are created during handler initialisation (one per export)
// and used by the generic request handler without knowledge of the
// underlying storage technology.
type OriginBackend interface {
	// CheckAvailability returns nil when the backend can serve requests.
	// If the backend cannot serve, the returned error's message is sent
	// to the client.  If the error also implements HTTPStatusCoder the
	// handler uses that status code; otherwise it defaults to 503.
	CheckAvailability() error

	// FileSystem returns the webdav.FileSystem that serves this export.
	FileSystem() webdav.FileSystem

	// Checksummer returns an OriginChecksummer for HEAD-request digest
	// headers, or nil if the backend does not support checksums.
	Checksummer() OriginChecksummer
}

// OriginChecksummer provides RFC 3230 Digest header values for files
// served by an origin backend.
type OriginChecksummer interface {
	// GetDigests returns RFC 3230 formatted digest strings (e.g.
	// "md5=...", "crc32c=...") for the given file.  wantDigest is the
	// raw Want-Digest header value from the client (comma-separated
	// algorithm names).
	GetDigests(relativePath string, wantDigest string) ([]string, error)
}

// HTTPStatusCoder is optionally implemented by errors returned from
// CheckAvailability to control the HTTP status code sent to clients.
type HTTPStatusCoder interface {
	HTTPStatusCode() int
}

// ---------------------------------------------------------------------------
// PelicanHeaders — generic request-metadata propagation
// ---------------------------------------------------------------------------

// pelicanHeadersKey is the context key for PelicanHeaders.
type pelicanHeadersKey struct{}

// PelicanHeaders holds the subset of client HTTP headers that should
// be propagated through internal layers (e.g. WebDAV → backend) for
// tracing and timeout purposes.
type PelicanHeaders struct {
	JobId   string
	Timeout string
}

// WithPelicanHeaders stores the given headers in ctx.
func WithPelicanHeaders(ctx context.Context, h *PelicanHeaders) context.Context {
	return context.WithValue(ctx, pelicanHeadersKey{}, h)
}

// PelicanHeadersFromContext retrieves previously stashed PelicanHeaders
// (or nil if none were stored).
func PelicanHeadersFromContext(ctx context.Context) *PelicanHeaders {
	if h, ok := ctx.Value(pelicanHeadersKey{}).(*PelicanHeaders); ok {
		return h
	}
	return nil
}

// StashPelicanHeaders is a convenience that extracts X-Pelican-JobId
// and X-Pelican-Timeout from the incoming request and returns a new
// request whose context carries the values.
func StashPelicanHeaders(r *http.Request) *http.Request {
	ctx := WithPelicanHeaders(r.Context(), &PelicanHeaders{
		JobId:   r.Header.Get("X-Pelican-JobId"),
		Timeout: r.Header.Get("X-Pelican-Timeout"),
	})
	return r.WithContext(ctx)
}
