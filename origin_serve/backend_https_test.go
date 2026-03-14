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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// HTTPSTokenMode / BackendMode constants
// ---------------------------------------------------------------------------

func TestHTTPSTokenModeConstants(t *testing.T) {
	assert.Equal(t, HTTPSTokenMode(0), HTTPSTokenNone)
	assert.Equal(t, HTTPSTokenMode(1), HTTPSTokenStatic)
	assert.Equal(t, HTTPSTokenMode(2), HTTPSTokenPassthrough)
	assert.Equal(t, HTTPSTokenMode(3), HTTPSTokenOAuth2)
}

func TestBackendModeConstants(t *testing.T) {
	assert.Equal(t, BackendMode(0), BackendModeUnknown)
	assert.Equal(t, BackendMode(1), BackendModeWebDAV)
	assert.Equal(t, BackendMode(2), BackendModeHTTP)
}

// ---------------------------------------------------------------------------
// Token passthrough context
// ---------------------------------------------------------------------------

func TestWithClientToken(t *testing.T) {
	ctx := context.Background()
	assert.Empty(t, tokenFromContext(ctx))

	ctx = WithClientToken(ctx, "my-token-123")
	assert.Equal(t, "my-token-123", tokenFromContext(ctx))
}

// ---------------------------------------------------------------------------
// simpleBearerAuth
// ---------------------------------------------------------------------------

func TestSimpleBearerAuth(t *testing.T) {
	auth := &simpleBearerAuth{tokenFunc: func() string { return "tok123" }}
	authenticator, body := auth.NewAuthenticator(nil)
	assert.Nil(t, body)
	assert.NotNil(t, authenticator)

	sba := authenticator.(*simpleBearerAuthenticator)

	// Authorize should set the header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := sba.Authorize(nil, req, "")
	require.NoError(t, err)
	assert.Equal(t, "Bearer tok123", req.Header.Get("Authorization"))

	// Clone should return an equivalent authenticator
	cloned := sba.Clone()
	assert.IsType(t, &simpleBearerAuthenticator{}, cloned)

	// Close should succeed
	assert.NoError(t, sba.Close())

	// Verify always returns false
	ok, err := sba.Verify(nil, nil, "")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSimpleBearerAuth_EmptyToken(t *testing.T) {
	auth := &simpleBearerAuth{tokenFunc: func() string { return "" }}
	authenticator, _ := auth.NewAuthenticator(nil)
	sba := authenticator.(*simpleBearerAuthenticator)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := sba.Authorize(nil, req, "")
	require.NoError(t, err)
	// Should not set Authorization header with empty token
	assert.Empty(t, req.Header.Get("Authorization"))
}

func TestSimpleBearerAuth_TokenRefresh(t *testing.T) {
	// Verify that the tokenFunc is called on each Authorize, so
	// a refreshed token is used for subsequent requests.
	callCount := 0
	auth := &simpleBearerAuth{tokenFunc: func() string {
		callCount++
		return fmt.Sprintf("tok-%d", callCount)
	}}
	authenticator, _ := auth.NewAuthenticator(nil)
	sba := authenticator.(*simpleBearerAuthenticator)

	req1 := httptest.NewRequest(http.MethodGet, "/a", nil)
	require.NoError(t, sba.Authorize(nil, req1, ""))
	assert.Equal(t, "Bearer tok-1", req1.Header.Get("Authorization"))

	req2 := httptest.NewRequest(http.MethodGet, "/b", nil)
	require.NoError(t, sba.Authorize(nil, req2, ""))
	assert.Equal(t, "Bearer tok-2", req2.Header.Get("Authorization"))
}

// ---------------------------------------------------------------------------
// httpsFileInfo
// ---------------------------------------------------------------------------

func TestHTTPSFileInfo(t *testing.T) {
	fi := &httpsFileInfo{name: "test.txt", size: 100, isDir: false}
	assert.Equal(t, "test.txt", fi.Name())
	assert.Equal(t, int64(100), fi.Size())
	assert.Equal(t, os.FileMode(0444), fi.Mode())
	assert.False(t, fi.IsDir())
	assert.Nil(t, fi.Sys())
	assert.False(t, fi.ModTime().IsZero()) // zero modtime gets replaced

	fiDir := &httpsFileInfo{name: "dir", isDir: true}
	assert.True(t, fiDir.IsDir())

	fiEtag := &httpsFileInfo{name: "e.txt", etag: `"abc123"`}
	sys := fiEtag.Sys()
	require.NotNil(t, sys)
	info, ok := sys.(*HTTPSFileSysInfo)
	require.True(t, ok)
	assert.Equal(t, `"abc123"`, info.ETag)
}

// ---------------------------------------------------------------------------
// httpsReadDirFile
// ---------------------------------------------------------------------------

func TestHTTPSReadDirFile(t *testing.T) {
	entries := []os.FileInfo{
		&httpsFileInfo{name: "a.txt"},
		&httpsFileInfo{name: "b.txt"},
	}
	df := &httpsReadDirFile{name: "/listing", entries: entries}

	// Stat
	info, err := df.Stat()
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, "listing", info.Name())

	// Readdir
	result, err := df.Readdir(-1)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Unsupported operations
	_, err = df.Read(nil)
	assert.Error(t, err)
	_, err = df.Seek(0, 0)
	assert.Error(t, err)
	_, err = df.Write(nil)
	assert.Error(t, err)
	require.NoError(t, df.Close())
}

func TestHTTPSReadDirFile_Partial(t *testing.T) {
	entries := []os.FileInfo{
		&httpsFileInfo{name: "a.txt"},
		&httpsFileInfo{name: "b.txt"},
		&httpsFileInfo{name: "c.txt"},
	}
	df := &httpsReadDirFile{name: "/dir", entries: entries}

	result, err := df.Readdir(2)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	result2, err := df.Readdir(-1)
	require.NoError(t, err)
	assert.Len(t, result2, 1)
}

// ---------------------------------------------------------------------------
// httpsWriteFile — unit tests
// ---------------------------------------------------------------------------

func TestHTTPSWriteFile_UnsupportedOps(t *testing.T) {
	wf := &httpsWriteFile{name: "/test"}
	_, err := wf.Read(nil)
	assert.Error(t, err)
	_, err = wf.Readdir(-1)
	assert.Error(t, err)
}

func TestHTTPSWriteFile_NoOpSeek(t *testing.T) {
	wf := &httpsWriteFile{name: "/test"}

	// Seek to current offset (0) should succeed
	pos, err := wf.Seek(0, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	pos, err = wf.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pos)

	// Write some data
	_, _ = wf.Write([]byte("hello"))

	// Seeking to current offset (5) should succeed
	pos, err = wf.Seek(5, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	pos, err = wf.Seek(0, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	pos, err = wf.Seek(0, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	// Non-current seek should fail
	_, err = wf.Seek(0, io.SeekStart)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-sequential")
}

func TestHTTPSWriteFile_Stat(t *testing.T) {
	wf := &httpsWriteFile{name: "/test.txt"}
	wf.buf = []byte("hello")
	info, err := wf.Stat()
	require.NoError(t, err)
	assert.Equal(t, "test.txt", info.Name())
	assert.Equal(t, int64(5), info.Size())
}

// ---------------------------------------------------------------------------
// httpsReadFile — unit tests
// ---------------------------------------------------------------------------

func TestHTTPSReadFile_Seek(t *testing.T) {
	body := io.NopCloser(strings.NewReader("0123456789"))
	rf := &httpsReadFile{
		name:          "/test.bin",
		body:          body,
		contentLength: 10,
	}
	defer rf.Close()

	// SeekStart
	pos, err := rf.Seek(5, io.SeekStart)
	require.NoError(t, err)
	assert.Equal(t, int64(5), pos)

	// SeekCurrent
	pos, err = rf.Seek(2, io.SeekCurrent)
	require.NoError(t, err)
	assert.Equal(t, int64(7), pos)

	// SeekEnd
	pos, err = rf.Seek(-3, io.SeekEnd)
	require.NoError(t, err)
	assert.Equal(t, int64(7), pos)
}

func TestHTTPSReadFile_Stat(t *testing.T) {
	body := io.NopCloser(strings.NewReader("content"))
	rf := &httpsReadFile{
		name:          "/data/file.txt",
		body:          body,
		contentLength: 7,
	}
	defer rf.Close()

	info, err := rf.Stat()
	require.NoError(t, err)
	assert.Equal(t, "file.txt", info.Name())
	assert.Equal(t, int64(7), info.Size())
	assert.False(t, info.IsDir())
}

func TestHTTPSReadFile_UnsupportedOps(t *testing.T) {
	body := io.NopCloser(strings.NewReader("x"))
	rf := &httpsReadFile{name: "/x", body: body}
	defer rf.Close()

	_, err := rf.Write(nil)
	assert.Error(t, err)
	_, err = rf.Readdir(-1)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Static token reading
// ---------------------------------------------------------------------------

func TestHTTPSFileSystem_ReadStaticToken(t *testing.T) {
	t.Run("FromFile", func(t *testing.T) {
		dir := t.TempDir()
		tokFile := dir + "/token"
		require.NoError(t, os.WriteFile(tokFile, []byte("  mytoken  \n"), 0600))

		fs := &httpsFileSystem{staticTokenFile: tokFile, tokenMode: HTTPSTokenStatic}
		assert.Equal(t, "mytoken", fs.readStaticToken())
	})

	t.Run("MissingFile", func(t *testing.T) {
		fs := &httpsFileSystem{staticTokenFile: "/nonexistent", tokenMode: HTTPSTokenStatic}
		assert.Empty(t, fs.readStaticToken())
	})

	t.Run("EmptyPath", func(t *testing.T) {
		fs := &httpsFileSystem{tokenMode: HTTPSTokenStatic}
		assert.Empty(t, fs.readStaticToken())
	})
}

// ---------------------------------------------------------------------------
// Integration test: HTTPS backend w/ a mock HTTP server
// ---------------------------------------------------------------------------

func TestHTTPSBackend_PlainHTTP_Integration(t *testing.T) {
	// Set up a simple in-memory file store served over HTTP
	store := map[string][]byte{
		"/data/hello.txt": []byte("Hello, World!"),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, PUT, DELETE, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			data, ok := store[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			data, ok := store[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
			_, _ = w.Write(data)
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			store[r.URL.Path] = body
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			delete(store, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenNone,
	})

	// Probe → should detect plain HTTP (no PROPFIND in Allow)
	require.NoError(t, backend.CheckAvailability())
	assert.Equal(t, BackendModeHTTP, backend.BackendMode())

	ctx := context.Background()
	fs := backend.FileSystem()

	// Stat existing file
	info, err := fs.Stat(ctx, "/data/hello.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(13), info.Size())

	// Stat non-existent file
	_, err = fs.Stat(ctx, "/nope.txt")
	assert.ErrorIs(t, err, os.ErrNotExist)

	// Read existing file
	rf, err := fs.OpenFile(ctx, "/data/hello.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	data, err := io.ReadAll(rf)
	require.NoError(t, err)
	assert.Equal(t, "Hello, World!", string(data))
	rf.Close()

	// Write a new file
	wf, err := fs.OpenFile(ctx, "/data/new.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("new content"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	// Verify it was stored
	assert.Equal(t, []byte("new content"), store["/data/new.txt"])

	// Delete
	require.NoError(t, fs.RemoveAll(ctx, "/data/new.txt"))
	_, exists := store["/data/new.txt"]
	assert.False(t, exists)

	// Read non-existent should return ErrNotExist
	_, err = fs.OpenFile(ctx, "/gone.txt", os.O_RDONLY, 0)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestHTTPSBackend_TokenPassthrough(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenPassthrough,
	})
	require.NoError(t, backend.CheckAvailability())

	ctx := WithClientToken(context.Background(), "client-bearer-xyz")
	rf, err := backend.FileSystem().OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer rf.Close()

	assert.Equal(t, "Bearer client-bearer-xyz", receivedAuth)
}

func TestHTTPSBackend_StaticToken(t *testing.T) {
	dir := t.TempDir()
	tokFile := dir + "/token"
	require.NoError(t, os.WriteFile(tokFile, []byte("static-tok"), 0600))

	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      server.URL,
		TokenMode:       HTTPSTokenStatic,
		StaticTokenFile: tokFile,
	})
	require.NoError(t, backend.CheckAvailability())

	rf, err := backend.FileSystem().OpenFile(context.Background(), "/file.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer rf.Close()

	assert.Equal(t, "Bearer static-tok", receivedAuth)
}

func TestHTTPSBackend_WebDAVProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, PUT, DELETE, HEAD, OPTIONS, PROPFIND, MKCOL, MOVE, COPY")
			w.Header().Set("DAV", "1, 2")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenNone,
	})
	require.NoError(t, backend.CheckAvailability())
	assert.Equal(t, BackendModeWebDAV, backend.BackendMode())
}

func TestHTTPSBackend_OPTIONSFails(t *testing.T) {
	// server that immediately closes so OPTIONS fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			// Force a connection close to trigger an error
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, _ := hj.Hijack()
				conn.Close()
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenNone,
	})
	// Should not error — just defaults to HTTP mode
	require.NoError(t, backend.CheckAvailability())
	assert.Equal(t, BackendModeHTTP, backend.BackendMode())
}

func TestHTTPSBackend_NoChecksummer(t *testing.T) {
	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: "https://example.com",
	})
	assert.Nil(t, backend.Checksummer())
}

func TestHTTPSBackend_StatETag(t *testing.T) {
	// Verify that ETag from HEAD responses is surfaced through Sys().
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodHead {
			w.Header().Set("ETag", `"abc-etag"`)
			w.Header().Set("Content-Length", "42")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenNone,
	})
	require.NoError(t, backend.CheckAvailability())

	info, err := backend.FileSystem().Stat(context.Background(), "/file.txt")
	require.NoError(t, err)
	assert.Equal(t, int64(42), info.Size())

	sys := info.Sys()
	require.NotNil(t, sys)
	hsi, ok := sys.(*HTTPSFileSysInfo)
	require.True(t, ok)
	assert.Equal(t, `"abc-etag"`, hsi.ETag)
}

// ---------------------------------------------------------------------------
// davPath and upstreamURL tests
// ---------------------------------------------------------------------------

func TestHTTPSFileSystem_DavPath(t *testing.T) {
	fs := &httpsFileSystem{serviceURL: "https://example.com", storagePrefix: ""}
	assert.Equal(t, "/foo.txt", fs.davPath("/foo.txt"))
	assert.Equal(t, "/foo.txt", fs.davPath("foo.txt"))

	fs2 := &httpsFileSystem{serviceURL: "https://example.com", storagePrefix: "/prefix"}
	assert.Equal(t, "/prefix/bar.txt", fs2.davPath("/bar.txt"))
}

func TestHTTPSFileSystem_UpstreamURL(t *testing.T) {
	fs := &httpsFileSystem{serviceURL: "https://example.com", storagePrefix: ""}
	assert.Equal(t, "https://example.com/foo.txt", fs.upstreamURL("/foo.txt"))

	fs2 := &httpsFileSystem{serviceURL: "https://example.com", storagePrefix: "/pfx"}
	assert.Equal(t, "https://example.com/pfx/bar.txt", fs2.upstreamURL("/bar.txt"))
}

// ---------------------------------------------------------------------------
// getToken dispatch tests
// ---------------------------------------------------------------------------

func TestHTTPSFileSystem_GetToken(t *testing.T) {
	t.Run("None", func(t *testing.T) {
		fs := &httpsFileSystem{tokenMode: HTTPSTokenNone}
		assert.Empty(t, fs.getToken(context.Background()))
	})

	t.Run("Passthrough", func(t *testing.T) {
		fs := &httpsFileSystem{tokenMode: HTTPSTokenPassthrough}
		ctx := WithClientToken(context.Background(), "pass-tok")
		assert.Equal(t, "pass-tok", fs.getToken(ctx))
	})

	t.Run("PassthroughEmpty", func(t *testing.T) {
		fs := &httpsFileSystem{tokenMode: HTTPSTokenPassthrough}
		assert.Empty(t, fs.getToken(context.Background()))
	})

	t.Run("OAuthNoConfig", func(t *testing.T) {
		fs := &httpsFileSystem{tokenMode: HTTPSTokenOAuth2}
		assert.Empty(t, fs.getToken(context.Background()))
	})
}

// ---------------------------------------------------------------------------
// HTTP-only backend: Mkdir and Rename should return errors
// ---------------------------------------------------------------------------

func TestHTTPSBackend_HTTPOnly_UnsupportedOps(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Allow", "GET, PUT, DELETE, HEAD, OPTIONS")
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL: server.URL,
		TokenMode:  HTTPSTokenNone,
	})
	require.NoError(t, backend.CheckAvailability())

	ctx := context.Background()
	err := backend.FileSystem().Mkdir(ctx, "/newdir", 0755)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotSupported))

	err = backend.FileSystem().Rename(ctx, "/a", "/b")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotSupported))
}

// ---------------------------------------------------------------------------
// Auto-mkdir tests
// ---------------------------------------------------------------------------

// mockWebDAVServer creates an httptest.Server that simulates a WebDAV-capable
// server with in-memory storage.  It supports MKCOL, PUT, PROPFIND (stat), and
// OPTIONS.  PUT to paths whose parent directory hasn't been created via MKCOL
// returns 409 Conflict, matching standard WebDAV semantics.
func mockWebDAVServer() (*httptest.Server, map[string][]byte) {
	files := map[string][]byte{}
	dirs := map[string]bool{"/": true}

	// normalize strips trailing slashes (except for root "/")
	normalize := func(p string) string {
		for len(p) > 1 && p[len(p)-1] == '/' {
			p = p[:len(p)-1]
		}
		return p
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := normalize(r.URL.Path)
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, PUT, DELETE, HEAD, OPTIONS, PROPFIND, MKCOL, MOVE, COPY")
			w.Header().Set("DAV", "1, 2")
			w.WriteHeader(http.StatusOK)

		case "MKCOL":
			if dirs[p] {
				// Already exists
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			// Check parent exists
			parent := p
			if idx := strings.LastIndex(parent, "/"); idx >= 0 {
				parent = parent[:idx]
				if parent == "" {
					parent = "/"
				}
			}
			if !dirs[parent] {
				w.WriteHeader(http.StatusConflict)
				return
			}
			dirs[p] = true
			w.WriteHeader(http.StatusCreated)

		case http.MethodPut:
			// Check that parent directory exists
			parent := p
			if idx := strings.LastIndex(parent, "/"); idx >= 0 {
				parent = parent[:idx]
				if parent == "" {
					parent = "/"
				}
			}
			if !dirs[parent] {
				w.WriteHeader(http.StatusConflict)
				return
			}
			body, _ := io.ReadAll(r.Body)
			files[p] = body
			w.WriteHeader(http.StatusCreated)

		case "PROPFIND":
			if dirs[p] {
				// Return a minimal multistatus response indicating a directory
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(207) // Multi-Status
				fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`, p)
				return
			}
			if _, ok := files[p]; ok {
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(207)
				fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype />
        <D:getcontentlength>%d</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`, p, len(files[p]))
				return
			}
			w.WriteHeader(http.StatusNotFound)

		case http.MethodHead:
			if _, ok := files[p]; ok {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(files[p])))
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)

		case http.MethodGet:
			if data, ok := files[p]; ok {
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
				_, _ = w.Write(data)
				return
			}
			w.WriteHeader(http.StatusNotFound)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})), files
}

func TestHTTPSBackend_AutoMkdir_CreatesParentDirs(t *testing.T) {
	server, files := mockWebDAVServer()
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      server.URL,
		TokenMode:       HTTPSTokenNone,
		EnableAutoMkdir: true,
	})
	require.NoError(t, backend.CheckAvailability())
	assert.Equal(t, BackendModeWebDAV, backend.BackendMode())

	ctx := context.Background()
	fs := backend.FileSystem()

	// PUT a file into a deeply nested path that doesn't exist yet.
	// Without auto-mkdir this would fail with 409 Conflict.
	wf, err := fs.OpenFile(ctx, "/a/b/c/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("deep content"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	// Verify the file was stored
	assert.Equal(t, []byte("deep content"), files["/a/b/c/file.txt"])
}

func TestHTTPSBackend_AutoMkdir_Disabled(t *testing.T) {
	server, _ := mockWebDAVServer()
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      server.URL,
		TokenMode:       HTTPSTokenNone,
		EnableAutoMkdir: false,
	})
	require.NoError(t, backend.CheckAvailability())

	ctx := context.Background()
	fs := backend.FileSystem()

	// Without auto-mkdir, PUT into a missing directory should fail.
	wf, err := fs.OpenFile(ctx, "/x/y/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("data"))
	require.NoError(t, err)
	err = wf.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "409")
}

func TestHTTPSBackend_AutoMkdir_ExistingParent(t *testing.T) {
	server, files := mockWebDAVServer()
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      server.URL,
		TokenMode:       HTTPSTokenNone,
		EnableAutoMkdir: true,
	})
	require.NoError(t, backend.CheckAvailability())

	ctx := context.Background()
	fs := backend.FileSystem()

	// First create /existing via MKCOL
	require.NoError(t, fs.Mkdir(ctx, "/existing", 0755))

	// Now PUT under /existing/sub/file.txt — only "sub" needs to be created
	wf, err := fs.OpenFile(ctx, "/existing/sub/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("hello"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	assert.Equal(t, []byte("hello"), files["/existing/sub/file.txt"])
}

func TestHTTPSBackend_AutoMkdir_TopLevelFile(t *testing.T) {
	server, files := mockWebDAVServer()
	defer server.Close()

	backend := newHTTPSBackend(HTTPSBackendOptions{
		ServiceURL:      server.URL,
		TokenMode:       HTTPSTokenNone,
		EnableAutoMkdir: true,
	})
	require.NoError(t, backend.CheckAvailability())

	ctx := context.Background()
	fs := backend.FileSystem()

	// PUT at root level should work directly without needing auto-mkdir
	wf, err := fs.OpenFile(ctx, "/root-file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = wf.Write([]byte("top level"))
	require.NoError(t, err)
	require.NoError(t, wf.Close())

	assert.Equal(t, []byte("top level"), files["/root-file.txt"])
}

func TestEnsureParentDirs_NoParent(t *testing.T) {
	// When the file is at the root, ensureParentDirs should be a no-op.
	fs := &httpsFileSystem{
		backendMode:     BackendModeWebDAV,
		enableAutoMkdir: true,
	}

	ctx := context.Background()
	assert.NoError(t, fs.ensureParentDirs(ctx, "/file.txt"))
	assert.NoError(t, fs.ensureParentDirs(ctx, "file.txt"))
}

func TestEnsureParentDirs_RequiresWebDAV(t *testing.T) {
	fs := &httpsFileSystem{
		backendMode:     BackendModeHTTP,
		enableAutoMkdir: true,
	}

	ctx := context.Background()
	err := fs.ensureParentDirs(ctx, "/a/b/file.txt")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-mkdir requires WebDAV")
}
