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
	auth := &simpleBearerAuth{token: "tok123"}
	authenticator, body := auth.NewAuthenticator(nil)
	assert.Nil(t, body)
	assert.NotNil(t, authenticator)

	sba := authenticator.(*simpleBearerAuthenticator)
	assert.Equal(t, "tok123", sba.token)

	// Authorize should set the header
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := sba.Authorize(nil, req, "")
	require.NoError(t, err)
	assert.Equal(t, "Bearer tok123", req.Header.Get("Authorization"))

	// Clone should return an equivalent authenticator
	cloned := sba.Clone()
	assert.IsType(t, &simpleBearerAuthenticator{}, cloned)
	assert.Equal(t, "tok123", cloned.(*simpleBearerAuthenticator).token)

	// Close should succeed
	assert.NoError(t, sba.Close())

	// Verify always returns false
	ok, err := sba.Verify(nil, nil, "")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestSimpleBearerAuth_EmptyToken(t *testing.T) {
	auth := &simpleBearerAuth{token: ""}
	authenticator, _ := auth.NewAuthenticator(nil)
	sba := authenticator.(*simpleBearerAuthenticator)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	err := sba.Authorize(nil, req, "")
	require.NoError(t, err)
	// Should not set Authorization header with empty token
	assert.Empty(t, req.Header.Get("Authorization"))
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
	_, err = wf.Seek(0, 0)
	assert.Error(t, err)
	_, err = wf.Readdir(-1)
	assert.Error(t, err)
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
			w.Write(data)
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
		w.Write([]byte("hello"))
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
		w.Write([]byte("ok"))
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
	assert.Contains(t, err.Error(), "mkdir not supported")

	err = backend.FileSystem().Rename(ctx, "/a", "/b")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rename not supported")
}
