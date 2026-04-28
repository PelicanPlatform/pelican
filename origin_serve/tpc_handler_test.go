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
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// toLocalhostURL rewrites an httptest URL (http://127.0.0.1:PORT) to use
// "localhost" instead of the literal IP for consistency.
func toLocalhostURL(serverURL string) string {
	u, _ := url.Parse(serverURL)
	u.Host = "localhost:" + u.Port()
	return u.String()
}

// mockBackend is a minimal OriginBackend for testing the TPC handler.
type mockBackend struct {
	fs webdav.FileSystem
}

func (mb *mockBackend) CheckAvailability() error                    { return nil }
func (mb *mockBackend) FileSystem() webdav.FileSystem               { return mb.fs }
func (mb *mockBackend) Checksummer() server_utils.OriginChecksummer { return nil }

// newMockBackend creates a mockBackend backed by a temporary directory.
func newMockBackend(t *testing.T) *mockBackend {
	t.Helper()
	tmpDir := t.TempDir()
	return &mockBackend{fs: webdav.Dir(tmpDir)}
}

// setupTPCRouter creates a gin engine with just the TPC handler at /*path.
func setupTPCRouter(backend *mockBackend) *gin.Engine {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	exportPrefixMap = map[string]string{"/": ""}
	engine.Handle("COPY", "/*path", func(c *gin.Context) {
		handleCopyTPC(c, backend, "/")
	})
	return engine
}

func TestHandleCopyTPC(t *testing.T) {
	// Disable SSRF protection for functional tests that connect to
	// httptest servers on localhost. The SSRF dialer is thoroughly
	// tested in config/ssrf_transport_test.go.
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	fileContent := []byte("hello from the TPC source server")

	// Source server that serves GET and HEAD
	srcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileContent)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(fileContent)
		case http.MethodHead:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileContent)))
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srcServer.Close()

	t.Run("SuccessfulTPC", func(t *testing.T) {
		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", toLocalhostURL(srcServer.URL)+"/testfile.txt")
		req.Header.Set("Authorization", "Bearer dest-token")
		req.Header.Set("TransferHeaderAuthorization", "Bearer src-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "success: Created")
		assert.Contains(t, body, "Perf Marker")
		assert.Contains(t, body, "Stripe Bytes Transferred:")

		// Verify the file was written to the backend
		f, err := backend.fs.OpenFile(context.Background(), "/testfile.txt", os.O_RDONLY, 0)
		require.NoError(t, err)
		defer f.Close()
		data, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.Equal(t, fileContent, data)
	})

	t.Run("MissingSourceHeader", func(t *testing.T) {
		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Missing required Source header")
	})

	t.Run("RejectsUnknownExportPrefix", func(t *testing.T) {
		backend := newMockBackend(t)
		gin.SetMode(gin.TestMode)
		router := gin.New()
		exportPrefixMap = map[string]string{"/": ""}
		router.Handle("COPY", "/*path", func(c *gin.Context) {
			handleCopyTPC(c, backend, "/missing")
		})

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", toLocalhostURL(srcServer.URL)+"/testfile.txt")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid destination prefix")
	})

	t.Run("InvalidSourceURL", func(t *testing.T) {
		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", "ftp://invalid-scheme/file")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid Source URL")
	})

	t.Run("SSRFBlocksLoopbackIP", func(t *testing.T) {
		// Enable SSRF protection for this subtest
		require.NoError(t, param.Server_SSRFProtection_Disabled.Set(false))
		require.NoError(t, param.Server_SSRFProtection_AllowedCIDRs.Set([]string{}))
		config.ResetSSRFTransportForTest()
		t.Cleanup(func() {
			require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
			config.ResetSSRFTransportForTest()
		})

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", "http://127.0.0.1:8080/testfile.txt")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Contains(t, w.Body.String(), "not publicly routable")
	})

	t.Run("SSRFBlocksPrivateIP", func(t *testing.T) {
		// Enable SSRF protection for this subtest
		require.NoError(t, param.Server_SSRFProtection_Disabled.Set(false))
		require.NoError(t, param.Server_SSRFProtection_AllowedCIDRs.Set([]string{}))
		config.ResetSSRFTransportForTest()
		t.Cleanup(func() {
			require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
			config.ResetSSRFTransportForTest()
		})

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", "http://10.0.0.1:8080/testfile.txt")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Contains(t, w.Body.String(), "not publicly routable")
	})

	t.Run("SourceServerError", func(t *testing.T) {
		errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access denied")
		}))
		defer errServer.Close()

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/testfile.txt", nil)
		req.Header.Set("Source", toLocalhostURL(errServer.URL)+"/testfile.txt")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadGateway, w.Code)
		assert.Contains(t, w.Body.String(), "Source returned HTTP 403")
	})

	t.Run("TransferAuthForwarded", func(t *testing.T) {
		var receivedAuth string
		authCheckServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Length", "5")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("hello"))
		}))
		defer authCheckServer.Close()

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/auth-test.txt", nil)
		req.Header.Set("Source", toLocalhostURL(authCheckServer.URL)+"/src.txt")
		req.Header.Set("TransferHeaderAuthorization", "Bearer my-source-token")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		assert.Equal(t, "Bearer my-source-token", receivedAuth)
	})

	t.Run("GenericTransferHeadersForwarded", func(t *testing.T) {
		var receivedHeaders http.Header
		headerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			w.Header().Set("Content-Length", "2")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))
		defer headerServer.Close()

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/hdr-test.txt", nil)
		req.Header.Set("Source", toLocalhostURL(headerServer.URL)+"/src.txt")
		// These should be forwarded (prefix stripped)
		req.Header.Set("TransferHeaderAuthorization", "Bearer tok")
		req.Header.Set("TransferHeaderX-Custom-Meta", "some-value")
		req.Header.Set("TransferHeaderAccept", "application/octet-stream")
		// These should be denied / not forwarded
		req.Header.Set("TransferHeaderHost", "evil.example.com")
		req.Header.Set("TransferHeaderContent-Length", "99999")
		req.Header.Set("TransferHeaderTransfer-Encoding", "chunked")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		// Forwarded headers
		assert.Equal(t, "Bearer tok", receivedHeaders.Get("Authorization"))
		assert.Equal(t, "some-value", receivedHeaders.Get("X-Custom-Meta"))
		assert.Equal(t, "application/octet-stream", receivedHeaders.Get("Accept"))
		// Denied headers must not appear (or must retain original values)
		assert.NotEqual(t, "evil.example.com", receivedHeaders.Get("Host"))
		assert.NotEqual(t, "99999", receivedHeaders.Get("Content-Length"))
		assert.NotEqual(t, "chunked", receivedHeaders.Get("Transfer-Encoding"))
	})

	t.Run("PerfMarkerFormat", func(t *testing.T) {
		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/markers.txt", nil)
		req.Header.Set("Source", toLocalhostURL(srcServer.URL)+"/testfile.txt")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		body := w.Body.String()

		// Verify the final performance marker reports the correct byte count
		expected := fmt.Sprintf("Stripe Bytes Transferred: %d", len(fileContent))
		assert.Contains(t, body, expected)
		assert.Contains(t, body, "Total Stripe Count: 1")
		assert.True(t, strings.HasSuffix(body, "success: Created\n"))
	})
}

func TestIsTPCRequest(t *testing.T) {
	t.Run("COPYWithSource", func(t *testing.T) {
		req := httptest.NewRequest("COPY", "/dest.txt", nil)
		req.Header.Set("Source", "http://example.com/src.txt")
		assert.True(t, isTPCRequest(req))
	})

	t.Run("COPYWithoutSource", func(t *testing.T) {
		req := httptest.NewRequest("COPY", "/dest.txt", nil)
		assert.False(t, isTPCRequest(req))
	})

	t.Run("GETWithSource", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/dest.txt", nil)
		req.Header.Set("Source", "http://example.com/src.txt")
		assert.False(t, isTPCRequest(req))
	})
}

func TestGetActionFromMethodCOPY(t *testing.T) {
	// Verify that COPY maps to Wlcg_Storage_Create
	action := getActionFromMethod("COPY")
	assert.Contains(t, action.String(), "storage.create")
}

func TestHandleCopyTPCMidTransferFailures(t *testing.T) {
	// Disable SSRF protection for functional tests that connect to
	// httptest servers on localhost.
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	require.NoError(t, param.Server_SSRFProtection_Disabled.Set(true))
	config.ResetSSRFTransportForTest()

	t.Run("SourceDisconnectsMidStream", func(t *testing.T) {
		// Source server sends some bytes then abruptly closes the connection
		const totalBytes = 8192
		const sentBeforeAbort = 2048
		srcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", totalBytes))
			w.WriteHeader(http.StatusOK)
			// Write partial data then let the handler return, closing the connection
			_, _ = w.Write(make([]byte, sentBeforeAbort))
			// Returning here closes the body before all advertised bytes are sent,
			// which the origin should detect as a read error or size mismatch.
		}))
		defer srcServer.Close()

		backend := newMockBackend(t)
		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/partial.txt", nil)
		req.Header.Set("Source", toLocalhostURL(srcServer.URL)+"/big.dat")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// The handler commits 201 before streaming, so the status is 201,
		// but the body must contain a failure marker.
		assert.Equal(t, http.StatusCreated, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "failure:")
		assert.NotContains(t, body, "success: Created")
	})

	t.Run("BackendWriteFailsMidStream", func(t *testing.T) {
		// Large enough source to guarantee the write path is exercised
		bigData := make([]byte, 4096)
		for i := range bigData {
			bigData[i] = byte(i % 251)
		}
		srcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(bigData)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bigData)
		}))
		defer srcServer.Close()

		backend := newMockBackend(t)
		// Replace the filesystem with one whose files fail after writing
		// a few bytes, simulating a disk-full or I/O error mid-transfer.
		backend.fs = &failAfterNBytesFS{
			real:      backend.fs,
			failAfter: 1024,
		}

		router := setupTPCRouter(backend)

		req := httptest.NewRequest("COPY", "/should-fail.txt", nil)
		req.Header.Set("Source", toLocalhostURL(srcServer.URL)+"/data.bin")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		// The handler already sent 201 (response started), so the body
		// must contain a failure marker instead of success.
		assert.Equal(t, http.StatusCreated, w.Code)
		body := w.Body.String()
		assert.Contains(t, body, "failure:")
		assert.Contains(t, body, "write to destination failed")
		assert.NotContains(t, body, "success: Created")
	})
}

// failAfterNBytesFS wraps a real webdav.FileSystem but returns files whose
// Write method returns an error after a configured number of bytes, simulating
// a disk-full or I/O error mid-transfer.
type failAfterNBytesFS struct {
	real      webdav.FileSystem
	failAfter int64 // fail after this many bytes written
}

func (f *failAfterNBytesFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	return f.real.Mkdir(ctx, name, perm)
}

func (f *failAfterNBytesFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	file, err := f.real.OpenFile(ctx, name, flag, perm)
	if err != nil {
		return nil, err
	}
	return &failAfterNBytesFile{real: file, remaining: f.failAfter}, nil
}

func (f *failAfterNBytesFS) RemoveAll(ctx context.Context, name string) error {
	return f.real.RemoveAll(ctx, name)
}

func (f *failAfterNBytesFS) Rename(ctx context.Context, oldName, newName string) error {
	return f.real.Rename(ctx, oldName, newName)
}

func (f *failAfterNBytesFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	return f.real.Stat(ctx, name)
}

// failAfterNBytesFile wraps a webdav.File and injects a write error
// after a configured number of bytes have been written.
type failAfterNBytesFile struct {
	real      webdav.File
	remaining int64
}

func (f *failAfterNBytesFile) Write(p []byte) (int, error) {
	if f.remaining <= 0 {
		return 0, fmt.Errorf("simulated disk I/O error")
	}
	toWrite := int64(len(p))
	if toWrite > f.remaining {
		// Write partial, then fail on the next call
		nBytes := int(f.remaining)
		n, err := f.real.Write(p[:nBytes])
		f.remaining = 0
		if err != nil {
			return n, err
		}
		return n, fmt.Errorf("simulated disk I/O error")
	}
	n, err := f.real.Write(p)
	f.remaining -= int64(n)
	return n, err
}

func (f *failAfterNBytesFile) Close() error               { return f.real.Close() }
func (f *failAfterNBytesFile) Read(p []byte) (int, error) { return f.real.Read(p) }
func (f *failAfterNBytesFile) Seek(offset int64, whence int) (int64, error) {
	return f.real.Seek(offset, whence)
}
func (f *failAfterNBytesFile) Readdir(count int) ([]os.FileInfo, error) { return f.real.Readdir(count) }
func (f *failAfterNBytesFile) Stat() (os.FileInfo, error)               { return f.real.Stat() }
