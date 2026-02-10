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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestHelperBrokerCreation tests that the helper broker is created correctly
func TestHelperBrokerCreation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-12345")
	require.NotNil(t, broker)

	assert.Equal(t, "test-cookie-12345", broker.GetAuthCookie())
	assert.NotNil(t, broker.pendingRequests)
	assert.NotNil(t, broker.connectionPool)
}

// TestHelperBrokerAuthCookieGeneration tests that auth cookies are generated correctly
func TestHelperBrokerAuthCookieGeneration(t *testing.T) {
	cookie1, err := generateAuthCookie()
	require.NoError(t, err)
	assert.Len(t, cookie1, 64) // 32 bytes hex encoded = 64 chars

	cookie2, err := generateAuthCookie()
	require.NoError(t, err)
	assert.Len(t, cookie2, 64)

	// Should be unique
	assert.NotEqual(t, cookie1, cookie2)
}

// TestHelperBrokerRetrieveEndpoint tests the retrieve endpoint actually works
func TestHelperBrokerRetrieveEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-abc123")
	SetHelperBroker(broker)
	defer SetHelperBroker(nil)

	// Set up gin router with the handler
	router := gin.New()
	RegisterHelperBrokerHandlers(router, ctx)

	t.Run("rejects missing auth header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/retrieve", nil)
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects invalid auth token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/retrieve", nil)
		req.Header.Set("Authorization", "Bearer wrong-cookie")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("returns timeout when no pending requests", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/retrieve", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-abc123")
		req.Header.Set("X-Pelican-Timeout", "200ms")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp helperRetrieveResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "timeout", resp.Status)
	})

	t.Run("returns request ID when pending request exists", func(t *testing.T) {
		// With the pendingCh design, RequestConnection blocks until a retrieve
		// handler receives the request from the channel.  So we must run the
		// retrieve handler concurrently with RequestConnection.

		// Channel to capture the retrieve response
		type retrieveResult struct {
			code int
			resp helperRetrieveResponse
		}
		resultCh := make(chan retrieveResult, 1)

		// Start the retrieve handler — it will block on pendingCh until a
		// RequestConnection sends a request.
		go func() {
			req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/retrieve", nil)
			req.Header.Set("Authorization", "Bearer test-cookie-abc123")
			req.Header.Set("X-Pelican-Timeout", "2s")
			rec := httptest.NewRecorder()

			router.ServeHTTP(rec, req)

			var r helperRetrieveResponse
			_ = json.NewDecoder(rec.Body).Decode(&r)
			resultCh <- retrieveResult{code: rec.Code, resp: r}
		}()

		// Give the retrieve handler a moment to start selecting on pendingCh
		time.Sleep(50 * time.Millisecond)

		// Create a pending request — this will unblock once the retrieve handler
		// receives it from pendingCh.
		go func() {
			shortCtx, shortCancel := context.WithTimeout(ctx, 2*time.Second)
			defer shortCancel()

			_, err := broker.RequestConnection(shortCtx)
			// Will fail because no one calls back, but it creates a pending request
			_ = err
		}()

		// Wait for the retrieve response
		select {
		case res := <-resultCh:
			assert.Equal(t, http.StatusOK, res.code)
			assert.Equal(t, "ok", res.resp.Status)
			assert.NotEmpty(t, res.resp.RequestID)
		case <-time.After(3 * time.Second):
			t.Fatal("retrieve handler did not return in time")
		}
	})
}

// TestHelperBrokerCallbackEndpoint tests the callback endpoint actually works
func TestHelperBrokerCallbackEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-callback")
	SetHelperBroker(broker)
	defer SetHelperBroker(nil)

	// Set up gin router with the handler
	router := gin.New()
	RegisterHelperBrokerHandlers(router, ctx)

	t.Run("rejects missing auth header", func(t *testing.T) {
		reqBody, _ := json.Marshal(helperCallbackRequest{
			RequestID: "test-request-id",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/callback", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects invalid auth token", func(t *testing.T) {
		reqBody, _ := json.Marshal(helperCallbackRequest{
			RequestID: "test-request-id",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/callback", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer wrong-cookie")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("rejects unknown request ID", func(t *testing.T) {
		reqBody, _ := json.Marshal(helperCallbackRequest{
			RequestID: "nonexistent-request-id",
		})

		req := httptest.NewRequest(http.MethodPost, "/api/v1.0/origin/ssh/callback", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-cookie-callback")
		rec := httptest.NewRecorder()

		router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var resp helperCallbackResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "error", resp.Status)
		assert.Contains(t, resp.Msg, "No such request")
	})
}

// TestHelperTransport tests the HelperTransport RoundTripper actually works
func TestHelperTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-transport")
	transport := NewHelperTransport(broker)
	require.NotNil(t, transport)

	t.Run("request without available connection times out", func(t *testing.T) {
		reqCtx, reqCancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer reqCancel()

		req, err := http.NewRequestWithContext(reqCtx, "GET", "http://helper/test", nil)
		require.NoError(t, err)

		_, err = transport.RoundTrip(req)
		assert.Error(t, err)
	})

	t.Run("round trip succeeds with pooled connection", func(t *testing.T) {
		// Create a mock server to respond to the request
		clientConn, serverConn := net.Pipe()
		defer clientConn.Close()
		defer serverConn.Close()

		// Pre-populate the pool with a connection to the mock server
		select {
		case broker.connectionPool <- clientConn:
		default:
			t.Fatal("failed to add connection to pool")
		}

		// Server goroutine: read request and send response
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			// Read the HTTP request
			buf := make([]byte, 1024)
			n, err := serverConn.Read(buf)
			if err != nil {
				return
			}
			// Verify we got an HTTP request
			if !bytes.Contains(buf[:n], []byte("GET /test HTTP/1.1")) {
				t.Errorf("unexpected request: %s", string(buf[:n]))
				return
			}
			// Send HTTP response
			response := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World"
			_, _ = serverConn.Write([]byte(response))
		}()

		req, err := http.NewRequestWithContext(ctx, "GET", "http://helper/test", nil)
		require.NoError(t, err)

		resp, err := transport.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, "Hello World", string(body))

		<-serverDone
	})
}

// TestOneShotListener tests the one-shot listener used for connection reversal
func TestOneShotListener(t *testing.T) {
	// Create a pipe to simulate a connection
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Use the pipe's address (dynamic, not fixed port)
	listener := newOneShotListener(serverConn, serverConn.LocalAddr())

	t.Run("accept returns the connection once", func(t *testing.T) {
		conn, err := listener.Accept()
		require.NoError(t, err)
		assert.NotNil(t, conn)
	})

	t.Run("accept returns error after first call", func(t *testing.T) {
		_, err := listener.Accept()
		assert.Error(t, err)
	})

	t.Run("addr returns the configured address", func(t *testing.T) {
		assert.Equal(t, serverConn.LocalAddr(), listener.Addr())
	})

	t.Run("close is idempotent", func(t *testing.T) {
		err := listener.Close()
		assert.NoError(t, err)

		err = listener.Close()
		assert.NoError(t, err)
	})
}

// TestHelperBrokerConnectionPool tests the connection pool mechanics
func TestHelperBrokerConnectionPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-pool")

	// Create a pipe to simulate connections
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Pre-populate the pool with a connection
	select {
	case broker.connectionPool <- serverConn:
	default:
		t.Fatal("failed to add connection to pool")
	}

	// RequestConnection should return the pooled connection immediately
	conn, err := broker.RequestConnection(ctx)
	require.NoError(t, err)
	assert.Equal(t, serverConn, conn)
}

// TestHelperBrokerConcurrentRequests tests handling of concurrent connection requests
func TestHelperBrokerConcurrentRequests(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-concurrent")

	numConns := 3
	var wg sync.WaitGroup

	// Pre-populate the pool with connections
	pipes := make([]struct{ client, server net.Conn }, numConns)
	for i := range pipes {
		client, server := net.Pipe()
		pipes[i].client = client
		pipes[i].server = server
		defer client.Close()
		defer server.Close()

		select {
		case broker.connectionPool <- pipes[i].server:
		default:
			t.Fatalf("failed to add connection %d to pool", i)
		}
	}

	// Start concurrent requests - they should all succeed
	results := make([]net.Conn, numConns)
	for i := 0; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := broker.RequestConnection(ctx)
			if err != nil {
				t.Errorf("request %d failed: %v", idx, err)
				return
			}
			results[idx] = conn
		}(i)
	}

	wg.Wait()

	// All connections should have been consumed
	for i, conn := range results {
		assert.NotNil(t, conn, "connection %d should not be nil", i)
	}

	// Pool should be empty now - next request should timeout
	shortCtx, shortCancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer shortCancel()

	_, err := broker.RequestConnection(shortCtx)
	assert.Error(t, err, "should timeout when pool is empty")
}

// TestReverseConnectionFlowIntegration tests the full reverse connection flow end-to-end
func TestReverseConnectionFlowIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-integration")
	SetHelperBroker(broker)
	defer SetHelperBroker(nil)

	// Start the origin server with helper broker handlers
	router := gin.New()
	RegisterHelperBrokerHandlers(router, ctx)
	originServer := httptest.NewServer(router)
	defer originServer.Close()

	// Create a mock "helper" that will poll and callback
	t.Run("full retrieve-callback-serve flow", func(t *testing.T) {
		// Channel to signal the helper served a request
		helperServed := make(chan string, 1)

		// Start a goroutine simulating the helper process
		go func() {
			// Poll for pending requests
			pollReq, _ := http.NewRequest(http.MethodPost, originServer.URL+"/api/v1.0/origin/ssh/retrieve", nil)
			pollReq.Header.Set("Authorization", "Bearer test-cookie-integration")
			pollReq.Header.Set("X-Pelican-Timeout", "5s")

			resp, err := http.DefaultClient.Do(pollReq)
			if err != nil {
				t.Logf("poll request failed: %v", err)
				return
			}
			defer resp.Body.Close()

			var pollResp helperRetrieveResponse
			if err := json.NewDecoder(resp.Body).Decode(&pollResp); err != nil {
				t.Logf("failed to decode poll response: %v", err)
				return
			}

			if pollResp.Status != "ok" || pollResp.RequestID == "" {
				t.Logf("no pending request: %s", pollResp.Status)
				return
			}

			// Got a request ID - now simulate serving a response
			helperServed <- pollResp.RequestID
		}()

		// Client side: request a connection
		go func() {
			shortCtx, shortCancel := context.WithTimeout(ctx, 3*time.Second)
			defer shortCancel()

			_, err := broker.RequestConnection(shortCtx)
			// This will timeout because we don't complete the callback
			// but the helper should receive the request ID
			_ = err
		}()

		// Wait for the helper to receive the request ID
		select {
		case reqID := <-helperServed:
			assert.NotEmpty(t, reqID)
		case <-time.After(3 * time.Second):
			t.Fatal("helper did not receive request ID in time")
		}
	})
}

// TestSSHFileSystemInterface tests that SSHFileSystem implements webdav.FileSystem
func TestSSHFileSystemInterface(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-fs")
	fs := NewSSHFileSystem(broker, "/test", "/data")

	require.NotNil(t, fs)

	// Verify that SSHFileSystem implements webdav.FileSystem interface
	var _ webdav.FileSystem = fs

	// Test URL construction
	url := fs.makeHelperURL("/subdir/file.txt")
	assert.Equal(t, "http://helper/test/subdir/file.txt", url)

	url = fs.makeHelperURL("")
	assert.Equal(t, "http://helper/test", url)

	url = fs.makeHelperURL("/")
	assert.Equal(t, "http://helper/test", url)
}

// TestSSHFileInfo tests the sshFileInfo implementation
func TestSSHFileInfo(t *testing.T) {
	modTime := time.Now()
	info := &sshFileInfo{
		name:    "test.txt",
		size:    1024,
		mode:    0644,
		modTime: modTime,
		isDir:   false,
	}

	assert.Equal(t, "test.txt", info.Name())
	assert.Equal(t, int64(1024), info.Size())
	assert.Equal(t, os.FileMode(0644), info.Mode())
	assert.Equal(t, modTime, info.ModTime())
	assert.False(t, info.IsDir())
	assert.Nil(t, info.Sys())

	// Test directory
	dirInfo := &sshFileInfo{
		name:  "subdir",
		mode:  0755 | os.ModeDir,
		isDir: true,
	}

	assert.True(t, dirInfo.IsDir())
	assert.True(t, dirInfo.Mode().IsDir())
}

// TestSSHFileMethods tests the sshFile implementation
func TestSSHFileMethods(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-file")
	fs := NewSSHFileSystem(broker, "/test", "/data")

	file := &sshFile{
		fs:   fs,
		name: "/testfile.txt",
		flag: os.O_RDONLY,
		ctx:  ctx,
	}

	t.Run("close is safe to call multiple times", func(t *testing.T) {
		err := file.Close()
		assert.NoError(t, err)

		err = file.Close()
		assert.NoError(t, err)
	})

	t.Run("seek to start", func(t *testing.T) {
		newFile := &sshFile{
			fs:         fs,
			name:       "/testfile.txt",
			flag:       os.O_RDONLY,
			ctx:        ctx,
			readOffset: 100,
		}

		offset, err := newFile.Seek(0, io.SeekStart)
		require.NoError(t, err)
		assert.Equal(t, int64(0), offset)
		assert.Equal(t, int64(0), newFile.readOffset)
	})

	t.Run("seek current", func(t *testing.T) {
		newFile := &sshFile{
			fs:         fs,
			name:       "/testfile.txt",
			flag:       os.O_RDONLY,
			ctx:        ctx,
			readOffset: 100,
		}

		offset, err := newFile.Seek(50, io.SeekCurrent)
		require.NoError(t, err)
		assert.Equal(t, int64(150), offset)
	})

	t.Run("seek negative position fails", func(t *testing.T) {
		newFile := &sshFile{
			fs:         fs,
			name:       "/testfile.txt",
			flag:       os.O_RDONLY,
			ctx:        ctx,
			readOffset: 0,
		}

		_, err := newFile.Seek(-10, io.SeekStart)
		assert.Error(t, err)
	})
}

// TestWebDAVXMLParsing tests parsing of PROPFIND responses
func TestWebDAVXMLParsing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	broker := NewHelperBroker(ctx, "test-cookie-xml")
	fs := NewSSHFileSystem(broker, "/test", "/data")

	t.Run("parse file response", func(t *testing.T) {
		xmlResponse := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/test/file.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype></D:resourcetype>
        <D:getcontentlength>1234</D:getcontentlength>
        <D:getlastmodified>Wed, 15 Jan 2025 10:30:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`

		info, err := fs.parseStatResponse(strings.NewReader(xmlResponse), "/test/file.txt")
		require.NoError(t, err)

		assert.Equal(t, "file.txt", info.Name())
		assert.Equal(t, int64(1234), info.Size())
		assert.False(t, info.IsDir())
	})

	t.Run("parse directory response", func(t *testing.T) {
		xmlResponse := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/test/subdir/</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype><D:collection/></D:resourcetype>
        <D:getlastmodified>Wed, 15 Jan 2025 10:30:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`

		info, err := fs.parseStatResponse(strings.NewReader(xmlResponse), "/test/subdir")
		require.NoError(t, err)

		assert.Equal(t, "subdir", info.Name())
		assert.True(t, info.IsDir())
	})
}

// TestIntegrationWithMockHelper tests the full flow with a mock helper server
func TestIntegrationWithMockHelper(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a mock helper server that serves WebDAV responses
	mockHelper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PROPFIND":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>` + r.URL.Path + `</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype></D:resourcetype>
        <D:getcontentlength>100</D:getcontentlength>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`))
		case "GET":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("test file content"))
		case "PUT":
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusCreated)
		case "MKCOL":
			w.WriteHeader(http.StatusCreated)
		case "DELETE":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer mockHelper.Close()

	// Create a custom transport that redirects to the mock helper
	broker := NewHelperBroker(ctx, "test-cookie-integration")

	// Create a custom HTTP client that uses the mock helper directly
	// This simulates what would happen after connection reversal
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Redirect all connections to the mock helper
				return net.Dial("tcp", mockHelper.Listener.Addr().String())
			},
		},
		Timeout: 5 * time.Second,
	}

	t.Run("stat file via client", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", "http://helper/test/file.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Depth", "0")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)

		// Parse the response
		fs := NewSSHFileSystem(broker, "/test", "/data")
		info, err := fs.parseStatResponse(resp.Body, "/test/file.txt")
		require.NoError(t, err)
		assert.Equal(t, "file.txt", info.Name())
	})

	t.Run("get file via client", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "GET", "http://helper/test/file.txt", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "test file content", string(body))
	})

	t.Run("put file via client", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "PUT", "http://helper/test/newfile.txt",
			strings.NewReader("new content"))
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("mkdir via client", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "MKCOL", "http://helper/test/newdir", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)
	})

	t.Run("delete via client", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, "DELETE", "http://helper/test/file.txt", nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})
}

// TestHelperCmdPollRetrieve tests the helper's poll/retrieve behavior
func TestHelperCmdPollRetrieve(t *testing.T) {
	// Create a mock origin server that simulates the retrieve endpoint
	requestReceived := make(chan struct{}, 1)
	mockOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1.0/origin/ssh/retrieve" {
			// Verify auth via Authorization: Bearer header
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			token := strings.TrimPrefix(authHeader, "Bearer ")

			if token != "test-cookie" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			select {
			case requestReceived <- struct{}{}:
			default:
			}

			// Simulate no pending requests (timeout)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"timeout"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockOrigin.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test the pollRetrieve function behavior
	client := &http.Client{Timeout: 1 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mockOrigin.URL+"/api/v1.0/origin/ssh/retrieve", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer test-cookie")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should receive the request
	select {
	case <-requestReceived:
		// Good
	case <-time.After(500 * time.Millisecond):
		t.Fatal("request was not received")
	}

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var pollResp helperRetrieveResponse
	err = json.NewDecoder(resp.Body).Decode(&pollResp)
	require.NoError(t, err)
	assert.Equal(t, "timeout", pollResp.Status)
}

// TestCallbackConnectionReversal tests the callback connection reversal mechanism
func TestCallbackConnectionReversal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create origin server with helper broker
	broker := NewHelperBroker(ctx, "test-cookie-reversal")
	SetHelperBroker(broker)
	defer SetHelperBroker(nil)

	// Test that multiple pre-populated connections can be consumed
	t.Run("multiple pool connections consumed in order", func(t *testing.T) {
		numConns := 3
		pipes := make([]struct{ client, server net.Conn }, numConns)

		// Pre-populate the pool with multiple connections
		for i := range pipes {
			client, server := net.Pipe()
			pipes[i].client = client
			pipes[i].server = server
			defer client.Close()
			defer server.Close()

			select {
			case broker.connectionPool <- pipes[i].server:
			default:
				t.Fatalf("failed to add connection %d to pool", i)
			}
		}

		// Request connections - should get them from the pool
		for i := 0; i < numConns; i++ {
			conn, err := broker.RequestConnection(ctx)
			require.NoError(t, err)
			assert.Equal(t, pipes[i].server, conn)
		}
	})
}

// TestHelperCapabilityEnforcement tests that capability restrictions are enforced at the helper layer
func TestHelperCapabilityEnforcement(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a helper process with specific capabilities
	helper := &HelperProcess{
		config: &HelperConfig{
			AuthCookie: "test-cookie-123",
			Exports: []ExportConfig{
				{
					FederationPrefix: "/test",
					StoragePrefix:    tmpDir,
					Capabilities: ExportCapabilities{
						PublicReads: true,
						Reads:       true,
						Writes:      false, // Writes disabled!
						Listings:    false, // Listings disabled!
					},
				},
			},
		},
	}

	// Create a mock handler that records if it was called
	handlerCalled := false
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := helper.wrapWithAuth(mockHandler)

	t.Run("PUT blocked when writes disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPut, "/test/file.txt", strings.NewReader("content"))
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "writes not permitted")
		assert.False(t, handlerCalled, "Handler should not be called when writes disabled")
	})

	t.Run("DELETE blocked when writes disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodDelete, "/test/file.txt", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "writes not permitted")
		assert.False(t, handlerCalled)
	})

	t.Run("MKCOL blocked when writes disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("MKCOL", "/test/newdir", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "writes not permitted")
		assert.False(t, handlerCalled)
	})

	t.Run("MOVE blocked when writes disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("MOVE", "/test/file.txt", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "writes not permitted")
		assert.False(t, handlerCalled)
	})

	t.Run("PROPFIND Depth:1 blocked when listings disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("PROPFIND", "/test/", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		req.Header.Set("Depth", "1")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "listings not permitted")
		assert.False(t, handlerCalled)
	})

	t.Run("PROPFIND Depth:infinity blocked when listings disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("PROPFIND", "/test/", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		req.Header.Set("Depth", "infinity")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Body.String(), "listings not permitted")
		assert.False(t, handlerCalled)
	})

	t.Run("PROPFIND Depth:0 allowed when listings disabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("PROPFIND", "/test/file.txt", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		req.Header.Set("Depth", "0")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerCalled, "Handler should be called for PROPFIND Depth:0")
	})

	t.Run("GET allowed (public reads)", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodGet, "/test/file.txt", nil)
		// No auth header - testing public reads
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerCalled, "Handler should be called for public GET")
	})

	t.Run("GET allowed with auth", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodGet, "/test/file.txt", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-123")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerCalled, "Handler should be called for authenticated GET")
	})
}

// TestHelperCapabilityEnforcementWithWritesEnabled tests writes work when enabled
func TestHelperCapabilityEnforcementWithWritesEnabled(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a helper process WITH writes enabled
	helper := &HelperProcess{
		config: &HelperConfig{
			AuthCookie: "test-cookie-456",
			Exports: []ExportConfig{
				{
					FederationPrefix: "/test",
					StoragePrefix:    tmpDir,
					Capabilities: ExportCapabilities{
						PublicReads: true,
						Reads:       true,
						Writes:      true, // Writes enabled!
						Listings:    true, // Listings enabled!
					},
				},
			},
		},
	}

	handlerCalled := false
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := helper.wrapWithAuth(mockHandler)

	t.Run("PUT allowed when writes enabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest(http.MethodPut, "/test/file.txt", strings.NewReader("content"))
		req.Header.Set("Authorization", "Bearer test-cookie-456")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerCalled, "Handler should be called when writes enabled")
	})

	t.Run("PROPFIND Depth:1 allowed when listings enabled", func(t *testing.T) {
		handlerCalled = false
		req := httptest.NewRequest("PROPFIND", "/test/", nil)
		req.Header.Set("Authorization", "Bearer test-cookie-456")
		req.Header.Set("Depth", "1")
		rec := httptest.NewRecorder()

		wrappedHandler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, handlerCalled, "Handler should be called when listings enabled")
	})
}
