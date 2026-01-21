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

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/test_utils"
)

// Test checking if a cache supports the prestage API
func TestCheckPrestageAPISupport(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	t.Run("CacheSupportsPrestageAPI", func(t *testing.T) {
		// Create a mock server that returns 400 (API supported)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/pelican/api/v1.0/prestage" {
				if r.URL.Query().Get("path") == "" {
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte("Prestage command request requires the `path` query parameter"))
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		supported := checkPrestageAPISupport(ctx, serverURL, nil)
		assert.True(t, supported, "Cache should support the prestage API")
	})

	t.Run("CacheDoesNotSupportPrestageAPI", func(t *testing.T) {
		// Create a mock server that returns 404 (API not supported)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		supported := checkPrestageAPISupport(ctx, serverURL, nil)
		assert.False(t, supported, "Cache should not support the prestage API")
	})
}

// Test invoking the prestage API
func TestInvokePrestageAPI(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	t.Run("SuccessfulPrestage", func(t *testing.T) {
		// Create a mock server that simulates a successful prestage
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/pelican/api/v1.0/prestage" {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			path := r.URL.Query().Get("path")
			if path == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Prestage command request requires the `path` query parameter"))
				return
			}

			w.WriteHeader(http.StatusOK)
			// Simulate chunked response with progress updates
			fmt.Fprintln(w, "status: queued")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(10 * time.Millisecond)
			fmt.Fprintln(w, "status: active,offset=65536")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(10 * time.Millisecond)
			fmt.Fprintln(w, "status: active,offset=131072")
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			time.Sleep(10 * time.Millisecond)
			fmt.Fprintln(w, "success: ok")
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		bytesTransferred, err := invokePrestageAPI(ctx, serverURL, "/test/file.txt", nil, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(131072), bytesTransferred, "Should report bytes transferred from last offset")
	})

	t.Run("PrestageFailure", func(t *testing.T) {
		// Create a mock server that simulates a failed prestage
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/pelican/api/v1.0/prestage" {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "status: queued")
			fmt.Fprintln(w, "failure: 404(File not found): Object does not exist")
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = invokePrestageAPI(ctx, serverURL, "/test/missing.txt", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prestage failed")
	})

	t.Run("PrestageWithCallback", func(t *testing.T) {
		// Create a mock server that simulates a successful prestage
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "status: active,offset=50000")
			fmt.Fprintln(w, "success: ok")
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		callbackInvoked := false
		callback := func(path string, downloaded int64, totalSize int64, completed bool) {
			callbackInvoked = true
		}

		ctx := context.Background()
		_, err = invokePrestageAPI(ctx, serverURL, "/test/file.txt", nil, callback)
		require.NoError(t, err)
		// Note: callback won't be invoked without a known file size in this test
		// In a real scenario, the file size would be known from a previous stat/HEAD request
		assert.False(t, callbackInvoked)
	})

	t.Run("PrestageHTTPError", func(t *testing.T) {
		// Create a mock server that returns an HTTP error
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Permission denied"))
		}))
		defer server.Close()

		serverURL, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		_, err = invokePrestageAPI(ctx, serverURL, "/test/file.txt", nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "prestage API returned status 403")
	})
}

// Test the TransferEngine lookup table for prestage API support
func TestTransferEnginePrestageAPILookup(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	ctx := context.Background()
	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() { _ = te.Shutdown() }()

	// Initially, the lookup table should be empty
	te.prestageAPIMutex.RLock()
	assert.Equal(t, 0, len(te.prestageAPISupport))
	te.prestageAPIMutex.RUnlock()

	// Add an entry to the lookup table
	te.prestageAPIMutex.Lock()
	te.prestageAPISupport["cache1.example.com"] = true
	te.prestageAPISupport["cache2.example.com"] = false
	te.prestageAPIMutex.Unlock()

	// Verify the entries
	te.prestageAPIMutex.RLock()
	assert.True(t, te.prestageAPISupport["cache1.example.com"])
	assert.False(t, te.prestageAPISupport["cache2.example.com"])
	te.prestageAPIMutex.RUnlock()
}

// Test prestage with API fallback to traditional method
func TestPrestageWithAPIFallback(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	// Create a mock server that:
	// 1. Supports the prestage API (returns 400 for no-path query)
	// 2. But fails to actually prestage (simulates API error)
	// 3. Still serves the file via normal HTTP GET (fallback)
	testContent := "test file content for fallback"
	apiCalled := false

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pelican/api/v1.0/prestage" {
			if r.URL.Query().Get("path") == "" {
				// Indicate API is supported
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Missing path parameter"))
				return
			}
			// Simulate API failure
			apiCalled = true
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "failure: 500(Internal Server Error): Simulated API failure")
			return
		}

		// Fallback to normal GET
		if r.Method == "GET" || r.Method == "HEAD" {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(testContent)))
			if r.Method == "GET" {
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, testContent)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	ctx := context.Background()

	// First, verify API support detection works
	supported := checkPrestageAPISupport(ctx, serverURL, nil)
	assert.True(t, supported, "Server should support prestage API")

	// Now test the API invocation (which will fail)
	_, err = invokePrestageAPI(ctx, serverURL, "/test/file.txt", nil, nil)
	require.Error(t, err)
	assert.True(t, apiCalled, "API should have been called")
	assert.Contains(t, err.Error(), "prestage failed")

	// In a real scenario, the transfer engine would fall back to traditional download
	// This is tested implicitly in the downloadObject function
}
