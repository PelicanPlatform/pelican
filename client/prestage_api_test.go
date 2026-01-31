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
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/pelican_url"
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

// Test prestage with API fallback to traditional method
func TestPrestageWithAPIFallback(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	// Create a mock server that:
	// 1. Supports the prestage API (returns 400 for no-path query)
	// 2. But fails to actually prestage (simulates API error)
	// 3. Still serves the file via normal HTTP GET (fallback)
	testContent := "test file content for fallback"
	apiCallCount := 0
	fallbackCallCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/pelican/api/v1.0/prestage" {
			if r.URL.Query().Get("path") == "" {
				// Indicate API is supported
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Missing path parameter"))
				return
			}
			// Simulate API failure
			apiCallCount++
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "failure: 500(Internal Server Error): Simulated API failure")
			return
		}

		// Fallback to normal GET
		if r.Method == "GET" || r.Method == "HEAD" {
			fallbackCallCount++
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
	serverURL.Path = "/test/file.txt" // Set the path for the file to prestage

	ctx := context.Background()

	// Create a transfer engine (needed for prestage API support caching)
	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)
	defer func() { _ = te.Shutdown() }()

	// Create a prestage transfer that will use the API and fall back
	transfer := &transferFile{
		xferType: transferTypePrestage,
		ctx:      ctx,
		engine:   te,
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test/file.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: serverURL,
		attempts: []transferAttemptDetails{
			{Url: serverURL},
		},
	}

	// Call downloadObject which should:
	// 1. Detect prestage API support
	// 2. Try the API (which will fail; we use the test server above)
	// 3. Fall back to traditional method (GET to /dev/null)
	transferResult, err := downloadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, transferResult.Error)

	// Verify the API was called
	assert.Equal(t, 1, apiCallCount, "Prestage API should have been called once")

	// Verify fallback to traditional method occurred (HEAD + GET)
	assert.GreaterOrEqual(t, fallbackCallCount, 1, "Fallback HTTP requests should have occurred")

	// Verify we got transfer results with multiple attempts
	assert.GreaterOrEqual(t, len(transferResult.Attempts), 2, "Should have at least 2 attempts (prestage API + fallback)")

	// First attempt should be the failed API call
	assert.NotNil(t, transferResult.Attempts[0].Error, "First attempt (prestage API) should have an error")

	// Last attempt should be successful
	lastAttempt := transferResult.Attempts[len(transferResult.Attempts)-1]
	assert.Nil(t, lastAttempt.Error, "Last attempt (fallback) should succeed")
}
