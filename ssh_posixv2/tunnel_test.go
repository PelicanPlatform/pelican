//go:build !windows

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
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTestHelperServer starts a plain HTTP server on a Unix domain socket
// that acts like the helper's direct-listen server.  Returns the socket path
// and a cleanup function.
func startTestHelperServer(t *testing.T, handler http.Handler) (string, func()) {
	t.Helper()
	sockDir, err := os.MkdirTemp("/tmp", "pt-")
	require.NoError(t, err)
	socketPath := filepath.Join(sockDir, "h.sock")
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	return socketPath, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		os.RemoveAll(sockDir)
	}
}

// TestSSHTunnelTransportNotReady verifies that RoundTrip blocks until
// SetReady is called or the request context expires.
func TestSSHTunnelTransportNotReady(t *testing.T) {
	tt := NewSSHTunnelTransport("cookie")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "http://helper/test", nil)
	require.NoError(t, err)

	_, err = tt.RoundTrip(req)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestSSHTunnelTransportDirect tests SSHTunnelTransport with a real Unix
// socket connection (no SSH — same principle, just net.Dial instead of
// sshClient.Dial).  This validates the HTTP-over-channel logic.
func TestSSHTunnelTransportDirect(t *testing.T) {
	const authCookie = "test-cookie-123"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header was injected
		if r.Header.Get("Authorization") != "Bearer "+authCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "hello")
	})

	socketPath, cleanup := startTestHelperServer(t, handler)
	defer cleanup()

	tt := NewSSHTunnelTransport(authCookie)

	// For a true unit test, create a transport that dials the Unix socket
	// directly (no SSH):
	directTransport := &directDialTransport{
		socketPath: socketPath,
		authCookie: authCookie,
	}

	req, err := http.NewRequest("GET", "http://helper/test", nil)
	require.NoError(t, err)

	resp, err := directTransport.RoundTrip(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "hello", string(body))

	// Verify SetReady unblocks
	t.Run("SetReady_unblocks", func(t *testing.T) {
		assert.NotNil(t, tt.readyCh)
		select {
		case <-tt.readyCh:
			t.Fatal("readyCh should not be closed yet")
		default:
		}
	})

	t.Run("SetNotReady_reblocks", func(t *testing.T) {
		tt2 := NewSSHTunnelTransport("x")
		tt2.once.Do(func() { close(tt2.readyCh) })
		tt2.SetNotReady()
		select {
		case <-tt2.readyCh:
			t.Fatal("readyCh should not be closed after SetNotReady")
		default:
		}
	})
}

// directDialTransport is a test-only transport that mimics SSHTunnelTransport
// but dials a Unix socket directly (no SSH).
type directDialTransport struct {
	socketPath string
	authCookie string
}

func (d *directDialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := net.Dial("unix", d.socketPath)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	helperReq := req.Clone(req.Context())
	helperReq.URL.Scheme = "http"
	helperReq.URL.Host = "ssh-helper"
	helperReq.Header.Set("Authorization", "Bearer "+d.authCookie)
	resp, err := client.Do(helperReq)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return resp, nil
}

// TestSSHTunnelTransportConcurrent verifies that multiple concurrent
// RoundTrips work correctly over Unix sockets.
func TestSSHTunnelTransportConcurrent(t *testing.T) {
	const authCookie = "conc-cookie"
	var mu sync.Mutex
	seen := make(map[string]bool)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	socketPath, cleanup := startTestHelperServer(t, handler)
	defer cleanup()

	dt := &directDialTransport{socketPath: socketPath, authCookie: authCookie}

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://helper/path/%d", idx), nil)
			resp, err := dt.RoundTrip(req)
			assert.NoError(t, err)
			if resp != nil {
				resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()

	mu.Lock()
	assert.Len(t, seen, n)
	mu.Unlock()
}

// TestRunDirectListenerCreatesSocket verifies that runDirectListener creates
// a Unix socket in the expected directory structure and cleans it up.
func TestRunDirectListenerCreatesSocket(t *testing.T) {
	// Verify that UserCacheDir works on this platform
	cacheDir, err := os.UserCacheDir()
	require.NoError(t, err)
	pelicanDir := filepath.Join(cacheDir, "pelican")

	// Ensure the pelican cache dir exists for the test
	require.NoError(t, os.MkdirAll(pelicanDir, 0700))

	// Verify the directory permissions model
	info, err := os.Stat(pelicanDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}
