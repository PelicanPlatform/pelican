//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestMain(m *testing.M) {
	cleanup := test_utils.SetupGlobalTestLogging()

	server_utils.ResetTestState()
	if err := config.InitClient(); err != nil {
		cleanup()
		os.Exit(1)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// TestNewTransferDetails checks the creation of transfer details
func TestNewTransferDetails(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	t.Run("ServerWithHTTPAndPort", func(t *testing.T) {
		server := "http://cache.edu:8000"
		transfers := generateTransferDetails(server, transferDetailsOptions{false, ""})
		assert.Equal(t, 2, len(transfers))
		assert.Equal(t, "cache.edu:8000", transfers[0].Url.Host)
		assert.Equal(t, "http", transfers[0].Url.Scheme)
		assert.Equal(t, true, transfers[0].Proxy)
		assert.Equal(t, "cache.edu:8000", transfers[1].Url.Host)
		assert.Equal(t, "http", transfers[1].Url.Scheme)
		assert.Equal(t, false, transfers[1].Proxy)
	})

	t.Run("ServerWithHTTPSAndPort", func(t *testing.T) {
		server := "https://cache.edu:8443"
		transfers := generateTransferDetails(server, transferDetailsOptions{true, ""})
		assert.Equal(t, 1, len(transfers))
		assert.Equal(t, "cache.edu:8443", transfers[0].Url.Host)
		assert.Equal(t, "https", transfers[0].Url.Scheme)
		assert.Equal(t, false, transfers[0].Proxy)
	})

	t.Run("ServerWithHTTPAndNoPort", func(t *testing.T) {
		server := "http://cache.edu"
		// Case 3: cache without port with http
		transfers := generateTransferDetails(server, transferDetailsOptions{false, ""})
		assert.Equal(t, 2, len(transfers))
		assert.Equal(t, "cache.edu", transfers[0].Url.Host)
		assert.Equal(t, "http", transfers[0].Url.Scheme)
		assert.Equal(t, true, transfers[0].Proxy)
		assert.Equal(t, "cache.edu", transfers[1].Url.Host)
		assert.Equal(t, "http", transfers[1].Url.Scheme)
		assert.Equal(t, false, transfers[1].Proxy)
	})

	t.Run("ServerWithHTTPSAndNoPort", func(t *testing.T) {
		// Case 4. cache without port with https
		server := "https://cache.edu"
		transfers := generateTransferDetails(server, transferDetailsOptions{true, ""})
		assert.Equal(t, 1, len(transfers))
		assert.Equal(t, "cache.edu", transfers[0].Url.Host)
		assert.Equal(t, "https", transfers[0].Url.Scheme)
		assert.Equal(t, false, transfers[0].Proxy)
	})
}

func TestNewTransferDetailsEnv(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	testCache := "http://cache.edu:8000"

	os.Setenv("OSG_DISABLE_PROXY_FALLBACK", "")
	test_utils.InitClient(t, map[string]any{})

	transfers := generateTransferDetails(testCache, transferDetailsOptions{})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, true, transfers[0].Proxy)

	os.Unsetenv("http_proxy")

	transfers = generateTransferDetails(testCache, transferDetailsOptions{true, ""})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	os.Unsetenv("OSG_DISABLE_PROXY_FALLBACK")
	server_utils.ResetTestState()
	err := config.InitClient()
	assert.Nil(t, err)
}

func TestSlowTransfers(t *testing.T) {
	t.Cleanup(func() {
		goleak.VerifyNone(t,
			// Ignore the progress bars
			goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.(*Progress).serve"),
			goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.heapManager.run"),
		)
	})
	t.Cleanup(test_utils.SetupTestLogging(t))

	ctx, _, _ := test_utils.TestContext(context.Background(), t)
	// Adjust down some timeouts to speed up the test
	test_utils.InitClient(t, map[string]any{
		"Client.SlowTransferWindow":     "2s",
		"Client.SlowTransferRampupTime": "1s",
	})

	channel := make(chan bool)
	slowDownload := 1024 * 10 // 10 KiB/s < 100 KiB/s
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Add("Content-Length", "1024000")
			w.WriteHeader(http.StatusOK)
			return
		}
		buffer := make([]byte, slowDownload)
		for {
			select {
			case <-channel:
				return
			default:
				_, err := w.Write(buffer)
				if err != nil {
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(1 * time.Second)
			}
		}
	}))

	defer svr.CloseClientConnections()
	defer svr.Close()

	testCache := svr.URL
	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	transfers := generateTransferDetails(testCache, transferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	finishedChannel := make(chan bool)
	var err error
	// Do a quick timeout
	go func() {
		fname := filepath.Join(t.TempDir(), "test.txt")
		var writer *os.File
		writer, err = os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		assert.NoError(t, err)
		defer writer.Close()
		_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
		finishedChannel <- true
	}()

	select {
	case <-finishedChannel:
		if err == nil {
			t.Fatal("Error is nil, download should have failed")
		}
	case <-time.After(time.Second * 160):
		// 120 seconds for warmup, 30 seconds for download
		t.Fatal("Maximum downloading time reach, download should have failed")
	}

	// Close the channel to allow the download to complete
	close(channel)

	// Make sure the errors are correct
	assert.NotNil(t, err)
	// Check we have an overlapping PelicanError type
	_, ok := err.(*error_codes.PelicanError)
	if ok {
		var slowTransferError *SlowTransferError
		assert.Contains(t, err.Error(), "Transfer.SlowTransfer Error: Error code 6002:")
		// Check we successfully wrapped an already defined SlowTransferError
		assert.True(t, errors.As(err, &slowTransferError))
	} else {
		t.Fatal("Error is not of type PelicanError")
	}
}

// Test stopped transfer
func TestStoppedTransfer(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Adjust down the timeouts
	test_utils.InitClient(t, map[string]any{
		"Client.StoppedTransferTimeout": "2s",
		"Client.SlowTransferRampupTime": "100s",
	})

	channel := make(chan bool)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Add("Content-Length", "102400")
			w.WriteHeader(http.StatusOK)
			return
		}
		buffer := make([]byte, 1024*100)
		for {
			select {
			case <-channel:
				return
			default:
				_, err := w.Write(buffer)
				if err != nil {
					return
				}
				w.(http.Flusher).Flush()
				time.Sleep(1 * time.Second)
				buffer = make([]byte, 0)
			}
		}
	}))

	defer svr.CloseClientConnections()
	defer svr.Close()

	testCache := svr.URL
	transfers := generateTransferDetails(testCache, transferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	finishedChannel := make(chan bool)
	var err error

	go func() {
		fname := filepath.Join(t.TempDir(), "test.txt")
		var writer *os.File
		writer, err = os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		assert.NoError(t, err)
		defer writer.Close()

		_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
		finishedChannel <- true
	}()

	select {
	case <-finishedChannel:
		if err == nil {
			t.Fatal("Download should have failed")
		}
	case <-time.After(time.Second * 150):
		t.Fatal("Download should have failed")
	}

	// Close the channel to allow the download to complete
	close(channel)

	// Make sure the errors are correct
	assert.NotNil(t, err)
	// Check that it's wrapped in a PelicanError and contains StoppedTransferError
	assert.True(t, errors.Is(err, &StoppedTransferError{}), "Error should contain StoppedTransferError")

	// Check that it's wrapped in a PelicanError with the correct code
	var pe *error_codes.PelicanError
	require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError")
	assert.Equal(t, 6001, pe.Code(), "Should be Transfer.StoppedTransfer error code")
	assert.Equal(t, "Transfer.StoppedTransfer", pe.ErrorType(), "Should be Transfer.StoppedTransfer error type")
	assert.True(t, pe.IsRetryable(), "StoppedTransfer should be retryable")

	assert.True(t, IsRetryable(err))
}

// Test connection error
func TestConnectionError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dialClosedPort: Listen failed: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Host: addr, Scheme: "http"}, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)

	// downloadHTTP returns unwrapped ConnectionSetupError; wrapping happens in the download loop
	var cse *ConnectionSetupError
	require.True(t, errors.As(err, &cse), "Error should be a ConnectionSetupError")

	// Verify that when wrapped, it has the correct properties (simulating download loop behavior)
	wrappedErr := error_codes.NewContact_ConnectionSetupError(cse)
	var pe *error_codes.PelicanError
	require.True(t, errors.As(wrappedErr, &pe), "Wrapped error should be a PelicanError")
	// Use the generated error code instead of hardcoding to make the test robust to code changes
	expectedErr := error_codes.NewContact_ConnectionSetupError(errors.New("test"))
	assert.Equal(t, expectedErr.Code(), pe.Code(), "Should map to Contact.ConnectionSetup error code")
	assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Should map to Contact.ConnectionSetup error type")
	assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "Connection setup failures should be retryable")
}

func TestAllocateMemoryError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Create a custom transport that returns ENOMEM to simulate the actual error condition
	// In production, this happens at handle_http.go:2780-2784 when client.Do returns ENOMEM
	enomemTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, syscall.Errno(syscall.ENOMEM)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: enomemTransport,
		Timeout:   time.Second,
	}

	// Create a request that will trigger the ENOMEM error
	req, err := http.NewRequestWithContext(ctx, "GET", "http://example.com/test", nil)
	require.NoError(t, err)

	// Call client.Do which should return ENOMEM
	_, err = client.Do(req)
	require.Error(t, err, "Should have an error from ENOMEM")

	// Verify that the error contains ENOMEM
	var sysErr syscall.Errno
	require.True(t, errors.As(err, &sysErr), "Error should be a syscall.Errno")
	assert.Equal(t, syscall.ENOMEM, sysErr, "Error should be ENOMEM")

}

func TestNetworkResetError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Set up an HTTP server that hijacks the connection and resets it during transfer
	// This simulates ECONNRESET/EPIPE during transfer
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection so we can control when to reset it
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Send HTTP response headers
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n")
		_, _ = bufrw.WriteString("Content-Length: 1000\r\n")
		_, _ = bufrw.WriteString("\r\n")
		_ = bufrw.Flush()

		// Send some data to ensure client starts reading
		_, _ = conn.Write([]byte("some data"))
		_ = conn.(*net.TCPConn).SetWriteDeadline(time.Now().Add(100 * time.Millisecond))

		// Give the client time to start reading the response body
		time.Sleep(100 * time.Millisecond)

		// Force TCP RST by setting SO_LINGER to 0
		// This causes the connection to send RST instead of FIN when closed
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0) // Set linger to 0 to send RST on close
			rawConn, err := tcpConn.SyscallConn()
			if err == nil {
				_ = rawConn.Control(func(fd uintptr) {
					// Also set SO_LINGER via syscall to ensure RST
					var linger syscall.Linger
					linger.Onoff = 1
					linger.Linger = 0
					_ = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
				})
			}
		}
		// Close connection with RST (due to SO_LINGER) while client is reading
		conn.Close()
	}))
	defer svr.Close()

	serverAddr := strings.TrimPrefix(svr.URL, "http://")

	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()

	// Call downloadHTTP which should trigger NetworkResetError when connection is reset
	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Scheme: "http", Host: serverAddr}, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)

	// The error should be wrapped as Contact.ConnectionReset in the download loop
	// We need to check the TransferAttemptError to see the wrapped error
	// But downloadHTTP returns the raw error, so we need to simulate the wrapping
	require.Error(t, err, "Should have an error from connection reset")

	// Check if it's a syscall error that would trigger NetworkResetError
	// The download loop checks for ECONNRESET/EPIPE at using errors.Is
	// errors.Is should work even if the error is wrapped (through ConnectionSetupError -> OpError -> ECONNRESET)
	require.True(t, errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE),
		"Error should be ECONNRESET or EPIPE (possibly wrapped), got: %T, error: %v", err, err)
}

func TestProxyConnectionError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Create a custom transport that simulates a proxy connection failure
	// In production, this happens when http.Client.Do() tries to connect to a proxy
	// and the connection fails (e.g., proxy is unreachable)
	proxyAddr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:3128")
	require.NoError(t, err)

	proxyConnectionErr := &net.OpError{
		Op:   "proxyconnect",
		Net:  "tcp",
		Addr: proxyAddr,
		Err:  errors.New("connection refused"),
	}

	// Create a custom transport that returns the proxy connection error
	customTransport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			// Return a proxy URL to force proxy usage
			return url.Parse("http://127.0.0.1:3128")
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// When the client tries to dial the proxy, return the proxy connection error
			if addr == "127.0.0.1:3128" {
				return nil, proxyConnectionErr
			}
			// For other addresses, use default dialer
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}

	// Create an HTTP client with the custom transport
	client := &http.Client{
		Transport: customTransport,
		Timeout:   time.Second,
	}

	// Create a request that will trigger the proxy connection
	req, err := http.NewRequestWithContext(ctx, "GET", "http://example.com/test", nil)
	require.NoError(t, err)

	// Call client.Do which should return the proxy connection error
	_, err = client.Do(req)
	require.Error(t, err, "Should have an error from proxy connection failure")

	// Verify that the error is a *net.OpError with Op == "proxyconnect"
	// The error might be wrapped in url.Error
	var ope *net.OpError
	var ue *url.Error
	if errors.As(err, &ue) {
		innerErr := ue.Unwrap()
		if innerOpe, ok := innerErr.(*net.OpError); ok {
			ope = innerOpe
		}
	}

	if ope == nil {
		require.True(t, errors.As(err, &ope), "Error should be a *net.OpError, got: %T, error: %v", err, err)
	}
	assert.Equal(t, "proxyconnect", ope.Op, "Error should be a proxyconnect operation")

	// Verify that when wrapped (as it would be in the download loop), it has the correct properties
	proxyErr := &ConnectionSetupError{URL: "http://example.com/test", Err: err}
	wrappedErr := error_codes.NewContact_ConnectionSetupError(proxyErr)
	var pe *error_codes.PelicanError
	require.True(t, errors.As(wrappedErr, &pe), "Wrapped error should be a PelicanError")
	// Use the generated error code instead of hardcoding to make the test robust to code changes
	expectedErr := error_codes.NewContact_ConnectionSetupError(errors.New("test"))
	assert.Equal(t, expectedErr.Code(), pe.Code(), "Should map to Contact.ConnectionSetup error code")
	assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Should map to Contact.ConnectionSetup error type")
	assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "Proxy connection failures should be retryable")
}

func TestTrailerError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Set up an HTTP server that returns an error trailer
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Transfer-Status")
		w.Header().Set("X-Transfer-Status", "500: Unable to read test.txt; input/output error")

		chunkedWriter := httputil.NewChunkedWriter(w)
		defer chunkedWriter.Close()

		_, err := chunkedWriter.Write([]byte("Test data"))
		if err != nil {
			t.Fatalf("Error writing to chunked writer: %v", err)
		}
	}))

	defer svr.Close()

	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	testCache := svr.URL
	transfers := generateTransferDetails(testCache, transferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	// Call DownloadHTTP and check if the error is returned correctly
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)

	assert.NotNil(t, err)
	// Check that it's wrapped in a PelicanError
	var pe *error_codes.PelicanError
	require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError")
	assert.Equal(t, 6000, pe.Code(), "Should be Transfer error code")
	assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error type")
	// Check the underlying error message
	assert.Contains(t, pe.Unwrap().Error(), "download error after server response started: Unable to read test.txt; input/output error")
}

func TestUploadZeroLengthFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//t.Logf("%s", dump)
		assert.Equal(t, "PUT", r.Method, "Not PUT Method")
		assert.Equal(t, int64(0), r.ContentLength, "ContentLength should be 0")
	}))
	defer ts.Close()
	reader := bytes.NewReader([]byte{})
	request, err := http.NewRequest("PUT", ts.URL, reader)
	if err != nil {
		assert.NoError(t, err)
	}

	request.Header.Set("Authorization", "Bearer test")
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	go runPut(request, responseChan, errorChan, false)
	select {
	case err := <-errorChan:
		assert.NoError(t, err)
	case response := <-responseChan:
		assert.Equal(t, http.StatusOK, response.StatusCode)
	case <-time.After(time.Second * 2):
		assert.Fail(t, "Timeout while waiting for response")
	}
}

func TestFailedUpload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//t.Logf("%s", dump)
		assert.Equal(t, "PUT", r.Method, "Not PUT Method")
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("Error"))
		assert.NoError(t, err)

	}))
	defer ts.Close()
	reader := strings.NewReader("test")
	request, err := http.NewRequest("PUT", ts.URL, reader)
	if err != nil {
		assert.NoError(t, err)
	}
	request.Header.Set("Authorization", "Bearer test")
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response)
	go runPut(request, responseChan, errorChan, false)
	select {
	case err := <-errorChan:
		assert.Error(t, err)
	case response := <-responseChan:
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	case <-time.After(time.Second * 2):
		assert.Fail(t, "Timeout while waiting for response")
	}
}

func TestUploadLocalFileNotFound(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for PROPFIND (stat) requests so upload doesn't think file exists
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		ctx:       context.Background(),
		localPath: "/nonexistent/path/to/file.txt",
		remoteURL: tsURL,
		xferType:  transferTypeUpload,
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   tsURL.Host,
				Path:   "/test/file.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					CollectionsUrl: tsURL, // Point to our mock server
				},
			},
		},
		callback: nil,
		attempts: []transferAttemptDetails{
			{
				Url:   tsURL,
				Proxy: false,
			},
		},
	}

	transferResult, err := uploadObject(transfer)
	require.Error(t, err)                  // uploadObject returns error when local stat fails
	require.Error(t, transferResult.Error) // And the result also contains the error

	// Verify it's wrapped in Parameter.FileNotFound PelicanError
	var pe *error_codes.PelicanError
	require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError")
	assert.Equal(t, 1011, pe.Code(), "Should be Parameter.FileNotFound error code")
	assert.Equal(t, "Parameter.FileNotFound", pe.ErrorType(), "Should be Parameter.FileNotFound error type")
	assert.False(t, pe.IsRetryable(), "Local file not found should not be retryable")

	// Verify the error message
	assert.Contains(t, err.Error(), "stat /nonexistent/path/to/file.txt: no such file or directory")
}

func TestSortAttempts(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)

	neverRespond := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	})
	alwaysRespond := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Header().Set("Content-Length", "1")
			w.Header().Set("Content-Range", "bytes 0-0/42")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("A"))
			require.NoError(t, err)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	svr1 := httptest.NewServer(neverRespond)
	defer svr1.Close()
	url1, err := url.Parse(svr1.URL)
	require.NoError(t, err)
	attempt1 := transferAttemptDetails{Url: url1}

	svr2 := httptest.NewServer(alwaysRespond)
	defer svr2.Close()
	url2, err := url.Parse(svr2.URL)
	require.NoError(t, err)
	attempt2 := transferAttemptDetails{Url: url2}

	svr3 := httptest.NewServer(alwaysRespond)
	defer svr3.Close()
	url3, err := url.Parse(svr3.URL)
	require.NoError(t, err)
	attempt3 := transferAttemptDetails{Url: url3}

	defer cancel()

	token := newTokenGenerator(nil, nil, config.TokenSharedRead, false)
	token.SetToken("aaa")
	size, results := sortAttempts(ctx, "/path", []transferAttemptDetails{attempt1, attempt2, attempt3}, token)
	assert.Equal(t, int64(42), size)
	assert.Equal(t, svr2.URL, results[0].Url.String())
	assert.Equal(t, svr3.URL, results[1].Url.String())
	assert.Equal(t, svr1.URL, results[2].Url.String())

	size, results = sortAttempts(ctx, "/path", []transferAttemptDetails{attempt2, attempt3, attempt1}, token)
	assert.Equal(t, int64(42), size)
	assert.Equal(t, svr2.URL, results[0].Url.String())
	assert.Equal(t, svr3.URL, results[1].Url.String())
	assert.Equal(t, svr1.URL, results[2].Url.String())

	size, results = sortAttempts(ctx, "/path", []transferAttemptDetails{attempt1, attempt1}, token)
	assert.Equal(t, int64(-1), size)
	assert.Equal(t, svr1.URL, results[0].Url.String())
	assert.Equal(t, svr1.URL, results[1].Url.String())

	size, results = sortAttempts(ctx, "/path", []transferAttemptDetails{attempt2, attempt3}, token)
	assert.Equal(t, int64(42), size)
	assert.Equal(t, svr2.URL, results[0].Url.String())
	assert.Equal(t, svr3.URL, results[1].Url.String())
}

func TestTimeoutHeaderSetForDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Transport.ResponseHeaderTimeout": 10 * time.Second,
	})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// We have this flag because our server will get a few requests throughout its lifetime and the other
	// requests do not contain the X-Pelican-Timeout header
	timeoutHeaderFound := false

	// Create a mock server to download from
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the "X-Pelican-Timeout" header is set
		if !timeoutHeaderFound {
			if r.Header.Get("X-Pelican-Timeout") == "" {
				t.Error("X-Pelican-Timeout header is not set")
			}
			assert.Equal(t, "9.5s", r.Header.Get("X-Pelican-Timeout"))
			timeoutHeaderFound = true
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	assert.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()
	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)
	assert.NoError(t, err)
	server_utils.ResetTestState()
}

func TestJobIdHeaderSetForDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})

	// Create a test .job.ad file
	jobAdFile, err := os.CreateTemp("", ".job.ad")
	assert.NoError(t, err)

	// Write the job ad to the file
	_, err = jobAdFile.WriteString("GlobalJobId = \"12345\"")
	assert.NoError(t, err)
	jobAdFile.Close()

	os.Setenv("_CONDOR_JOB_AD", jobAdFile.Name())
	jobAdOnce = sync.Once{}

	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// We have this flag because our server will get a few requests throughout its lifetime and the other
	// requests do not contain the X-Pelican-Timeout header
	timeoutHeaderFound := false

	// Create a mock server to download from
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the "X-Pelican-Timeout" header is set
		if !timeoutHeaderFound {
			if r.Header.Get("X-Pelican-JobId") == "" {
				t.Error("X-Pelican-JobId header is not set")
			}
			assert.Equal(t, "12345", r.Header.Get("X-Pelican-JobId"))
			timeoutHeaderFound = true
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	assert.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()
	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)
	assert.NoError(t, err)
	server_utils.ResetTestState()
	os.Unsetenv("_CONDOR_JOB_AD")
}

// Server test object for testing user agent
type (
	server_test struct {
		server     *httptest.Server
		user_agent *string
	}
)

// Test to ensure the user-agent header is being updating in the request made within DownloadHTTP()
func TestProjInUserAgent(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	server_test := server_test{}
	// Create a mock server to download from
	server_test.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Note: we check for this HEAD request because within DownloadHTTP() we make a HEAD request to get the content length
		// This request is a different user-agent header (and different request) so we need to ignore it so server_test.user_agent is not overwritten
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		userAgent := r.UserAgent()
		server_test.user_agent = &userAgent
	}))
	defer server_test.server.Close()
	defer server_test.server.CloseClientConnections()

	serverURL, err := url.Parse(server_test.server.URL)
	assert.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()
	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "test", nil)
	assert.NoError(t, err)

	// Test the user-agent header is what we expect it to be
	assert.Equal(t, "pelican-client/"+config.GetVersion()+" project/test", *server_test.user_agent)
}

// The test should prove that the function getObjectServersToTry returns the correct number of servers,
// and that any duplicates are removed
func TestGetObjectServersToTry(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	sortedServers := []string{
		"http://cache-1.com", // set an HTTP scheme to check that it's switched to https
		"https://cache-2.com",
		"https://cache-2.com", // make sure duplicates are removed
		"https://cache-3.com",
		"https://cache-4.com",
		"https://cache-5.com",
	}

	t.Run("RequiredTokenTriggersHTTPS", func(t *testing.T) {
		directorResponse := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				RequireToken: true,
			},
		}
		job := &TransferJob{
			dirResp: directorResponse,
		}
		transfers := getObjectServersToTry(sortedServers, job, 3, "")

		// Check that there are no duplicates in the result
		cacheSet := make(map[string]bool)
		for _, transfer := range transfers {
			if cacheSet[transfer.Url.String()] {
				t.Errorf("Found duplicate cache: %v", transfer.Url.String())
			}
			cacheSet[transfer.Url.String()] = true
		}
		// Verify we got the correct caches in our transfer attempt details
		require.Len(t, transfers, 3)
		assert.Equal(t, "https://cache-1.com", transfers[0].Url.String())
		assert.Equal(t, "https://cache-2.com", transfers[1].Url.String())
		assert.Equal(t, "https://cache-3.com", transfers[2].Url.String())
	})

	t.Run("NoRequiredTokenPreservesHTTP", func(t *testing.T) {
		directorResponse := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				RequireToken: false,
			},
		}
		job := &TransferJob{
			dirResp: directorResponse,
		}
		transfers := getObjectServersToTry(sortedServers, job, 3, "")

		cacheSet := make(map[string]bool)
		for _, transfer := range transfers {
			if cacheSet[transfer.Url.String()] {
				t.Errorf("Found duplicate cache: %v", transfer.Url.String())
			}
			cacheSet[transfer.Url.String()] = true
		}

		require.Len(t, transfers, 3)
		assert.Equal(t, "http://cache-1.com", transfers[0].Url.String())
		assert.Equal(t, "https://cache-2.com", transfers[1].Url.String())
		assert.Equal(t, "https://cache-3.com", transfers[2].Url.String())
	})
}

// Test that the project name is correctly extracted from the job ad file
func TestSearchJobAd(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Create a temporary file
	tempFile, err := os.CreateTemp("", "test")
	assert.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Write a project name and job id to the file
	_, err = tempFile.WriteString("ProjectName = \"testProject\"\nGlobalJobId = \"12345\"")
	assert.NoError(t, err)
	tempFile.Close()
	t.Run("TestNoJobAd", func(t *testing.T) {
		// Unset this environment var
		os.Unsetenv("_CONDOR_JOB_AD")
		// Call GetProjectName and check the result
		jobAdOnce = sync.Once{}
		projectName, found := searchJobAd(attrProjectName)
		assert.False(t, found)
		assert.Equal(t, "", projectName)
	})

	t.Run("TestProjectNameAd", func(t *testing.T) {
		// Set the _CONDOR_JOB_AD environment variable to the temp file's name
		os.Setenv("_CONDOR_JOB_AD", tempFile.Name())
		defer os.Unsetenv("_CONDOR_JOB_AD")

		// Call GetProjectName and check the result
		jobAdOnce = sync.Once{}
		projectName, found := searchJobAd(attrProjectName)
		assert.True(t, found)
		assert.Equal(t, "testProject", projectName)
	})

	t.Run("TestGlobalJobIdAd", func(t *testing.T) {
		// Set the _CONDOR_JOB_AD environment variable to the temp file's name
		os.Setenv("_CONDOR_JOB_AD", tempFile.Name())
		defer os.Unsetenv("_CONDOR_JOB_AD")

		// Call GetProjectName and check the result
		jobAdOnce = sync.Once{}
		jobId, found := searchJobAd(attrJobId)
		assert.True(t, found)
		assert.Equal(t, "12345", jobId)
	})
}

// Test error messages when a 504 Gateway Timeout occurs
func TestGatewayTimeout(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	err = transferResult.Error
	log.Debugln("Received download error:", err)

	// Check that it's wrapped in a PelicanError with Transfer.TimedOut
	var pe *error_codes.PelicanError
	require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError")
	assert.Equal(t, 6003, pe.Code(), "Should be Transfer.TimedOut error code")
	assert.Equal(t, "Transfer.TimedOut", pe.ErrorType(), "Should be Transfer.TimedOut error type")
	assert.True(t, pe.IsRetryable(), "Timeout should be retryable")

	// Check that the underlying StatusCodeError is still there
	var sce *StatusCodeError
	if errors.As(err, &sce) {
		assert.Equal(t, "cache timed out waiting on origin", sce.Error())
	} else {
		require.Fail(t, "downloadObject did not return a status code error", "%s", err)
	}
}

// TestStatusCodeErrorWrapping tests that different HTTP status codes are wrapped correctly
func TestStatusCodeErrorWrapping(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	testCases := []struct {
		name          string
		statusCode    int
		expectedCode  int
		expectedType  string
		expectedRetry bool
		expectedErrFn func(error) *error_codes.PelicanError
	}{
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectedCode:  4000,
			expectedType:  "Authorization",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewAuthorizationError(errors.New("test"))
			},
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectedCode:  4000,
			expectedType:  "Authorization",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewAuthorizationError(errors.New("test"))
			},
		},
		{
			name:          "404 Not Found",
			statusCode:    http.StatusNotFound,
			expectedCode:  5011,
			expectedType:  "Specification.FileNotFound",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewSpecification_FileNotFoundError(errors.New("test"))
			},
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectedCode:  5000,
			expectedType:  "Specification",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewSpecificationError(errors.New("test"))
			},
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "504 Gateway Timeout",
			statusCode:    http.StatusGatewayTimeout,
			expectedCode:  6003,
			expectedType:  "Transfer.TimedOut",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransfer_TimedOutError(errors.New("test"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
			}))
			defer svr.Close()
			svrURL, err := url.Parse(svr.URL)
			require.NoError(t, err)

			transfer := &transferFile{
				ctx: context.Background(),
				job: &TransferJob{
					remoteURL: &pelican_url.PelicanURL{
						Scheme: "pelican://",
						Host:   svrURL.Host,
						Path:   svrURL.Path + "/test.txt",
					},
				},
				localPath: "/dev/null",
				remoteURL: svrURL,
				attempts: []transferAttemptDetails{
					{
						Url: svrURL,
					},
				},
			}
			transferResult, err := downloadObject(transfer)
			assert.NoError(t, err)
			err = transferResult.Error
			require.Error(t, err, "Should have an error for status code %d", tc.statusCode)

			// Check that it's wrapped in a PelicanError with the expected type
			var pe *error_codes.PelicanError
			require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError for status %d", tc.statusCode)

			// Use the expected error function to get the expected values
			expectedErr := tc.expectedErrFn(errors.New("test"))
			assert.Equal(t, expectedErr.Code(), pe.Code(), "Status %d should map to error code %d", tc.statusCode, tc.expectedCode)
			assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Status %d should map to error type %s", tc.statusCode, tc.expectedType)
			assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "Status %d retryability should be %v", tc.statusCode, tc.expectedRetry)
		})
	}
}

// TestStatusCodeErrorWrappingUpload tests that different HTTP status codes are wrapped correctly during uploads
func TestStatusCodeErrorWrappingUpload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
		"TLSSkipVerify": true,
	})

	testCases := []struct {
		name          string
		statusCode    int
		expectedCode  int
		expectedType  string
		expectedRetry bool
		expectedErrFn func(error) *error_codes.PelicanError
	}{
		{
			name:          "401 Unauthorized",
			statusCode:    http.StatusUnauthorized,
			expectedCode:  4000,
			expectedType:  "Authorization",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewAuthorizationError(errors.New("test"))
			},
		},
		{
			name:          "403 Forbidden",
			statusCode:    http.StatusForbidden,
			expectedCode:  4000,
			expectedType:  "Authorization",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewAuthorizationError(errors.New("test"))
			},
		},
		{
			name:          "400 Bad Request",
			statusCode:    http.StatusBadRequest,
			expectedCode:  5000,
			expectedType:  "Specification",
			expectedRetry: false,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewSpecificationError(errors.New("test"))
			},
		},
		{
			name:          "500 Internal Server Error",
			statusCode:    http.StatusInternalServerError,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "502 Bad Gateway",
			statusCode:    http.StatusBadGateway,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "503 Service Unavailable",
			statusCode:    http.StatusServiceUnavailable,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransferError(errors.New("test"))
			},
		},
		{
			name:          "504 Gateway Timeout",
			statusCode:    http.StatusGatewayTimeout,
			expectedCode:  6003,
			expectedType:  "Transfer.TimedOut",
			expectedRetry: true,
			expectedErrFn: func(err error) *error_codes.PelicanError {
				return error_codes.NewTransfer_TimedOutError(errors.New("test"))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configDir := t.TempDir()
			testfileLocation := filepath.Join(configDir, "testfile.txt")
			err := os.WriteFile(testfileLocation, []byte("test content"), fs.FileMode(0600))
			require.NoError(t, err)

			svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Return 404 for PROPFIND (stat) requests so upload doesn't think file exists
				if r.Method == "PROPFIND" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				// For PUT requests, return the test status code
				if r.Method == "PUT" {
					w.WriteHeader(tc.statusCode)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer svr.Close()
			svrURL, err := url.Parse(svr.URL)
			require.NoError(t, err)

			transfer := &transferFile{
				ctx: context.Background(),
				job: &TransferJob{
					remoteURL: &pelican_url.PelicanURL{
						Scheme: "pelican://",
						Host:   svrURL.Host,
						Path:   svrURL.Path + "/test.txt",
					},
					dirResp: server_structs.DirectorResponse{
						XPelNsHdr: server_structs.XPelNs{
							Namespace:      "/test",
							RequireToken:   false,
							CollectionsUrl: svrURL,
						},
					},
				},
				localPath: testfileLocation,
				remoteURL: svrURL,
				attempts: []transferAttemptDetails{
					{
						Url: svrURL,
					},
				},
			}
			transferResult, err := uploadObject(transfer)
			assert.NoError(t, err)
			err = transferResult.Error
			require.Error(t, err, "Should have an error for status code %d", tc.statusCode)

			// Check that it's wrapped in a PelicanError with the expected type
			// The error might be in TransferErrors, so we need to check both
			var te *TransferErrors
			if errors.As(err, &te) {
				// Extract the first error from TransferErrors
				if len(te.errors) > 0 {
					if tsErr, ok := te.errors[0].(*TimestampedError); ok && tsErr != nil {
						err = tsErr.err
					} else {
						err = te.errors[0]
					}
				}
			}

			var pe *error_codes.PelicanError
			require.True(t, errors.As(err, &pe), "Error should be wrapped in PelicanError for status %d, got: %T %v", tc.statusCode, err, err)

			// Use the expected error function to get the expected values
			expectedErr := tc.expectedErrFn(errors.New("test"))
			assert.Equal(t, expectedErr.Code(), pe.Code(), "Status %d should map to error code %d", tc.statusCode, tc.expectedCode)
			assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Status %d should map to error type %s", tc.statusCode, tc.expectedType)
			assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "Status %d retryability should be %v", tc.statusCode, tc.expectedRetry)
		})
	}
}

// TestHttpErrRespWithNonStatusCodeError tests that HttpErrResp with non-StatusCodeError inner error
// is wrapped correctly based on HTTP status code using wrapErrorByStatusCode
func TestHttpErrRespWithNonStatusCodeError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	testCases := []struct {
		name          string
		statusCode    int
		expectedCode  int
		expectedType  string
		expectedRetry bool
		innerError    error
	}{
		{
			name:          "404 with generic error",
			statusCode:    http.StatusNotFound,
			expectedCode:  5011,
			expectedType:  "Specification.FileNotFound",
			expectedRetry: false,
			innerError:    errors.New("some other error"),
		},
		{
			name:          "500 with generic error",
			statusCode:    http.StatusInternalServerError,
			expectedCode:  6000,
			expectedType:  "Transfer",
			expectedRetry: true,
			innerError:    errors.New("server error"),
		},
		{
			name:          "400 with generic error",
			statusCode:    http.StatusBadRequest,
			expectedCode:  5000,
			expectedType:  "Specification",
			expectedRetry: false,
			innerError:    errors.New("bad request"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test wrapErrorByStatusCode directly (used by HttpErrResp handler)
			wrappedErr := wrapErrorByStatusCode(tc.statusCode, tc.innerError)
			require.Error(t, wrappedErr)

			var pe *error_codes.PelicanError
			require.True(t, errors.As(wrappedErr, &pe), "Error should be wrapped in PelicanError")
			assert.Equal(t, tc.expectedCode, pe.Code(), "Status %d should map to error code %d", tc.statusCode, tc.expectedCode)
			assert.Equal(t, tc.expectedType, pe.ErrorType(), "Status %d should map to error type %s", tc.statusCode, tc.expectedType)
			assert.Equal(t, tc.expectedRetry, pe.IsRetryable(), "Status %d retryability should be %v", tc.statusCode, tc.expectedRetry)

			// Verify the inner error is preserved
			assert.True(t, errors.Is(wrappedErr, tc.innerError), "Original error should be preserved in error chain")
		})
	}
}

// TestCatchAllErrorWrapping tests that unknown error types are wrapped as generic TransferError
func TestCatchAllErrorWrapping(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	// Create a generic error that doesn't match any specific error type checks
	genericErr := errors.New("some unknown error type")

	// Test that wrapErrorByStatusCode wraps it correctly for a 500 status
	wrappedErr := wrapErrorByStatusCode(http.StatusInternalServerError, genericErr)
	require.Error(t, wrappedErr)

	var pe *error_codes.PelicanError
	require.True(t, errors.As(wrappedErr, &pe), "Error should be wrapped in PelicanError")
	assert.Equal(t, 6000, pe.Code(), "Should be Transfer error code")
	assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error type")
	assert.True(t, pe.IsRetryable(), "Should be retryable")

	// Verify the original error is preserved
	assert.True(t, errors.Is(wrappedErr, genericErr), "Original error should be preserved in error chain")
}

func TestInvalidByteInChunkLengthError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Set up an HTTP server that sends malformed chunk encoding
	// This simulates the "invalid byte in chunk length" error
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hijack the connection so we can send malformed chunk encoding
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
			return
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Send HTTP response headers with chunked transfer encoding
		_, _ = bufrw.WriteString("HTTP/1.1 200 OK\r\n")
		_, _ = bufrw.WriteString("Transfer-Encoding: chunked\r\n")
		_, _ = bufrw.WriteString("\r\n")
		_ = bufrw.Flush()

		// Send malformed chunk length (invalid byte 'X' in chunk length)
		// This should trigger "invalid byte in chunk length" error in Go's HTTP client
		_, _ = conn.Write([]byte("X\r\n")) // Invalid chunk length
		_ = bufrw.Flush()
	}))
	defer svr.Close()

	serverAddr := strings.TrimPrefix(svr.URL, "http://")

	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	assert.NoError(t, err)
	defer writer.Close()

	// Call downloadHTTP which should trigger InvalidByteInChunkLengthError
	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Scheme: "http", Host: serverAddr}, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)

	require.Error(t, err, "Should have an error from invalid chunk length")

	// Verify that the error is an InvalidByteInChunkLengthError (unwrapped, since it's created in downloadHTTP)
	var invalidChunkErr *InvalidByteInChunkLengthError
	require.True(t, errors.As(err, &invalidChunkErr), "Error should be an InvalidByteInChunkLengthError, got: %T, error: %v", err, err)

	// Verify that when wrapped, it has the correct properties (simulating download loop behavior)
	wrappedErr := error_codes.NewTransferError(invalidChunkErr)
	var pe *error_codes.PelicanError
	require.True(t, errors.As(wrappedErr, &pe), "Wrapped error should be a PelicanError")
	expectedErr := error_codes.NewTransferError(errors.New("test"))
	assert.Equal(t, expectedErr.Code(), pe.Code(), "Should map to TransferError error code")
	assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Should map to TransferError error type")
	assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "InvalidByteInChunkLengthError should be retryable (wrapped as TransferError)")
}

// Test checksum calculation and validation
func TestChecksum(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.Header().Set("Digest", "crc32c=977b8112")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("test file content"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	assert.NoError(t, transferResult.Error)
	// Checksum validation
	assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
	info := transferResult.ServerChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

	assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
	info = transferResult.ClientChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
}

// Test behavior when checksum is incorrect
func TestChecksumIncorrectWhenRequired(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.Header().Set("Digest", "crc32c=977b8111") // Incorrect checksum; should be 977b8112
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("test file content"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
		requireChecksum: true,
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	assert.Error(t, transferResult.Error)

	// Verify that the error is wrapped as a PelicanError
	var pe *error_codes.PelicanError
	require.True(t, errors.As(transferResult.Error, &pe), "Error should be wrapped as PelicanError")
	expectedErr := error_codes.NewTransfer_ChecksumMismatchError(errors.New("test"))
	assert.Equal(t, expectedErr.Code(), pe.Code(), "Should map to Transfer.ChecksumMismatch error code")
	assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Should map to Transfer.ChecksumMismatch error type")
	assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "ChecksumMismatchError should be retryable (wrapped as Transfer.ChecksumMismatch)")

	// Extract the inner ChecksumMismatchError to verify the error message
	var incorrectChecksumError *ChecksumMismatchError
	require.True(t, errors.As(transferResult.Error, &incorrectChecksumError), "Error should contain ChecksumMismatchError")
	assert.Equal(t, "checksum mismatch for crc32c; client computed 977b8112, server reported 977b8111", incorrectChecksumError.Error())

	// Checksum validation
	assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
	info := transferResult.ServerChecksums[0]
	assert.Equal(t, "977b8111", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

	assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
	info = transferResult.ClientChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
}

func TestChecksumIncorrectWhenNotRequired(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.Header().Set("Digest", "crc32c=977b8111") // Incorrect checksum; should be 977b8112
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("test file content"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
		requireChecksum: false,
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	// We should expect an error because even when the checksum is not required, we still want to verify that the checksum is correct.
	// We wouldn't want the object downloaded to different than the original.
	assert.Error(t, transferResult.Error, "Should error when requireChecksum is false")

	// Checksum validation
	assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
	info := transferResult.ServerChecksums[0]
	assert.Equal(t, "977b8111", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

	assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
	info = transferResult.ClientChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
}

// Test behavior when checksum is missing
func TestChecksumMissing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("test file content"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
		requireChecksum: true,
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	assert.Error(t, transferResult.Error)
	assert.True(t, errors.Is(transferResult.Error, ErrServerChecksumMissing), "Expected checksum missing error")
}

func TestChecksumPut(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Run("test-good-checksum", func(t *testing.T) {
		test_utils.InitClient(t, map[string]any{
			param.Logging_Level.GetName(): "debug",
			param.TLSSkipVerify.GetName(): true,
		})

		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, "test file content", string(body))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "HEAD" {
				w.Header().Set("Content-Length", "17")
				w.Header().Set("Digest", "crc32c=977b8112")
				w.WriteHeader(http.StatusOK)
			}

			if r.Method == "PROPFIND" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer svr.Close()
		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		tempDir := t.TempDir()
		tempFile := filepath.Join(tempDir, "testfile.txt")
		err = os.WriteFile(tempFile, []byte("test file content"), 0644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				requireChecksum:    true,
				requestedChecksums: []ChecksumType{AlgCRC32C},
				dirResp: server_structs.DirectorResponse{
					ObjectServers: []*url.URL{svrURL},
				},
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/testfile.txt",
				},
			},
			localPath: tempFile,
			remoteURL: svrURL,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
		}
		transferResult, err := uploadObject(transfer)
		assert.NoError(t, err)
		assert.NoError(t, transferResult.Error)

		assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
		info := transferResult.ServerChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

		assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
		info = transferResult.ClientChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
	})

	t.Run("test-bad-checksum", func(t *testing.T) {
		test_utils.InitClient(t, map[string]any{
			param.Logging_Level.GetName(): "debug",
			param.TLSSkipVerify.GetName(): true,
		})

		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, "test file content", string(body))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "HEAD" {
				w.Header().Set("Content-Length", "17")
				w.Header().Set("Digest", "crc32c=977b8111") // Incorrect checksum; should be 977b8112
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == "PROPFIND" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer svr.Close()
		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		tempDir := t.TempDir()
		tempFile := filepath.Join(tempDir, "testfile.txt")
		err = os.WriteFile(tempFile, []byte("test file content"), 0644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				requireChecksum:    true,
				requestedChecksums: []ChecksumType{AlgCRC32C},
				dirResp: server_structs.DirectorResponse{
					ObjectServers: []*url.URL{svrURL},
				},
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/testfile.txt",
				},
			},
			localPath: tempFile,
			remoteURL: svrURL,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
			requireChecksum: true,
		}
		transferResult, err := uploadObject(transfer)
		assert.NoError(t, err)
		require.Error(t, transferResult.Error)

		// Verify that the error is wrapped as a PelicanError
		var pe *error_codes.PelicanError
		require.True(t, errors.As(transferResult.Error, &pe), "Error should be wrapped as PelicanError")
		expectedErr := error_codes.NewTransfer_ChecksumMismatchError(errors.New("test"))
		assert.Equal(t, expectedErr.Code(), pe.Code(), "Should map to Transfer.ChecksumMismatch error code")
		assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType(), "Should map to Transfer.ChecksumMismatch error type")
		assert.Equal(t, expectedErr.IsRetryable(), pe.IsRetryable(), "ChecksumMismatchError should be retryable (wrapped as Transfer.ChecksumMismatch)")

		// Extract the inner ChecksumMismatchError to verify the error message
		var checksumError *ChecksumMismatchError
		require.ErrorAs(t, transferResult.Error, &checksumError)
		assert.Equal(t, "checksum mismatch for crc32c; client computed 977b8112, server reported 977b8111", checksumError.Error())

		assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
		info := transferResult.ServerChecksums[0]
		assert.Equal(t, "977b8111", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

		assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
		info = transferResult.ClientChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
	})

	t.Run("test-algorithm-mismatch", func(t *testing.T) {
		test_utils.InitClient(t, map[string]any{
			param.Logging_Level.GetName(): "debug",
			param.TLSSkipVerify.GetName(): true,
		})

		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, "test file content", string(body))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "HEAD" {
				w.Header().Set("Content-Length", "17")
				// Server returns MD5 checksum but client requested CRC32C
				w.Header().Set("Digest", "md5=5eb63bbbe01eeed093cb22bb8f5acdc3")
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == "PROPFIND" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer svr.Close()
		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		tempDir := t.TempDir()
		tempFile := filepath.Join(tempDir, "testfile.txt")
		err = os.WriteFile(tempFile, []byte("test file content"), 0644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				requireChecksum:    true,
				requestedChecksums: []ChecksumType{AlgCRC32C},
				dirResp: server_structs.DirectorResponse{
					ObjectServers: []*url.URL{svrURL},
				},
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/testfile.txt",
				},
			},
			localPath: tempFile,
			remoteURL: svrURL,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
			requireChecksum: true,
		}
		transferResult, err := uploadObject(transfer)
		assert.NoError(t, err)
		require.Error(t, transferResult.Error)
		assert.True(t, errors.Is(transferResult.Error, ErrServerChecksumMissing), "Expected checksum missing error when algorithms don't match")

		// Server provided MD5 checksum but client requested CRC32C
		assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
		info := transferResult.ServerChecksums[0]
		assert.Equal(t, "5eb63bbbe01eeed093cb22bb8f5acdc3", checksumValueToHttpDigest(info.Algorithm, info.Value))
		assert.Equal(t, ChecksumType(AlgMD5), info.Algorithm)

		// Client computed CRC32C checksum
		assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
		info = transferResult.ClientChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
	})

	t.Run("test-no-error-when-requireChecksum-false", func(t *testing.T) {
		test_utils.InitClient(t, map[string]any{
			param.Logging_Level.GetName(): "debug",
			param.TLSSkipVerify.GetName(): true,
		})

		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, "test file content", string(body))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "HEAD" {
				w.Header().Set("Content-Length", "17")
				// Server returns different algorithm than requested
				w.Header().Set("Digest", "md5=5eb63bbbe01eeed093cb22bb8f5acdc3")
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == "PROPFIND" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer svr.Close()
		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		tempDir := t.TempDir()
		tempFile := filepath.Join(tempDir, "testfile.txt")
		err = os.WriteFile(tempFile, []byte("test file content"), 0644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				requireChecksum:    false, // Don't require checksum
				requestedChecksums: []ChecksumType{AlgCRC32C},
				dirResp: server_structs.DirectorResponse{
					ObjectServers: []*url.URL{svrURL},
				},
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/testfile.txt",
				},
			},
			localPath: tempFile,
			remoteURL: svrURL,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
			requireChecksum: false,
		}
		transferResult, err := uploadObject(transfer)
		assert.NoError(t, err)
		assert.NoError(t, transferResult.Error, "Should not error when requireChecksum is false")

		// Server provided MD5 checksum
		assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
		info := transferResult.ServerChecksums[0]
		assert.Equal(t, "5eb63bbbe01eeed093cb22bb8f5acdc3", checksumValueToHttpDigest(info.Algorithm, info.Value))
		assert.Equal(t, ChecksumType(AlgMD5), info.Algorithm)

		// Client computed CRC32C checksum
		assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
		info = transferResult.ClientChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
	})

	t.Run("test-missing-checksum-when-required", func(t *testing.T) {
		test_utils.InitClient(t, map[string]any{
			param.Logging_Level.GetName(): "debug",
			param.TLSSkipVerify.GetName(): true,
		})

		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PUT" {
				body, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				assert.Equal(t, "test file content", string(body))
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == "HEAD" {
				w.Header().Set("Content-Length", "17")
				// No Digest header - server doesn't provide checksum
				w.WriteHeader(http.StatusOK)
			}
			if r.Method == "PROPFIND" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}))
		defer svr.Close()
		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		tempDir := t.TempDir()
		tempFile := filepath.Join(tempDir, "testfile.txt")
		err = os.WriteFile(tempFile, []byte("test file content"), 0644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				requireChecksum:    true,
				requestedChecksums: []ChecksumType{AlgCRC32C},
				dirResp: server_structs.DirectorResponse{
					ObjectServers: []*url.URL{svrURL},
				},
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/testfile.txt",
				},
			},
			localPath: tempFile,
			remoteURL: svrURL,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
			requireChecksum: true,
		}
		transferResult, err := uploadObject(transfer)
		assert.NoError(t, err)
		require.Error(t, transferResult.Error)
		assert.True(t, errors.Is(transferResult.Error, ErrServerChecksumMissing), "Expected checksum missing error when server provides no checksum")

		// No server checksums provided
		assert.Equal(t, 0, len(transferResult.ServerChecksums), "Checksum count is %d but should be 0", len(transferResult.ServerChecksums))

		// Client still computed CRC32C checksum
		assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
		info := transferResult.ClientChecksums[0]
		assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
		assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)
	})
}

// Test behavior when resuming a transfer after an EOF
//
// Sets up two servers, one that returns the first 9 bytes and then an EOF (simulating a network
// error), and another that returns the rest of the file. The test checks that the transfer resumes
// after the first attempt and that the checksums are calculated and validated properly.
func TestResume(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	svr1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.Header().Set("Digest", "crc32c=977b8112")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("test file"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr1.Close()
	svr1URL, err := url.Parse(svr1.URL)
	require.NoError(t, err)

	svr2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			require.Equal(t, "bytes=9-", r.Header.Get("Range"))
			w.Header().Set("Content-Range", "bytes 9-16/17")
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte(" content"))
			assert.NoError(t, err)
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr2.Close()
	svr2URL, err := url.Parse(svr2.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svr1URL.Host,
				Path:   svr1URL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svr1URL,
		attempts: []transferAttemptDetails{
			{
				Url: svr1URL,
			},
			{
				Url: svr2URL,
			},
		},
		requireChecksum: true,
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	assert.NoError(t, transferResult.Error)

	assert.Equal(t, 1, len(transferResult.ServerChecksums), "Checksum count is %d but should be 1", len(transferResult.ServerChecksums))
	info := transferResult.ServerChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

	assert.Equal(t, 1, len(transferResult.ClientChecksums), "Checksum count is %d but should be 1", len(transferResult.ClientChecksums))
	info = transferResult.ClientChecksums[0]
	assert.Equal(t, "977b8112", hex.EncodeToString(info.Value))
	assert.Equal(t, ChecksumType(AlgCRC32C), info.Algorithm)

	// Check that two attempts were made
	assert.Equal(t, 2, len(transferResult.Attempts), "Expected 2 attempts, got %d", len(transferResult.Attempts))
	tae := &TransferAttemptError{}
	require.True(t, errors.As(transferResult.Attempts[0].Error, &tae), "Got error of type %T; expected transfer attempt error", transferResult.Attempts[0].Error)
	// The error should be wrapped as a PelicanError, but the original io.ErrUnexpectedEOF should be preserved
	assert.True(t, errors.Is(tae.Unwrap(), io.ErrUnexpectedEOF), "Expected original error to be preserved in error chain")
	assert.Equal(t, int64(9), transferResult.Attempts[0].TransferFileBytes)
	assert.NoError(t, transferResult.Attempts[1].Error)
	assert.Equal(t, int64(8), transferResult.Attempts[1].TransferFileBytes)
	assert.Equal(t, int64(17), transferResult.TransferredBytes)
}

// Test failed connection setup error message for downloads
func TestFailedConnectionSetupError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Transport.ResponseHeaderTimeout": "500ms",
		"Logging.Level":                   "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	err = transferResult.Error
	log.Debugln("Received connection error:", err)
	var hte *HeaderTimeoutError
	if errors.As(err, &hte) {
		require.Equal(t, "timeout waiting for HTTP response (TCP connection successful)", hte.Error())
	} else {
		require.Fail(t, "Slow server did not generate a HeaderTimeoutError")
	}
	assert.True(t, IsRetryable(err))
	assert.Error(t, err)
}

// Test that head requests with downloads contain the download token if it exists
func TestHeadRequestWithDownloadToken(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		}
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	token := newTokenGenerator(nil, nil, config.TokenSharedRead, false)
	token.SetToken("test-token")
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath: os.DevNull,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
		token: token,
	}
	_, _ = downloadObject(transfer)
}

// Test error message generated on a failed upload
//
// Creates a server that does nothing but stall; examines the
// corresponding error message out to the user.
func TestFailedUploadError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	configDir := t.TempDir()
	test_utils.InitClient(t, map[string]any{
		"Transport.ResponseHeaderTimeout": "500ms",
		"TLSSkipVerify":                   true,
		"Logging.Level":                   "debug",
	})

	testfileLocation := filepath.Join(configDir, "testfile.txt")
	err := os.WriteFile(testfileLocation, []byte("Hello, world!\n"), fs.FileMode(0600))
	require.NoError(t, err)

	shutdownChan := make(chan bool)
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		<-shutdownChan
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	defer close(shutdownChan)
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		ctx: context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					Namespace:      "/test",
					RequireToken:   false,
					CollectionsUrl: svrURL,
				},
			},
		},
		localPath: testfileLocation,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}
	transferResult, err := uploadObject(transfer)
	assert.NoError(t, err)
	err = transferResult.Error
	log.Debugln("Received error:", err)
	var te *TransferErrors
	if errors.As(err, &te) {
		log.Debugln("Received transfer error:", te.UserError())
	} else {
		require.Fail(t, "Returned error (%s) is not a TransferError type", err.Error())
	}
	var hte *HeaderTimeoutError
	if errors.As(err, &hte) {
		require.Equal(t, "timeout waiting for HTTP response (TCP connection successful)", hte.Error())
	}
	require.Error(t, err)
}

// Test error message generated on a failed upload
//
// Creates a server that does nothing but stall; examines the
// corresponding error message out to the user.
func TestFailedLargeUploadError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Transport.ResponseHeaderTimeout": "500ms",
		"TLSSkipVerify":                   true,
		"Logging.Level":                   "debug",
		"Client.StoppedTransferTimeout":   "1s",
	})

	testfileLocation := filepath.Join(t.TempDir(), "testfile.txt")
	fp, err := os.OpenFile(testfileLocation, os.O_WRONLY|os.O_CREATE, os.FileMode(0600))
	require.NoError(t, err)
	test_utils.WriteBigBuffer(t, fp, 40)

	shutdownChan := make(chan bool)
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		<-shutdownChan
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	defer close(shutdownChan)
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		ctx: context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					Namespace:      "/test",
					RequireToken:   false,
					CollectionsUrl: svrURL,
				},
			},
		},
		localPath: testfileLocation,
		remoteURL: svrURL,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}
	transferResult, err := uploadObject(transfer)
	assert.NoError(t, err)
	err = transferResult.Error
	log.Debugln("Received error:", err)
	var te *TransferErrors
	if errors.As(err, &te) {
		log.Debugln("Received transfer error:", te.UserError())
	} else {
		require.Fail(t, "Returned error (%s) is not a TransferError type", err.Error())
	}
	var hte *HeaderTimeoutError
	if errors.As(err, &hte) {
		require.Equal(t, "timeout waiting for HTTP response (TCP connection successful)", hte.Error())
	}
	require.Error(t, err)
}

func TestNewTransferEngine(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()
	// Test we fail if we do not call initclient() before
	t.Run("TestInitClientNotCalled", func(t *testing.T) {
		config.ResetClientInitialized()
		ctx := context.Background()
		_, err := NewTransferEngine(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client has not been initialized, unable to create transfer engine")
	})

	t.Run("TestInitClientCalled", func(t *testing.T) {
		err := config.InitClient()
		require.NoError(t, err)
		ctx := context.Background()
		_, err = NewTransferEngine(ctx)
		assert.NoError(t, err)
	})
}

func TestListHttp(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	type test struct {
		name          string
		pUrl          *pelican_url.PelicanURL
		dirResp       server_structs.DirectorResponse
		expectedError string
	}
	tests := []test{
		{
			name: "valid-collections-url",
			pUrl: &pelican_url.PelicanURL{
				Scheme: "pelican",
				Host:   "something.com",
				Path:   "/foo/bar/baz",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					RequireToken: false,
					Namespace:    "/foo/bar",
					CollectionsUrl: &url.URL{
						Scheme: "https",
						Host:   "collections.example.com",
					},
				},
			},
			expectedError: "no such host", // punt on setting up a real server, and accept this "success" looks like a connection error
		},
		{
			name: "no-collections-url",
			pUrl: &pelican_url.PelicanURL{
				Scheme: "pelican",
				Host:   "something.com",
				Path:   "/foo/bar/baz",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					RequireToken: false,
					Namespace:    "/foo/bar",
				},
			},
			expectedError: "Collections URL not found in director response. Are you sure there's an origin for prefix /foo/bar that supports listings?",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := listHttp(test.pUrl, test.dirResp, nil, false, 0)
			if test.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInvalidByteInChunkLength(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Create a test server that sends an invalid chunk length
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		conn, bufrw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack failed: %v", err)
		}
		defer conn.Close()

		// Write a properly formatted HTTP response with an invalid chunk length
		if _, err := bufrw.WriteString("HTTP/1.1 200 OK\r\n"); err != nil {
			t.Fatalf("failed to write status line: %v", err)
		}
		if _, err := bufrw.WriteString("Content-Type: text/plain\r\n"); err != nil {
			t.Fatalf("failed to write content-type: %v", err)
		}
		if _, err := bufrw.WriteString("Transfer-Encoding: chunked\r\n"); err != nil {
			t.Fatalf("failed to write transfer-encoding: %v", err)
		}
		if _, err := bufrw.WriteString("Connection: close\r\n"); err != nil {
			t.Fatalf("failed to write connection: %v", err)
		}
		if _, err := bufrw.WriteString("\r\n"); err != nil {
			t.Fatalf("failed to write header separator: %v", err)
		}
		if _, err := bufrw.WriteString("1g\r\n"); err != nil { // Invalid chunk length
			t.Fatalf("failed to write chunk length: %v", err)
		}
		if _, err := bufrw.WriteString("data\r\n"); err != nil {
			t.Fatalf("failed to write chunk data: %v", err)
		}
		if _, err := bufrw.WriteString("0\r\n\r\n"); err != nil {
			t.Fatalf("failed to write chunk terminator: %v", err)
		}
		if err := bufrw.Flush(); err != nil {
			t.Fatalf("failed to flush buffer: %v", err)
		}
	}))

	defer svr.CloseClientConnections()
	defer svr.Close()

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.Equal(t, 1, len(transfers))

	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
	require.Error(t, err)
	t.Logf("error: %v", err)

	// Verify that the error is an InvalidByteInChunkLengthError (unwrapped, since it's created in downloadHTTP)
	var invalidChunkErr *InvalidByteInChunkLengthError
	require.True(t, errors.As(err, &invalidChunkErr), "Error should be an InvalidByteInChunkLengthError")

	// Wrap the error as it would be in the download loop, then check retryability
	wrappedErr := error_codes.NewTransferError(invalidChunkErr)
	assert.True(t, IsRetryable(wrappedErr), "Invalid chunk length error should be retryable (wrapped as TransferError)")
}

func TestUnexpectedEOFInTransferStatus(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	// Create a test server that sends an EOF error in the X-Transfer-Status trailer
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Transfer-Status")

		// Write the body
		_, err := w.Write([]byte("hello"))
		require.NoError(t, err)

		// Set the trailer
		w.Header().Set("X-Transfer-Status", "500: unexpected EOF")
	}))
	defer svr.Close()

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.Equal(t, 1, len(transfers))

	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
	require.Error(t, err)
	t.Logf("error: %v", err)
	assert.True(t, IsRetryable(err), "Unexpected EOF error should be retryable")
}

func TestTLSCertificateError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Generate a self-signed certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	svr := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	svr.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{derBytes},
			PrivateKey:  priv,
		}},
	}
	svr.StartTLS()
	defer svr.Close()

	// Use the server's URL but with localhost
	serverURL, err := url.Parse(svr.URL)
	require.NoError(t, err)
	serverURL.Host = "localhost:" + strings.Split(serverURL.Host, ":")[1]

	// Create a test file to upload
	testData := []byte("test data")
	fname := filepath.Join(t.TempDir(), "test.txt")
	err = os.WriteFile(fname, testData, 0o644)
	require.NoError(t, err)

	// Create the PUT request
	file, err := os.Open(fname)
	require.NoError(t, err)
	defer file.Close()

	request, err := http.NewRequest("PUT", serverURL.String(), file)
	require.NoError(t, err)

	// Set up channels for response and error handling
	errorChan := make(chan error, 1)
	responseChan := make(chan *http.Response, 1)

	// Run the PUT request
	go runPut(request, responseChan, errorChan, false)

	// Wait for either an error or response
	select {
	case err := <-errorChan:
		require.Error(t, err)
		t.Logf("error: %v", err)
		assert.Contains(t, err.Error(), "certificate signed by unknown authority")
		// runPut returns the underlying TLS validation error; wrapping happens in the upload error handler.
		require.True(t, isTLSCertificateValidationError(err), "Error should be TLS certificate validation error")
		// Simulate upload error handler wrapping (TLS certificate validation errors are specification errors,
		// not retryable)
		wrappedErr := error_codes.NewSpecificationError(err)
		assert.False(t, IsRetryable(wrappedErr), "Wrapped TLS certificate validation error should not be retryable")
	case response := <-responseChan:
		t.Fatalf("Expected error but got response: %v", response)
	case <-time.After(time.Second * 2):
		t.Fatal("Timeout while waiting for response")
	}
}

func TestPutOverwrite(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"TLSSkipVerify": true,
	})

	t.Run("ObjectExists", func(t *testing.T) {
		// Create a server that responds to WebDAV PROPFIND requests indicating the object exists
		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PROPFIND" {
				// Simulate existing object - return WebDAV response
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(http.StatusMultiStatus)
				response := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/hello.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>1024</D:getcontentlength>
        <D:getlastmodified>Wed, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`
				_, err := w.Write([]byte(response))
				require.NoError(t, err)
				return
			}
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}))
		defer svr.Close()

		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		// Create a token generator with a test token
		token := newTokenGenerator(nil, nil, config.TokenSharedWrite, false)
		token.SetToken("test-token")

		// Create a test file to upload
		testData := []byte("test content")
		fname := filepath.Join(t.TempDir(), "test.txt")
		err = os.WriteFile(fname, testData, 0o644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/hello.txt",
				},
				dirResp: server_structs.DirectorResponse{
					XPelNsHdr: server_structs.XPelNs{
						Namespace:      "/test",
						RequireToken:   true,
						CollectionsUrl: svrURL,
					},
				},
				token: token,
			},
			remoteURL: svrURL,
			localPath: fname,
			token:     token,
		}

		result, err := uploadObject(transfer)
		require.Error(t, err)
		var pe *error_codes.PelicanError
		require.ErrorAs(t, result.Error, &pe)
		expectedErr := error_codes.NewSpecification_FileAlreadyExistsError(nil)
		assert.Equal(t, expectedErr.ErrorType(), pe.ErrorType())
		assert.Contains(t, result.Error.Error(), "remote object already exists, upload aborted")
	})

	t.Run("ObjectDoesNotExist", func(t *testing.T) {
		// Create a server that responds to WebDAV PROPFIND requests with 404 (object doesn't exist)
		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PROPFIND" {
				// Simulate non-existing object - return 404
				w.WriteHeader(http.StatusNotFound)
				return
			}
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}))
		defer svr.Close()

		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		// Create a token generator with a test token
		token := newTokenGenerator(nil, nil, config.TokenSharedWrite, false)
		token.SetToken("test-token")

		// Create a test file to upload
		testData := []byte("test content")
		fname := filepath.Join(t.TempDir(), "test.txt")
		err = os.WriteFile(fname, testData, 0o644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/test.txt",
				},
				dirResp: server_structs.DirectorResponse{
					XPelNsHdr: server_structs.XPelNs{
						Namespace:      "/test",
						RequireToken:   true,
						CollectionsUrl: svrURL,
					},
				},
				token: token,
			},
			remoteURL: svrURL,
			localPath: fname,
			token:     token,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
		}

		result, err := uploadObject(transfer)
		require.NoError(t, err)
		require.NoError(t, result.Error) // Should succeed when object doesn't exist
	})

	t.Run("StatError", func(t *testing.T) {
		// Create a server that returns an error on WebDAV PROPFIND requests
		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PROPFIND" {
				// Simulate server error
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}))
		defer svr.Close()

		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		// Create a token generator with a test token
		token := newTokenGenerator(nil, nil, config.TokenSharedWrite, false)
		token.SetToken("test-token")

		// Create a test file to upload
		testData := []byte("test content")
		fname := filepath.Join(t.TempDir(), "test.txt")
		err = os.WriteFile(fname, testData, 0o644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/hello.txt",
				},
				dirResp: server_structs.DirectorResponse{
					XPelNsHdr: server_structs.XPelNs{
						Namespace:      "/test",
						RequireToken:   true,
						CollectionsUrl: svrURL,
					},
				},
				token: token,
			},
			remoteURL: svrURL,
			localPath: fname,
			token:     token,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
		}

		// Capture log warnings
		var logBuf bytes.Buffer
		origOut := log.StandardLogger().Out
		log.SetOutput(&logBuf)
		origLevel := config.GetEffectiveLogLevel()
		config.SetLogging(log.WarnLevel)
		defer func() {
			log.SetOutput(origOut)
			config.SetLogging(origLevel)
		}()

		result, err := uploadObject(transfer)
		require.NoError(t, err) // We should not get an error from the uploadObject call
		require.NoError(t, result.Error)

		// Ensure the expected warning was logged
		assert.Contains(t, logBuf.String(), "Failed to check if object exists at the origin, proceeding with upload")
	})

	t.Run("OverwriteEnabled", func(t *testing.T) {
		// Create a server that responds to WebDAV PROPFIND requests indicating the object exists
		// But the upload should still proceed because overwrites are enabled
		svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "PROPFIND" {
				// Simulate existing object - return WebDAV response
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(http.StatusMultiStatus)
				response := `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/test.txt</D:href>
    <D:propstat>
      <D:prop>
        <D:resourcetype/>
        <D:getcontentlength>1024</D:getcontentlength>
        <D:getlastmodified>Wed, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`
				_, err := w.Write([]byte(response))
				require.NoError(t, err)
				return
			}
			if r.Method == "PUT" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		}))
		defer svr.Close()

		// Trust the test server certificate instead of skipping verification
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: svr.Certificate().Raw})
		certFile := filepath.Join(t.TempDir(), "ca.pem")
		require.NoError(t, os.WriteFile(certFile, certPEM, 0o644))

		// Test that overwrite protection is skipped when Client.EnableOverwrites is enabled
		test_utils.InitClient(t, map[string]any{
			param.Server_TLSCACertificateFile.GetName(): certFile,
			param.Client_EnableOverwrites.GetName():     true,
		})

		svrURL, err := url.Parse(svr.URL)
		require.NoError(t, err)

		// Create a token generator with a test token
		token := newTokenGenerator(nil, nil, config.TokenSharedWrite, false)
		token.SetToken("test-token")

		// Create a test file to upload
		testData := []byte("test content for overwrite")
		fname := filepath.Join(t.TempDir(), "test.txt")
		err = os.WriteFile(fname, testData, 0o644)
		require.NoError(t, err)

		transfer := &transferFile{
			ctx: context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/test.txt",
				},
				dirResp: server_structs.DirectorResponse{
					XPelNsHdr: server_structs.XPelNs{
						Namespace:      "/test",
						RequireToken:   true,
						CollectionsUrl: svrURL,
					},
				},
				token: token,
			},
			remoteURL: svrURL,
			localPath: fname,
			token:     token,
			attempts: []transferAttemptDetails{
				{
					Url: svrURL,
				},
			},
		}

		// The upload should succeed despite the object existing because overwrites are enabled
		result, err := uploadObject(transfer)
		require.NoError(t, err)
		require.NoError(t, result.Error) // Should succeed with overwrites enabled
	})
}

func TestPackAutoSegfaultRegression(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			// Send some compressed-like data to trigger pack handling
			_, err := w.Write([]byte("compressed data content"))
			assert.NoError(t, err)
			w.(http.Flusher).Flush()
		} else {
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	destDir := filepath.Join(t.TempDir(), "nonexistent", "subdir")
	destFile := filepath.Join(destDir, "downloaded.txt")

	transfer := &transferFile{
		ctx: context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svrURL.Host,
				Path:   svrURL.Path + "/test.txt",
			},
		},
		localPath:  destFile,
		remoteURL:  svrURL,
		xferType:   transferTypeDownload,
		packOption: "auto",
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}

	transferResult, err := downloadObject(transfer)

	// We expect either an error from downloadObject OR an error in the transfer result
	// since pack=auto requires a directory destination
	if err != nil {
		t.Logf("downloadObject returned error: %v", err)
	} else if transferResult.Error != nil {
		errorMsg := transferResult.Error.Error()
		if strings.Contains(errorMsg, "destination path is not a directory") {
			// This is the pack-related error we're looking for
			t.Logf("Got expected pack-related error: %v", errorMsg)
		} else if strings.Contains(errorMsg, "unexpected EOF") {
			// This is a transfer error, but the important thing is we didn't segfault
			// The pack logic should have run and handled the destination path issue
			t.Logf("Got transfer error (expected in test environment): %v", errorMsg)
			t.Logf("Test passed: no segfault occurred, pack logic handled the case properly")
		} else {
			t.Fatalf("Got other error: %v", errorMsg)
		}
	} else {
		// This shouldn't happen - we should get some kind of error
		t.Fatal("Expected either downloadObject error or transferResult error, but got neither")
	}

}

func TestPermissionDeniedError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	remoteURL := &pelican_url.PelicanURL{
		Scheme: "pelican://",
		Host:   svrURL.Host,
		Path:   svrURL.Path + "/test.txt",
	}
	tj := &TransferJob{
		remoteURL: remoteURL,
		token:     newTokenGenerator(remoteURL, nil, config.TokenSharedRead, false),
	}
	transfer := &transferFile{
		ctx:       context.Background(),
		job:       tj,
		remoteURL: svrURL,
		token:     tj.token,
		attempts: []transferAttemptDetails{
			{
				Url: svrURL,
			},
		},
	}

	t.Run("expired-token", func(t *testing.T) {
		expiredTime := time.Now().Add(-time.Hour)
		expiredJWT := fmt.Sprintf(`{"alg":"none","typ":"JWT"}.{"exp":%d,"iat":%d,"sub":"test"}.`,
			expiredTime.Unix(), expiredTime.Add(-time.Hour).Unix())
		transfer.job.token.SetToken(expiredJWT)

		time.Sleep(time.Second * 4) // Sleep for longer than the token lifetime
		res, err := downloadObject(transfer)
		require.NoError(t, err)
		require.Error(t, res.Error)

		var pde *PermissionDeniedError
		require.ErrorAs(t, res.Error, &pde)
		assert.Equal(t, true, pde.expired)
		assert.Contains(t, pde.message, "token expired")
	})
}

// Test recursive listings and depth handling using a minimal WebDAV-like server
func TestListHttpRecursiveAndDepth(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		param.Logging_Level.GetName(): "debug",
	})

	// Real WebDAV server using in-memory FS
	memFS := webdav.NewMemFS()
	ctx := context.Background()
	require.NoError(t, memFS.Mkdir(ctx, "/root", 0o755))
	// file1 at /root/file1.txt
	f1, err := memFS.OpenFile(ctx, "/root/file1.txt", os.O_CREATE|os.O_RDWR, 0o644)
	require.NoError(t, err)
	_, err = f1.Write([]byte("hello world!")) // 12 bytes
	require.NoError(t, err)
	require.NoError(t, f1.Close())
	// dirA with file2
	require.NoError(t, memFS.Mkdir(ctx, "/root/dirA", 0o755))
	f2, err := memFS.OpenFile(ctx, "/root/dirA/file2.txt", os.O_CREATE|os.O_RDWR, 0o644)
	require.NoError(t, err)
	_, err = f2.Write([]byte("content")) // 7 bytes
	require.NoError(t, err)
	require.NoError(t, f2.Close())

	wh := &webdav.Handler{FileSystem: memFS, LockSystem: webdav.NewMemLS()}
	svr := httptest.NewServer(wh)
	defer svr.Close()

	collURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	// Build inputs for listHttp
	pUrl := &pelican_url.PelicanURL{Scheme: "pelican", Host: collURL.Host, Path: "/root"}
	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace:      "/root",
			RequireToken:   false,
			CollectionsUrl: collURL,
		},
	}

	// Helper to convert slice to a set for stable assertions
	toSet := func(in []FileInfo) map[string]FileInfo {
		m := make(map[string]FileInfo)
		for _, fi := range in {
			m[fi.Name] = fi
		}
		return m
	}

	t.Run("recursive-unlimited-depth", func(t *testing.T) {
		files, err := listHttp(pUrl, dirResp, nil, true, -1)
		require.NoError(t, err)
		s := toSet(files)
		// Expect both immediate children and nested file
		require.Contains(t, s, "/root/dirA")
		assert.True(t, s["/root/dirA"].IsCollection)
		require.Contains(t, s, "/root/file1.txt")
		assert.False(t, s["/root/file1.txt"].IsCollection)
		require.Contains(t, s, "/root/dirA/file2.txt")
		assert.False(t, s["/root/dirA/file2.txt"].IsCollection)
	})

	t.Run("depth-0-no-recursion", func(t *testing.T) {
		files, err := listHttp(pUrl, dirResp, nil, true, 0)
		require.NoError(t, err)
		s := toSet(files)
		// Only immediate children
		require.Contains(t, s, "/root/dirA")
		require.Contains(t, s, "/root/file1.txt")
		assert.NotContains(t, s, "/root/dirA/file2.txt")
	})

	t.Run("depth-1-current-behavior-matches-depth-0", func(t *testing.T) {
		// Note: current implementation recurses only when currentDepth+1 < maxDepth,
		// so depth=1 behaves like depth=0. This test documents existing behavior.
		files, err := listHttp(pUrl, dirResp, nil, true, 1)
		require.NoError(t, err)
		s := toSet(files)
		// Only immediate children, no nested files
		require.Contains(t, s, "/root/dirA")
		require.Contains(t, s, "/root/file1.txt")
		assert.NotContains(t, s, "/root/dirA/file2.txt")
	})
}

// TestWrapDownloadError tests the wrapDownloadError function to ensure it correctly wraps
// all error types that can be returned from downloadHTTP. This test verifies that the
// refactored function behaves exactly like the original inline error handling code.
func TestWrapDownloadError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Logging.Level": "debug",
	})

	transferEndpointURL := "http://example.com/test"

	t.Run("proxy_connection_error", func(t *testing.T) {
		proxyAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:3128")
		proxyErr := &net.OpError{
			Op:   "proxyconnect",
			Net:  "tcp",
			Addr: proxyAddr,
			Err:  errors.New("connection refused"),
		}

		wrappedErr, isProxyErr, modifiedProxyStr := wrapDownloadError(proxyErr, transferEndpointURL, "")
		require.True(t, isProxyErr, "Should be identified as proxy error")
		assert.Contains(t, modifiedProxyStr, "127.0.0.1:3128", "Should include proxy address in modifiedProxyStr")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionSetup", pe.ErrorType(), "Should be Contact.ConnectionSetup error type")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("proxy_connection_error_no_addr", func(t *testing.T) {
		proxyErr := &net.OpError{
			Op:  "proxyconnect",
			Net: "tcp",
			Err: errors.New("connection refused"),
		}

		_, isProxyErr, modifiedProxyStr := wrapDownloadError(proxyErr, transferEndpointURL, "")
		require.True(t, isProxyErr, "Should be identified as proxy error")
		assert.Empty(t, modifiedProxyStr, "Should be empty when no address")
	})

	t.Run("permission_denied_error_expired_token", func(t *testing.T) {
		expiredTime := time.Now().Add(-time.Hour)
		expiredJWT := fmt.Sprintf(`{"alg":"none","typ":"JWT"}.{"exp":%d,"iat":%d,"sub":"test"}.`,
			expiredTime.Unix(), expiredTime.Add(-time.Hour).Unix())

		pde := &PermissionDeniedError{}
		wrappedErr, isProxyErr, _ := wrapDownloadError(pde, transferEndpointURL, expiredJWT)
		require.False(t, isProxyErr, "Should not be proxy error")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Authorization", pe.ErrorType(), "Should be Authorization error type")

		// Verify the PermissionDeniedError was updated
		var wrappedPde *PermissionDeniedError
		require.True(t, errors.As(wrappedErr, &wrappedPde), "Should contain PermissionDeniedError")
		assert.True(t, wrappedPde.expired, "Token should be marked as expired")
		assert.Contains(t, wrappedPde.message, "token expired", "Message should indicate token expired")
	})

	t.Run("permission_denied_error_invalid_token", func(t *testing.T) {
		emptyToken := ""
		pde := &PermissionDeniedError{}
		wrappedErr, _, _ := wrapDownloadError(pde, transferEndpointURL, emptyToken)

		var wrappedPde *PermissionDeniedError
		require.True(t, errors.As(wrappedErr, &wrappedPde), "Should contain PermissionDeniedError")
		// With empty/invalid token, it should say "token could not be parsed"
		assert.Contains(t, wrappedPde.message, "token could not be parsed", "Message should indicate parsing error")
		assert.False(t, wrappedPde.expired, "Token should not be marked as expired when parsing fails")
		// Note: The "valid but rejected" case is tested in TestPermissionDeniedError integration test
	})

	t.Run("permission_denied_error_invalid_token", func(t *testing.T) {
		pde := &PermissionDeniedError{}
		wrappedErr, _, _ := wrapDownloadError(pde, transferEndpointURL, "invalid-jwt")

		var wrappedPde *PermissionDeniedError
		require.True(t, errors.As(wrappedErr, &wrappedPde), "Should contain PermissionDeniedError")
		assert.Contains(t, wrappedPde.message, "token could not be parsed", "Message should indicate parsing error")
	})

	t.Run("connection_reset_error", func(t *testing.T) {
		resetErr := syscall.ECONNRESET
		wrappedErr, isProxyErr, _ := wrapDownloadError(resetErr, transferEndpointURL, "")
		require.False(t, isProxyErr, "Should not be proxy error")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionReset", pe.ErrorType(), "Should be Contact.ConnectionReset error type")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("epipe_error", func(t *testing.T) {
		pipeErr := syscall.EPIPE
		wrappedErr, _, _ := wrapDownloadError(pipeErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionReset", pe.ErrorType(), "Should be Contact.ConnectionReset error type")
	})

	t.Run("allocate_memory_error", func(t *testing.T) {
		allocErr := &allocateMemoryError{Err: errors.New("out of memory")}
		wrappedErr, _, _ := wrapDownloadError(allocErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error type")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("invalid_chunk_length_error", func(t *testing.T) {
		chunkErr := &InvalidByteInChunkLengthError{Err: errors.New("invalid byte in chunk length")}
		wrappedErr, _, _ := wrapDownloadError(chunkErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error type")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("httperrresp_with_pelicanerror_inner", func(t *testing.T) {
		innerErr := error_codes.NewTransferError(errors.New("inner error"))
		httpErr := &HttpErrResp{
			Code: http.StatusInternalServerError,
			Str:  "request failed",
			Err:  innerErr,
		}

		wrappedErr, _, _ := wrapDownloadError(httpErr, transferEndpointURL, "")
		// Should return the inner error directly since it's already a PelicanError
		assert.Equal(t, innerErr, wrappedErr, "Should return inner error directly")
	})

	t.Run("httperrresp_with_statuscodeerror_inner", func(t *testing.T) {
		sce := StatusCodeError(http.StatusNotFound)
		httpErr := &HttpErrResp{
			Code: http.StatusNotFound,
			Str:  "request failed",
			Err:  &sce,
		}

		wrappedErr, _, _ := wrapDownloadError(httpErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Specification.FileNotFound", pe.ErrorType(), "Should be FileNotFound for 404")
	})

	t.Run("httperrresp_with_generic_inner", func(t *testing.T) {
		genericErr := errors.New("generic error")
		httpErr := &HttpErrResp{
			Code: http.StatusInternalServerError,
			Str:  "request failed",
			Err:  genericErr,
		}

		wrappedErr, _, _ := wrapDownloadError(httpErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error for 5xx")
		assert.True(t, errors.Is(wrappedErr, genericErr), "Should preserve original error")
	})

	t.Run("connectionsetuperror_with_statuscodeerror_inner", func(t *testing.T) {
		sce := StatusCodeError(http.StatusUnauthorized)
		cse := &ConnectionSetupError{
			URL: transferEndpointURL,
			Err: &sce,
		}

		wrappedErr, _, _ := wrapDownloadError(cse, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Authorization", pe.ErrorType(), "Should be Authorization for 401")
	})

	t.Run("connectionsetuperror_with_tls_certificate_error", func(t *testing.T) {
		tlsErr := errors.New("x509: certificate verification failed")
		cse := &ConnectionSetupError{
			URL: transferEndpointURL,
			Err: tlsErr,
		}

		wrappedErr, _, _ := wrapDownloadError(cse, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Specification", pe.ErrorType(), "Should be Specification error for TLS certificate validation")
		assert.False(t, pe.IsRetryable(), "TLS certificate errors should not be retryable")
	})

	t.Run("connectionsetuperror_with_header_timeout", func(t *testing.T) {
		headerTimeoutErr := errors.New("net/http: timeout awaiting response headers")
		urlErr := &url.Error{
			Op:  "GET",
			URL: transferEndpointURL,
			Err: headerTimeoutErr,
		}
		cse := &ConnectionSetupError{
			URL: transferEndpointURL,
			Err: urlErr,
		}

		wrappedErr, _, _ := wrapDownloadError(cse, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Transfer.HeaderTimeout", pe.ErrorType(), "Should be HeaderTimeout error")
	})

	t.Run("connectionsetuperror_generic", func(t *testing.T) {
		cse := &ConnectionSetupError{
			URL: transferEndpointURL,
			Err: errors.New("connection failed"),
		}

		wrappedErr, _, _ := wrapDownloadError(cse, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionSetup", pe.ErrorType(), "Should be ConnectionSetup error")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("dns_error", func(t *testing.T) {
		dnsErr := &net.DNSError{
			Err:         "no such host",
			Name:        "example.invalid",
			Server:      "",
			IsTimeout:   false,
			IsTemporary: false,
		}

		wrappedErr, _, _ := wrapDownloadError(dnsErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionSetup", pe.ErrorType(), "Should be ConnectionSetup error")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("context_deadline_error", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(time.Millisecond) // Ensure deadline is exceeded
		deadlineErr := ctx.Err()

		wrappedErr, _, _ := wrapDownloadError(deadlineErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Contact.ConnectionSetup", pe.ErrorType(), "Should be ConnectionSetup error")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
	})

	t.Run("already_wrapped_pelicanerror", func(t *testing.T) {
		originalErr := errors.New("some error")
		pe := error_codes.NewTransferError(originalErr)

		wrappedErr, _, _ := wrapDownloadError(pe, transferEndpointURL, "")

		// Should return the error directly without double-wrapping
		assert.Equal(t, pe, wrappedErr, "Should return PelicanError directly")
	})

	t.Run("generic_unknown_error", func(t *testing.T) {
		unknownErr := errors.New("some unknown error type")

		wrappedErr, _, _ := wrapDownloadError(unknownErr, transferEndpointURL, "")

		var pe *error_codes.PelicanError
		require.True(t, errors.As(wrappedErr, &pe), "Should be wrapped as PelicanError")
		assert.Equal(t, "Transfer", pe.ErrorType(), "Should be Transfer error type")
		assert.True(t, pe.IsRetryable(), "Should be retryable")
		assert.True(t, errors.Is(wrappedErr, unknownErr), "Should preserve original error")
	})
}

func TestIsIdleConnectionError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Run("detects_idle_connection_error", func(t *testing.T) {
		err := errors.New("http: server closed idle connection")
		assert.True(t, isIdleConnectionError(err), "Should detect idle connection error")
	})

	t.Run("detects_wrapped_idle_connection_error", func(t *testing.T) {
		innerErr := errors.New("http: server closed idle connection")
		wrappedErr := errors.Wrap(innerErr, "additional context")
		assert.True(t, isIdleConnectionError(wrappedErr), "Should detect wrapped idle connection error")
	})

	t.Run("detects_tls_unexpected_message", func(t *testing.T) {
		err := errors.New("tls: unexpected message")
		assert.True(t, isIdleConnectionError(err), "Should detect TLS unexpected message error")
	})

	t.Run("does_not_detect_other_errors", func(t *testing.T) {
		err := errors.New("some other error")
		assert.False(t, isIdleConnectionError(err), "Should not detect non-idle connection errors")
	})

	t.Run("handles_nil_error", func(t *testing.T) {
		assert.False(t, isIdleConnectionError(nil), "Should handle nil error")
	})
}

func TestIsRetryableWebDavError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Run("detects_idle_connection_error", func(t *testing.T) {
		err := errors.New("http: server closed idle connection")
		assert.True(t, isRetryableWebDavError(err), "Should detect idle connection error")
	})

	t.Run("detects_timeout_awaiting_response_headers", func(t *testing.T) {
		err := errors.New("net/http: timeout awaiting response headers")
		assert.True(t, isRetryableWebDavError(err), "Should detect timeout awaiting response headers")
	})

	t.Run("detects_wrapped_timeout_error", func(t *testing.T) {
		innerErr := errors.New("timeout awaiting response headers")
		wrappedErr := errors.Wrap(innerErr, "Propfind failed")
		assert.True(t, isRetryableWebDavError(wrappedErr), "Should detect wrapped timeout error")
	})

	t.Run("does_not_detect_other_errors", func(t *testing.T) {
		err := errors.New("some other error")
		assert.False(t, isRetryableWebDavError(err), "Should not detect non-retriable errors")
	})

	t.Run("handles_nil_error", func(t *testing.T) {
		assert.False(t, isRetryableWebDavError(nil), "Should handle nil error")
	})
}

// TestDirectoryPermissionsRespectUmask tests that directories created during
// downloads respect different umask values
func TestDirectoryPermissionsRespectUmask(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	// Save original umask
	oldUmask := syscall.Umask(0)
	defer syscall.Umask(oldUmask)

	testCases := []struct {
		name         string
		umask        int
		expectedPerm os.FileMode
	}{
		{
			name:         "umask_0022_standard",
			umask:        0022,
			expectedPerm: 0755, // drwxr-xr-x - most common default
		},
		{
			name:         "umask_0002_group_writable",
			umask:        0002,
			expectedPerm: 0775, // drwxrwxr-x
		},
		{
			name:         "umask_0077_restrictive",
			umask:        0077,
			expectedPerm: 0700, // drwx------
		},
		{
			name:         "umask_0027_group_readable",
			umask:        0027,
			expectedPerm: 0750, // drwxr-x---
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
			defer cancel()

			// Set the test umask
			syscall.Umask(tc.umask)

			// Create a mock HTTP server that serves a file
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "13")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, "test content\n")
			}))
			defer server.Close()

			serverURL, err := url.Parse(server.URL)
			require.NoError(t, err)

			tempDir := t.TempDir()
			destPath := filepath.Join(tempDir, "testdir", "subdir", "file.txt")

			pUrl, err := pelican_url.Parse("pelican://test/file.txt", nil, nil)
			require.NoError(t, err)

			// Create a minimal transfer job and transfer file
			job := &TransferJob{
				ctx:       ctx,
				uuid:      uuid.New(),
				remoteURL: pUrl,
			}

			transfer := &transferFile{
				ctx:       ctx,
				job:       job,
				xferType:  transferTypeDownload,
				localPath: destPath,
				remoteURL: serverURL,
				attempts:  []transferAttemptDetails{{Url: serverURL, Proxy: false}},
			}

			// Call downloadObject which will create the directories
			_, err = downloadObject(transfer)
			require.NoError(t, err)

			// Check the top-level directory permissions
			dirPath := filepath.Join(tempDir, "testdir")
			info, err := os.Stat(dirPath)
			require.NoError(t, err)

			actualPerm := info.Mode().Perm()

			// Assert that the directory permission match the expected permissions based on the umask
			assert.Equal(t, tc.expectedPerm, actualPerm,
				fmt.Sprintf("With umask %#o, directory should have permissions %#o but has %#o",
					tc.umask, tc.expectedPerm, actualPerm))

			// Also check the subdirectory has the same permissions
			subdirPath := filepath.Join(tempDir, "testdir", "subdir")
			subinfo, err := os.Stat(subdirPath)
			require.NoError(t, err)

			actualSubPerm := subinfo.Mode().Perm()
			assert.Equal(t, tc.expectedPerm, actualSubPerm,
				fmt.Sprintf("Subdirectory with umask %#o should have %#o but has %#o",
					tc.umask, tc.expectedPerm, actualSubPerm))
		})
	}
}

// TestUpload403WithSyncEnabled verifies that when sync is enabled, a 403 response
// during upload is treated as "file already exists" and doesn't cause an error
func TestUpload403WithSyncEnabled(t *testing.T) {
	test_utils.InitClient(t, map[string]any{
		param.TLSSkipVerify.GetName(): true,
	})

	// Create a temporary file to upload
	tempFile, err := os.CreateTemp("", "test-upload-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString("test content")
	require.NoError(t, err)
	tempFile.Close()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for PROPFIND (stat) requests
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Return 403 Forbidden for PUT (file already exists, no overwrite)
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}))
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	ctx := context.Background()
	transfer := &transferFile{
		ctx:       ctx,
		localPath: tempFile.Name(),
		remoteURL: tsURL,
		xferType:  transferTypeUpload,
		job: &TransferJob{
			ctx:       ctx,
			syncLevel: SyncSize, // Sync is enabled
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   tsURL.Host,
				Path:   "/test/file.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					CollectionsUrl: tsURL,
				},
			},
		},
		callback: nil,
		attempts: []transferAttemptDetails{
			{
				Url:   tsURL,
				Proxy: false,
			},
		},
	}

	transferResult, err := uploadObject(transfer)
	// With sync enabled, 403 should be treated as success (file already exists)
	assert.NoError(t, err, "Upload with sync enabled should not error on 403")
	assert.NoError(t, transferResult.Error, "Transfer result should not contain error on 403 with sync")

	// Verify the object was recorded in the skipped list
	transfer.job.skipped403.Lock()
	assert.Equal(t, 1, len(transfer.job.skipped403Objs), "Should have recorded 1 skipped object")
	assert.Contains(t, transfer.job.skipped403Objs, tsURL.Path, "Should have recorded the correct object path")
	transfer.job.skipped403.Unlock()
}

// TestUpload403WithSyncDisabled verifies that when sync is disabled, a 403 response
// during upload is still treated as an error
func TestUpload403WithSyncDisabled(t *testing.T) {
	test_utils.InitClient(t, map[string]any{
		param.TLSSkipVerify.GetName(): true,
	})

	// Create a temporary file to upload
	tempFile, err := os.CreateTemp("", "test-upload-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString("test content")
	require.NoError(t, err)
	tempFile.Close()

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 403 Forbidden for PUT
		if r.Method == "PUT" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}))
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	ctx := context.Background()
	transfer := &transferFile{
		ctx:       ctx,
		localPath: tempFile.Name(),
		remoteURL: tsURL,
		xferType:  transferTypeUpload,
		job: &TransferJob{
			ctx:       ctx,
			syncLevel: SyncNone, // Sync is disabled
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   tsURL.Host,
				Path:   "/test/file.txt",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					CollectionsUrl: tsURL,
				},
			},
		},
		callback: nil,
		attempts: []transferAttemptDetails{
			{
				Url:   tsURL,
				Proxy: false,
			},
		},
	}

	transferResult, err := uploadObject(transfer)
	// uploadObject always returns nil for err; check transferResult.Error instead
	assert.NoError(t, err, "uploadObject should not return error in err return value")
	// With sync disabled, 403 should still be an error in transferResult.Error
	require.Error(t, transferResult.Error, "Transfer result should contain error on 403 without sync")

	// Verify it contains an HTTP 403 error
	// The error is wrapped in TransferErrors, so we need to unwrap it
	var te *TransferErrors
	require.True(t, errors.As(transferResult.Error, &te), "Error should be TransferErrors")
	require.Greater(t, len(te.errors), 0, "TransferErrors should contain at least one error")

	// Check if any of the errors is a 403
	var found403 bool
	for _, wrappedErr := range te.errors {
		var httpErr *HttpErrResp
		if errors.As(wrappedErr, &httpErr) && httpErr.Code == http.StatusForbidden {
			found403 = true
			break
		}
	}
	assert.True(t, found403, "Should find an HTTP 403 error in the transfer errors")

	// Verify the object was NOT recorded in the skipped list (since sync is disabled)
	transfer.job.skipped403.Lock()
	assert.Equal(t, 0, len(transfer.job.skipped403Objs), "Should not have recorded any skipped objects when sync is disabled")
	transfer.job.skipped403.Unlock()
}

// TestRecursiveUpload403WithSync verifies that recursive directory uploads properly handle 403 errors
// This tests the walkDirUpload -> uploadObject flow
func TestRecursiveUpload403WithSync(t *testing.T) {
	test_utils.InitClient(t, map[string]any{
		param.TLSSkipVerify.GetName(): true,
	})

	// Create a temporary directory with multiple files
	tempDir := t.TempDir()
	file1Path := filepath.Join(tempDir, "file1.txt")
	file2Path := filepath.Join(tempDir, "file2.txt")
	file3Path := filepath.Join(tempDir, "file3.txt")

	err := os.WriteFile(file1Path, []byte("content1"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file2Path, []byte("content2"), 0644)
	require.NoError(t, err)
	err = os.WriteFile(file3Path, []byte("content3"), 0644)
	require.NoError(t, err)

	// Mock server that returns:
	// - 403 for file1 and file2 (already exist)
	// - 201 for file3 (new file, successfully created)
	uploadedFiles := make(map[string]bool)
	var mu sync.Mutex

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for PROPFIND (stat) requests - simulate listing disabled
		if r.Method == "PROPFIND" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Handle PUT requests
		if r.Method == "PUT" {
			mu.Lock()
			defer mu.Unlock()

			// file1 and file2 already exist (403), file3 is new (201)
			if strings.Contains(r.URL.Path, "file1.txt") || strings.Contains(r.URL.Path, "file2.txt") {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if strings.Contains(r.URL.Path, "file3.txt") {
				uploadedFiles[r.URL.Path] = true
				w.WriteHeader(http.StatusCreated)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	require.NoError(t, err)

	// Create a transfer engine and client
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	te, err := NewTransferEngine(ctx)
	require.NoError(t, err)

	// Create a transfer job for recursive upload with sync enabled
	remoteURL, err := pelican_url.Parse("pelican://"+tsURL.Host+"/test/dir", nil, nil)
	require.NoError(t, err)

	tj := &TransferJob{
		ctx:       ctx,
		uuid:      uuid.New(),
		localPath: tempDir,
		remoteURL: remoteURL,
		recursive: true,
		syncLevel: SyncSize, // Sync enabled
		xferType:  transferTypeUpload,
		dirResp: server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				CollectionsUrl: tsURL,
			},
			ObjectServers: []*url.URL{tsURL},
		},
	}

	// Manually create the transfer attempts
	transfers := []transferAttemptDetails{{Url: tsURL, Proxy: false}}

	// Create channel for files
	files := make(chan *clientTransferFile, 10)

	// Run walkDirUpload to queue files
	err = te.walkDirUpload(&clientTransferJob{uuid: uuid.New(), job: tj}, transfers, files, tempDir)
	require.NoError(t, err)

	close(files)

	// Process all queued files
	var results []TransferResults
	for file := range files {
		result, err := uploadObject(file.file)
		require.NoError(t, err, "uploadObject should not return error")
		results = append(results, result)
		tj.activeXfer.Add(-1)
	}

	// Verify results:
	// - 3 transfers attempted (file1, file2, file3)
	// - 2 skipped due to 403 (file1, file2)
	// - 1 successful upload (file3)
	require.Equal(t, 3, len(results), "Should have 3 transfer results")

	tj.skipped403.Lock()
	skippedCount := len(tj.skipped403Objs)
	skippedPaths := make([]string, len(tj.skipped403Objs))
	copy(skippedPaths, tj.skipped403Objs)
	tj.skipped403.Unlock()

	// Verify 2 files were skipped (file1 and file2)
	assert.Equal(t, 2, skippedCount, "Should have skipped 2 files due to 403")

	// Verify file3 was uploaded (path will be /test/dir/file3.txt)
	mu.Lock()
	var file3Uploaded bool
	for path := range uploadedFiles {
		if strings.Contains(path, "file3.txt") {
			file3Uploaded = true
			break
		}
	}
	mu.Unlock()
	assert.True(t, file3Uploaded, "file3.txt should have been uploaded")

	// Verify the skipped files are file1 and file2
	var hasFile1, hasFile2 bool
	for _, path := range skippedPaths {
		if strings.Contains(path, "file1.txt") {
			hasFile1 = true
		}
		if strings.Contains(path, "file2.txt") {
			hasFile2 = true
		}
	}
	assert.True(t, hasFile1, "file1.txt should be in skipped list")
	assert.True(t, hasFile2, "file2.txt should be in skipped list")

	// Verify none of the results have errors
	for i, result := range results {
		assert.NoError(t, result.Error, "Result %d should not have error", i)
	}
}

// TestDownloadHTTPETag verifies that downloadHTTP correctly extracts the
// ETag from the HTTP response and returns it to the caller.
func TestDownloadHTTPETag(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	expectedETag := `"abc123def456"`
	body := []byte("Hello, ETag world!")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", expectedETag)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	downloaded, _, _, _, etag, err := downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(body)), downloaded)
	assert.Equal(t, expectedETag, etag, "ETag should be returned from the response")

	// Verify content
	readBack, err := os.ReadFile(fname)
	require.NoError(t, err)
	assert.Equal(t, body, readBack)
}

// TestDownloadHTTPETagMissing verifies that when the server does not
// provide an ETag header, downloadHTTP returns an empty string.
func TestDownloadHTTPETagMissing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	body := []byte("No ETag here")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, etag, err := downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)
	assert.NoError(t, err)
	assert.Empty(t, etag, "ETag should be empty when the server doesn't provide one")
}

// TestMetadataChannel verifies that downloadHTTP sends TransferMetadata
// on the provided channel before starting the data transfer.
func TestMetadataChannel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	expectedETag := `"meta-etag-789"`
	expectedSize := 42
	body := bytes.Repeat([]byte("x"), expectedSize)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", expectedETag)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("Last-Modified", "Thu, 01 Jan 2025 00:00:00 GMT")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	metadataChan := make(chan TransferMetadata, 1)

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", metadataChan,
	)
	assert.NoError(t, err)

	select {
	case metadata := <-metadataChan:
		assert.Equal(t, expectedETag, metadata.ETag, "metadata ETag should match response header")
		assert.Equal(t, int64(expectedSize), metadata.Size, "metadata Size should match Content-Length")
		assert.Equal(t, "application/octet-stream", metadata.ContentType)
		assert.Equal(t, "max-age=3600", metadata.CacheControl)
		assert.False(t, metadata.LastModified.IsZero(), "Last-Modified should be parsed")
	default:
		t.Fatal("expected metadata on channel but none was sent")
	}
}

// TestMetadataChannelNil verifies that downloadHTTP does not panic when
// the metadata channel is nil.
func TestMetadataChannelNil(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	body := []byte("no channel")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, -1, "", "", nil,
	)
	assert.NoError(t, err, "downloadHTTP should not panic when metadataChan is nil")
}

// TestDownloadHTTPByteRange verifies that downloadHTTP correctly requests
// and receives a byte range from the server.
func TestDownloadHTTPByteRange(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	fullBody := []byte("0123456789ABCDEFGHIJ") // 20 bytes
	rangeEnd := int64(9)                       // bytes 0-9

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			assert.Equal(t, fmt.Sprintf("bytes=0-%d", rangeEnd), rangeHeader)

			partial := fullBody[:rangeEnd+1]
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(partial)))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", rangeEnd, len(fullBody)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(partial)
		} else {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fullBody)))
			w.WriteHeader(http.StatusOK)
			w.Write(fullBody)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	// bytesSoFar=0, byteRangeEnd=9 → Range: bytes=0-9
	downloaded, _, _, _, _, err := downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, rangeEnd, -1, "", "", nil,
	)
	assert.NoError(t, err)
	assert.Equal(t, rangeEnd+1, downloaded, "downloaded bytes should equal the range size")

	readBack, err := os.ReadFile(fname)
	require.NoError(t, err)
	assert.Equal(t, fullBody[:rangeEnd+1], readBack, "downloaded content should match the requested range")
}

// TestDownloadHTTPResume verifies that downloadHTTP sends a Range header
// when bytesSoFar > 0 for resume functionality.
func TestDownloadHTTPResume(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{})
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	fullBody := []byte("Hello, resume world! This is a test of resume functionality.")
	resumeOffset := int64(20)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader != "" {
			assert.Equal(t, fmt.Sprintf("bytes=%d-", resumeOffset), rangeHeader)

			partial := fullBody[resumeOffset:]
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(partial)))
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", resumeOffset, int64(len(fullBody))-1, len(fullBody)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(partial)
		} else {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fullBody)))
			w.WriteHeader(http.StatusOK)
			w.Write(fullBody)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	fname := filepath.Join(t.TempDir(), "test.txt")

	// Pre-populate the file with the initial bytes that were "already downloaded"
	err = os.WriteFile(fname, fullBody[:resumeOffset], 0644)
	require.NoError(t, err)

	// Open for append so downloadHTTP writes after the existing bytes
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_APPEND, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	downloaded, _, _, _, _, err := downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, resumeOffset, -1, -1, "", "", nil,
	)
	assert.NoError(t, err)
	assert.Equal(t, int64(len(fullBody))-resumeOffset, downloaded, "should download remaining bytes after resume offset")
}

// TestUploadETag verifies that uploadObject captures the ETag from a
// successful PUT response.
func TestUploadETag(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[string]any{
		"Client.EnableOverwrites": true,
	})

	expectedETag := `"upload-etag-xyz"`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			// Drain the body
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			w.Header().Set("ETag", expectedETag)
			w.WriteHeader(http.StatusCreated)
		} else if r.Method == "HEAD" {
			// For checksum fetch
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "PROPFIND" {
			// statHttp uses PROPFIND — return 404 to indicate object doesn't exist
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	// Create a temp file to upload
	tmpDir := t.TempDir()
	localPath := filepath.Join(tmpDir, "upload.txt")
	err = os.WriteFile(localPath, []byte("upload content"), 0644)
	require.NoError(t, err)

	remoteURL, err := url.Parse(server.URL + "/test/upload.txt")
	require.NoError(t, err)

	job := &TransferJob{
		uuid:      uuid.New(),
		project:   "test",
		syncLevel: SyncNone,
	}
	job.ctx = context.Background()

	transfer := &transferFile{
		ctx:       context.Background(),
		job:       job,
		localPath: localPath,
		remoteURL: remoteURL,
		attempts:  []transferAttemptDetails{{Url: serverURL, Proxy: false}},
	}

	result, err := uploadObject(transfer)
	assert.NoError(t, err)
	assert.NoError(t, result.Error)
	assert.Equal(t, expectedETag, result.ETag, "upload should capture ETag from PUT response")
}
