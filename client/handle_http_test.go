//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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
	server_utils.ResetTestState()
	if err := config.InitClient(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestNewTransferDetails checks the creation of transfer details
func TestNewTransferDetails(t *testing.T) {
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
	defer goleak.VerifyNone(t,
		// Ignore the progress bars
		goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.(*Progress).serve"),
		goleak.IgnoreTopFunction("github.com/vbauerster/mpb/v8.heapManager.run"),
	)
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
		_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, "", "")
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

		_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, "", "")
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

	_, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Host: addr, Scheme: "http"}, Proxy: false},
		fname, writer, 0, -1, "", "",
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Scheme: "http", Host: serverAddr}, Proxy: false},
		fname, writer, 0, -1, "", "",
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

func TestTrailerError(t *testing.T) {
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

	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, "", "")

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

	token := NewTokenGenerator(nil, nil, config.TokenSharedRead, false)
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, "", "",
	)
	assert.NoError(t, err)
	server_utils.ResetTestState()
}

func TestJobIdHeaderSetForDownload(t *testing.T) {
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, "", "",
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false},
		fname, writer, 0, -1, "", "test")
	assert.NoError(t, err)

	// Test the user-agent header is what we expect it to be
	assert.Equal(t, "pelican-client/"+config.GetVersion()+" project/test", *server_test.user_agent)
}

// The test should prove that the function getObjectServersToTry returns the correct number of servers,
// and that any duplicates are removed
func TestGetObjectServersToTry(t *testing.T) {
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
				if te.errors != nil && len(te.errors) > 0 {
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

func TestInvalidByteInChunkLengthError(t *testing.T) {
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil,
		transferAttemptDetails{Url: &url.URL{Scheme: "http", Host: serverAddr}, Proxy: false},
		fname, writer, 0, -1, "", "",
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
		requireChecksum: true,
	}
	transferResult, err := downloadObject(transfer)
	assert.NoError(t, err)
	assert.Error(t, transferResult.Error)
	assert.True(t, errors.Is(transferResult.Error, ErrServerChecksumMissing), "Expected checksum missing error")
}

func TestChecksumPut(t *testing.T) {
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
		ctx: context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   svr1URL.Host,
				Path:   svr1URL.Path + "/test.txt",
			},
		},
		localPath: "/dev/null",
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
	assert.Equal(t, "unexpected EOF", tae.Unwrap().Error())
	assert.Equal(t, int64(9), transferResult.Attempts[0].TransferFileBytes)
	assert.NoError(t, transferResult.Attempts[1].Error)
	assert.Equal(t, int64(8), transferResult.Attempts[1].TransferFileBytes)
	assert.Equal(t, int64(17), transferResult.TransferredBytes)
}

// Test failed connection setup error message for downloads
func TestFailedConnectionSetupError(t *testing.T) {
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
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		}
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	token := NewTokenGenerator(nil, nil, config.TokenSharedRead, false)
	token.SetToken("test-token")
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
		token: token,
	}
	_, _ = downloadObject(transfer)
}

// Test error message generated on a failed upload
//
// Creates a server that does nothing but stall; examines the
// corresponding error message out to the user.
func TestFailedUploadError(t *testing.T) {

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

	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, "", "")
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

	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], fname, writer, 0, -1, "", "")
	require.Error(t, err)
	t.Logf("error: %v", err)
	assert.True(t, IsRetryable(err), "Unexpected EOF error should be retryable")
}

func TestTLSCertificateError(t *testing.T) {
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
		// runPut returns unwrapped ConnectionSetupError; wrapping happens in upload error handler
		// Verify it's a ConnectionSetupError and that when wrapped, it's retryable
		var cse *ConnectionSetupError
		require.True(t, errors.As(err, &cse), "Error should be a ConnectionSetupError")
		// Simulate upload error handler wrapping
		wrappedErr := error_codes.NewContact_ConnectionSetupError(cse)
		assert.True(t, IsRetryable(wrappedErr), "Wrapped TLS certificate error should be retryable")
	case response := <-responseChan:
		t.Fatalf("Expected error but got response: %v", response)
	case <-time.After(time.Second * 2):
		t.Fatal("Timeout while waiting for response")
	}
}

func TestPutOverwrite(t *testing.T) {
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
		token := NewTokenGenerator(nil, nil, config.TokenSharedWrite, false)
		token.SetToken("test-token")

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
			token:     token,
		}

		result, err := uploadObject(transfer)
		require.Error(t, err)
		require.Equal(t, "remote object already exists, upload aborted", result.Error.Error())
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
		token := NewTokenGenerator(nil, nil, config.TokenSharedWrite, false)
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
		token := NewTokenGenerator(nil, nil, config.TokenSharedWrite, false)
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
		origLevel := log.GetLevel()
		log.SetLevel(log.WarnLevel)
		defer func() {
			log.SetOutput(origOut)
			log.SetLevel(origLevel)
		}()

		result, err := uploadObject(transfer)
		require.NoError(t, err) // We should not get an error from the uploadObject call
		require.NoError(t, result.Error)

		// Ensure the expected warning was logged
		assert.Contains(t, logBuf.String(), "Failed to check if object exists at the origin, proceeding with upload")
	})
}

func TestPackAutoSegfaultRegression(t *testing.T) {
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
		token:     NewTokenGenerator(remoteURL, nil, config.TokenSharedRead, false),
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
