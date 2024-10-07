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
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestMain(m *testing.M) {
	viper.Reset()
	if err := config.InitClient(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestIsPort calls main.hasPort with a hostname, checking
// for a valid return value.
func TestIsPort(t *testing.T) {

	if hasPort("blah.not.port:") {
		t.Fatal("Failed to parse port when : at end")
	}

	if !hasPort("host:1") {
		t.Fatal("Failed to parse with port = 1")
	}

	if hasPort("https://example.com") {
		t.Fatal("Failed when scheme is specified")
	}
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
	viper.Reset()
	err := config.InitClient()
	assert.Nil(t, err)
}

func TestSlowTransfers(t *testing.T) {
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
		_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], filepath.Join(t.TempDir(), "test.txt"), -1, "", "")
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
	channel <- true

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
		_, _, _, _, err = downloadHTTP(ctx, nil, nil, transfers[0], filepath.Join(t.TempDir(), "test.txt"), -1, "", "")
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
	channel <- true

	// Make sure the errors are correct
	assert.NotNil(t, err)
	assert.IsType(t, &StoppedTransferError{}, err, err.Error())
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

	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: &url.URL{Host: addr, Scheme: "http"}, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), -1, "", "")

	assert.IsType(t, &ConnectionSetupError{}, err)

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
	_, _, _, _, err := downloadHTTP(ctx, nil, nil, transfers[0], filepath.Join(t.TempDir(), "test.txt"), -1, "", "")

	assert.NotNil(t, err)
	assert.EqualError(t, err, "transfer error: Unable to read test.txt; input/output error")
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
	go runPut(request, responseChan, errorChan)
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
	go runPut(request, responseChan, errorChan)
	select {
	case err := <-errorChan:
		assert.Error(t, err)
	case response := <-responseChan:
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	case <-time.After(time.Second * 2):
		assert.Fail(t, "Timeout while waiting for response")
	}
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
			w.Header().Set("Content-Length", "42")
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

	token := newTokenGenerator(nil, nil, false, false)
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), -1, "", "")
	assert.NoError(t, err)
	viper.Reset()
}

func TestJobIdHeaderSetForDownload(t *testing.T) {
	test_utils.InitClient(t, map[string]any{})

	// Create a test .job.ad file
	jobAdFile, err := os.CreateTemp("", ".job.ad")
	assert.NoError(t, err)

	// Write the job ad to the file
	_, err = jobAdFile.WriteString("GlobalJobId = 12345")
	assert.NoError(t, err)
	jobAdFile.Close()

	os.Setenv("_CONDOR_JOB_AD", jobAdFile.Name())
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), -1, "", "")
	assert.NoError(t, err)
	viper.Reset()
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
	_, _, _, _, err = downloadHTTP(ctx, nil, nil, transferAttemptDetails{Url: serverURL, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), -1, "", "test")
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
	_, err = tempFile.WriteString("ProjectName = \"testProject\"\nGlobalJobId = 12345")
	assert.NoError(t, err)
	tempFile.Close()
	t.Run("TestNoJobAd", func(t *testing.T) {
		// Unset this environment var
		os.Unsetenv("_CONDOR_JOB_AD")
		// Call GetProjectName and check the result
		projectName := searchJobAd(projectName)
		assert.Equal(t, "", projectName)
	})

	t.Run("TestProjectNameAd", func(t *testing.T) {
		// Set the _CONDOR_JOB_AD environment variable to the temp file's name
		os.Setenv("_CONDOR_JOB_AD", tempFile.Name())
		defer os.Unsetenv("_CONDOR_JOB_AD")

		// Call GetProjectName and check the result
		projectName := searchJobAd(projectName)
		assert.Equal(t, "testProject", projectName)
	})

	t.Run("TestGlobalJobIdAd", func(t *testing.T) {
		// Set the _CONDOR_JOB_AD environment variable to the temp file's name
		os.Setenv("_CONDOR_JOB_AD", tempFile.Name())
		defer os.Unsetenv("_CONDOR_JOB_AD")

		// Call GetProjectName and check the result
		jobId := searchJobAd(jobId)
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
		ctx:       context.Background(),
		job:       &TransferJob{},
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
	var sce *StatusCodeError
	if errors.As(err, &sce) {
		assert.Equal(t, "cache timed out waiting on origin", sce.Error())
	} else {
		require.Fail(t, "downloadObject did not return a status code error: %s", err)
	}
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
		ctx:       context.Background(),
		job:       &TransferJob{},
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

	token := newTokenGenerator(nil, nil, false, false)
	token.SetToken("test-token")
	transfer := &transferFile{
		ctx:       context.Background(),
		job:       &TransferJob{},
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
		<-shutdownChan
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	defer close(shutdownChan)
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		ctx:       context.Background(),
		job:       &TransferJob{},
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
		<-shutdownChan
		w.WriteHeader(http.StatusOK)
	}))
	defer svr.CloseClientConnections()
	defer svr.Close()
	defer close(shutdownChan)
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	transfer := &transferFile{
		ctx:       context.Background(),
		job:       &TransferJob{},
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
	viper.Reset()
	defer viper.Reset()
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
