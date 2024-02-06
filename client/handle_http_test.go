//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
	"encoding/json"
	"io"
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
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

func TestMain(m *testing.M) {
	if err := config.InitClient(); err != nil {
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestIsPort calls main.hasPort with a hostname, checking
// for a valid return value.
func TestIsPort(t *testing.T) {

	if HasPort("blah.not.port:") {
		t.Fatal("Failed to parse port when : at end")
	}

	if !HasPort("host:1") {
		t.Fatal("Failed to parse with port = 1")
	}

	if HasPort("https://example.com") {
		t.Fatal("Failed when scheme is specified")
	}
}

// TestNewTransferDetails checks the creation of transfer details
func TestNewTransferDetails(t *testing.T) {
	os.Setenv("http_proxy", "http://proxy.edu:3128")

	// Case 1: cache with http
	testCache := namespaces.Cache{
		AuthEndpoint: "cache.edu:8443",
		Endpoint:     "cache.edu:8000",
		Resource:     "Cache",
	}
	transfers := NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 2: cache with https
	transfers = NewTransferDetails(testCache, TransferDetailsOptions{true, ""})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "cache.edu:8443", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)

	testCache.Endpoint = "cache.edu"
	// Case 3: cache without port with http
	transfers = NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 4. cache without port with https
	testCache.AuthEndpoint = "cache.edu"
	transfers = NewTransferDetails(testCache, TransferDetailsOptions{true, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "cache.edu:8444", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	assert.Equal(t, "cache.edu:8443", transfers[1].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)
}

func TestNewTransferDetailsEnv(t *testing.T) {

	testCache := namespaces.Cache{
		AuthEndpoint: "cache.edu:8443",
		Endpoint:     "cache.edu:8000",
		Resource:     "Cache",
	}

	os.Setenv("OSG_DISABLE_PROXY_FALLBACK", "")
	err := config.InitClient()
	assert.Nil(t, err)
	transfers := NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, true, transfers[0].Proxy)

	transfers = NewTransferDetails(testCache, TransferDetailsOptions{true, ""})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	os.Unsetenv("OSG_DISABLE_PROXY_FALLBACK")
	viper.Reset()
	err = config.InitClient()
	assert.Nil(t, err)
}

func TestSlowTransfers(t *testing.T) {
	// Adjust down some timeouts to speed up the test
	viper.Set("Client.SlowTransferWindow", 5)
	viper.Set("Client.SlowTransferRampupTime", 10)

	channel := make(chan bool)
	slowDownload := 1024 * 10 // 10 KiB/s < 100 KiB/s
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	testCache := namespaces.Cache{
		AuthEndpoint: svr.URL,
		Endpoint:     svr.URL,
		Resource:     "Cache",
	}
	transfers := NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	finishedChannel := make(chan bool)
	var err error
	// Do a quick timeout
	go func() {
		_, _, _, err = DownloadHTTP(transfers[0], filepath.Join(t.TempDir(), "test.txt"), "", nil)
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
	assert.IsType(t, &SlowTransferError{}, err)
}

// Test stopped transfer
func TestStoppedTransfer(t *testing.T) {
	// Adjust down the timeouts
	viper.Set("Client.StoppedTransferTimeout", 3)
	viper.Set("Client.SlowTransferRampupTime", 100)

	channel := make(chan bool)
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	testCache := namespaces.Cache{
		AuthEndpoint: svr.URL,
		Endpoint:     svr.URL,
		Resource:     "Cache",
	}
	transfers := NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	finishedChannel := make(chan bool)
	var err error

	go func() {
		_, _, _, err = DownloadHTTP(transfers[0], filepath.Join(t.TempDir(), "test.txt"), "", nil)
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
}

// Test connection error
func TestConnectionError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dialClosedPort: Listen failed: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	_, _, _, err = DownloadHTTP(TransferDetails{Url: url.URL{Host: addr, Scheme: "http"}, Proxy: false}, filepath.Join(t.TempDir(), "test.txt"), "", nil)

	assert.IsType(t, &ConnectionSetupError{}, err)

}

func TestTrailerError(t *testing.T) {
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

	testCache := namespaces.Cache{
		AuthEndpoint: svr.URL,
		Endpoint:     svr.URL,
		Resource:     "Cache",
	}
	transfers := NewTransferDetails(testCache, TransferDetailsOptions{false, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, svr.URL, transfers[0].Url.String())

	// Call DownloadHTTP and check if the error is returned correctly
	_, _, _, err := DownloadHTTP(transfers[0], filepath.Join(t.TempDir(), "test.txt"), "", nil)

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
	go doPut(request, responseChan, errorChan)
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
	go doPut(request, responseChan, errorChan)
	select {
	case err := <-errorChan:
		assert.Error(t, err)
	case response := <-responseChan:
		assert.Equal(t, http.StatusInternalServerError, response.StatusCode)
	case <-time.After(time.Second * 2):
		assert.Fail(t, "Timeout while waiting for response")
	}
}

func generateFileTestScitoken() (string, error) {
	// Issuer is whichever server that initiates the test, so it's the server itself
	issuerUrl, err := config.GetServerIssuerURL()
	if err != nil {
		return "", err
	}
	if issuerUrl == "" { // if empty, then error
		return "", errors.New("Failed to create token: Invalid iss, Server_ExternalWebUrl is empty")
	}

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	if err != nil {
		return "", errors.Wrap(err, "failed to create 'read' scope for file test token:")
	}
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	if err != nil {
		return "", errors.Wrap(err, "failed to create 'modify' scope for file test token:")
	}
	scopes = append(scopes, modScope)

	fTestTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuerUrl,
		Audience:     []string{param.Origin_Url.GetString()},
		Version:      "1.0",
		Subject:      "origin",
	}
	fTestTokenCfg.AddScopes(scopes)

	// CreateToken also handles validation for us
	tok, err := fTestTokenCfg.CreateToken()
	if err != nil {
		return "", errors.Wrap(err, "failed to create file test token:")
	}

	return tok, nil
}

func TestFullUpload(t *testing.T) {
	// Setup our test federation
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRootD-Test_Origin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(t, err)

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(t, err)

	viper.Set("ConfigDir", tmpPath)

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
	config.InitConfig()

	originDir, err := os.MkdirTemp("", "Origin")
	assert.NoError(t, err)

	// Change the permissions of the temporary directory
	permissions = os.FileMode(0777)
	err = os.Chmod(originDir, permissions)
	require.NoError(t, err)

	viper.Set("Origin.ExportVolume", originDir+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.EnableWrite", true)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Xrootd.RunLocation", tmpPath)
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)
	viper.Set("Logging.Origin.Scitokens", "debug")

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	fedCancel, err := launchers.LaunchModules(ctx, modules)
	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200)
	require.NoError(t, err)

	httpc := http.Client{
		Transport: config.GetTransport(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(t, err)

	assert.Equal(t, resp.StatusCode, http.StatusOK)

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	expectedResponse := struct {
		JwksUri string `json:"jwks_uri"`
	}{}
	err = json.Unmarshal(responseBody, &expectedResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, expectedResponse.JwksUri)

	t.Run("testFullUpload", func(t *testing.T) {
		testFileContent := "test file content"

		// Create the temporary file to upload
		tempFile, err := os.CreateTemp(t.TempDir(), "test")
		assert.NoError(t, err, "Error creating temp file")
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		// Create a token file
		token, err := generateFileTestScitoken()
		assert.NoError(t, err)
		tempToken, err := os.CreateTemp(t.TempDir(), "token")
		assert.NoError(t, err, "Error creating temp token file")
		defer os.Remove(tempToken.Name())
		_, err = tempToken.WriteString(token)
		assert.NoError(t, err, "Error writing to temp token file")
		tempToken.Close()
		ObjectClientOptions.Token = tempToken.Name()

		// Upload the file
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "stash:///test/" + fileName

		methods := []string{"http"}
		transferResults, err := DoStashCPSingle(tempFile.Name(), uploadURL, methods, false)
		assert.NoError(t, err, "Error uploading file")
		assert.Equal(t, int64(len(testFileContent)), transferResults[0].TransferedBytes, "Uploaded file size does not match")

		// Upload an osdf file
		uploadURL = "osdf:///test/stuff/blah.txt"
		assert.NoError(t, err, "Error parsing upload URL")
		transferResults, err = DoStashCPSingle(tempFile.Name(), uploadURL, methods, false)
		assert.NoError(t, err, "Error uploading file")
		assert.Equal(t, int64(len(testFileContent)), transferResults[0].TransferedBytes, "Uploaded file size does not match")
	})
	t.Cleanup(func() {
		ObjectClientOptions.Token = ""
		os.RemoveAll(tmpPath)
		os.RemoveAll(originDir)
	})

	cancel()
	fedCancel()
	assert.NoError(t, egrp.Wait())
	viper.Reset()
}
