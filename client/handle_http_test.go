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
	"fmt"
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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

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

type FedTest struct {
	T         *testing.T
	TmpPath   string
	OriginDir string
	Output    *os.File
	Cancel    context.CancelFunc
	FedCancel context.CancelFunc
	ErrGroup  *errgroup.Group
}

func (f *FedTest) Spinup() {
	//////////////////////////////Setup our test federation//////////////////////////////////////////
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), f.T)

	modules := config.ServerType(0)
	modules.Set(config.OriginType)
	modules.Set(config.DirectorType)
	modules.Set(config.RegistryType)

	// Create our own temp directory (for some reason t.TempDir() does not play well with xrootd)
	tmpPathPattern := "XRootD-Test_Origin*"
	tmpPath, err := os.MkdirTemp("", tmpPathPattern)
	require.NoError(f.T, err)
	f.TmpPath = tmpPath

	// Need to set permissions or the xrootd process we spawn won't be able to write PID/UID files
	permissions := os.FileMode(0755)
	err = os.Chmod(tmpPath, permissions)
	require.NoError(f.T, err)

	viper.Set("ConfigDir", tmpPath)

	config.InitConfig()
	// Create a file to capture output from commands
	output, err := os.CreateTemp(f.T.TempDir(), "output")
	assert.NoError(f.T, err)
	f.Output = output
	viper.Set("Logging.LogLocation", output.Name())

	originDir, err := os.MkdirTemp("", "Origin")
	assert.NoError(f.T, err)
	f.OriginDir = originDir

	// Change the permissions of the temporary origin directory
	permissions = os.FileMode(0777)
	err = os.Chmod(originDir, permissions)
	require.NoError(f.T, err)

	viper.Set("Origin.ExportVolume", originDir+":/test")
	viper.Set("Origin.Mode", "posix")
	viper.Set("Origin.EnableFallbackRead", true)
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.EnableWrite", true)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(f.T.TempDir(), "ns-registry.sqlite"))
	viper.Set("Xrootd.RunLocation", tmpPath)
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)

	err = config.InitServer(ctx, modules)
	require.NoError(f.T, err)

	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	f.FedCancel, err = launchers.LaunchModules(ctx, modules)
	if err != nil {
		f.T.Fatalf("Failure in fedServeInternal: %v", err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200)
	require.NoError(f.T, err)

	httpc := http.Client{
		Transport: config.GetTransport(),
	}
	resp, err := httpc.Get(desiredURL)
	require.NoError(f.T, err)

	assert.Equal(f.T, resp.StatusCode, http.StatusOK)

	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(f.T, err)
	expectedResponse := struct {
		JwksUri string `json:"jwks_uri"`
	}{}
	err = json.Unmarshal(responseBody, &expectedResponse)
	require.NoError(f.T, err)

	f.Cancel = cancel
	f.ErrGroup = egrp
}

func (f *FedTest) Teardown() {
	os.RemoveAll(f.TmpPath)
	os.RemoveAll(f.OriginDir)
	f.Cancel()
	f.FedCancel()
	assert.NoError(f.T, f.ErrGroup.Wait())
	viper.Reset()
}

func TestObjectCopyAuth(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	// Other set-up items:
	testFileContent := "test file content"
	// Create the temporary file to upload
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	assert.NoError(t, err, "Error creating temp file")
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	assert.NoError(t, err, "Error writing to temp file")
	tempFile.Close()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	audience := config.GetServerAudience()

	// Create a token file
	tokenConfig := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuer,
		Audience:     []string{audience},
		Subject:      "origin",
	}

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes)
	token, err := tokenConfig.CreateToken()
	assert.NoError(t, err)
	tempToken, err := os.CreateTemp(t.TempDir(), "token")
	assert.NoError(t, err, "Error creating temp token file")
	defer os.Remove(tempToken.Name())
	_, err = tempToken.WriteString(token)
	assert.NoError(t, err, "Error writing to temp token file")
	tempToken.Close()
	// Disable progress bars to not reuse the same mpb instance
	ObjectClientOptions.ProgressBars = false

	// This tests pelican object get/put with a pelican:// url
	t.Run("testPelicanObjectCopyWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + fileName

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoStashCPSingle(tempFile.Name(), uploadURL, []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoStashCPSingle(uploadURL, t.TempDir(), []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
	})

	// This tests pelican object copy with an osdf url
	t.Run("testPelicanObjectCopyWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + fileName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running since we manually discover "osg-htc.org" therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := newPelicanURL(uploadURL, "osdf")
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.directorUrl)
		assert.Equal(t, "https://osdf-registry.osg-htc.org", pelicanURL.registryUrl)
		assert.Equal(t, "osg-htc.org", pelicanURL.discoveryUrl)
	})

	// This tests osdf object copy with a pelican:// url
	t.Run("testOsdfObjectCopyWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + fileName

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoStashCPSingle(tempFile.Name(), uploadURL, []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoStashCPSingle(uploadURL, t.TempDir(), []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
	})

	// This tests osdf object copy with an osdf url
	t.Run("testOsdfObjectCopyWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "osdf:///test/" + fileName

		// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
		metadata, err := config.DiscoverUrlFederation("https://" + hostname)
		assert.NoError(t, err)
		viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
		viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
		viper.Set("Federation.DiscoveryUrl", hostname)

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoStashCPSingle(tempFile.Name(), uploadURL, []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoStashCPSingle(uploadURL, t.TempDir(), []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
		viper.Reset()
	})
}

// A test that spins up a federation, and tests object get and put
func TestGetAndPutAuth(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	// Other set-up items:
	testFileContent := "test file content"
	// Create the temporary file to upload
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	assert.NoError(t, err, "Error creating temp file")
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	assert.NoError(t, err, "Error writing to temp file")
	tempFile.Close()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	audience := config.GetServerAudience()

	// Create a token file
	tokenConfig := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuer,
		Audience:     []string{audience},
		Subject:      "origin",
	}

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes)
	token, err := tokenConfig.CreateToken()
	assert.NoError(t, err)
	tempToken, err := os.CreateTemp(t.TempDir(), "token")
	assert.NoError(t, err, "Error creating temp token file")
	defer os.Remove(tempToken.Name())
	_, err = tempToken.WriteString(token)
	assert.NoError(t, err, "Error writing to temp token file")
	tempToken.Close()
	// Disable progress bars to not reuse the same mpb instance
	ObjectClientOptions.ProgressBars = false

	// This tests pelican object get/put with a pelican:// url
	t.Run("testPelicanObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + fileName

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoPut(tempFile.Name(), uploadURL, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoGet(uploadURL, t.TempDir(), false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testPelicanObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + fileName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := newPelicanURL(uploadURL, "osdf")
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.directorUrl)
		assert.Equal(t, "https://osdf-registry.osg-htc.org", pelicanURL.registryUrl)
		assert.Equal(t, "osg-htc.org", pelicanURL.discoveryUrl)
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + fileName

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoPut(tempFile.Name(), uploadURL, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoGet(uploadURL, t.TempDir(), false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "osdf:///test/" + fileName

		// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
		metadata, err := config.DiscoverUrlFederation("https://" + hostname)
		assert.NoError(t, err)
		viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
		viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
		viper.Set("Federation.DiscoveryUrl", hostname)

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferResultsUpload, err := DoStashCPSingle(tempFile.Name(), uploadURL, []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := DoStashCPSingle(uploadURL, t.TempDir(), []string{"http"}, false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
		}
		ObjectClientOptions.Token = ""
		viper.Reset()
	})
}

// A test that spins up the federation, where the origin is in EnablePublicReads mode. Then GET a file from the origin without a token
func TestGetPublicRead(t *testing.T) {
	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()
	t.Run("testPubObjGet", func(t *testing.T) {
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(fed.OriginDir, "test1234.txt"))
		assert.NoError(t, err, "Error creating temp file")
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		ObjectClientOptions.ProgressBars = false

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + fileName

		// Download the file with GET. Shouldn't need a token to succeed
		transferResults, err := DoGet(uploadURL, t.TempDir(), false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResults[0].TransferredBytes, int64(17))
		}
	})
}

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	// Create a token file
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	audience := config.GetServerAudience()

	tokenConfig := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuer,
		Audience:     []string{audience},
		Subject:      "origin",
	}
	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes)
	token, err := tokenConfig.CreateToken()
	assert.NoError(t, err)
	tempToken, err := os.CreateTemp(t.TempDir(), "token")
	assert.NoError(t, err, "Error creating temp token file")
	defer os.Remove(tempToken.Name())
	_, err = tempToken.WriteString(token)
	assert.NoError(t, err, "Error writing to temp token file")
	tempToken.Close()

	// Disable progress bars to not reuse the same mpb instance
	ObjectClientOptions.ProgressBars = false

	// Make our test directories and files
	tempDir, err := os.MkdirTemp("", "UploadDir")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)
	permissions := os.FileMode(0777)
	err = os.Chmod(tempDir, permissions)
	require.NoError(t, err)

	testFileContent1 := "test file content"
	testFileContent2 := "more test file content!"
	tempFile1, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp1 file")
	tempFile2, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp2 file")
	defer os.Remove(tempFile1.Name())
	defer os.Remove(tempFile2.Name())
	_, err = tempFile1.WriteString(testFileContent1)
	assert.NoError(t, err, "Error writing to temp1 file")
	tempFile1.Close()
	_, err = tempFile2.WriteString(testFileContent2)
	assert.NoError(t, err, "Error writing to temp2 file")
	tempFile2.Close()

	t.Run("testPelicanRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + dirName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := newPelicanURL(uploadURL, "osdf")
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.directorUrl)
		assert.Equal(t, "https://osdf-registry.osg-htc.org", pelicanURL.registryUrl)
		assert.Equal(t, "osg-htc.org", pelicanURL.discoveryUrl)
	})

	t.Run("testPelicanRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		ObjectClientOptions.Token = tempToken.Name()
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + dirName

		// Upload the file with PUT
		transferDetailsUpload, err := DoPut(tempDir, uploadURL, true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytes17 := 0
			countBytes23 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case int64(17):
					countBytes17++
					continue
				case int64(23):
					countBytes23++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not upload proper amount of bytes")
				}
			}
			if countBytes17 != 1 || countBytes23 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not uploaded correctly")
			}
		} else if len(transferDetailsUpload) != 2 {
			t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
		}

		// Download the files we just uploaded
		transferDetailsDownload, err := DoGet(uploadURL, t.TempDir(), true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytesUploadIdx0 := 0
			countBytesUploadIdx1 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			// In this case, we want to match them to the sizes of the uploaded files
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case transferDetailsUpload[0].TransferredBytes:
					countBytesUploadIdx0++
					continue
				case transferDetailsUpload[1].TransferredBytes:
					countBytesUploadIdx1++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not download proper amount of bytes")
				}
			}
			if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not downloaded correctly")
			} else if len(transferDetailsDownload) != 2 {
				t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
			}
		}
		ObjectClientOptions.Token = ""
	})

	t.Run("testOsdfRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		ObjectClientOptions.Token = tempToken.Name()
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "pelican://" + hostname + "/test/" + dirName

		// Upload the file with PUT
		transferDetailsUpload, err := DoPut(tempDir, uploadURL, true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytes17 := 0
			countBytes23 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case int64(17):
					countBytes17++
					continue
				case int64(23):
					countBytes23++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not upload proper amount of bytes")
				}
			}
			if countBytes17 != 1 || countBytes23 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not uploaded correctly")
			}
		} else if len(transferDetailsUpload) != 2 {
			t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
		}

		// Download the files we just uploaded
		transferDetailsDownload, err := DoGet(uploadURL, t.TempDir(), true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytesUploadIdx0 := 0
			countBytesUploadIdx1 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			// In this case, we want to match them to the sizes of the uploaded files
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case transferDetailsUpload[0].TransferredBytes:
					countBytesUploadIdx0++
					continue
				case transferDetailsUpload[1].TransferredBytes:
					countBytesUploadIdx1++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not download proper amount of bytes")
				}
			}
			if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not downloaded correctly")
			} else if len(transferDetailsDownload) != 2 {
				t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
			}
		}
		ObjectClientOptions.Token = ""
	})

	t.Run("testOsdfRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())
		uploadURL := "osdf:///test/" + dirName

		// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
		metadata, err := config.DiscoverUrlFederation("https://" + hostname)
		assert.NoError(t, err)
		viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
		viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
		viper.Set("Federation.DiscoveryUrl", hostname)

		// Upload the file with PUT
		ObjectClientOptions.Token = tempToken.Name()
		transferDetailsUpload, err := DoPut(tempDir, uploadURL, true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytes17 := 0
			countBytes23 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case int64(17):
					countBytes17++
					continue
				case int64(23):
					countBytes23++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not upload proper amount of bytes")
				}
			}
			if countBytes17 != 1 || countBytes23 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not uploaded correctly")
			}
		} else if len(transferDetailsUpload) != 2 {
			t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
		}

		// Download the files we just uploaded
		transferDetailsDownload, err := DoGet(uploadURL, t.TempDir(), true)
		assert.NoError(t, err)
		if err == nil && len(transferDetailsUpload) == 2 {
			countBytesUploadIdx0 := 0
			countBytesUploadIdx1 := 0
			// Verify we got the correct files back (have to do this since files upload in different orders at times)
			// In this case, we want to match them to the sizes of the uploaded files
			for _, transfer := range transferDetailsUpload {
				transferredBytes := transfer.TransferredBytes
				switch transferredBytes {
				case transferDetailsUpload[0].TransferredBytes:
					countBytesUploadIdx0++
					continue
				case transferDetailsUpload[1].TransferredBytes:
					countBytesUploadIdx1++
					continue
				default:
					// We got a byte amount we are not expecting
					t.Fatal("did not download proper amount of bytes")
				}
			}
			if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
				// We would hit this case if 1 counter got hit twice for some reason
				t.Fatal("One of the files was not downloaded correctly")
			} else if len(transferDetailsDownload) != 2 {
				t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
			}
		}
		viper.Reset()
		ObjectClientOptions.Token = ""
	})
}
