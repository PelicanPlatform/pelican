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

package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

var (
	//go:embed resources/test-https-origin.yml
	httpsOriginConfig string
)

// TestReadMultiTransfer test if we can read multiple transfers from stdin
func TestReadMultiTransfer(t *testing.T) {
	t.Parallel()

	// Test with multiple transfers
	t.Run("TestMultiTransfers", func(t *testing.T) {
		stdin := "[ LocalFileName = \"/path/to/local/copy/of/foo\"; Url = \"url://server/some/directory//foo\" ]\n[ LocalFileName = \"/path/to/local/copy/of/bar\"; Url = \"url://server/some/directory//bar\" ]\n[ LocalFileName = \"/path/to/local/copy/of/qux\"; Url = \"url://server/some/directory//qux\" ]"
		transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.NoError(t, err)
		assert.Equal(t, 3, len(transfers))
		assert.Equal(t, "/path/to/local/copy/of/foo", transfers[0].localFile)
		assert.Equal(t, "url://server/some/directory//foo", transfers[0].url.String())
		assert.Equal(t, "/path/to/local/copy/of/bar", transfers[1].localFile)
		assert.Equal(t, "url://server/some/directory//bar", transfers[1].url.String())
		assert.Equal(t, "/path/to/local/copy/of/qux", transfers[2].localFile)
		assert.Equal(t, "url://server/some/directory//qux", transfers[2].url.String())
	})

	// Test with single transfers
	t.Run("TestSingleTransfer", func(t *testing.T) {
		stdin := "[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
		transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(transfers))
		assert.Equal(t, "url://server/some/directory//blah", transfers[0].url.String())
		assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].localFile)
	})

	// Test that we fail if we do not have a Url or LocalFileName
	t.Run("TestNoUrlOrLocalFileNameSet", func(t *testing.T) {
		stdin := "[ SomeAttributeHereOfSomeImportance = \"This/is/some/junk/for/a/test\" ] "
		_, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "No transfers found")
	})

	// Test that we fail when we only have a Url
	t.Run("TestNoLocalFileNameSet", func(t *testing.T) {
		stdin := "[ Url = \"url://server/some/directory//blah\" ]"
		_, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "No transfers found")
	})

	// Test that we fail when we only have a LocalFileName
	t.Run("TestNoUrlSet", func(t *testing.T) {
		stdin := "[ LocalFileName = \"/path/to/local/copy/of/blah\" ]"
		_, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "No transfers found")
	})

	// Test that we do not fail if we have some attributes before the Url and LocalFileName
	t.Run("TestSomeAttrBeforeUrlAndLocalFileName", func(t *testing.T) {
		stdin := "[ SomeAttributeHereOfSomeImportance = \"This/is/some/junk/for/a/test\" ]\n[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
		transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
		assert.NoError(t, err)
		assert.Equal(t, 1, len(transfers))
		assert.Equal(t, "url://server/some/directory//blah", transfers[0].url.String())
		assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].localFile)
	})
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

	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StoragePrefix", originDir)
	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.EnableDirectReads", true)
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.EnableWrites", true)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(f.T.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", tmpPath)

	err = config.InitServer(ctx, modules)
	require.NoError(f.T, err)

	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	_, f.FedCancel, err = launchers.LaunchModules(ctx, modules)
	if err != nil {
		f.T.Fatalf("Failure in fedServeInternal: %v", err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/.well-known/openid-configuration"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200, false)
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
	server_utils.ResetOriginExports()
	f.Cancel()
	f.FedCancel()
	assert.NoError(f.T, f.ErrGroup.Wait())
	viper.Reset()
}

// Test the main function for the pelican plugin
func TestStashPluginMain(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()

	oldPrefix, err := config.SetPreferredPrefix(config.StashPrefix)
	defer func() {
		_, err = config.SetPreferredPrefix(oldPrefix)
		require.NoError(t, err)
	}()
	assert.NoError(t, err)

	// Temp dir for downloads
	tempDir := os.TempDir()
	defer os.Remove(tempDir)

	// Parts of test adapted from: https://stackoverflow.com/questions/26225513/how-to-test-os-exit-scenarios-in-go
	// Basically, we need to run the test like this since StashPluginMain calls os.Exit() which is not good for our tests
	// and leaves xrootd running. To work with this, we wrap the test in its own command and parse the output for successful run
	if os.Getenv("RUN_STASHPLUGIN") == "1" {
		viper.Set("Origin.EnablePublicReads", true)
		// Since we have the prefix as STASH, we need to unset various osg-htc.org URLs to
		// avoid real web lookups.
		viper.Set("Federation.DiscoveryUrl", "")
		viper.Set("Xrootd.SummaryMonitoringHost", "")
		viper.Set("Xrootd.DetailedMonitoringHost", "")
		viper.Set("Logging.Level", "debug")
		fed := FedTest{T: t}
		fed.Spinup()
		defer fed.Teardown()

		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(fed.OriginDir, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), fileName)

		// Download a test file
		args := []string{uploadURL, tempDir}
		stashPluginMain(args)
		return
	}

	// Create a process to run the command (since stashPluginMain calls os.Exit(0))
	cmd := exec.Command(os.Args[0], "-test.run=TestStashPluginMain")
	cmd.Env = append(os.Environ(), "RUN_STASHPLUGIN=1", "STASH_LOGGING_LEVEL=debug")

	// Create buffers for stderr (the output we want for test)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	err = cmd.Run()
	assert.NoError(t, err, stderr.String()+"\n=====\n"+stdout.String())

	// changing output for "\\" since in windows there are excess "\" printed in debug logs
	output := strings.Replace(stderr.String(), "\\\\", "\\", -1)

	// Check captured output for successful download
	expectedOutput := "Downloading object from pelican:///test/test.txt to " + tempDir
	assert.Contains(t, output, expectedOutput)
	successfulDownloadMsg := "HTTP Transfer was successful"
	assert.Contains(t, output, successfulDownloadMsg)
	amountDownloaded := "Downloaded bytes: 17"
	assert.Contains(t, output, amountDownloaded)
}

// Test multiple downloads from the plugin
func TestPluginMulti(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()

	dirName := t.TempDir()

	viper.Set("Logging.Level", "debug")
	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.ExportVolumes", "/test")
	viper.Set("Origin.EnablePublicReads", true)
	fed := fed_test_utils.NewFedTest(t, "")
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	// Drop the testFileContent into the origin directory
	destDir := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir, os.FileMode(0755)))
	log.Debugln("Will create origin file at", destDir)
	err := os.WriteFile(filepath.Join(destDir, "test.txt"), []byte("test file content"), fs.FileMode(0644))
	require.NoError(t, err)
	downloadUrl1 := url.URL{
		Scheme: "pelican",
		Host:   host,
		Path:   "/test/test/test.txt",
	}
	localPath1 := filepath.Join(dirName, "test.txt")
	err = os.WriteFile(filepath.Join(destDir, "test2.txt"), []byte("second test file content"), fs.FileMode(0644))
	require.NoError(t, err)
	downloadUrl2 := url.URL{
		Scheme: "pelican",
		Host:   host,
		Path:   "/test/test/test2.txt",
	}
	localPath2 := filepath.Join(dirName, "test2.txt")

	workChan := make(chan PluginTransfer, 2)
	workChan <- PluginTransfer{url: &downloadUrl1, localFile: localPath1}
	workChan <- PluginTransfer{url: &downloadUrl2, localFile: localPath2}
	close(workChan)

	results := make(chan *classads.ClassAd, 5)
	fed.Egrp.Go(func() error {
		return runPluginWorker(fed.Ctx, false, workChan, results)
	})

	done := false
	for !done {
		select {
		case <-fed.Ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			// Process results as soon as we get them
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.True(t, boolVal)
		}
	}
}

// Test multiple downloads from the plugin
func TestPluginDirectRead(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()
	server_utils.ResetOriginExports()

	dirName := t.TempDir()

	viper.Set("Logging.Level", "debug")
	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StoragePrefix", "/<SOMETHING THAT WILL BE OVERRIDDEN>")
	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("Origin.EnableDirectReads", true)
	fed := fed_test_utils.NewFedTest(t, "")
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	log.Debugln("Will create origin file at", fed.Exports[0].StoragePrefix)
	err := os.WriteFile(filepath.Join(fed.Exports[0].StoragePrefix, "test.txt"), []byte("test file content"), fs.FileMode(0644))
	require.NoError(t, err)
	downloadUrl := url.URL{
		Scheme:   "pelican",
		Host:     host,
		Path:     "/test/test.txt",
		RawQuery: "directread",
	}
	localPath := filepath.Join(dirName, "test.txt")

	workChan := make(chan PluginTransfer, 2)
	workChan <- PluginTransfer{url: &downloadUrl, localFile: localPath}
	close(workChan)

	results := make(chan *classads.ClassAd, 5)
	fed.Egrp.Go(func() error {
		return runPluginWorker(fed.Ctx, false, workChan, results)
	})

	var developerData map[string]interface{}
	done := false
	for !done {
		select {
		case <-fed.Ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			// Process results as soon as we get them
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.True(t, boolVal)

			// Assert that our endpoint is always the origin and not the cache
			data, err := resultAd.Get("DeveloperData")
			assert.NoError(t, err)
			developerData, ok = data.(map[string]interface{})
			require.True(t, ok)

			attempts, ok := developerData["Attempts"].(int)
			require.True(t, ok)

			for i := 0; i < attempts; i++ {
				key := fmt.Sprintf("Endpoint%d", i)
				endpoint, ok := developerData[key].(string)
				require.True(t, ok)
				assert.Equal(t, param.Origin_Url.GetString(), "https://"+endpoint)
			}
		}
	}
}

// We ran into a bug where the start time for the transfer was not recorded correctly and was almost always the same as the end time
// (since they were set at similar sections of code). This test ensures that they are different and that the start time is before the end time.
func TestPluginCorrectStartAndEndTime(t *testing.T) {
	test_utils.InitClient(t, nil)
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()

	// Set up our http backend so that we can sleep during transfer
	body := "Hello, World!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == "GET" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			time.Sleep(1 * time.Second)
			_, err := w.Write([]byte(body))
			require.NoError(t, err)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	viper.Set("Origin.HttpServiceUrl", srv.URL+"/test2")

	config.InitConfig()
	tmpPath := t.TempDir()

	fed := fed_test_utils.NewFedTest(t, httpsOriginConfig)
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	downloadUrl := url.URL{
		Scheme: "pelican",
		Host:   host,
		Path:   "/test/hello_world",
	}

	workChan := make(chan PluginTransfer, 2)
	workChan <- PluginTransfer{url: &downloadUrl, localFile: tmpPath}
	close(workChan)

	results := make(chan *classads.ClassAd, 5)
	fed.Egrp.Go(func() error {
		return runPluginWorker(fed.Ctx, false, workChan, results)
	})

	done := false
	for !done {
		select {
		case <-fed.Ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			// Process results as soon as we get them
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.True(t, boolVal)

			// Assert that our start time is different from end time (and less than the end time)
			startTime, err := resultAd.Get("TransferStartTime")
			assert.NoError(t, err)
			startTimeVal, ok := startTime.(int64)
			require.True(t, ok)
			assert.True(t, startTimeVal > 0)

			endTime, err := resultAd.Get("TransferEndTime")
			assert.NoError(t, err)
			endTimeVal, ok := endTime.(int64)
			require.True(t, ok)
			assert.True(t, endTimeVal > 0)

			require.True(t, startTimeVal < endTimeVal)
		}
	}
}

// Test the functionality of the failTransfer function, ensuring the proper classads are being set and returned
func TestFailTransfer(t *testing.T) {
	// Test when we call failTransfer with an upload
	t.Run("TestWithUpload", func(t *testing.T) {
		results := make(chan *classads.ClassAd, 1)
		failTransfer("pelican://some/example.txt", "/path/to/local.txt", results, true, errors.New("test error"))
		result := <-results

		// Check TransferUrl set
		transferUrl, _ := result.Get("TransferUrl")
		transferUrlStr, ok := transferUrl.(string)
		require.True(t, ok)
		assert.Equal(t, "pelican://some/example.txt", transferUrlStr)

		// Check TransferType set
		transferType, _ := result.Get("TransferType")
		transferTypeStr, ok := transferType.(string)
		require.True(t, ok)
		assert.Equal(t, "upload", transferTypeStr)

		// Check TransferFileName set
		transferFileName, _ := result.Get("TransferFileName")
		transferFileNameStr, ok := transferFileName.(string)
		require.True(t, ok)
		assert.Equal(t, "local.txt", transferFileNameStr)

		// Check TransferRetryable set
		transferRetryable, _ := result.Get("TransferRetryable")
		transferRetryableBool, ok := transferRetryable.(bool)
		require.True(t, ok)
		assert.False(t, transferRetryableBool)

		// Check TransferSuccess set
		transferSuccess, _ := result.Get("TransferSuccess")
		transferSuccessBool, ok := transferSuccess.(bool)
		require.True(t, ok)
		assert.False(t, transferSuccessBool)

		// Check TransferError set
		transferError, _ := result.Get("TransferError")
		transferErrorStr, ok := transferError.(string)
		require.True(t, ok)
		assert.Equal(t, "test error", transferErrorStr)
	})

	// Test when we call failTransfer with a download
	t.Run("TestWithDownload", func(t *testing.T) {
		results := make(chan *classads.ClassAd, 1)
		failTransfer("pelican://some/example.txt", "/path/to/local.txt", results, false, errors.New("test error"))
		result := <-results

		// Check TransferUrl set
		transferUrl, _ := result.Get("TransferUrl")
		transferUrlStr, ok := transferUrl.(string)
		require.True(t, ok)
		assert.Equal(t, "pelican://some/example.txt", transferUrlStr)

		// Check TransferType set
		transferType, _ := result.Get("TransferType")
		transferTypeStr, ok := transferType.(string)
		require.True(t, ok)
		assert.Equal(t, "download", transferTypeStr)

		// Check TransferFileName set
		transferFileName, _ := result.Get("TransferFileName")
		transferFileNameStr, ok := transferFileName.(string)
		require.True(t, ok)
		assert.Equal(t, "example.txt", transferFileNameStr)

		// Check TransferRetryable set
		transferRetryable, _ := result.Get("TransferRetryable")
		transferRetryableBool, ok := transferRetryable.(bool)
		require.True(t, ok)
		assert.False(t, transferRetryableBool)

		// Check TransferSuccess set
		transferSuccess, _ := result.Get("TransferSuccess")
		transferSuccessBool, ok := transferSuccess.(bool)
		require.True(t, ok)
		assert.False(t, transferSuccessBool)

		// Check TransferError set
		transferError, _ := result.Get("TransferError")
		transferErrorStr, ok := transferError.(string)
		require.True(t, ok)
		assert.Equal(t, "test error", transferErrorStr)
	})

	// Test when we call failTransfer with a retryable error
	t.Run("TestWithRetry", func(t *testing.T) {
		results := make(chan *classads.ClassAd, 1)
		failTransfer("pelican://some/example.txt", "/path/to/local.txt", results, false, &client.SlowTransferError{})
		result := <-results

		// Check TransferUrl set
		transferUrl, _ := result.Get("TransferUrl")
		transferUrlStr, ok := transferUrl.(string)
		require.True(t, ok)
		assert.Equal(t, "pelican://some/example.txt", transferUrlStr)

		// Check TransferType set
		transferType, _ := result.Get("TransferType")
		transferTypeStr, ok := transferType.(string)
		require.True(t, ok)
		assert.Equal(t, "download", transferTypeStr)

		// Check TransferFileName set
		transferFileName, _ := result.Get("TransferFileName")
		transferFileNameStr, ok := transferFileName.(string)
		require.True(t, ok)
		assert.Equal(t, "example.txt", transferFileNameStr)

		// Check TransferRetryable set
		transferRetryable, _ := result.Get("TransferRetryable")
		transferRetryableBool, ok := transferRetryable.(bool)
		require.True(t, ok)
		assert.True(t, transferRetryableBool)

		// Check TransferSuccess set
		transferSuccess, _ := result.Get("TransferSuccess")
		transferSuccessBool, ok := transferSuccess.(bool)
		require.True(t, ok)
		assert.False(t, transferSuccessBool)

		// Check TransferError set
		transferError, _ := result.Get("TransferError")
		transferErrorStr, ok := transferError.(string)
		require.True(t, ok)
		assert.Equal(t, "cancelled transfer, too slow; detected speed=0 B/s, total transferred=0 B, total transfer time=0s, cache miss", transferErrorStr)
	})
}

// Test recursive downloads from the plugin
func TestPluginRecursiveDownload(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()
	server_utils.ResetOriginExports()

	dirName := t.TempDir()

	viper.Set("Logging.Level", "debug")
	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StoragePrefix", "/<THIS WILL BE OVERRIDDEN>")
	viper.Set("Origin.EnablePublicReads", true)
	fed := fed_test_utils.NewFedTest(t, "")
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	// Drop the testFileContent into the origin directory
	destDir := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir, os.FileMode(0755)))
	log.Debugln("Will create origin file at", destDir)
	err := os.WriteFile(filepath.Join(destDir, "test.txt"), []byte("test file content"), fs.FileMode(0644))
	require.NoError(t, err)
	downloadUrl1 := url.URL{
		Scheme:   "pelican",
		Host:     host,
		Path:     "/test/test",
		RawQuery: "recursive=true",
	}
	localPath1 := filepath.Join(dirName, "test.txt")
	err = os.WriteFile(filepath.Join(destDir, "test2.txt"), []byte("second test file content"), fs.FileMode(0644))
	require.NoError(t, err)

	// Test recursive download succeeds
	t.Run("TestRecursiveSuccess", func(t *testing.T) {
		workChan := make(chan PluginTransfer, 1)
		workChan <- PluginTransfer{url: &downloadUrl1, localFile: localPath1}
		//workChan <- PluginTransfer{url: &downloadUrl2, localFile: localPath2}
		close(workChan)

		results := make(chan *classads.ClassAd, 5)
		fed.Egrp.Go(func() error {
			return runPluginWorker(fed.Ctx, false, workChan, results)
		})

		resultAds := []*classads.ClassAd{}
		done := false
		for !done {
			select {
			case <-fed.Ctx.Done():
				break
			case resultAd, ok := <-results:
				if !ok {
					done = true
					break
				}
				// Process results as soon as we get them
				transferSuccess, err := resultAd.Get("TransferSuccess")
				assert.NoError(t, err)
				boolVal, ok := transferSuccess.(bool)
				require.True(t, ok)
				assert.True(t, boolVal)
				resultAds = append(resultAds, resultAd)
			}
		}
		// Check we get 2 result ads back (each file has been downloaded)
		assert.Equal(t, 2, len(resultAds))
	})

	// Check to make sure the plugin properly fails when setting recursive=true on a file
	// instead of a directory
	t.Run("TestRecursiveFailureOnRecursiveSetForFile", func(t *testing.T) {
		// Change the downloadUrl to be a path to a file instead of a directory
		downloadUrl1 := url.URL{
			Scheme:   "pelican",
			Host:     host,
			Path:     "/test/test/test.txt",
			RawQuery: "recursive=true",
		}

		workChan := make(chan PluginTransfer, 1)
		workChan <- PluginTransfer{url: &downloadUrl1, localFile: localPath1}
		close(workChan)

		results := make(chan *classads.ClassAd, 5)
		err = runPluginWorker(fed.Ctx, false, workChan, results)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read remote directory: PROPFIND /test/test/test.txt/: 500")
	})

	t.Run("TestRecursiveFailureDirNotFound", func(t *testing.T) {
		// Change the downloadUrl to be a path to a file instead of a directory
		downloadUrl1 := url.URL{
			Scheme:   "pelican",
			Host:     host,
			Path:     "/test/SomeDirectoryThatDoesNotExist:)",
			RawQuery: "recursive=true",
		}

		workChan := make(chan PluginTransfer, 1)
		workChan <- PluginTransfer{url: &downloadUrl1, localFile: localPath1}
		close(workChan)

		results := make(chan *classads.ClassAd, 5)
		err = runPluginWorker(fed.Ctx, false, workChan, results)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read remote directory: PROPFIND /test/SomeDirectoryThatDoesNotExist:)/: 404")
	})
}

func TestWriteOutfile(t *testing.T) {
	t.Run("TestOutfileSuccess", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", true)
			resultAd.Set("TransferLocalMachineName", "abcdefghijk")
			resultAd.Set("TransferFileBytes", 12)
			resultAd.Set("TransferTotalBytes", 27538253)
			resultAd.Set("TransferUrl", "foo.txt")
			resultAds = append(resultAds, resultAd)
		}
		success, retryable, err := writeOutfile(nil, resultAds, tempFile)
		assert.NoError(t, err)
		assert.True(t, success, "writeOutfile failed :(")
		assert.False(t, retryable, "writeOutfile returned retryable true when it should be false")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferFileBytes = 12;")
		assert.Contains(t, string(tempFileContent), "TransferTotalBytes = 27538253;")
		assert.Contains(t, string(tempFileContent), "TransferSuccess = true;")
		assert.Contains(t, string(tempFileContent), "TransferUrl = \"foo.txt\";")
	})

	t.Run("TestOutfileAlwaysIncludeUrlAndFileName", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", true)
			resultAd.Set("TransferLocalMachineName", "abcdefghijk")
			resultAd.Set("TransferFileBytes", 12)
			resultAd.Set("TransferTotalBytes", 27538253)
			resultAds = append(resultAds, resultAd)
		}
		success, retryable, err := writeOutfile(nil, resultAds, tempFile)
		assert.NoError(t, err)
		assert.True(t, success, "writeOutfile failed :(")
		assert.False(t, retryable, "writeOutfile returned retryable true when it should be false")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferFileBytes = 12;")
		assert.Contains(t, string(tempFileContent), "TransferTotalBytes = 27538253;")
		assert.Contains(t, string(tempFileContent), "TransferSuccess = true;")
		// Ensure we get empty strings for these classads
		assert.Contains(t, string(tempFileContent), "TransferUrl = \"\";")
		assert.Contains(t, string(tempFileContent), "TransferFileName = \"\";")
	})

	t.Run("TestOutfileFailureNoRetry", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", false)
			resultAd.Set("TransferRetryable", false)
			resultAd.Set("TransferLocalMachineName", "abcdefghijk")
			resultAd.Set("TransferFileBytes", 12)
			resultAd.Set("TransferTotalBytes", 27538253)
			resultAd.Set("TransferUrl", "foo.txt")
			resultAds = append(resultAds, resultAd)
		}
		success, retryable, err := writeOutfile(nil, resultAds, tempFile)
		assert.NoError(t, err)
		assert.False(t, success, "writeOutfile failed :(")
		assert.False(t, retryable, "writeOutfile returned retryable true when it should be false")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferFileBytes = 12;")
		assert.Contains(t, string(tempFileContent), "TransferSuccess = false;")
		assert.Contains(t, string(tempFileContent), "TransferRetryable = false;")
		assert.Contains(t, string(tempFileContent), "TransferUrl = \"foo.txt\";")
	})

	t.Run("TestOutfileFailureWithRetry", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", false)
			resultAd.Set("TransferRetryable", true)
			resultAd.Set("TransferLocalMachineName", "abcdefghijk")
			resultAd.Set("TransferFileBytes", 12)
			resultAd.Set("TransferTotalBytes", 27538253)
			resultAd.Set("TransferUrl", "foo.txt")
			resultAds = append(resultAds, resultAd)
		}
		success, retryable, err := writeOutfile(nil, resultAds, tempFile)
		assert.NoError(t, err)
		assert.False(t, success, "writeOutfile failed :(")
		assert.True(t, retryable, "writeOutfile returned retryable true when it should be true")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferFileBytes = 12;")
		assert.Contains(t, string(tempFileContent), "TransferSuccess = false;")
		assert.Contains(t, string(tempFileContent), "TransferRetryable = true;")
		assert.Contains(t, string(tempFileContent), "TransferUrl = \"foo.txt\";")
	})

	// Test the check in writeOutfile if we have an error sent to the function and have an error in our resultAds
	// In this case, the TransferError should not be overwritten
	t.Run("TestAlreadyFailed", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", false)
			resultAd.Set("TransferError", "This is some error here")
			resultAds = append(resultAds, resultAd)
		}
		writeErr := errors.New("This is the error that is passed to writeOutfile")
		success, _, err := writeOutfile(writeErr, resultAds, tempFile)
		assert.NoError(t, err)
		assert.False(t, success, "writeOutfile failed :(")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferSuccess = false;")
		assert.Contains(t, string(tempFileContent), "TransferError = \"This is some error here\";")
	})

	// In this case, we have an error sent to writeOutFile but no errors in the resultAds, we want to ensure
	// TransferSuccess is false and TransferError is populated with the error
	t.Run("TestNotAlreadyFailed", func(t *testing.T) {
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(t.TempDir(), "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		assert.NoError(t, err, "Error writing to temp file")
		defer tempFile.Close()
		defer os.Remove(tempFile.Name())

		// Set up test result ads
		var resultAds []*classads.ClassAd
		for i := 0; i < 4; i++ {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", true)
			resultAds = append(resultAds, resultAd)
		}
		writeErr := errors.New("This is the error that is passed to writeOutfile")
		success, _, err := writeOutfile(writeErr, resultAds, tempFile)
		assert.NoError(t, err)
		assert.False(t, success, "writeOutfile failed :(")
		tempFileContent, err := os.ReadFile(tempFile.Name())
		assert.NoError(t, err)

		// assert the output file contains some of our result ads
		assert.Contains(t, string(tempFileContent), "TransferSuccess = false;")
		assert.Contains(t, string(tempFileContent), "TransferError = \"This is the error that is passed to writeOutfile\";")
	})

}

// This test checks if the destination (local file) is parsed correctly
// and we get the direct path to the file or source added to the destination for directories
func TestParseDestination(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	// clean up
	defer os.RemoveAll(tempDir)

	// Create a temporary file in the temporary directory
	tempFile, err := os.CreateTemp(tempDir, "test")
	if err != nil {
		t.Fatal(err)
	}
	tempFile.Close()

	tests := []struct {
		name     string
		transfer PluginTransfer
		want     string
	}{
		{
			name: "destination is a directory",
			transfer: PluginTransfer{
				localFile: tempDir,
				url:       &url.URL{Path: "/path/to/source"},
			},
			want: filepath.Join(tempDir, "source"),
		},
		{
			name: "destination is a file",
			transfer: PluginTransfer{
				localFile: tempFile.Name(),
				url:       &url.URL{Path: "/path/to/source"},
			},
			want: tempFile.Name(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseDestination(test.transfer)
			if got != test.want {
				t.Errorf("parseDestination() = %v, want %v", got, test.want)
			}
		})
	}
}
