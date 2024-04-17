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
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestReadMultiTransfer test if we can read multiple transfers from stdin
func TestReadMultiTransfer(t *testing.T) {
	t.Parallel()

	// Test with multiple transfers
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

	// Test with single transfers
	stdin = "[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
	transfers, err = readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "url://server/some/directory//blah", transfers[0].url.String())
	assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].localFile)
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

	_, err := config.SetPreferredPrefix(config.StashPrefix)
	assert.NoError(t, err)

	// Temp dir for downloads
	tempDir := os.TempDir()
	defer os.Remove(tempDir)

	// Parts of test adapted from: https://stackoverflow.com/questions/26225513/how-to-test-os-exit-scenarios-in-go
	// Basically, we need to run the test like this since StashPluginMain calls os.Exit() which is not good for our tests
	// and leaves xrootd running. To work with this, we wrap the test in its own command and parse the output for successful run
	if os.Getenv("RUN_STASHPLUGIN") == "1" {
		viper.Set("Origin.EnablePublicReads", true)
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
		os.Unsetenv("STASH_LOGGING_LEVEL")
		os.Unsetenv("RUN_STASHPLUGIN")
		return
	}

	// Create a process to run the command (since stashPluginMain calls os.Exit(0))
	cmd := exec.Command(os.Args[0], "-test.run=TestStashPluginMain")
	cmd.Env = append(os.Environ(), "RUN_STASHPLUGIN=1", "STASH_LOGGING_LEVEL=debug")

	// Create buffers for stderr (the output we want for test)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	assert.NoError(t, err, stderr.String())

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
		success, retryable := writeOutfile(nil, resultAds, tempFile)
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
		success, retryable := writeOutfile(nil, resultAds, tempFile)
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
		success, retryable := writeOutfile(nil, resultAds, tempFile)
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

}

// This test checks if query parameters in the url are correct
// We want invalid or > 1 query to cause an error
func TestQuery(t *testing.T) {
	t.Run("TestValidRecursive", func(t *testing.T) {
		transferStr := "pelican://something/here?recursive=true"
		transferUrl, err := url.Parse(transferStr)
		assert.NoError(t, err)

		err = checkValidQuery(transferUrl)
		assert.NoError(t, err)
	})

	t.Run("TestValidPack", func(t *testing.T) {
		transferStr := "pelican://something/here?pack=tar.gz"
		transferUrl, err := url.Parse(transferStr)
		assert.NoError(t, err)

		err = checkValidQuery(transferUrl)
		assert.NoError(t, err)
	})

	t.Run("TestInvalidQuery", func(t *testing.T) {
		transferStr := "pelican://something/here?recrustive=true"
		transferUrl, err := url.Parse(transferStr)
		assert.NoError(t, err)

		err = checkValidQuery(transferUrl)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid query parameters procided in url: pelican://something/here?recrustive=true")
	})

	t.Run("TestBothQueryCheckFailure", func(t *testing.T) {
		transferStr := "pelican://something/here?pack=tar.gz&recursive=true"
		transferUrl, err := url.Parse(transferStr)
		assert.NoError(t, err)

		err = checkValidQuery(transferUrl)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Cannot have both recursive and pack query parameters")
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
