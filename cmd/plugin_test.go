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
	"regexp"
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
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/test-https-origin.yml
	httpsOriginConfig string

	//go:embed resources/public-test-origin.yml
	publicTestOrigin string
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

	modules := server_structs.ServerType(0)
	modules.Set(server_structs.OriginType)
	modules.Set(server_structs.DirectorType)
	modules.Set(server_structs.RegistryType)

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
	viper.Set(param.Server_DbLocation.GetName(), filepath.Join(f.T.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", tmpPath)
	viper.Set("Director.DbLocation", filepath.Join(f.T.TempDir(), "director.sqlite"))
	viper.Set(param.Origin_DbLocation.GetName(), filepath.Join(f.T.TempDir(), "origin.sqlite"))
	viper.Set(param.Cache_DbLocation.GetName(), filepath.Join(f.T.TempDir(), "cache.sqlite"))

	err = config.InitServer(ctx, modules)
	require.NoError(f.T, err)

	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)

	_, f.FedCancel, err = launchers.LaunchModules(ctx, modules)
	if err != nil {
		f.FedCancel()
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
	server_utils.ResetTestState()
	director.ResetState()
}

// Test the main function for the pelican plugin
func TestStashPluginMain(t *testing.T) {
	server_utils.ResetTestState()

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
	expectedPattern := `Downloading object from pelican://[^/]+/test/test.txt to ` + regexp.QuoteMeta(tempDir)
	matched, err := regexp.MatchString(expectedPattern, output)
	assert.NoError(t, err)
	assert.True(t, matched, "Output does not match expected pattern")
	successfulDownloadMsg := "HTTP Transfer was successful"
	assert.Contains(t, output, successfulDownloadMsg)
	amountDownloaded := "Downloaded bytes: 17"
	assert.Contains(t, output, amountDownloaded)
}

// This test creates a directory containing two files, adds the paths of both files and the directory itself (without any recursive option) to the infile, and then passes it to the plugin for upload.
// The test then verifies the following:
// - Both files are successfully uploaded.
// - The directory itself is not uploaded, and no empty file with the directory name is created at the destination.
// - An appropriate message indicating the directory upload failure is returned in the corresponding resultad.
func TestInfileUploadWithDirAndFiles(t *testing.T) {

	server_utils.ResetTestState()
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	if os.Getenv("RUN_STASHPLUGIN") == "1" {
		viper.Set("Logging.Level", "debug")
		viper.Set("TLSSkipVerify", true)

		if err := config.PrintConfig(); err != nil {
			return
		}
		infile := os.Getenv("TEMP_INFILE")
		outfile := os.Getenv("TEMP_OUTFILE")
		args := []string{"-upload", "-infile", infile, "-outfile", outfile}
		stashPluginMain(args)
	}

	oldPrefix, err := config.SetPreferredPrefix(config.StashPrefix)
	assert.NoError(t, err)

	defer func() {
		_, err = config.SetPreferredPrefix(oldPrefix)
		require.NoError(t, err)
	}()

	tempUploadDir, err := os.MkdirTemp("", "TempUploadDir")
	require.NoError(t, err)
	defer os.RemoveAll(tempUploadDir)
	permissions := os.FileMode(0755)
	err = os.Chmod(tempUploadDir, permissions)
	require.NoError(t, err)

	tempObject1Content := "temp object 1 content"
	tempObject1, err := os.Create(filepath.Join(tempUploadDir, "tempObject1"))
	assert.NoError(t, err, "Error creating temp file")
	_, err = tempObject1.WriteString(tempObject1Content)
	assert.NoError(t, err, "Error writing to temp file")
	defer tempObject1.Close()

	tempObject2Content := "temp object 2 content"
	tempObject2, err := os.Create(filepath.Join(tempUploadDir, "tempObject2"))
	assert.NoError(t, err, "Error creating temp file")
	_, err = tempObject2.WriteString(tempObject2Content)
	assert.NoError(t, err, "Error writing to temp file")
	defer tempObject2.Close()

	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("TLSSkipVerify", true)
	// Since we have the prefix as STASH, we need to unset various osg-htc.org URLs to
	// avoid real web lookups.
	viper.Set("Federation.DiscoveryUrl", "")
	viper.Set("Xrootd.SummaryMonitoringHost", "")
	viper.Set("Xrootd.DetailedMonitoringHost", "")
	viper.Set("Logging.Level", "debug")
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()
	tokenConfig.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/"))
	token, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	tempToken, err := os.CreateTemp(t.TempDir(), "token")
	require.NoError(t, err, "Error creating temp token file")
	defer os.Remove(tempToken.Name())
	_, err = tempToken.WriteString(token)
	require.NoError(t, err, "Error writing to temp token file")
	tempToken.Close()

	viper.Set("Logging.DisableProgressBars", true)
	tempDir, err := os.MkdirTemp("", "TempDir")
	require.NoError(t, err, "Error creating temp dir")
	defer os.RemoveAll(tempDir)

	tempInfile, err := os.Create(filepath.Join(tempDir, "tempInfile"))
	require.NoError(t, err, "Error creating temp infile")
	defer os.Remove(tempInfile.Name())

	urlTemplate := "pelican://%s:%d/test/%s"
	serverHostname := param.Server_Hostname.GetString()
	serverWebPort := param.Server_WebPort.GetInt()

	infileContent := fmt.Sprintf(
		"[ Url = %s; LocalFileName = %s ]\n"+
			"[ Url = %s; LocalFileName = %s ]\n"+
			"[ Url = %s; LocalFileName = %s ]\n",
		fmt.Sprintf(urlTemplate, serverHostname, serverWebPort, "tempObject1"), tempObject1.Name(),
		fmt.Sprintf(urlTemplate, serverHostname, serverWebPort, "TempUploadDir"), tempUploadDir,
		fmt.Sprintf(urlTemplate, serverHostname, serverWebPort, "tempObject2"), tempObject2.Name(),
	)

	_, err = tempInfile.WriteString(infileContent)
	require.NoError(t, err, "Error writing to temp file")

	err = tempInfile.Close()
	require.NoError(t, err)

	t.Logf("Infile contents for testing:\n%s", infileContent)

	tempOutfilePath := filepath.Join(tempDir, "tempOutfile")

	// Create a process to run the command (since stashPluginMain calls os.Exit(0))
	cmd := exec.Command(os.Args[0], "-test.run=TestInfileUploadWithDirAndFiles")
	cmd.Env = append(os.Environ(), "RUN_STASHPLUGIN=1", "TEMP_INFILE="+tempInfile.Name(), "TEMP_OUTFILE="+tempOutfilePath, "BEARER_TOKEN="+token)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err = cmd.Run()

	output := strings.Replace(stderr.String(), "\\\\", "\\", -1)
	t.Log("Stderr of the Plugin Subprocess Start\n", output, "\nStderr of the Plugin Subprocess End\n")

	expectedMessage := "Pelican Client Error: the provided path '" + tempUploadDir + "' is a directory, but a file is expected"

	outfileContent, err := os.ReadFile(tempOutfilePath)
	require.NoError(t, err, "Error reading Outfile")

	t.Logf("Contents of generated outfile :\n%s", string(outfileContent))

	assert.Contains(t, string(outfileContent), expectedMessage, "Expected message not found in Outfile")

	entries, err := os.ReadDir(fed.OriginDir)
	require.NoError(t, err)

	foundTempObject1 := false
	foundTempObject2 := false

	for _, entry := range entries {
		switch entry.Name() {
		case "tempObject1":
			if entry.Type().IsRegular() {
				foundTempObject1 = true
				content, err := os.ReadFile(filepath.Join(fed.OriginDir, entry.Name()))
				require.NoError(t, err, "Error reading tempObject1")
				assert.Equal(t, tempObject1Content, string(content), "tempObject1 does not contain the expected content")
			}
		case "tempObject2":
			if entry.Type().IsRegular() {
				foundTempObject2 = true
				content, err := os.ReadFile(filepath.Join(fed.OriginDir, entry.Name()))
				require.NoError(t, err, "Error reading tempObject2")
				assert.Equal(t, tempObject2Content, string(content), "tempObject2 does not contain the expected content")
			}
		default:
			// If any other file or directory is present, fail the test
			t.Fatalf("Unexpected entry found in fed.OriginDir: %s", entry.Name())
		}
	}

	assert.True(t, foundTempObject1, "Expected tempObject1 file to be present in fed.OriginDir")
	assert.True(t, foundTempObject2, "Expected tempObject2 file to be present in fed.OriginDir")
	assert.Equal(t, 2, len(entries), "Expected exactly 2 entries in fed.OriginDir")
}

// Test multiple downloads from the plugin
func TestPluginMulti(t *testing.T) {
	server_utils.ResetTestState()

	dirName := t.TempDir()

	fed := fed_test_utils.NewFedTest(t, publicTestOrigin)
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

			log.Debugln("Got result ad:", resultAd)
			// Verify the checksums
			fileName, err := resultAd.Get("TransferFileName")
			require.NoError(t, err)
			fileNameString, ok := fileName.(string)
			require.True(t, ok)

			devData, err := resultAd.Get("DeveloperData")
			require.NoError(t, err)
			devDataMap, ok := devData.(map[string]interface{})
			require.True(t, ok)
			checksum, ok := devDataMap["ClientChecksums"]
			require.True(t, ok)
			checksumMap, ok := checksum.(map[string]interface{})
			require.True(t, ok, "Expected transfer checksum to be a map type; was %T", checksum)
			checksumValue, ok := checksumMap["crc32c"]
			require.True(t, ok)
			checksumString, ok := checksumValue.(string)
			require.True(t, ok)

			if fileNameString == filepath.Base(localPath1) {
				assert.Equal(t, "977b8112", checksumString)
			} else if fileNameString == filepath.Base(localPath2) {
				assert.Equal(t, "b99ecaad", checksumString)
			} else {
				t.Fatalf("Unexpected file name: %s", fileNameString)
			}
		}
	}
}

// Test multiple downloads from the plugin
func TestPluginDirectRead(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	dirName := t.TempDir()

	fed := fed_test_utils.NewFedTest(t, publicTestOrigin)
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
	server_utils.ResetOriginExports()
	defer server_utils.ResetTestState()
	var storageName string

	// Set up our http backend so that we can sleep during transfer
	body := "Hello, World!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.Path == storageName {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == "GET" && r.URL.Path == storageName {
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
	viper.Set("Origin.HttpServiceUrl", srv.URL)

	fed := fed_test_utils.NewFedTest(t, httpsOriginConfig)
	storageName = fed.Exports[0].StoragePrefix + "/hello_world"
	discoveryHost := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	downloadUrl := url.URL{
		Scheme: "pelican",
		Host:   discoveryHost,
		Path:   "/my-prefix/hello_world",
	}

	tmpPath := t.TempDir()
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

		// Check DeveloperData is now populated
		devData, err := result.Get("DeveloperData")
		require.NoError(t, err)
		require.NotNil(t, devData)
		devDataMap, ok := devData.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, 1, devDataMap["Attempts"])
		assert.Equal(t, "test error", devDataMap["TransferError1"])
		assert.Equal(t, false, devDataMap["IsRetryable1"])
		assert.NotEmpty(t, devDataMap["PelicanClientVersion"])

		// Check TransferErrorData is now populated (bug fix)
		errData, err := result.Get("TransferErrorData")
		require.NoError(t, err)
		require.NotNil(t, errData)
		errorDataList := errData.([]interface{})
		require.Equal(t, 1, len(errorDataList))
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
		failTransfer("pelican://some/example.txt", "/path/to/local.txt", results, false, error_codes.NewTransfer_SlowTransferError(&client.SlowTransferError{}))
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
		assert.Contains(t, transferErrorStr, "cancelled transfer, too slow; detected speed=0 B/s, total transferred=0 B, total transfer time=0s, cache miss")
	})

	// Test that DeveloperData and TransferErrorData are populated for director timeout errors
	t.Run("TestDirectorTimeoutError", func(t *testing.T) {
		results := make(chan *classads.ClassAd, 1)
		innerErr := errors.New("Get \"https://osdf-director.osg-htc.org/test\": dial tcp 128.105.82.132:443: i/o timeout")
		directorErr := error_codes.NewTransfer_DirectorTimeoutError(innerErr)
		failTransfer("osdf://test/file", "/path/to/local.txt", results, false, directorErr)
		result := <-results

		// Check that DeveloperData exists and has expected fields
		developerData, err := result.Get("DeveloperData")
		require.NoError(t, err)
		devDataMap, ok := developerData.(map[string]interface{})
		require.True(t, ok)

		// Check PelicanClientVersion
		version, ok := devDataMap["PelicanClientVersion"]
		require.True(t, ok)
		assert.NotEmpty(t, version)

		attempts, ok := devDataMap["Attempts"]
		require.True(t, ok)
		assert.Equal(t, 1, attempts)

		// Check that TransferErrorData exists and has expected fields
		transferErrorData, err := result.Get("TransferErrorData")
		require.NoError(t, err)
		errDataSlice, ok := transferErrorData.([]interface{})
		require.True(t, ok)
		require.Len(t, errDataSlice, 1)

		// Check the error classification
		errDataMap, ok := errDataSlice[0].(map[string]interface{})
		require.True(t, ok)

		// Create the expected error to get the expected values
		expectedErr := error_codes.NewTransfer_DirectorTimeoutError(innerErr)

		// Check top-level ErrorType (should be base type like "Transfer")
		errorType, ok := errDataMap["ErrorType"]
		require.True(t, ok)
		assert.Equal(t, "Transfer", errorType)

		// Check DeveloperData within TransferErrorData
		errDevData, ok := errDataMap["DeveloperData"]
		require.True(t, ok)
		errDevDataMap, ok := errDevData.(map[string]interface{})
		require.True(t, ok)

		// Check PelicanErrorCode
		errorCode, ok := errDevDataMap["PelicanErrorCode"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.Code(), errorCode)

		// Check ErrorType
		errType, ok := errDevDataMap["ErrorType"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.ErrorType(), errType)

		// Check Retryable
		retryable, ok := errDevDataMap["Retryable"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.IsRetryable(), retryable.(bool))
	})

	// Test that DeveloperData and TransferErrorData are populated for file not found errors
	t.Run("TestFileNotFoundError", func(t *testing.T) {
		results := make(chan *classads.ClassAd, 1)
		innerErr := errors.New("local object \"/path/to/missing.txt\" does not exist")
		fileNotFoundErr := error_codes.NewSpecification_FileNotFoundError(innerErr)
		failTransfer("osdf://test/file", "/path/to/missing.txt", results, true, fileNotFoundErr)
		result := <-results

		// Check that DeveloperData exists
		developerData, err := result.Get("DeveloperData")
		require.NoError(t, err)
		_, ok := developerData.(map[string]interface{})
		require.True(t, ok)

		// Check that TransferErrorData exists and has expected fields
		transferErrorData, err := result.Get("TransferErrorData")
		require.NoError(t, err)
		errDataSlice, ok := transferErrorData.([]interface{})
		require.True(t, ok)
		require.Len(t, errDataSlice, 1)

		// Check the error classification
		errDataMap, ok := errDataSlice[0].(map[string]interface{})
		require.True(t, ok)

		// Create the expected error to get the expected values
		expectedErr := error_codes.NewSpecification_FileNotFoundError(innerErr)

		// Check top-level ErrorType (should be base type like "Specification")
		errorType, ok := errDataMap["ErrorType"]
		require.True(t, ok)
		assert.Equal(t, "Specification", errorType)

		// Check DeveloperData within TransferErrorData
		errDevData, ok := errDataMap["DeveloperData"]
		require.True(t, ok)
		errDevDataMap, ok := errDevData.(map[string]interface{})
		require.True(t, ok)

		// Check PelicanErrorCode
		errorCode, ok := errDevDataMap["PelicanErrorCode"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.Code(), errorCode)

		// Check ErrorType
		errType, ok := errDevDataMap["ErrorType"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.ErrorType(), errType)

		// Check Retryable
		retryable, ok := errDevDataMap["Retryable"]
		require.True(t, ok)
		assert.Equal(t, expectedErr.IsRetryable(), retryable.(bool))
	})
}

// Test the createTransferError function for proper error classification
func TestCreateTransferError(t *testing.T) {
	// Test director timeout error
	t.Run("DirectorTimeoutError", func(t *testing.T) {
		innerErr := errors.New("Get \"https://osdf-director.osg-htc.org/test\": dial tcp 128.105.82.132:443: i/o timeout")
		err := error_codes.NewTransfer_DirectorTimeoutError(innerErr)
		transferError := createTransferError(err)

		assert.Equal(t, "Transfer", transferError["ErrorType"])

		devData, ok := transferError["DeveloperData"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, err.Code(), devData["PelicanErrorCode"])
		assert.Equal(t, err.ErrorType(), devData["ErrorType"])
		assert.Contains(t, devData["ErrorMessage"], "dial tcp")
		assert.Equal(t, err.IsRetryable(), devData["Retryable"].(bool))
	})

	// Test file not found error
	t.Run("FileNotFoundError", func(t *testing.T) {
		innerErr := errors.New("local object \"/path/to/file.txt\" does not exist")
		err := error_codes.NewSpecification_FileNotFoundError(innerErr)
		transferError := createTransferError(err)

		assert.Equal(t, "Specification", transferError["ErrorType"])

		devData, ok := transferError["DeveloperData"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, err.Code(), devData["PelicanErrorCode"])
		assert.Equal(t, err.ErrorType(), devData["ErrorType"])
		assert.Contains(t, devData["ErrorMessage"].(string), "does not exist")
		assert.Equal(t, err.IsRetryable(), devData["Retryable"].(bool))
	})

	// Test 404 error
	t.Run("RemoteFileNotFoundError", func(t *testing.T) {
		innerErr := errors.New("server returned 404 Not Found")
		err := error_codes.NewSpecification_FileNotFoundError(innerErr)
		transferError := createTransferError(err)

		assert.Equal(t, "Specification", transferError["ErrorType"])

		devData, ok := transferError["DeveloperData"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, err.Code(), devData["PelicanErrorCode"])
		assert.Equal(t, err.ErrorType(), devData["ErrorType"])
		assert.Contains(t, devData["ErrorMessage"].(string), "404 Not Found")
		assert.Equal(t, err.IsRetryable(), devData["Retryable"].(bool))
	})

	// Test slow transfer error
	t.Run("SlowTransferError", func(t *testing.T) {
		innerErr := &client.SlowTransferError{}
		err := error_codes.NewTransfer_SlowTransferError(innerErr)
		transferError := createTransferError(err)

		assert.Equal(t, "Transfer", transferError["ErrorType"])

		devData, ok := transferError["DeveloperData"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, err.Code(), devData["PelicanErrorCode"])
		assert.Equal(t, err.ErrorType(), devData["ErrorType"])
		assert.Equal(t, err.IsRetryable(), devData["Retryable"].(bool))
	})

	// Test unprocessed error
	t.Run("UnprocessedError", func(t *testing.T) {
		err := errors.New("some random error message")
		transferError := createTransferError(err)

		devData, ok := transferError["DeveloperData"].(map[string]interface{})
		require.True(t, ok)

		assert.Equal(t, 0, devData["PelicanErrorCode"])
		assert.Equal(t, "Unprocessed", devData["ErrorType"])
		assert.Equal(t, "Unprocessed error type", devData["ErrorMessage"])
	})
}

// Test recursive downloads from the plugin
func TestPluginRecursiveDownload(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	dirName := t.TempDir()

	fed := fed_test_utils.NewFedTest(t, publicTestOrigin)
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

	t.Run("TestRecursiveFailureDirNotFound", func(t *testing.T) {
		// Change the downloadUrl to be a path to a file instead of a directory
		downloadUrl1 := url.URL{
			Scheme:   "pelican",
			Host:     host,
			Path:     "/test/SomeDirectoryThatDoesNotExist",
			RawQuery: "recursive",
		}

		workChan := make(chan PluginTransfer, 1)
		workChan <- PluginTransfer{url: &downloadUrl1, localFile: localPath1}
		close(workChan)

		results := make(chan *classads.ClassAd, 5)
		err = runPluginWorker(fed.Ctx, false, workChan, results)
		assert.Error(t, err)
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
		{
			name: "destination is unpacked file",
			transfer: PluginTransfer{
				localFile: filepath.Join(tempDir, "test.tar"),
				url:       &url.URL{Path: "/path/to/source", RawQuery: "pack=auto", Scheme: "pelican"},
			},
			want: tempDir,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := parseDestination(test.transfer)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestWriteTransferErrorMessage(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	currentDir, err := os.Getwd()
	require.NoError(t, err)

	tmpFile := currentDir + "/.machine.ad"

	testCases := []struct {
		name          string
		content       string
		resultMessage string
	}{
		{
			name: "TestTransferErrorMsgSiteAndHost",
			content: "GLIDEIN_ResourceName = \"TestResourceName\"" + "\n" +
				"GLIDEIN_Site = \"TestResourceSite\"" + "\n" +
				"GPUs = 0" + "\n" +
				"K8SNamespace = \"TestNamespaceName\"" + "\n" +
				"K8SPhysicalHostName = \"TestHostName\"" + "\n" +
				"K8SPodName = \"osg-direct-67854503-000001-xbr5r\"",
			resultMessage: "; Site: TestResourceSite; Hostname: TestHostName)",
		},
		{
			name: "TestTransferErrorMsgSite",
			content: "GLIDEIN_ResourceName = \"TestResourceName\"" + "\n" +
				"GLIDEIN_Site = \"TestResourceSite\"" + "\n" +
				"GPUs = 0",
			resultMessage: "; Site: TestResourceSite)",
		},
		{
			name: "TestTransferErrorMsgHost",
			content: "K8SNamespace = \"TestNamespaceName\"" + "\n" +
				"K8SPhysicalHostName = \"TestHostName\"" + "\n" +
				"K8SPodName = \"osg-direct-67854503-000001-xbr5r\"",
			resultMessage: "; Hostname: TestHostName)",
		},
		{
			name: "TestTransferErrorMsgNoSiteOrHost",
			content: "GLIDEIN_ResourceName = \"TestResourceName\"" + "\n" +
				"GPUs = 0" + "\n" +
				"K8SNamespace = \"TestNamespaceName\"" + "\n" +
				"K8SPodName = \"osg-direct-67854503-000001-xbr5r\"",
			resultMessage: ")",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			err := os.WriteFile(tmpFile, []byte(test.content), 0644)
			require.NoError(t, err)
			defer os.Remove(tmpFile)

			errMsg := writeTransferErrorMessage("Test Error Message", "")
			baseResultMessage := fmt.Sprintf("Pelican Client Error: Test Error Message (Version: %s", config.GetVersion())
			require.Equal(t, errMsg, fmt.Sprintf("%s%s", baseResultMessage, test.resultMessage))
		})
	}
}

func TestTransferError404(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Isolate the test so it doesn't use system config
	viper.Set("ConfigDir", t.TempDir())
	err := config.InitClient()
	require.NoError(t, err)

	// Second server that returns 404
	secondServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer secondServer.Close()

	// First server returns Link header pointing to second server
	directorServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", secondServer.URL)
		w.Header().Set("X-Pelican-Namespace", "namespace=/test-namespace, require-token=false")
		linkHeader := fmt.Sprintf(`<%s>; rel="duplicate"; pri=1; depth=0`, secondServer.URL)
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer directorServer.Close()

	fInfo := pelican_url.FederationDiscovery{
		DirectorEndpoint: directorServer.URL,
	}

	viper.Set(param.TLSSkipVerify.GetName(), true)

	test_utils.MockFederationRoot(t, &fInfo, nil)
	ctx, _, egrp := test_utils.TestContext(context.Background(), t)
	objectUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	objectUrl.Path = "/test-namespace/object"
	objectUrl.Scheme = "pelican"

	workChan := make(chan PluginTransfer, 1)
	workChan <- PluginTransfer{url: objectUrl, localFile: "/tmp/targetfile"}
	close(workChan)
	results := make(chan *classads.ClassAd, 2)
	egrp.Go(func() error {
		return runPluginWorker(ctx, false, workChan, results)
	})

	done := false
	for !done {
		select {
		case <-ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.False(t, boolVal)

			log.Debugln("Got result ad:", resultAd)

			errData, err := resultAd.Get("TransferErrorData")
			require.NoError(t, err)
			errorDataList := errData.([]interface{})
			require.Equal(t, 1, len(errorDataList))
			errorData := errorDataList[0].(map[string]interface{})
			errorTypeStr, ok := errorData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, "Specification", errorTypeStr)
			developerData, ok := errorData["DeveloperData"].(map[string]interface{})
			require.True(t, ok)

			// Create the expected error to get the expected values
			// Simulate what the actual code does: StatusCodeError gets wrapped
			sce := client.StatusCodeError(http.StatusNotFound)
			expectedErr := error_codes.NewSpecification_FileNotFoundError(&sce)

			pelicanErrorCode, ok := developerData["PelicanErrorCode"].(int)
			require.True(t, ok)
			assert.Equal(t, expectedErr.Code(), pelicanErrorCode)

			pelicanErrorMessage, ok := developerData["ErrorMessage"].(string)
			require.True(t, ok)
			assert.Equal(t, expectedErr.Unwrap().Error(), pelicanErrorMessage)

			pelicanErrorType, ok := developerData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, expectedErr.ErrorType(), pelicanErrorType)

			retryable, ok := developerData["Retryable"].(bool)
			require.True(t, ok)
			assert.Equal(t, expectedErr.IsRetryable(), retryable)
		}
	}
}

func TestTransferErrorSlowTransfer(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Isolate the test so it doesn't use system config
	viper.Set("ConfigDir", t.TempDir())
	err := config.InitClient()
	require.NoError(t, err)

	// Create a server that sends data very slowly
	body := strings.Repeat("Hello, World!", 1000) // ~13KB of data
	slowServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		// Write small chunks with long delays to ensure we trigger the slow transfer detection
		chunk := make([]byte, 100)
		for i := 0; i < len(body); i += len(chunk) {
			end := i + len(chunk)
			if end > len(body) {
				end = len(body)
			}
			time.Sleep(500 * time.Millisecond) // Long delay between chunks
			_, err := w.Write([]byte(body[i:end]))
			if err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	}))
	defer slowServer.Close()

	// Create a director server that points to our slow server
	directorServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", slowServer.URL+r.URL.Path)
		w.Header().Set("X-Pelican-Namespace", "namespace=/test-namespace, require-token=false")
		linkHeader := fmt.Sprintf(`<%s%s>; rel="duplicate"; pri=1; depth=0`, slowServer.URL, r.URL.Path)
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer directorServer.Close()

	// Set up federation info pointing to our slow server
	fInfo := pelican_url.FederationDiscovery{
		DirectorEndpoint: directorServer.URL,
	}

	viper.Set(param.TLSSkipVerify.GetName(), true)
	viper.Set(param.Client_StoppedTransferTimeout.GetName(), 1*time.Second)
	viper.Set(param.Client_MinimumDownloadSpeed.GetName(), 10000)                  // 10KB/s minimum speed
	viper.Set(param.Client_SlowTransferWindow.GetName(), 500*time.Millisecond)     // Short window to detect slow transfer quickly
	viper.Set(param.Client_SlowTransferRampupTime.GetName(), 100*time.Millisecond) // Short rampup time

	test_utils.MockFederationRoot(t, &fInfo, nil)
	ctx, _, egrp := test_utils.TestContext(context.Background(), t)
	objectUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	objectUrl.Path = "/test-namespace/object"
	objectUrl.Scheme = "pelican"

	workChan := make(chan PluginTransfer, 1)
	workChan <- PluginTransfer{url: objectUrl, localFile: "/tmp/targetfile"}
	close(workChan)
	results := make(chan *classads.ClassAd, 2)
	egrp.Go(func() error {
		return runPluginWorker(ctx, false, workChan, results)
	})

	done := false
	for !done {
		select {
		case <-ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.False(t, boolVal)

			errData, err := resultAd.Get("TransferErrorData")
			require.NoError(t, err)
			errorDataList := errData.([]interface{})
			require.Equal(t, 1, len(errorDataList))
			errorData := errorDataList[0].(map[string]interface{})
			errorTypeStr, ok := errorData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, "Transfer", errorTypeStr)
			developerData, ok := errorData["DeveloperData"].(map[string]interface{})
			require.True(t, ok)

			// Create the expected error to get the expected values
			expectedErr := error_codes.NewTransfer_SlowTransferError(nil)

			// Check top-level ErrorType (should be base type like "Transfer")
			assert.Equal(t, "Transfer", errorTypeStr)

			pelicanErrorCode, ok := developerData["PelicanErrorCode"].(int)
			require.True(t, ok)
			assert.Equal(t, expectedErr.Code(), pelicanErrorCode)

			retryable, ok := developerData["Retryable"].(bool)
			require.True(t, ok)
			assert.Equal(t, expectedErr.IsRetryable(), retryable)

			errorType, ok := developerData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, expectedErr.ErrorType(), errorType)
		}
	}
}

func TestTransferErrorDirectorTimeout(t *testing.T) {
	testErr := errors.New("dial tcp 128.105.82.132:443: i/o timeout")
	testErr = errors.Wrap(testErr, "error while querying the director at https://osdf-director.osg-htc.org")
	testErr = error_codes.NewTransfer_DirectorTimeoutError(testErr)

	results := make(chan *classads.ClassAd, 1)
	failTransfer("osdf://osg-htc.org/chtc/PUBLIC/test.txt", "/tmp/test.txt", results, false, testErr)
	resultAd := <-results

	// Basic fields should be set
	transferSuccess, _ := resultAd.Get("TransferSuccess")
	assert.False(t, transferSuccess.(bool))

	transferRetryable, _ := resultAd.Get("TransferRetryable")
	assert.True(t, transferRetryable.(bool), "Director timeout should be retryable")

	// Verify DeveloperData is populated
	devData, err := resultAd.Get("DeveloperData")
	require.NoError(t, err, "DeveloperData should be present for director failures")
	require.NotNil(t, devData)
	devDataMap, ok := devData.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, devDataMap["Attempts"])
	assert.NotEmpty(t, devDataMap["TransferError1"])
	assert.NotNil(t, devDataMap["IsRetryable1"])
	assert.Equal(t, true, devDataMap["IsRetryable1"], "Director timeout should be retryable")
	assert.NotEmpty(t, devDataMap["PelicanClientVersion"])

	// Verify TransferErrorData is populated
	errData, err := resultAd.Get("TransferErrorData")
	require.NoError(t, err, "TransferErrorData should be present for director failures")
	require.NotNil(t, errData)
	errorDataList := errData.([]interface{})
	require.Equal(t, 1, len(errorDataList), "Should have one error in TransferErrorData")

	errorData := errorDataList[0].(map[string]interface{})
	errorTypeStr, ok := errorData["ErrorType"].(string)
	require.True(t, ok)
	assert.Equal(t, "Transfer", errorTypeStr, "Should be Transfer error type")

	developerData, ok := errorData["DeveloperData"].(map[string]interface{})
	require.True(t, ok)

	// Verify it's wrapped with Transfer.DirectorTimeout PelicanError
	expectedErr := error_codes.NewTransfer_DirectorTimeoutError(errors.New("timeout"))
	pelicanErrorCode, ok := developerData["PelicanErrorCode"].(int)
	require.True(t, ok)
	assert.Equal(t, expectedErr.Code(), pelicanErrorCode, "Should have Transfer.DirectorTimeout code 6005")

	pelicanErrorType, ok := developerData["ErrorType"].(string)
	require.True(t, ok)
	assert.Equal(t, expectedErr.ErrorType(), pelicanErrorType, "Should be Transfer.DirectorTimeout")

	retryable, ok := developerData["Retryable"].(bool)
	require.True(t, ok)
	assert.True(t, retryable, "Director timeout should be retryable")
}

func TestTransferErrorHeaderTimeout(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Isolate the test so it doesn't use system config
	viper.Set("ConfigDir", t.TempDir())
	err := config.InitClient()
	require.NoError(t, err)

	// Create a server that sleeps before sending any response
	timeoutServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			// HEAD requests succeed quickly so we can get past the director phase
			w.Header().Set("Content-Length", "13")
			w.WriteHeader(http.StatusOK)
			return
		}
		// Sleep longer than the response header timeout
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer timeoutServer.Close()

	// Create a director server that points to our timeout server
	directorServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", timeoutServer.URL+r.URL.Path)
		w.Header().Set("X-Pelican-Namespace", "namespace=/test-namespace, require-token=false")
		linkHeader := fmt.Sprintf(`<%s%s>; rel="duplicate"; pri=1; depth=0`, timeoutServer.URL, r.URL.Path)
		w.Header().Set("Link", linkHeader)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer directorServer.Close()

	// Set up federation info pointing to our timeout server
	fInfo := pelican_url.FederationDiscovery{
		DirectorEndpoint: directorServer.URL,
	}

	viper.Set(param.TLSSkipVerify.GetName(), true)
	// Set a very short response header timeout to ensure we hit it first
	viper.Set(param.Transport_ResponseHeaderTimeout.GetName(), "100ms")
	// Set a longer stopped transfer timeout to ensure we don't hit it first
	viper.Set(param.Client_StoppedTransferTimeout.GetName(), "30s")
	// Set a longer idle timeout to ensure we don't hit it first
	viper.Set(param.Transport_IdleConnTimeout.GetName(), "30s")
	// Set a longer TLS handshake timeout to ensure we don't hit it first
	viper.Set(param.Transport_TLSHandshakeTimeout.GetName(), "30s")

	test_utils.MockFederationRoot(t, &fInfo, nil)
	ctx, _, egrp := test_utils.TestContext(context.Background(), t)
	objectUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	objectUrl.Path = "/test-namespace/object"
	objectUrl.Scheme = "pelican"

	workChan := make(chan PluginTransfer, 1)
	workChan <- PluginTransfer{url: objectUrl, localFile: "/tmp/targetfile"}
	close(workChan)
	results := make(chan *classads.ClassAd, 2)
	egrp.Go(func() error {
		return runPluginWorker(ctx, false, workChan, results)
	})

	done := false
	for !done {
		select {
		case <-ctx.Done():
			break
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			transferSuccess, err := resultAd.Get("TransferSuccess")
			assert.NoError(t, err)
			boolVal, ok := transferSuccess.(bool)
			require.True(t, ok)
			assert.False(t, boolVal)

			errData, err := resultAd.Get("TransferErrorData")
			require.NoError(t, err)
			errorDataList := errData.([]interface{})
			require.Equal(t, 1, len(errorDataList))
			errorData := errorDataList[0].(map[string]interface{})
			errorTypeStr, ok := errorData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, "Transfer", errorTypeStr)
			developerData, ok := errorData["DeveloperData"].(map[string]interface{})
			require.True(t, ok)

			// Create the expected error to get the expected values
			expectedErr := error_codes.NewTransfer_HeaderTimeoutError(&client.HeaderTimeoutError{})

			// Check top-level ErrorType (should be base type like "Transfer")
			assert.Equal(t, "Transfer", errorTypeStr)

			pelicanErrorCode, ok := developerData["PelicanErrorCode"].(int)
			require.True(t, ok)
			assert.Equal(t, expectedErr.Code(), pelicanErrorCode)

			retryable, ok := developerData["Retryable"].(bool)
			require.True(t, ok)
			assert.Equal(t, expectedErr.IsRetryable(), retryable)

			errorType, ok := developerData["ErrorType"].(string)
			require.True(t, ok)
			assert.Equal(t, expectedErr.ErrorType(), errorType)
		}
	}
}
