//go:build linux

/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"
)

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

	// Increase the log level; otherwise, its difficult to debug failures
	viper.Set("Logging.Level", "Debug")
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

func TestGetAndPutAuth(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	t.Run("testObjectPutAndGet", func(t *testing.T) {
		testFileContent := "test file content"
		// Create the temporary file to upload
		tempFile, err := os.CreateTemp(t.TempDir(), "test")
		assert.NoError(t, err, "Error creating temp file")
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		// Create a token file
		tokenConfig := utils.TokenConfig{
			TokenProfile: utils.WLCG,
			Lifetime:     time.Minute,
			Issuer:       param.Origin_Url.GetString(),
			Audience:     []string{param.Origin_Url.GetString()},
			Subject:      "origin",
		}
		tokenConfig.AddRawScope("storage.read:/ storage.modify:/")
		token, err := tokenConfig.CreateToken()
		assert.NoError(t, err)
		tempToken, err := os.CreateTemp(t.TempDir(), "token")
		assert.NoError(t, err, "Error creating temp token file")
		defer os.Remove(tempToken.Name())
		_, err = tempToken.WriteString(token)
		assert.NoError(t, err, "Error writing to temp token file")
		tempToken.Close()
		// Disable progress bars to not reuse the same mpb instance
		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "osdf:///test/" + fileName

		// Upload the file with PUT
		rootCmd.SetArgs([]string{"object", "put", tempFile.Name(), uploadURL, "-d", "-t", tempToken.Name()})
		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object put")

		out, err := io.ReadAll(fed.Output)
		assert.NoError(t, err)
		// Confirm we're uploading size we are expecting
		assert.Contains(t, string(out), "Uploaded bytes: 17")

		// Download that same file with GET
		rootCmd.SetArgs([]string{"object", "get", uploadURL, t.TempDir(), "-t", tempToken.Name(), "-c", param.Origin_Url.GetString(), "-d"})
		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object get")

		out, err = io.ReadAll(fed.Output)
		assert.NoError(t, err)
		// Confirm we download same amount of bytes as upload
		assert.Contains(t, string(out), "Downloaded bytes: 17")
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
		tempFile, err := os.Create(filepath.Join(fed.OriginDir, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		defer os.Remove(tempFile.Name())
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "osdf:///test/" + fileName

		// Download the file with GET. Shouldn't need a token to succeed
		rootCmd.SetArgs([]string{"object", "get", uploadURL, t.TempDir(), "-c", param.Origin_Url.GetString(), "-d"})
		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object get")

		out, err := io.ReadAll(fed.Output)
		assert.NoError(t, err)
		// Confirm we download same amount of bytes as upload
		assert.Contains(t, string(out), "Downloaded bytes: 17")
	})
}

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()
	t.Run("testRecursiveGetAndPut", func(t *testing.T) {
		//////////////////////////SETUP///////////////////////////
		// Create a token file
		tokenConfig := utils.TokenConfig{
			TokenProfile: utils.WLCG,
			Lifetime:     time.Minute,
			Issuer:       param.Origin_Url.GetString(),
			Audience:     []string{param.Origin_Url.GetString()},
			Subject:      "origin",
		}
		tokenConfig.AddRawScope("storage.read:/ storage.modify:/")
		token, err := tokenConfig.CreateToken()
		assert.NoError(t, err)
		tempToken, err := os.CreateTemp(t.TempDir(), "token")
		assert.NoError(t, err, "Error creating temp token file")
		defer os.Remove(tempToken.Name())
		_, err = tempToken.WriteString(token)
		assert.NoError(t, err, "Error writing to temp token file")
		tempToken.Close()

		// Disable progress bars to not reuse the same mpb instance
		viper.Set("Logging.DisableProgressBars", true)

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

		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadURL := "osdf:///test/" + dirName

		//////////////////////////////////////////////////////////

		// Upload the file with PUT
		rootCmd.SetArgs([]string{"object", "put", tempDir, uploadURL, "-d", "-r", "-t", tempToken.Name()})

		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object put")
		out, err := io.ReadAll(fed.Output)
		assert.NoError(t, err)

		// Confirm we're uploading size we are expecting
		assert.Contains(t, string(out), "Uploaded bytes: 23")
		assert.Contains(t, string(out), "Uploaded bytes: 17")

		// Download that same file with GET
		rootCmd.SetArgs([]string{"object", "get", uploadURL, t.TempDir(), "-d", "-r", "-c", param.Origin_Url.GetString(), "-t", tempToken.Name()})

		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object get")

		out, err = io.ReadAll(fed.Output)
		assert.NoError(t, err)
		// Confirm we download same amount of bytes as upload
		assert.Contains(t, string(out), "Downloaded bytes: 23")
		assert.Contains(t, string(out), "Downloaded bytes: 17")
	})

}
