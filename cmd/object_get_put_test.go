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

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/utils"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAndPut(t *testing.T) {
	//////////////////////////////Setup our test federation//////////////////////////////////////////
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()

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
	// Create a file to capture output from commands
	output, err := os.CreateTemp(t.TempDir(), "output")
	assert.NoError(t, err)
	defer os.Remove(output.Name())
	viper.Set("Logging.LogLocation", output.Name())

	originDir, err := os.MkdirTemp("", "Origin")
	assert.NoError(t, err)

	// Change the permissions of the temporary origin directory
	permissions = os.FileMode(0777)
	err = os.Chmod(originDir, permissions)
	require.NoError(t, err)

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
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Xrootd.RunLocation", tmpPath)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	fedCancel, err := launchers.LaunchModules(ctx, modules)
	if err != nil {
		t.Fatalf("Failure in fedServeInternal: %v", err)
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
	//////////////////////////////////////////////////////////////////////////////////////////
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
			Lifetime: time.Minute,
			Issuer: param.Origin_Url.GetString(),
			Audience: []string{param.Origin_Url.GetString()},
			Subject: "origin",
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

		out, err := io.ReadAll(output)
		assert.NoError(t, err)
		// Confirm we're uploading size we are expecting
		assert.Contains(t, string(out), "Uploaded bytes: 17")

		// Download that same file with GET
		rootCmd.SetArgs([]string{"object", "get", uploadURL, t.TempDir(), "-t", tempToken.Name(), "-c", param.Origin_Url.GetString(), "-d"})
		err = rootCmd.Execute()
		assert.NoError(t, err, "Failed to run pelican object get")

		out, err = io.ReadAll(output)
		assert.NoError(t, err)
		// Confirm we download same amount of bytes as upload
		assert.Contains(t, string(out), "Downloaded bytes: 17")
	})
	// cleanup
	os.RemoveAll(tmpPath)
	os.RemoveAll(originDir)

	cancel()
	fedCancel()
	assert.NoError(t, egrp.Wait())
	viper.Reset()
}
