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

package client_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	//go:embed resources/both-auth.yml
	bothAuthOriginCfg string

	//go:embed resources/both-public.yml
	bothPublicOriginCfg string

	//go:embed resources/one-pub-one-auth.yml
	mixedAuthOriginCfg string
)

func generateFileTestScitoken() (string, error) {
	// Issuer is whichever server that initiates the test, so it's the server itself
	issuerUrl, err := config.GetServerIssuerURL()
	if err != nil {
		return "", err
	}
	if issuerUrl == "" { // if empty, then error
		return "", errors.New("Failed to create token: Invalid iss, Server_ExternalWebUrl is empty")
	}

	fTestTokenCfg := token.NewWLCGToken()
	fTestTokenCfg.Lifetime = time.Minute
	fTestTokenCfg.Issuer = issuerUrl
	fTestTokenCfg.Subject = "origin"
	fTestTokenCfg.AddAudiences(config.GetServerAudience())
	fTestTokenCfg.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Storage_Modify, "/"))

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
	server_utils.ResetOriginExports()
	defer viper.Reset()
	defer server_utils.ResetOriginExports()

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

	viper.Set("Origin.FederationPrefix", "/test")
	viper.Set("Origin.StoragePrefix", originDir)
	viper.Set("Origin.StorageType", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.EnableWrites", true)
	viper.Set("TLSSkipVerify", true)
	viper.Set("Server.EnableUI", false)
	viper.Set("Registry.DbLocation", filepath.Join(t.TempDir(), "ns-registry.sqlite"))
	viper.Set("Origin.RunLocation", tmpPath)
	viper.Set("Registry.RequireOriginApproval", false)
	viper.Set("Registry.RequireCacheApproval", false)
	viper.Set("Logging.Origin.Scitokens", "debug")
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	fedCancel, err := launchers.LaunchModules(ctx, modules)
	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
	}

	desiredURL := param.Server_ExternalWebUrl.GetString() + "/api/v1.0/health"
	err = server_utils.WaitUntilWorking(ctx, "GET", desiredURL, "director", 200, false)
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
		Msg string `json:"message"`
	}{}
	err = json.Unmarshal(responseBody, &expectedResponse)
	require.NoError(t, err)

	assert.NotEmpty(t, expectedResponse.Msg)

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

		// Upload the file
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "stash:///test/" + fileName

		transferResults, err := client.DoCopy(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err, "Error uploading file")
		assert.Equal(t, int64(len(testFileContent)), transferResults[0].TransferredBytes, "Uploaded file size does not match")

		// Upload an osdf file
		uploadURL = "pelican:///test/stuff/blah.txt"
		assert.NoError(t, err, "Error parsing upload URL")
		transferResults, err = client.DoCopy(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err, "Error uploading file")
		assert.Equal(t, int64(len(testFileContent)), transferResults[0].TransferredBytes, "Uploaded file size does not match")
	})
	t.Cleanup(func() {
		os.RemoveAll(tmpPath)
		os.RemoveAll(originDir)
	})

	viper.Reset()
}

// A test that spins up a federation, and tests object get and put
func TestGetAndPutAuth(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

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
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudiences(audience)

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
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

	// This tests object get/put with a pelican:// url
	t.Run("testPelicanObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("pelican")
		// Set path for object to upload/download
		for _, export := range *fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s/%s", export.FederationPrefix, fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testPelicanObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("pelican")
		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			// Minimal fix of test as it is soon to be replaced
			uploadURL := fmt.Sprintf("pelican://%s/%s", export.FederationPrefix, fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s/%s", export.FederationPrefix, fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			// Minimal fix of test as it is soon to be replaced
			uploadURL := fmt.Sprintf("pelican://%s/%s", export.FederationPrefix, fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})
}

// A test that spins up the federation, where the origin is in EnablePublicReads mode. Then GET a file from the origin without a token
func TestGetPublicRead(t *testing.T) {
	ctx, _, _ := test_utils.TestContext(context.Background(), t)
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	t.Run("testPubObjGet", func(t *testing.T) {
		for _, export := range *fed.Exports {
			testFileContent := "test file content"
			// Drop the testFileContent into the origin directory
			tempFile, err := os.Create(filepath.Join(export.StoragePrefix, "test.txt"))
			assert.NoError(t, err, "Error creating temp file")
			defer os.Remove(tempFile.Name())
			_, err = tempFile.WriteString(testFileContent)
			assert.NoError(t, err, "Error writing to temp file")
			tempFile.Close()

			viper.Set("Logging.DisableProgressBars", true)

			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s/%s", export.FederationPrefix, fileName)

			// Download the file with GET. Shouldn't need a token to succeed
			transferResults, err := client.DoGet(ctx, uploadURL, t.TempDir(), false)
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResults[0].TransferredBytes, int64(17))
			}
		}
	})
}

// A test that tests the statHttp function
func TestStatHttp(t *testing.T) {
	ctx, _, _ := test_utils.TestContext(context.Background(), t)
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)

	t.Run("testStatHttpPelicanScheme", func(t *testing.T) {
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(((*fed.Exports)[0]).StoragePrefix, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := fmt.Sprintf("pelican://%s/%s", ((*fed.Exports)[0]).FederationPrefix, fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		objectSize, err := client.DoStat(ctx, uploadURL)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, int64(17), int64(objectSize))
		}
	})

	t.Run("testStatHttpOSDFScheme", func(t *testing.T) {
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(((*fed.Exports)[0]).StoragePrefix, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		// Minimal fix of test as it is soon to be replaced
		uploadURL := fmt.Sprintf("pelican://%s/%s", ((*fed.Exports)[0]).FederationPrefix, fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		objectSize, err := client.DoStat(ctx, uploadURL)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, int64(17), int64(objectSize))
		}
	})

	t.Run("testStatHttpIncorrectScheme", func(t *testing.T) {
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(((*fed.Exports)[0]).StoragePrefix, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := fmt.Sprintf("some://incorrect/scheme/%s", fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		objectSize, err := client.DoStat(ctx, uploadURL)
		assert.Error(t, err)
		assert.Equal(t, uint64(0), objectSize)
		assert.Contains(t, err.Error(), "Unsupported scheme requested")
	})
}
