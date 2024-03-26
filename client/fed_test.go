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
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
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

// A test that spins up a federation, and tests object get and put
func TestGetAndPutAuth(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	te := client.NewTransferEngine(fed.Ctx)

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
		_, err := config.SetPreferredPrefix("PELICAN")
		assert.NoError(t, err)

		// Set path for object to upload/download
		for _, export := range *fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testPelicanObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("PELICAN")
		assert.NoError(t, err)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + fileName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running since we manually discover "osg-htc.org" therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := te.NewPelicanURL(uploadURL)
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.DirectorUrl)
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("OSDF")
		assert.NoError(t, err)

		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("OSDF")
		assert.NoError(t, err)

		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			// Minimal fix of test as it is soon to be replaced
			uploadURL := fmt.Sprintf("osdf://%s/%s", export.FederationPrefix, fileName)
			hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

			// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
			metadata, err := config.DiscoverUrlFederation(fed.Ctx, "https://"+hostname)
			assert.NoError(t, err)
			viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
			viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
			viper.Set("Federation.DiscoveryUrl", hostname)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})
	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// A test that spins up a federation, and tests object get and put
func TestCopyAuth(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	te := client.NewTransferEngine(fed.Ctx)

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
	t.Run("testPelicanObjectCopyWithPelicanUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("PELICAN")
		assert.NoError(t, err)

		// Set path for object to upload/download
		for _, export := range *fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoCopy(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testPelicanObjectCopyWithOSDFUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("PELICAN")
		assert.NoError(t, err)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + fileName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running since we manually discover "osg-htc.org" therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := te.NewPelicanURL(uploadURL)
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.DirectorUrl)
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectCopyWithPelicanUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("OSDF")
		assert.NoError(t, err)

		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoCopy(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectCopyWithOSDFUrl", func(t *testing.T) {
		_, err := config.SetPreferredPrefix("OSDF")
		assert.NoError(t, err)

		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			// Minimal fix of test as it is soon to be replaced
			uploadURL := fmt.Sprintf("osdf://%s/%s", export.FederationPrefix, fileName)
			hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

			// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
			metadata, err := config.DiscoverUrlFederation(fed.Ctx, "https://"+hostname)
			assert.NoError(t, err)
			viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
			viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
			viper.Set("Federation.DiscoveryUrl", hostname)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoCopy(te, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(te, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})
	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// A test that spins up the federation, where the origin is in EnablePublicReads mode. Then GET a file from the origin without a token
func TestGetPublicRead(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)
	te := client.NewTransferEngine(fed.Ctx)

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
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, fileName)

			// Download the file with GET. Shouldn't need a token to succeed
			transferResults, err := client.DoGet(te, uploadURL, t.TempDir(), false)
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResults[0].TransferredBytes, int64(17))
			}
		}
	})
	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
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
