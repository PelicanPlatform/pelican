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
	"fmt"
	"net/http"
	"net/http/httptest"
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

	//go:embed resources/pub-export-no-directread.yml
	pubExportNoDirectRead string

	//go:embed resources/pub-origin-no-directread.yml
	pubOriginNoDirectRead string

	//go:embed resources/test-https-origin.yml
	httpsOriginConfig string
)

// Helper function to get a temporary token file
// NOTE: when used make sure to call os.Remove() on the file
func getTempToken(t *testing.T) (tempToken *os.File, tkn string) {
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Storage_Modify.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)
	tkn, err = tokenConfig.CreateToken()
	assert.NoError(t, err)
	tmpTok := filepath.Join(t.TempDir(), "token")
	tempToken, err = os.OpenFile(tmpTok, os.O_CREATE|os.O_RDWR, 0644)
	assert.NoError(t, err, "Error opening the temp token file")
	_, err = tempToken.WriteString(tkn)
	assert.NoError(t, err, "Error writing to temp token file")

	return
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

	tempToken, tmpTkn := getTempToken(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	// Disable progress bars to not reuse the same mpb instance
	viper.Set("Logging.DisableProgressBars", true)

	// This tests object get/put with a pelican:// url
	t.Run("testPelicanObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.PelicanPrefix)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()
		assert.NoError(t, err)

		// Set path for object to upload/download
		for _, export := range fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

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

	// We ran into a bug with the token option not working how it should. This test ensures that transfer option works how it should
	t.Run("testPelicanObjectPutAndGetWithWithTokenOption", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.PelicanPrefix)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()
		assert.NoError(t, err)

		// Set path for object to upload/download
		for _, export := range fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoPut(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithToken(tmpTkn))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithToken(tmpTkn))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

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
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
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
	t.Cleanup(func() {
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// A test that spins up a federation, and tests object get and put
func TestCopyAuth(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	te, err := client.NewTransferEngine(fed.Ctx)
	require.NoError(t, err)

	// Other set-up items:
	testFileContent := "test file content"
	// Create the temporary file to upload
	tempFile, err := os.CreateTemp(t.TempDir(), "test")
	assert.NoError(t, err, "Error creating temp file")
	defer os.Remove(tempFile.Name())
	_, err = tempFile.WriteString(testFileContent)
	assert.NoError(t, err, "Error writing to temp file")
	tempFile.Close()

	tempToken, _ := getTempToken(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())
	// Disable progress bars to not reuse the same mpb instance
	viper.Set("Logging.DisableProgressBars", true)

	// This tests object get/put with a pelican:// url
	t.Run("testPelicanObjectCopyWithPelicanUrl", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		// Set path for object to upload/download
		for _, export := range fed.Exports {
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoCopy(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, int64(17), transferResultsUpload[0].TransferredBytes)
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, int64(17), transferResultsDownload[0].TransferredBytes)
			}
		}
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectCopyWithPelicanUrl", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempFile.Name()
			fileName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", fileName)

			// Upload the file with PUT
			transferResultsUpload, err := client.DoCopy(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsDownload[0].TransferredBytes, transferResultsUpload[0].TransferredBytes)
			}
		}
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectCopyWithOSDFUrl", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
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
			transferResultsUpload, err := client.DoCopy(fed.Ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
			}

			// Download that same file with GET
			transferResultsDownload, err := client.DoCopy(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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

	t.Run("testPubObjGet", func(t *testing.T) {
		for _, export := range fed.Exports {
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
			transferResults, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
			assert.NoError(t, err)
			if err == nil {
				assert.Equal(t, transferResults[0].TransferredBytes, int64(17))
			}
		}
	})
	t.Cleanup(func() {
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
	})
}

// A test that spins up a federation, and tests object stat
func TestObjectStat(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	defer server_utils.ResetOriginExports()
	defer viper.Reset()
	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	// Other set-up items:
	testFileContent := "test file content"
	// Create the temporary file to upload
	tempFileName := filepath.Join(t.TempDir(), "test")
	tempFile, err := os.OpenFile(tempFileName, os.O_CREATE|os.O_RDWR, 0644)
	assert.NoError(t, err, "Error creating temp file")
	_, err = tempFile.WriteString(testFileContent)
	assert.NoError(t, err, "Error writing to temp file")
	tempFile.Close()

	// Get a temporary token file
	tempToken, _ := getTempToken(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	// Disable progress bars to not reuse the same mpb instance
	viper.Set("Logging.DisableProgressBars", true)

	// Make directories for test within origin exports
	destDir1 := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir1, os.FileMode(0755)))
	destDir2 := filepath.Join(fed.Exports[1].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir2, os.FileMode(0755)))

	// This tests object stat with no flags set
	t.Run("testPelicanObjectStatNoFlags", func(t *testing.T) {
		for _, export := range fed.Exports {
			statUrl := fmt.Sprintf("pelican://%s:%d%s/hello_world.txt", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), export.FederationPrefix)
			var got client.FileInfo
			if export.Capabilities.PublicReads {
				statInfo, err := client.DoStat(fed.Ctx, statUrl, client.WithTokenLocation(""))
				got = *statInfo
				require.NoError(t, err)
			} else {
				statInfo, err := client.DoStat(fed.Ctx, statUrl, client.WithTokenLocation(tempToken.Name()))
				got = *statInfo
				require.NoError(t, err)
			}
			assert.Equal(t, int64(13), got.Size)
			assert.Equal(t, "hello_world.txt", got.Name)
		}
	})

	// This tests object stat when used on a directory
	t.Run("testPelicanObjectStatOnDirectory", func(t *testing.T) {
		for _, export := range fed.Exports {
			statUrl := fmt.Sprintf("pelican://%s:%s%s/test", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()), export.FederationPrefix)
			if export.Capabilities.PublicReads {
				statInfo, err := client.DoStat(fed.Ctx, statUrl, client.WithTokenLocation(""))
				require.NoError(t, err)
				assert.Equal(t, int64(0), statInfo.Size)
			} else {
				statInfo, err := client.DoStat(fed.Ctx, statUrl, client.WithTokenLocation(tempToken.Name()))
				require.NoError(t, err)
				assert.Equal(t, int64(0), statInfo.Size)
			}
		}
	})

	// Ensure stat works with an OSDF scheme
	t.Run("testObjectStatOSDFScheme", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(fed.Exports[0].StoragePrefix, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)

		statUrl := fmt.Sprintf("osdf://%s/%s", fed.Exports[0].FederationPrefix, fileName)
		hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

		// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
		metadata, err := config.DiscoverUrlFederation(fed.Ctx, "https://"+hostname)
		assert.NoError(t, err)
		viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
		viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
		viper.Set("Federation.DiscoveryUrl", hostname)

		// Stat the file
		statInfo, err := client.DoStat(fed.Ctx, statUrl)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, int64(17), int64(statInfo.Size))
			assert.Equal(t, "test.txt", statInfo.Name)
		}
	})

	// Ensure stat fails if it does not recognize the url scheme
	t.Run("testObjectStatIncorrectScheme", func(t *testing.T) {
		testFileContent := "test file content"
		// Drop the testFileContent into the origin directory
		tempFile, err := os.Create(filepath.Join(fed.Exports[0].StoragePrefix, "test.txt"))
		assert.NoError(t, err, "Error creating temp file")
		_, err = tempFile.WriteString(testFileContent)
		assert.NoError(t, err, "Error writing to temp file")
		tempFile.Close()

		viper.Set("Logging.DisableProgressBars", true)

		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := fmt.Sprintf("some://incorrect/scheme/%s", fileName)

		// Stat the file
		objStat, err := client.DoStat(fed.Ctx, uploadURL)
		assert.Error(t, err)
		assert.Nil(t, objStat)
		assert.Contains(t, err.Error(), "Do not understand the destination scheme: some. Permitted values are file, osdf, pelican, stash, ")
	})
}

// Test the functionality of the direct reads feature (?directread)
func TestDirectReads(t *testing.T) {
	defer viper.Reset()
	t.Run("testDirectReadsSuccess", func(t *testing.T) {
		viper.Reset()
		server_utils.ResetOriginExports()
		viper.Set("Origin.EnableDirectReads", true)
		fed := fed_test_utils.NewFedTest(t, bothPublicOriginCfg)
		export := fed.Exports[0]
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
		uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s?directread", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
			export.FederationPrefix, fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		transferResults, err := client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
		require.NoError(t, err)
		assert.Equal(t, transferResults[0].TransferredBytes, int64(17))

		// Assert that the file was not cached
		cacheDataLocation := param.Cache_LocalRoot.GetString() + export.FederationPrefix
		filepath := filepath.Join(cacheDataLocation, filepath.Base(tempFile.Name()))
		_, err = os.Stat(filepath)
		assert.True(t, os.IsNotExist(err))

		// Assert our endpoint was the origin and not the cache
		for _, attempt := range transferResults[0].Attempts {
			assert.Equal(t, "https://"+attempt.Endpoint, param.Origin_Url.GetString())
		}
	})

	// Test that direct reads fail if DirectReads=false is set for origin config but true for namespace/export
	t.Run("testDirectReadsDirectReadFalseByOrigin", func(t *testing.T) {
		viper.Reset()
		server_utils.ResetOriginExports()
		fed := fed_test_utils.NewFedTest(t, pubOriginNoDirectRead)
		export := fed.Exports[0]
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
		uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s?directread", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
			export.FederationPrefix, fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		_, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No origins on specified endpoint have direct reads enabled")
	})

	// Test that direct reads fail if DirectReads=false is set for namespace/export config but true for origin
	t.Run("testDirectReadsDirectReadFalseByNamespace", func(t *testing.T) {
		viper.Reset()
		server_utils.ResetOriginExports()
		fed := fed_test_utils.NewFedTest(t, pubExportNoDirectRead)
		export := fed.Exports[0]
		export.Capabilities.DirectReads = false
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
		uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s?directread", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
			export.FederationPrefix, fileName)

		// Download the file with GET. Shouldn't need a token to succeed
		_, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No origins on specified endpoint have direct reads enabled")
	})
}

// Test the functionality of NewTransferJob, checking we return at the correct locations for certain errors
func TestNewTransferJob(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	server_utils.ResetOriginExports()
	defer server_utils.ResetOriginExports()
	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	te, err := client.NewTransferEngine(fed.Ctx)
	require.NoError(t, err)

	// Test when we have a failure during namespace lookup (here we will get a 404)
	t.Run("testFailureToGetNamespaceInfo", func(t *testing.T) {
		tc, err := te.NewClient()
		assert.NoError(t, err)

		// have a file/namespace that does not exist
		mockRemoteUrl, err := url.Parse("/first/something/file.txt")
		require.NoError(t, err)
		_, err = tc.NewTransferJob(context.Background(), mockRemoteUrl, "/dest", false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get namespace information for remote URL /first/something/file.txt")
	})

	// Test when we fail to get a token on our auth required namespace
	t.Run("testFailureToGetToken", func(t *testing.T) {
		tc, err := te.NewClient()
		assert.NoError(t, err)

		// use our auth required namespace
		mockRemoteUrl, err := url.Parse("/second/namespace/hello_world.txt")
		require.NoError(t, err)
		_, err = tc.NewTransferJob(context.Background(), mockRemoteUrl, "/dest", false, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get token for transfer: failed to find or generate a token as required for /second/namespace/hello_world.txt")
	})

	// Test success
	t.Run("testSuccess", func(t *testing.T) {
		tc, err := te.NewClient()
		assert.NoError(t, err)

		remoteUrl, err := url.Parse("/first/namespace/hello_world.txt")
		require.NoError(t, err)
		_, err = tc.NewTransferJob(context.Background(), remoteUrl, t.TempDir(), false, false)
		assert.NoError(t, err)
	})
}

// A test that spins up a federation, and tests object list
func TestObjectList(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()
	defer server_utils.ResetOriginExports()
	defer viper.Reset()
	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

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

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

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

	// Make directories for test within origin exports
	destDir1 := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir1, os.FileMode(0755)))
	destDir2 := filepath.Join(fed.Exports[1].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir2, os.FileMode(0755)))

	// This tests object ls with no flags set
	t.Run("testPelicanObjectLsNoFlags", func(t *testing.T) {
		for _, export := range fed.Exports {
			listURL := fmt.Sprintf("pelican://%s:%d%s", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), export.FederationPrefix)
			if export.Capabilities.PublicReads {
				get, err := client.DoList(fed.Ctx, listURL, client.WithTokenLocation(""))
				require.NoError(t, err)
				require.Len(t, get, 2)
			} else {
				get, err := client.DoList(fed.Ctx, listURL, client.WithTokenLocation(tempToken.Name()))
				require.NoError(t, err)
				require.Len(t, get, 2)
			}
		}
	})

	t.Run("testPelicanObjectLsNoTokForProtectedNs", func(t *testing.T) {
		for _, export := range fed.Exports {
			listURL := fmt.Sprintf("pelican://%s:%d%s", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), export.FederationPrefix)
			if !export.Capabilities.PublicReads {
				get, err := client.DoList(fed.Ctx, listURL, client.WithTokenLocation(""))
				require.Error(t, err)
				assert.Len(t, get, 0)
				assert.Contains(t, err.Error(), "failed to get token for transfer: failed to find or generate a token as required")

				// No error if it's with token
				get, err = client.DoList(fed.Ctx, listURL, client.WithTokenLocation(tempToken.Name()))
				require.NoError(t, err)
				require.Len(t, get, 2)
			} else {
				get, err := client.DoList(fed.Ctx, listURL, client.WithTokenLocation(tempToken.Name()))
				require.NoError(t, err)
				require.Len(t, get, 2)
			}
		}
	})

	// Test we fail when we have an incorrect namespace
	t.Run("testPelicanObjectLsFailWhenNamespaceIncorrect", func(t *testing.T) {
		// set the prefix to /first instead of /first/namespace
		federationPrefix := "/first/"
		listURL := fmt.Sprintf("pelican://%s:%s%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()), federationPrefix)

		_, err := client.DoList(fed.Ctx, listURL, nil, client.WithTokenLocation(tempToken.Name()))
		require.Error(t, err)
		require.Contains(t, err.Error(), "404: No namespace found for path. Either it doesn't exist, or the Director is experiencing problems")
	})
}

// This tests object ls but for an origin that supports listings but with an object store that does not support PROPFIND.
// We should get a 405 returned. This is a separate test since we need a completely different origin
func TestObjectList405Error(t *testing.T) {
	test_utils.InitClient(t, nil)
	server_utils.ResetOriginExports()
	defer server_utils.ResetOriginExports()
	err := config.InitClient()
	require.NoError(t, err)

	// Set up our http backend so that we can return a 405 on a PROPFIND
	body := "Hello, World!"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == "GET" && r.URL.Path == "/test2/hello_world" {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusPartialContent)
			_, err := w.Write([]byte(body))
			require.NoError(t, err)
			return
		} else if r.Method == "PROPFIND" && r.URL.Path == "/test2/hello_world" {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()
	viper.Set("Origin.HttpServiceUrl", srv.URL+"/test2")

	config.InitConfig()
	fed := fed_test_utils.NewFedTest(t, httpsOriginConfig)
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	_, err = client.DoList(fed.Ctx, "pelican://"+host+"/test/hello_world")
	require.Error(t, err)
	require.Contains(t, err.Error(), "405: object listings are not supported by the discovered origin")
}
