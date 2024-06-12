//go:build linux

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
	"fmt"
	"io/fs"
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
	config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	te, err := client.NewTransferEngine(fed.Ctx)
	require.NoError(t, err)

	// Create a token file
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()
	tokenConfig.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Storage_Modify, "/"))
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
	innerTempDir, err := os.MkdirTemp(tempDir, "InnerUploadDir")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)
	defer os.RemoveAll(tempDir)
	permissions := os.FileMode(0755)
	err = os.Chmod(tempDir, permissions)
	require.NoError(t, err)
	err = os.Chmod(innerTempDir, permissions)
	require.NoError(t, err)

	testFileContent1 := "test file content"
	testFileContent2 := "more test file content!"
	innerTestFileContent := "this content is within another dir!"
	tempFile1, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp1 file")
	tempFile2, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp2 file")
	innerTempFile, err := os.CreateTemp(innerTempDir, "testInner")
	assert.NoError(t, err, "Error creating inner test file")
	defer os.Remove(tempFile1.Name())
	defer os.Remove(tempFile2.Name())
	defer os.Remove(innerTempFile.Name())

	_, err = tempFile1.WriteString(testFileContent1)
	assert.NoError(t, err, "Error writing to temp1 file")
	tempFile1.Close()
	_, err = tempFile2.WriteString(testFileContent2)
	assert.NoError(t, err, "Error writing to temp2 file")
	tempFile2.Close()
	_, err = innerTempFile.WriteString(innerTestFileContent)
	assert.NoError(t, err, "Error writing to inner test file")
	innerTempFile.Close()

	t.Run("testPelicanRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	t.Run("testOsdfRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()
		assert.NoError(t, err)
		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("osdf:///%s/%s/%s", export.FederationPrefix, "osdf_osdf", dirName)
			hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

			// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
			metadata, err := config.DiscoverUrlFederation(fed.Ctx, "https://"+hostname)
			assert.NoError(t, err)
			viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
			viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
			viper.Set("Federation.DiscoveryUrl", hostname)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			tmpDir := t.TempDir()
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, tmpDir, true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, tmpDir, true, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	t.Run("testOsdfRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		oldPref, err := config.SetPreferredPrefix(config.OsdfPrefix)
		assert.NoError(t, err)
		defer func() {
			_, err := config.SetPreferredPrefix(oldPref)
			require.NoError(t, err)
		}()

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)
			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
		server_utils.ResetOriginExports()
	})
}

// Helper function to verify a successful transfer by looking at the total bytes transferred and amount of results sent back
func verifySuccessfulTransfer(t *testing.T, transferResults []client.TransferResults) {
	expectedBytes := int64(75)
	var totalBytes int64 // we expect this to be 17+23+35 = 75
	for _, transfer := range transferResults {
		totalBytes += transfer.TransferredBytes
	}

	require.Equal(t, 3, len(transferResults), fmt.Sprintf("incorrect number of transfers reported %d", len(transferResults)))
	require.Equal(t, expectedBytes, totalBytes, fmt.Sprintf("incorrect number of transferred bytes: %d", totalBytes))

}

// Test that recursive uploads and downloads work with the ?recursive query
func TestRecursiveUploadsAndDownloadsWithQuery(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	te, err := client.NewTransferEngine(fed.Ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a viper.Reset for good measure. Keeps our env squeaky clean!
		viper.Reset()
		server_utils.ResetOriginExports()
	})

	// Create a token file
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()
	tokenConfig.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Storage_Read, "/"),
		token_scopes.NewResourceScope(token_scopes.Storage_Modify, "/"))
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
	innerTempDir, err := os.MkdirTemp(tempDir, "InnerUploadDir")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)
	permissions := os.FileMode(0755)
	err = os.Chmod(tempDir, permissions)
	require.NoError(t, err)
	err = os.Chmod(innerTempDir, permissions)
	require.NoError(t, err)

	testFileContent1 := "test file content"
	testFileContent2 := "more test file content!"
	innerTestFileContent := "this content is within another dir!"
	tempFile1, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp1 file")
	tempFile2, err := os.CreateTemp(tempDir, "test1")
	assert.NoError(t, err, "Error creating temp2 file")
	innerTempFile, err := os.CreateTemp(innerTempDir, "testInner")
	assert.NoError(t, err, "Error creating inner test file")
	defer os.Remove(tempFile1.Name())
	defer os.Remove(tempFile2.Name())
	defer os.Remove(innerTempFile.Name())

	_, err = tempFile1.WriteString(testFileContent1)
	assert.NoError(t, err, "Error writing to temp1 file")
	tempFile1.Close()
	_, err = tempFile2.WriteString(testFileContent2)
	assert.NoError(t, err, "Error writing to temp2 file")
	tempFile2.Close()
	_, err = innerTempFile.WriteString(innerTestFileContent)
	assert.NoError(t, err, "Error writing to inner test file")
	innerTempFile.Close()

	// Test we work with just the query
	t.Run("testRecursiveGetAndPutWithQuery", func(t *testing.T) {
		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s?recursive", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	// Test we work with a value assigned to it (we print deprecation warning)
	t.Run("testRecursiveGetAndPutWithQueryWithValueTrue", func(t *testing.T) {
		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s?recursive=true", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	// Test we work with a value assigned to it but says recursive=false (we print deprecation warning and ignore arguments in query so we still work)
	t.Run("testRecursiveGetAndPutWithQueryWithValueFalse", func(t *testing.T) {
		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s?recursive=false", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	// Test we work with both recursive and directread query params
	t.Run("testRecursiveGetAndPutWithQueryAndDirectread", func(t *testing.T) {
		_, err := config.SetPreferredPrefix(config.PelicanPrefix)
		assert.NoError(t, err)

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s?recursive&directread", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})
}

// This tests that is origins disable listings, we should fail the download
// Note: origins disabling listings override the existence of dirlisthost, causing a failure
func TestFailureOnOriginDisablingListings(t *testing.T) {
	viper.Reset()
	server_utils.ResetOriginExports()

	viper.Set("Logging.Level", "debug")
	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.ExportVolumes", "/test")
	viper.Set("Origin.EnablePublicReads", true)
	viper.Set("Origin.EnableListings", false)
	fed := fed_test_utils.NewFedTest(t, "")

	destDir := filepath.Join(fed.Exports[0].StoragePrefix, "test")
	require.NoError(t, os.MkdirAll(destDir, os.FileMode(0755)))
	log.Debugln("Will create origin file at", destDir)
	err := os.WriteFile(filepath.Join(destDir, "test.txt"), []byte("test file content"), fs.FileMode(0644))
	require.NoError(t, err)
	downloadURL := fmt.Sprintf("pelican://%s:%s%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
		fed.Exports[0].FederationPrefix, "test")

	_, err = client.DoGet(fed.Ctx, downloadURL, t.TempDir(), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "origin and/or namespace does not support directory listings")
}
