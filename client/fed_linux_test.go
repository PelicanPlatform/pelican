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
	config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s", discoveryUrl.Host,
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
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

		oldHost, err := pelican_url.SetOsdfDiscoveryHost(discoveryUrl.String())
		require.NoError(t, err)
		defer func() {
			_, _ = pelican_url.SetOsdfDiscoveryHost(oldHost)
		}()

		for _, export := range fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadUrl := fmt.Sprintf("osdf://%s/%s/%s", export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			tmpDir := t.TempDir()
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, tmpDir, true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, tmpDir, true, client.WithTokenLocation(tempToken.Name()))
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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s", discoveryUrl.Host,
				export.FederationPrefix, "osdf_osdf", dirName)
			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})

	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()

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
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	te, err := client.NewTransferEngine(fed.Ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		if err := te.Shutdown(); err != nil {
			log.Errorln("Failure when shutting down transfer engine:", err)
		}
		// Throw in a config.Reset for good measure. Keeps our env squeaky clean!
		server_utils.ResetTestState()

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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s?recursive", discoveryUrl.Host, export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s?recursive=true", discoveryUrl.Host, export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s?recursive=false", discoveryUrl.Host, export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
			uploadUrl := fmt.Sprintf("pelican://%s%s/%s/%s?recursive&directread", discoveryUrl.Host, export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, false, client.WithTokenLocation(tempToken.Name()))
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsUpload)

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
			}
			require.NoError(t, err)
			verifySuccessfulTransfer(t, transferDetailsDownload)
		}
	})
}

// This tests that is origins disable listings, we should fail the download
// Note: origins disabling listings override the existence of dirlisthost, causing a failure
func TestFailureOnOriginDisablingListings(t *testing.T) {
	server_utils.ResetTestState()

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
	assert.Contains(t, err.Error(), "no collections URL found in director response")
}

func TestSyncUpload(t *testing.T) {
	// Create instance of test federation
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
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
	tempDir := t.TempDir()
	innerTempDir, err := os.MkdirTemp(tempDir, "InnerUploadDir")
	assert.NoError(t, err)
	permissions := os.FileMode(0755)
	err = os.Chmod(tempDir, permissions)
	require.NoError(t, err)
	err = os.Chmod(innerTempDir, permissions)
	require.NoError(t, err)

	testFileContent1 := "test file content"
	testFileContent2 := "more test file content!"
	innerTestFileContent := "this content is within another dir!"
	tempFile1, err := os.CreateTemp(tempDir, "test1")
	require.NoError(t, err, "Error creating temp1 file")
	tempFile2, err := os.CreateTemp(tempDir, "test1")
	require.NoError(t, err, "Error creating temp2 file")
	innerTempFile, err := os.CreateTemp(innerTempDir, "testInner")
	require.NoError(t, err, "Error creating inner test file")

	_, err = tempFile1.WriteString(testFileContent1)
	require.NoError(t, err, "Error writing to temp1 file")
	tempFile1.Close()
	_, err = tempFile2.WriteString(testFileContent2)
	require.NoError(t, err, "Error writing to temp2 file")
	tempFile2.Close()
	_, err = innerTempFile.WriteString(innerTestFileContent)
	require.NoError(t, err, "Error writing to inner test file")
	innerTempFile.Close()

	t.Run("testSyncUploadFull", func(t *testing.T) {
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_upload/%s", discoveryUrl.Host, dirName)

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsUpload)

		// Download the files we just uploaded
		transferDetailsDownload, err := client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsDownload)
	})

	t.Run("testSyncUploadNone", func(t *testing.T) {
		// Set path for object to upload/download
		dirName := filepath.Base(tempDir)
		uploadUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_upload_none/%s", discoveryUrl.Host, dirName)

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsUpload)

		// Synchronize the uploaded files again.
		transferDetailsUpload, err = client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)

		// Should have already been uploaded once
		assert.Len(t, transferDetailsUpload, 0)
	})

	t.Run("testSyncUploadPartial", func(t *testing.T) {
		// Set path for object to upload/download
		dirName := filepath.Base(tempDir)
		uploadUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_upload_partial/%s", discoveryUrl.Host, dirName)
		uploadInnerUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_upload_partial/%s/%s", discoveryUrl.Host, dirName, filepath.Base(innerTempDir))

		// Upload some files with PUT
		transferDetailsUpload, err := client.DoPut(fed.Ctx, innerTempDir, uploadInnerUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		require.Len(t, transferDetailsUpload, 1)

		// Change the contents of the already-uploaded file; changes shouldn't be detected as the size stays the same
		newTestFileContent := "XXXX content is within another XXXX"
		err = os.WriteFile(innerTempFile.Name(), []byte(newTestFileContent), os.FileMode(0755))
		require.NoError(t, err)

		// Upload again; this time there should be fewer uploads as the subdir was already moved.
		transferDetailsUpload, err = client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		require.Len(t, transferDetailsUpload, 2)

		// Download all the objects
		downloadDir := t.TempDir()
		transferDetailsDownload, err := client.DoGet(fed.Ctx, uploadUrl, downloadDir, true, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsDownload)

		// Verify we received the original contents, not any modified contents
		contentBytes, err := os.ReadFile(filepath.Join(downloadDir, dirName, filepath.Base(innerTempDir), filepath.Base(innerTempFile.Name())))
		require.NoError(t, err)
		assert.Equal(t, innerTestFileContent, string(contentBytes))
	})
}

func TestSyncDownload(t *testing.T) {
	// Create instance of test federation
	server_utils.ResetTestState()

	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
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
	tempDir := t.TempDir()
	innerTempDir, err := os.MkdirTemp(tempDir, "InnerUploadDir")
	assert.NoError(t, err)
	permissions := os.FileMode(0755)
	err = os.Chmod(tempDir, permissions)
	require.NoError(t, err)
	err = os.Chmod(innerTempDir, permissions)
	require.NoError(t, err)

	testFileContent1 := "test file content"
	testFileContent2 := "more test file content!"
	innerTestFileContent := "this content is within another dir!"
	tempFile1, err := os.CreateTemp(tempDir, "test1")
	require.NoError(t, err, "Error creating temp1 file")
	tempFile2, err := os.CreateTemp(tempDir, "test1")
	require.NoError(t, err, "Error creating temp2 file")
	innerTempFile, err := os.CreateTemp(innerTempDir, "testInner")
	require.NoError(t, err, "Error creating inner test file")

	_, err = tempFile1.WriteString(testFileContent1)
	require.NoError(t, err, "Error writing to temp1 file")
	tempFile1.Close()
	_, err = tempFile2.WriteString(testFileContent2)
	require.NoError(t, err, "Error writing to temp2 file")
	tempFile2.Close()
	_, err = innerTempFile.WriteString(innerTestFileContent)
	require.NoError(t, err, "Error writing to inner test file")
	innerTempFile.Close()

	// Set path for object to upload/download
	tempPath := tempDir
	dirName := filepath.Base(tempPath)
	uploadUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_download/%s", discoveryUrl.Host, dirName)

	// Upload the file with PUT
	transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
	require.NoError(t, err)
	verifySuccessfulTransfer(t, transferDetailsUpload)

	t.Run("testSyncDownloadFull", func(t *testing.T) {
		// Download the files we just uploaded
		transferDetailsDownload, err := client.DoGet(fed.Ctx, uploadUrl, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsDownload)
	})

	t.Run("testSyncDownloadNone", func(t *testing.T) {
		// Set path for object to upload/download
		dirName := t.TempDir()

		// Synchronize the uploaded files to a local directory
		transferDetailsDownload, err := client.DoGet(fed.Ctx, uploadUrl, dirName, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsDownload)

		// Synchronize the files again; should result in no transfers
		transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, dirName, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		assert.NoError(t, err)
		assert.Len(t, transferDetailsDownload, 0)
	})

	t.Run("testSyncDownloadPartial", func(t *testing.T) {
		// Set path for object to upload/download
		downloadDir := t.TempDir()
		dirName := filepath.Base(tempDir)
		uploadUrl = fmt.Sprintf("pelican://%s/first/namespace/sync_download_partial/%s", discoveryUrl.Host, dirName)
		uploadInnerUrl := fmt.Sprintf("pelican://%s/first/namespace/sync_download_partial/%s/%s", discoveryUrl.Host, dirName, filepath.Base(innerTempDir))

		// Upload the initial files
		transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadUrl, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		verifySuccessfulTransfer(t, transferDetailsUpload)

		// Download the inner directory
		innerDownloadDir := filepath.Join(downloadDir, dirName, filepath.Base(innerTempDir))
		transferDetailsDownload, err := client.DoGet(fed.Ctx, uploadInnerUrl, innerDownloadDir, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		require.Len(t, transferDetailsDownload, 1)

		// Change the contents of one already-uploaded file and re-upload it.
		// Filesize is the same so a re-download should be skipped.
		newTestFileContent := "XXXX content is within another XXXX"
		err = os.WriteFile(innerTempFile.Name(), []byte(newTestFileContent), os.FileMode(0755))
		require.NoError(t, err)
		transferDetailsUpload, err = client.DoPut(fed.Ctx, innerTempDir, uploadInnerUrl, true, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)
		require.Len(t, transferDetailsUpload, 1)

		// Download all the objects
		transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl, downloadDir, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		assert.Len(t, transferDetailsDownload, 2)

		// Verify we received the original contents, not any modified contents
		contentBytes, err := os.ReadFile(filepath.Join(innerDownloadDir, filepath.Base(innerTempFile.Name())))
		require.NoError(t, err)
		assert.Equal(t, innerTestFileContent, string(contentBytes))

		// Change the local size, then re-sync
		innerDownloadFile := filepath.Join(innerDownloadDir, filepath.Base(innerTempFile.Name()))
		log.Debugln("Overwriting old version of file", innerDownloadFile)
		err = os.Remove(innerDownloadFile)
		require.NoError(t, err)
		err = os.WriteFile(innerDownloadFile, []byte("XXXX"), os.FileMode(0755))
		require.NoError(t, err)
		log.Debugln("Re-downloading file direct from origin")
		transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadUrl+"?directread", downloadDir, true, client.WithTokenLocation(tempToken.Name()), client.WithSynchronize(client.SyncSize))
		require.NoError(t, err)
		assert.Len(t, transferDetailsDownload, 1)
		contentBytes, err = os.ReadFile(filepath.Join(innerDownloadDir, filepath.Base(innerTempFile.Name())))
		require.NoError(t, err)
		assert.Equal(t, newTestFileContent, string(contentBytes))
	})
}
