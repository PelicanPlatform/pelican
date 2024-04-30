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
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/client"
	config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	te := client.NewTransferEngine(fed.Ctx)

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
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 3 {
				countBytes17 := 0
				countBytes23 := 0
				countBytes35 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				for _, transfer := range transferDetailsUpload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case int64(17):
						countBytes17++
						continue
					case int64(23):
						countBytes23++
						continue
					case int64(35):
						countBytes35++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 || countBytes35 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 3 {
				t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
			}

			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
			}
			assert.NoError(t, err)
			if err == nil && len(transferDetailsDownload) == 3 {
				countBytesDownloadIdx0 := 0
				countBytesDownloadIdx1 := 0
				countBytesDownloadIdx2 := 0

				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsDownload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsDownload[0].TransferredBytes:
						countBytesDownloadIdx0++
						continue
					case transferDetailsDownload[1].TransferredBytes:
						countBytesDownloadIdx1++
						continue
					case transferDetailsDownload[2].TransferredBytes:
						countBytesDownloadIdx2++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesDownloadIdx0 != 1 || countBytesDownloadIdx1 != 1 || countBytesDownloadIdx2 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				} else if len(transferDetailsDownload) != 3 {
					t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
				}
			}
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
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 3 {
				countBytes17 := 0
				countBytes23 := 0
				countBytes35 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				for _, transfer := range transferDetailsUpload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case int64(17):
						countBytes17++
						continue
					case int64(23):
						countBytes23++
						continue
					case int64(35):
						countBytes35++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 || countBytes35 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 3 {
				t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
			}

			// Download the files we just uploaded
			tmpDir := t.TempDir()
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, tmpDir, true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, tmpDir, true, client.WithTokenLocation(tempToken.Name()))
			}
			assert.NoError(t, err)
			if err == nil && len(transferDetailsDownload) == 3 {
				countBytesDownloadIdx0 := 0
				countBytesDownloadIdx1 := 0
				countBytesDownloadIdx2 := 0

				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsDownload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsDownload[0].TransferredBytes:
						countBytesDownloadIdx0++
						continue
					case transferDetailsDownload[1].TransferredBytes:
						countBytesDownloadIdx1++
						continue
					case transferDetailsDownload[2].TransferredBytes:
						countBytesDownloadIdx2++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesDownloadIdx0 != 1 || countBytesDownloadIdx1 != 1 || countBytesDownloadIdx2 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				} else if len(transferDetailsDownload) != 3 {
					t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
				}
			}
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
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 3 {
				countBytes17 := 0
				countBytes23 := 0
				countBytes35 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				for _, transfer := range transferDetailsUpload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case int64(17):
						countBytes17++
						continue
					case int64(23):
						countBytes23++
						continue
					case int64(35):
						countBytes35++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 || countBytes35 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 3 {
				t.Fatalf("Amount of transfers results returned for upload was not correct. Transfer details returned: %d", len(transferDetailsUpload))
			}
			// Download the files we just uploaded
			var transferDetailsDownload []client.TransferResults
			if export.Capabilities.PublicReads {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true)
			} else {
				transferDetailsDownload, err = client.DoGet(fed.Ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
			}
			assert.NoError(t, err)
			if err == nil && len(transferDetailsDownload) == 3 {
				countBytesDownloadIdx0 := 0
				countBytesDownloadIdx1 := 0
				countBytesDownloadIdx2 := 0

				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsDownload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsDownload[0].TransferredBytes:
						countBytesDownloadIdx0++
						continue
					case transferDetailsDownload[1].TransferredBytes:
						countBytesDownloadIdx1++
						continue
					case transferDetailsDownload[2].TransferredBytes:
						countBytesDownloadIdx2++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesDownloadIdx0 != 1 || countBytesDownloadIdx1 != 1 || countBytesDownloadIdx2 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				} else if len(transferDetailsDownload) != 3 {
					t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
				}
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
