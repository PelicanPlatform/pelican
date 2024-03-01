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
	"context"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pelicanplatform/pelican/client"
	config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	viper.Reset()
	server_utils.ResetOriginExports()

	fed := fed_test_utils.NewFedTest(t, mixedAuthOriginCfg)

	//////////////////////////SETUP///////////////////////////
	// Create a token file
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	audience := config.GetServerAudience()

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudiences(audience)
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

	t.Run("testPelicanRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadStr := "osdf:///test/" + dirName
		uploadURL, err := url.Parse(uploadStr)
		assert.NoError(t, err)

		// For OSDF url's, we don't want to rely on osdf metadata to be running therefore, just ensure we get correct metadata for the url:
		pelicanURL, err := client.NewPelicanURL(uploadURL, "osdf")
		assert.NoError(t, err)

		// Check valid metadata:
		assert.Equal(t, "https://osdf-director.osg-htc.org", pelicanURL.DirectorUrl)
		assert.Equal(t, "https://osdf-registry.osg-htc.org", pelicanURL.RegistryUrl)
		assert.Equal(t, "osg-htc.org", pelicanURL.DiscoveryUrl)
	})

	t.Run("testPelicanRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		config.SetPreferredPrefix("PELICAN")

		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 2 {
				countBytes17 := 0
				countBytes23 := 0
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
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 2 {
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
			if err == nil && len(transferDetailsUpload) == 2 {
				countBytesUploadIdx0 := 0
				countBytesUploadIdx1 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsUpload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsUpload[0].TransferredBytes:
						countBytesUploadIdx0++
						continue
					case transferDetailsUpload[1].TransferredBytes:
						countBytesUploadIdx1++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				} else if len(transferDetailsDownload) != 2 {
					t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
				}
			}
		}
	})

	t.Run("testOsdfRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			// Note: minimally fixing this test as it is soon to be replaced
			uploadURL := fmt.Sprintf("osdf:///%s/%s/%s",
				export.FederationPrefix, "osdf_osdf", dirName)

			hostname := fmt.Sprintf("%v:%v", param.Server_WebHost.GetString(), param.Server_WebPort.GetInt())

			// Set our metadata values in config since that is what this url scheme - prefix combo does in handle_http
			metadata, err := config.DiscoverUrlFederation("https://" + hostname)
			assert.NoError(t, err)
			viper.Set("Federation.DirectorUrl", metadata.DirectorEndpoint)
			viper.Set("Federation.RegistryUrl", metadata.NamespaceRegistrationEndpoint)
			viper.Set("Federation.DiscoveryUrl", hostname)

			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 2 {
				countBytes17 := 0
				countBytes23 := 0
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
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 2 {
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
			if err == nil && len(transferDetailsDownload) == 2 {
				countBytesUploadIdx0 := 0
				countBytesUploadIdx1 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsDownload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsUpload[0].TransferredBytes:
						countBytesUploadIdx0++
						continue
					case transferDetailsUpload[1].TransferredBytes:
						countBytesUploadIdx1++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				}
				contents, err := os.ReadFile(filepath.Join(tmpDir, path.Join(dirName, path.Base(tempFile2.Name()))))
				assert.NoError(t, err)
				assert.Equal(t, testFileContent2, string(contents))
				contents, err = os.ReadFile(filepath.Join(tmpDir, path.Join(dirName, path.Base(tempFile1.Name()))))
				assert.NoError(t, err)
				assert.Equal(t, testFileContent1, string(contents))
			} else if err == nil && len(transferDetailsDownload) != 2 {
				t.Fatalf("Number of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
			}
		}
	})

	t.Run("testOsdfRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		config.SetPreferredPrefix("OSDF")
		for _, export := range *fed.Exports {
			// Set path for object to upload/download
			tempPath := tempDir
			dirName := filepath.Base(tempPath)
			uploadURL := fmt.Sprintf("pelican://%s:%s%s/%s/%s", param.Server_Hostname.GetString(), strconv.Itoa(param.Server_WebPort.GetInt()),
				export.FederationPrefix, "osdf_osdf", dirName)


			// Upload the file with PUT
			transferDetailsUpload, err := client.DoPut(fed.Ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
			assert.NoError(t, err)
			if err == nil && len(transferDetailsUpload) == 2 {
				countBytes17 := 0
				countBytes23 := 0
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
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not upload proper amount of bytes")
					}
				}
				if countBytes17 != 1 || countBytes23 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not uploaded correctly")
				}
			} else if len(transferDetailsUpload) != 2 {
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
			if err == nil && len(transferDetailsUpload) == 2 {
				countBytesUploadIdx0 := 0
				countBytesUploadIdx1 := 0
				// Verify we got the correct files back (have to do this since files upload in different orders at times)
				// In this case, we want to match them to the sizes of the uploaded files
				for _, transfer := range transferDetailsUpload {
					transferredBytes := transfer.TransferredBytes
					switch transferredBytes {
					case transferDetailsUpload[0].TransferredBytes:
						countBytesUploadIdx0++
						continue
					case transferDetailsUpload[1].TransferredBytes:
						countBytesUploadIdx1++
						continue
					default:
						// We got a byte amount we are not expecting
						t.Fatal("did not download proper amount of bytes")
					}
				}
				if countBytesUploadIdx0 != 1 || countBytesUploadIdx1 != 1 {
					// We would hit this case if 1 counter got hit twice for some reason
					t.Fatal("One of the files was not downloaded correctly")
				} else if len(transferDetailsDownload) != 2 {
					t.Fatalf("Amount of transfers results returned for download was not correct. Transfer details returned: %d", len(transferDetailsDownload))
				}
			}
		}
	})
}
