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
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
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

	viper.Set("Origin.ExportVolume", originDir+":/test")
	viper.Set("Origin.Mode", "posix")
	// Disable functionality we're not using (and is difficult to make work on Mac)
	viper.Set("Origin.EnableCmsd", false)
	viper.Set("Origin.EnableMacaroons", false)
	viper.Set("Origin.EnableVoms", false)
	viper.Set("Origin.EnableWrite", true)
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
	fed := fed_test_utils.NewFedTest(t)

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
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "pelican:///test/" + fileName

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
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testPelicanObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("pelican")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		// Minimal fix of test as it is soon to be replaced
		uploadURL := "pelican:///test/" + fileName

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
	})

	// This tests object get/put with a pelican:// url
	t.Run("testOsdfObjectPutAndGetWithPelicanUrl", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		uploadURL := "pelican:///test/" + fileName

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
	})

	// This tests pelican object get/put with an osdf url
	t.Run("testOsdfObjectPutAndGetWithOSDFUrl", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		// Set path for object to upload/download
		tempPath := tempFile.Name()
		fileName := filepath.Base(tempPath)
		// Minimal fix of test as it is soon to be replaced
		uploadURL := "pelican:///test/" + fileName

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
	})
}

// A test that spins up the federation, where the origin is in EnablePublicReads mode. Then GET a file from the origin without a token
func TestGetPublicRead(t *testing.T) {
	ctx, _, _ := test_utils.TestContext(context.Background(), t)
	viper.Reset()
	viper.Set("Origin.EnablePublicReads", true)
	fed := fed_test_utils.NewFedTest(t)

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
		uploadURL := "pelican:///test/" + fileName

		// Download the file with GET. Shouldn't need a token to succeed
		transferResults, err := client.DoGet(ctx, uploadURL, t.TempDir(), false)
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResults[0].TransferredBytes, int64(17))
		}
	})
}

func TestRecursiveUploadsAndDownloads(t *testing.T) {
	// Create instance of test federation
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	viper.Reset()
	fed_test_utils.NewFedTest(t)

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
		config.SetPreferredPrefix("pelican")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		// Note: minimally fixing this test as it is soon to be replaced
		uploadURL := "pelican://" + param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt()) + "/test/" + dirName

		//////////////////////////////////////////////////////////

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
		require.NoError(t, err)
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
		transferDetailsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
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
	})

	t.Run("testPelicanRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		config.SetPreferredPrefix("pelican")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadURL := "pelican:///test/" + dirName

		//////////////////////////////////////////////////////////

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
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
		transferDetailsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
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
	})

	t.Run("testOsdfRecursiveGetAndPutOsdfURL", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		// Note: minimally fixing this test as it is soon to be replaced
		uploadURL := "pelican://" + param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt()) + "/test/" + dirName

		//////////////////////////////////////////////////////////

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
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
		transferDetailsDownload, err := client.DoGet(ctx, uploadURL, tmpDir, true, client.WithTokenLocation(tempToken.Name()))
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
	})

	t.Run("testOsdfRecursiveGetAndPutPelicanURL", func(t *testing.T) {
		config.SetPreferredPrefix("osdf")
		// Set path for object to upload/download
		tempPath := tempDir
		dirName := filepath.Base(tempPath)
		uploadURL := "pelican:///test/" + dirName

		//////////////////////////////////////////////////////////

		// Upload the file with PUT
		transferDetailsUpload, err := client.DoPut(ctx, tempDir, uploadURL, true, client.WithTokenLocation(tempToken.Name()))
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
		transferDetailsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), true, client.WithTokenLocation(tempToken.Name()))
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
	})
}
