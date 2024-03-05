//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/launchers"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
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

	fTestTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuerUrl,
		Audience:     []string{config.GetServerAudience()},
		Version:      "1.0",
		Subject:      "origin",
	}
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

	err = config.InitServer(ctx, modules)
	require.NoError(t, err)

	fedCancel, err := launchers.LaunchModules(ctx, modules)
	defer fedCancel()
	if err != nil {
		log.Errorln("Failure in fedServeInternal:", err)
		require.NoError(t, err)
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

	cancel()
	fedCancel()
	assert.NoError(t, egrp.Wait())
	viper.Reset()
}

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
	viper.Set("Origin.Port", 0)
	viper.Set("Server.WebPort", 0)
	viper.Set("Origin.RunLocation", tmpPath)

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

// A test that spins up a federation, and tests object get and put
func TestGetAndPutAuth(t *testing.T) {
	// Create instance of test federation
	ctx, _, _ := test_utils.TestContext(context.Background(), t)

	viper.Reset()
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

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
	tokenConfig := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuer,
		Audience:     []string{audience},
		Subject:      "origin",
	}

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
		transferResultsUpload, err := client.DoPut(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
		transferResultsUpload, err := client.DoPut(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
		transferResultsUpload, err := client.DoPut(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
		transferResultsUpload, err := client.DoPut(ctx, tempFile.Name(), uploadURL, false, client.WithTokenLocation(tempToken.Name()))
		assert.NoError(t, err)
		if err == nil {
			assert.Equal(t, transferResultsUpload[0].TransferredBytes, int64(17))
		}

		// Download that same file with GET
		transferResultsDownload, err := client.DoGet(ctx, uploadURL, t.TempDir(), false, client.WithTokenLocation(tempToken.Name()))
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
	fed := FedTest{T: t}
	fed.Spinup()
	defer fed.Teardown()

	//////////////////////////SETUP///////////////////////////
	// Create a token file
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	audience := config.GetServerAudience()

	tokenConfig := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       issuer,
		Audience:     []string{audience},
		Subject:      "origin",
	}
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