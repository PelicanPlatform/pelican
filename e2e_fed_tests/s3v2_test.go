//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package fed_tests

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

const s3v2MemOriginConfig = `
Origin:
  StorageType: s3v2
  ObjectProviderURL: "mem://"
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`

// getS3v2Token creates a token with broad read/create/modify scopes for S3v2 tests.
func getS3v2Token(t *testing.T) string {
	t.Helper()
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	createScope, err := token_scopes.Wlcg_Storage_Create.Path("/")
	require.NoError(t, err)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	tokenConfig.AddScopes(readScope, createScope, modScope)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	return tkn
}

// TestS3v2MemOriginUploadDownload tests the full federation round-trip
// using the in-memory blob backend (mem://).
func TestS3v2MemOriginUploadDownload(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0, "Federation should have at least one export")
	assert.Equal(t, "/test", ft.Exports[0].FederationPrefix)

	testContent := "Hello from the S3v2 mem:// federation test!"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "test_file.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getS3v2Token(t)

	// Upload
	uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, uploadResults)
	assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))

	// Download
	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, downloadResults)
	assert.Equal(t, uploadResults[0].TransferredBytes, downloadResults[0].TransferredBytes)

	// Verify content
	got, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(got))
}

// TestS3v2MemOriginStat tests stat operations against the in-memory backend.
func TestS3v2MemOriginStat(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)

	// Upload a file first (mem backend starts empty)
	testContent := []byte("Stat me via the federation")
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "stat_test.txt")
	require.NoError(t, os.WriteFile(localFile, testContent, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/stat_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getS3v2Token(t)

	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// Stat the file
	statInfo, err := client.DoStat(ft.Ctx, uploadURL, client.WithToken(testToken))
	require.NoError(t, err)
	assert.Equal(t, int64(len(testContent)), statInfo.Size)
	assert.Equal(t, "/test/stat_test.txt", statInfo.Name)
}

// TestS3v2MemOriginMultipleFiles tests uploading and downloading multiple files.
func TestS3v2MemOriginMultipleFiles(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)

	testFiles := map[string]string{
		"alpha.txt": "Content alpha",
		"beta.txt":  "Content beta",
		"gamma.txt": "Content gamma",
	}

	localTmpDir := t.TempDir()
	testToken := getS3v2Token(t)

	// Upload all files
	for name, content := range testFiles {
		localFile := filepath.Join(localTmpDir, name)
		require.NoError(t, os.WriteFile(localFile, []byte(content), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)

		results, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err, "Failed to upload %s", name)
		require.NotEmpty(t, results)
	}

	// Download and verify all files
	for name, expected := range testFiles {
		downloadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
		downloadFile := filepath.Join(localTmpDir, "dl_"+name)

		results, err := client.DoGet(ft.Ctx, downloadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err, "Failed to download %s", name)
		require.NotEmpty(t, results)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, expected, string(got), "Content mismatch for %s", name)
	}
}

// TestS3v2MemOriginLargeFile tests transferring a 10 MB file through the federation.
func TestS3v2MemOriginLargeFile(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)

	largeContent := make([]byte, 10*1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	originalHash := fmt.Sprintf("%x", md5.Sum(largeContent))

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "large.bin")
	require.NoError(t, os.WriteFile(localFile, largeContent, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/large.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	testToken := getS3v2Token(t)

	uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, uploadResults)
	assert.Equal(t, int64(len(largeContent)), uploadResults[0].TransferredBytes)

	downloadFile := filepath.Join(localTmpDir, "large_dl.bin")
	downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, downloadResults)
	assert.Equal(t, uploadResults[0].TransferredBytes, downloadResults[0].TransferredBytes)

	got, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	gotHash := fmt.Sprintf("%x", md5.Sum(got))
	assert.Equal(t, originalHash, gotHash, "Downloaded file hash should match original")
}

// TestS3v2MemOriginListing tests directory listing through the federation.
func TestS3v2MemOriginListing(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)

	testToken := getS3v2Token(t)
	localTmpDir := t.TempDir()

	// Upload several files to populate the mem backend
	files := []string{"a.txt", "b.txt", "c.txt"}
	for _, name := range files {
		localFile := filepath.Join(localTmpDir, name)
		require.NoError(t, os.WriteFile(localFile, []byte("content of "+name), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err, "Failed to upload %s", name)
	}

	// List the /test/ directory
	listURL := fmt.Sprintf("pelican://%s:%d/test/",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
	require.NoError(t, err)
	require.NotEmpty(t, entries, "Listing should return entries")

	// Check that our uploaded files appear in the listing
	nameSet := make(map[string]bool)
	for _, e := range entries {
		nameSet[e.Name] = true
	}
	for _, name := range files {
		found := false
		for key := range nameSet {
			if strings.Contains(key, name) {
				found = true
				break
			}
		}
		assert.True(t, found, "Listing should contain %s", name)
	}
}

// TestS3v2MemOriginOverwrite tests overwriting an existing file.
func TestS3v2MemOriginOverwrite(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, s3v2MemOriginConfig)
	require.NotNil(t, ft)

	testToken := getS3v2Token(t)
	localTmpDir := t.TempDir()

	// Enable client-side overwrites so the second PUT doesn't fail with FileAlreadyExists
	require.NoError(t, param.Set(param.Client_EnableOverwrites.GetName(), true))
	defer func() {
		require.NoError(t, param.Set(param.Client_EnableOverwrites.GetName(), false))
	}()

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/overwrite.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// First upload
	localFile := filepath.Join(localTmpDir, "v1.txt")
	require.NoError(t, os.WriteFile(localFile, []byte("version 1"), 0644))
	_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// Overwrite with new content
	localFile2 := filepath.Join(localTmpDir, "v2.txt")
	require.NoError(t, os.WriteFile(localFile2, []byte("version 2"), 0644))
	_, err = client.DoPut(ft.Ctx, localFile2, uploadURL, false, client.WithToken(testToken))
	require.NoError(t, err)

	// Download and verify we get the latest version
	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
	require.NoError(t, err)

	got, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, "version 2", string(got))
}

// ---------------------------------------------------------------------------
// Minio-backed federation tests
// ---------------------------------------------------------------------------

// TestS3v2MinioOriginUploadDownload runs a full Pelican federation backed by
// a real MinIO server. It exercises the complete S3v2 data path: director
// redirect → origin HTTP handler → gocloud.dev/blob/s3blob → MinIO. Skipped
// if minio is not installed.
func TestS3v2MinioOriginUploadDownload(t *testing.T) {
	test_utils.SkipIfNoMinio(t)
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	minioEndpoint, accessKey, secretKey := test_utils.StartMinio(t, "test-bucket")

	// Write credential files for the origin to read.
	credDir := t.TempDir()
	akFile := filepath.Join(credDir, "access-key")
	skFile := filepath.Join(credDir, "secret-key")
	require.NoError(t, os.WriteFile(akFile, []byte(accessKey), 0600))
	require.NoError(t, os.WriteFile(skFile, []byte(secretKey), 0600))

	// S3 params must be in the YAML config so they survive NewFedTest's
	// config.InitServer → viper.MergeConfig flow and are available when
	// GetOriginExports() runs.
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: s3v2
  S3ServiceUrl: %s
  S3Region: us-east-1
  S3Bucket: test-bucket
  S3AccessKeyfile: %s
  S3SecretKeyfile: %s
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, minioEndpoint, akFile, skFile)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0)

	testToken := getS3v2Token(t)
	localTmpDir := t.TempDir()

	t.Run("UploadAndDownload", func(t *testing.T) {
		testContent := "Hello from the MinIO-backed federation test!"
		localFile := filepath.Join(localTmpDir, "test_file.txt")
		require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/test_file.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, uploadResults)
		assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))

		downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
		downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, downloadResults)
		assert.Equal(t, uploadResults[0].TransferredBytes, downloadResults[0].TransferredBytes)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, string(got))
	})

	t.Run("Stat", func(t *testing.T) {
		content := []byte("Stat me via the MinIO federation")
		localFile := filepath.Join(localTmpDir, "stat_test.txt")
		require.NoError(t, os.WriteFile(localFile, content, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/stat_test.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)

		statInfo, err := client.DoStat(ft.Ctx, uploadURL, client.WithToken(testToken))
		require.NoError(t, err)
		assert.Equal(t, int64(len(content)), statInfo.Size)
	})

	t.Run("LargeFile", func(t *testing.T) {
		largeContent := make([]byte, 5*1024*1024) // 5 MB
		for i := range largeContent {
			largeContent[i] = byte(i % 256)
		}
		originalHash := fmt.Sprintf("%x", md5.Sum(largeContent))

		localFile := filepath.Join(localTmpDir, "large.bin")
		require.NoError(t, os.WriteFile(localFile, largeContent, 0644))

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/large.bin",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)

		downloadFile := filepath.Join(localTmpDir, "large_dl.bin")
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		gotHash := fmt.Sprintf("%x", md5.Sum(got))
		assert.Equal(t, originalHash, gotHash)
	})

	t.Run("Listing", func(t *testing.T) {
		for _, name := range []string{"list_a.txt", "list_b.txt"} {
			localFile := filepath.Join(localTmpDir, name)
			require.NoError(t, os.WriteFile(localFile, []byte("content of "+name), 0644))

			uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), name)
			_, err := client.DoPut(ft.Ctx, localFile, uploadURL, false, client.WithToken(testToken))
			require.NoError(t, err)
		}

		listURL := fmt.Sprintf("pelican://%s:%d/test/",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
		entries, err := client.DoList(ft.Ctx, listURL, client.WithToken(testToken))
		require.NoError(t, err)
		require.NotEmpty(t, entries)

		nameSet := make(map[string]bool)
		for _, e := range entries {
			nameSet[e.Name] = true
		}
		for _, name := range []string{"list_a.txt", "list_b.txt"} {
			found := false
			for key := range nameSet {
				if strings.Contains(key, name) {
					found = true
					break
				}
			}
			assert.True(t, found, "Listing should contain %s", name)
		}
	})

	t.Run("Overwrite", func(t *testing.T) {
		// Enable client-side overwrites so the second PUT doesn't fail with FileAlreadyExists
		require.NoError(t, param.Set(param.Client_EnableOverwrites.GetName(), true))
		defer func() {
			require.NoError(t, param.Set(param.Client_EnableOverwrites.GetName(), false))
		}()

		uploadURL := fmt.Sprintf("pelican://%s:%d/test/overwrite_minio.txt",
			param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

		v1 := filepath.Join(localTmpDir, "v1.txt")
		require.NoError(t, os.WriteFile(v1, []byte("version 1"), 0644))
		_, err := client.DoPut(ft.Ctx, v1, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)

		v2 := filepath.Join(localTmpDir, "v2.txt")
		require.NoError(t, os.WriteFile(v2, []byte("version 2"), 0644))
		_, err = client.DoPut(ft.Ctx, v2, uploadURL, false, client.WithToken(testToken))
		require.NoError(t, err)

		downloadFile := filepath.Join(localTmpDir, "overwrite_dl.txt")
		_, err = client.DoGet(ft.Ctx, uploadURL, downloadFile, false, client.WithToken(testToken))
		require.NoError(t, err)

		got, err := os.ReadFile(downloadFile)
		require.NoError(t, err)
		assert.Equal(t, "version 2", string(got))
	})
}
