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

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

var (
	bothAuthOriginCfg = `
Origin:
  Exports:
    - FederationPrefix: /test
      StoragePrefix: /tmp/test
      Capabilities: [Reads, Writes, DirectReads, Listings]
`
)

// Helper function to get a temporary token file
func getTempTokenForTest(t *testing.T) (tempToken *os.File, tkn string) {
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir()))

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	// Create a token file
	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "origin"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	assert.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
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

// TestObjectPutToDirectoryInfersFilename tests that uploading to a directory
// infers the destination filename from the source file, similar to cp/scp behavior.
func TestObjectPutToDirectoryInfersFilename(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Use an authenticated origin configuration
	fed := fed_test_utils.NewFedTest(t, bothAuthOriginCfg)

	// Create test files
	testFileContent1 := "test file content for directory inference"
	tempFile1, err := os.CreateTemp(t.TempDir(), "test1-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile1.Name())
	_, err = tempFile1.WriteString(testFileContent1)
	require.NoError(t, err)
	tempFile1.Close()

	testFileContent2 := "second test file content"
	tempFile2, err := os.CreateTemp(t.TempDir(), "test2-*.txt")
	require.NoError(t, err)
	defer os.Remove(tempFile2.Name())
	_, err = tempFile2.WriteString(testFileContent2)
	require.NoError(t, err)
	tempFile2.Close()

	// Get token
	tempToken, _ := getTempTokenForTest(t)
	defer tempToken.Close()
	defer os.Remove(tempToken.Name())

	// Disable progress bars
	require.NoError(t, param.Set("Logging.DisableProgressBars", true))

	namespacePrefix := fed.Exports[0].FederationPrefix
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	host := discoveryUrl.Host

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
	})

	// First upload a file to create a "directory" at the destination
	subdirUploadURL := fmt.Sprintf("pelican://%s%s/testdir/%s", host, namespacePrefix, filepath.Base(tempFile1.Name()))

	rootCmd.SetContext(fed.Ctx)
	rootCmd.SetArgs([]string{"object", "put", "-t", tempToken.Name(), tempFile1.Name(), subdirUploadURL})

	err = rootCmd.Execute()
	require.NoError(t, err)

	// Now test that uploading to just the namespace/testdir infers the filename
	dirUploadURL := fmt.Sprintf("pelican://%s%s/testdir", host, namespacePrefix)

	rootCmd.SetContext(fed.Ctx)
	rootCmd.SetArgs([]string{"object", "put", "-t", tempToken.Name(), tempFile2.Name(), dirUploadURL})

	err = rootCmd.Execute()
	require.NoError(t, err)

	// Verify the file was uploaded to testdir/<inferred-filename>
	inferredUploadURL := fmt.Sprintf("pelican://%s%s/testdir/%s", host, namespacePrefix, filepath.Base(tempFile2.Name()))

	downloadDir := t.TempDir()
	downloadPath := filepath.Join(downloadDir, "downloaded-file.txt")

	_, err = client.DoGet(fed.Ctx, inferredUploadURL, downloadPath, false, client.WithTokenLocation(tempToken.Name()))
	require.NoError(t, err)

	// Verify the downloaded file has the correct content
	downloadedContent, err := os.ReadFile(downloadPath)
	require.NoError(t, err)
	assert.Equal(t, testFileContent2, string(downloadedContent))
}
