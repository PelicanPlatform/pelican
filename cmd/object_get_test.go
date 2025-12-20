//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/test_utils"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestObjectGetDirectFlag tests that the --direct flag causes downloads to come from the origin
// instead of going through a cache. This test requires xrootd to be installed and actually
// invokes the command-line flag parsing code.
func TestObjectGetDirectFlag(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Skip if xrootd is not available
	if _, err := exec.LookPath("xrootd"); err != nil {
		t.Skip("Skipping test because xrootd is not installed")
	}

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	require.NoError(t, param.Set(param.Origin_EnableDirectReads.GetName(), true))
	require.NoError(t, param.Set(param.Logging_DisableProgressBars.GetName(), true))

	// Create a test federation with cache and origin
	fed := fed_test_utils.NewFedTest(t, "")

	// Get the host and port for building the URL
	host := param.Server_Hostname.GetString() + ":" + strconv.Itoa(param.Server_WebPort.GetInt())

	// Create a test file in the origin's storage
	testFileContent := "test file content for direct read"
	testFileName := "test-direct-read.txt"
	originFilePath := filepath.Join(fed.Exports[0].StoragePrefix, testFileName)
	err := os.WriteFile(originFilePath, []byte(testFileContent), fs.FileMode(0644))
	require.NoError(t, err)

	// Create a temporary directory for downloads
	downloadDir := t.TempDir()

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(context.TODO())
	})

	t.Run("WithDirectFlag", func(t *testing.T) {
		// Test with --direct flag - should read from origin
		downloadUrl := fmt.Sprintf("pelican://%s%s/%s", host, fed.Exports[0].FederationPrefix, testFileName)
		localPath := filepath.Join(downloadDir, "with-direct-flag.txt")
		transferStatsPath := filepath.Join(downloadDir, "transfer-stats-direct.json")

		// Use rootCmd with full command path to properly invoke the subcommand
		rootCmd.SetContext(fed.Ctx)

		// Set arguments to simulate: pelican object get --direct --transfer-stats <path> <url> <dest>
		rootCmd.SetArgs([]string{"object", "get", "--direct", "--transfer-stats", transferStatsPath, downloadUrl, localPath})

		// Execute the command
		err := rootCmd.Execute()
		require.NoError(t, err)

		// Verify the file was downloaded
		downloadedContent, err := os.ReadFile(localPath)
		require.NoError(t, err)
		assert.Equal(t, testFileContent, string(downloadedContent))

		// Read transfer stats to verify the endpoint used
		statsData, err := os.ReadFile(transferStatsPath)
		require.NoError(t, err)

		var transferResults [][]client.TransferResults
		err = json.Unmarshal(statsData, &transferResults)
		require.NoError(t, err)
		require.NotEmpty(t, transferResults)
		require.NotEmpty(t, transferResults[0])

		// Assert that the file was not cached
		cacheDataLocation := param.Cache_StorageLocation.GetString() + fed.Exports[0].FederationPrefix
		cachedFilePath := filepath.Join(cacheDataLocation, testFileName)
		_, err = os.Stat(cachedFilePath)
		assert.True(t, os.IsNotExist(err), "File should not be cached when using direct read")

		// Assert our endpoint was the origin and not the cache
		require.NotEmpty(t, transferResults[0][0].Attempts, "Transfer should have at least one attempt")
		for _, attempt := range transferResults[0][0].Attempts {
			assert.Equal(t, param.Origin_Url.GetString(), "https://"+attempt.Endpoint,
				"Transfer should have used the origin endpoint, not cache")
		}
	})

	t.Run("WithoutDirectFlag", func(t *testing.T) {
		// Test without --direct flag - may go through cache
		downloadUrl := fmt.Sprintf("pelican://%s%s/%s", host, fed.Exports[0].FederationPrefix, testFileName)
		localPath := filepath.Join(downloadDir, "without-direct-flag.txt")
		transferStatsPath := filepath.Join(downloadDir, "transfer-stats-normal.json")

		// Use rootCmd with full command path to properly invoke the subcommand
		rootCmd.SetContext(fed.Ctx)

		// Set arguments WITHOUT --direct flag
		rootCmd.SetArgs([]string{"object", "get", "--transfer-stats", transferStatsPath, downloadUrl, localPath})

		// Execute the command
		err := rootCmd.Execute()
		require.NoError(t, err)

		// Verify the file was downloaded
		downloadedContent, err := os.ReadFile(localPath)
		require.NoError(t, err)
		assert.Equal(t, testFileContent, string(downloadedContent))

		// Read transfer stats
		statsData, err := os.ReadFile(transferStatsPath)
		require.NoError(t, err)

		var transferResults [][]client.TransferResults
		err = json.Unmarshal(statsData, &transferResults)
		require.NoError(t, err)
		require.NotEmpty(t, transferResults)
		require.NotEmpty(t, transferResults[0])

		// Verify transfer succeeded - endpoint might be cache or origin
		assert.Equal(t, int64(len(testFileContent)), transferResults[0][0].TransferredBytes)
	})
}

// TestAddQueryParam tests the URL transformation function
func TestAddQueryParam(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	tests := []struct {
		name        string
		input       string
		key         string
		value       string
		expected    string
		expectError bool
	}{
		{
			name:     "Add directread to simple URL",
			input:    "osdf:///pelicanplatform/test/hello-world.txt",
			key:      "directread",
			value:    "",
			expected: "osdf:///pelicanplatform/test/hello-world.txt?directread=",
		},
		{
			name:     "Add directread to URL with existing query",
			input:    "pelican://example.com/path?pack=auto",
			key:      "directread",
			value:    "",
			expected: "pelican://example.com/path?directread=&pack=auto",
		},
		{
			name:     "Add pack to simple URL",
			input:    "https://example.com/path/to/file",
			key:      "pack",
			value:    "auto",
			expected: "https://example.com/path/to/file?pack=auto",
		},
		{
			name:        "Invalid URL",
			input:       "://invalid",
			key:         "directread",
			value:       "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := addQueryParam(tt.input, tt.key, tt.value)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Parse both URLs to compare query parameters
			resultURL, err := url.Parse(result)
			require.NoError(t, err)

			expectedURL, err := url.Parse(tt.expected)
			require.NoError(t, err)

			// Verify the specified parameter exists
			_, exists := resultURL.Query()[tt.key]
			assert.True(t, exists, fmt.Sprintf("%s parameter should exist in result URL", tt.key))
			assert.Equal(t, tt.value, resultURL.Query().Get(tt.key), fmt.Sprintf("%s parameter should have expected value", tt.key))

			// Verify all query parameters match
			assert.Equal(t, expectedURL.Query(), resultURL.Query(), "Query parameters should match")

			// Verify path and scheme match
			assert.Equal(t, expectedURL.Scheme, resultURL.Scheme)
			assert.Equal(t, expectedURL.Path, resultURL.Path)
		})
	}
}
