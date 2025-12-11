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
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestObjectGetDirectFlag tests that the --direct flag causes downloads to come from the origin
// instead of going through a cache. This test requires xrootd to be installed and actually
// invokes the command-line flag parsing code.
func TestObjectGetDirectFlag(t *testing.T) {
	// Skip if xrootd is not available
	if _, err := exec.LookPath("xrootd"); err != nil {
		t.Skip("Skipping test because xrootd is not installed")
	}

	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	viper.Set(param.Origin_EnableDirectReads.GetName(), true)
	viper.Set(param.Logging_DisableProgressBars.GetName(), true)

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

	// Helper function to create a test command instance
	createTestGetCmd := func() *cobra.Command {
		cmd := &cobra.Command{
			Use:   "get {source ...} {destination}",
			Short: "Get a file from a Pelican federation",
			Run:   getMain,
			PreRun: func(cmd *cobra.Command, args []string) {
				commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
			},
		}

		// Add the same flags as the real getCmd
		flagSet := cmd.Flags()
		flagSet.StringP("cache", "c", "", "")
		flagSet.StringP("token", "t", "", "")
		flagSet.BoolP("recursive", "r", false, "")
		flagSet.String("caches", "", "")
		flagSet.String("transfer-stats", "", "")
		flagSet.String("pack", "", "")
		flagSet.Bool("direct", false, "")

		cmd.SetContext(fed.Ctx)
		return cmd
	}

	t.Run("WithDirectFlag", func(t *testing.T) {
		// Test with --direct flag - should read from origin
		downloadUrl := fmt.Sprintf("pelican://%s%s/%s", host, fed.Exports[0].FederationPrefix, testFileName)
		localPath := filepath.Join(downloadDir, "with-direct-flag.txt")
		transferStatsPath := filepath.Join(downloadDir, "transfer-stats-direct.json")

		// Create a fresh command instance
		cmd := createTestGetCmd()

		// Set arguments to simulate: pelican object get --direct --transfer-stats <path> <url> <dest>
		cmd.SetArgs([]string{"--direct", "--transfer-stats", transferStatsPath, downloadUrl, localPath})

		// Execute the command
		err := cmd.Execute()
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

		// Create a fresh command instance
		cmd := createTestGetCmd()

		// Set arguments WITHOUT --direct flag
		cmd.SetArgs([]string{"--transfer-stats", transferStatsPath, downloadUrl, localPath})

		// Execute the command
		err := cmd.Execute()
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

// TestAddDirectReadQuery tests the URL transformation function
func TestAddDirectReadQuery(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:     "Simple URL without query",
			input:    "osdf:///pelicanplatform/test/hello-world.txt",
			expected: "osdf:///pelicanplatform/test/hello-world.txt?directread=",
		},
		{
			name:     "URL with existing query parameter",
			input:    "pelican://example.com/path?pack=auto",
			expected: "pelican://example.com/path?directread=&pack=auto",
		},
		{
			name:     "HTTPS URL",
			input:    "https://example.com/path/to/file",
			expected: "https://example.com/path/to/file?directread=",
		},
		{
			name:        "Invalid URL",
			input:       "://invalid",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := addDirectReadQuery(tt.input)

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

			// Verify directread parameter exists and is empty
			_, exists := resultURL.Query()["directread"]
			assert.True(t, exists, "directread parameter should exist in result URL")
			assert.Equal(t, "", resultURL.Query().Get("directread"), "directread parameter should be empty")

			// Verify all query parameters match
			assert.Equal(t, expectedURL.Query(), resultURL.Query(), "Query parameters should match")

			// Verify path and scheme match
			assert.Equal(t, expectedURL.Scheme, resultURL.Scheme)
			assert.Equal(t, expectedURL.Path, resultURL.Path)
		})
	}
}
