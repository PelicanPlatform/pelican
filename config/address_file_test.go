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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestWriteAddressFile(t *testing.T) {
	t.Cleanup(func() { ResetConfig() })

	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	setRuntimeDir := func(t *testing.T) {
		t.Helper()
		viper.Set(param.RuntimeDir.GetName(), tmpDir)
	}

	// Set up ConfigDir
	require.NoError(t, param.Set("ConfigDir", tmpDir))
	setRuntimeDir(t)

	t.Run("WriteAddressFileWithAllModules", func(t *testing.T) {
		// Set up test parameters
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://test.example.com:8443"))
		require.NoError(t, param.Set("Origin.Url", "https://test.example.com:8444"))
		require.NoError(t, param.Set("Cache.Url", "https://test.example.com:8445"))

		// Create modules with all types enabled
		modules := server_structs.OriginType | server_structs.CacheType | server_structs.DirectorType

		// Write the address file
		err := WriteAddressFile(modules)
		require.NoError(t, err)

		// Check that the file was created
		addressFilePath := filepath.Join(tmpDir, "pelican.addresses")
		_, err = os.Stat(addressFilePath)
		require.NoError(t, err, "Address file should exist")

		// Read and verify content
		content, err := os.ReadFile(addressFilePath)
		require.NoError(t, err)

		contentStr := string(content)
		assert.Contains(t, contentStr, "SERVER_EXTERNAL_WEB_URL=https://test.example.com:8443")
		assert.Contains(t, contentStr, "ORIGIN_URL=https://test.example.com:8444")
		assert.Contains(t, contentStr, "CACHE_URL=https://test.example.com:8445")
	})

	t.Run("WriteAddressFileOriginOnly", func(t *testing.T) {
		require.NoError(t, param.Set("ConfigDir", tmpDir))
		setRuntimeDir(t)
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://origin.example.com:9443"))
		require.NoError(t, param.Set("Origin.Url", "https://origin.example.com:9444"))

		// Create modules with only origin enabled
		modules := server_structs.OriginType

		// Write the address file
		err := WriteAddressFile(modules)
		require.NoError(t, err)

		// Check that the file was created
		addressFilePath := filepath.Join(tmpDir, "pelican.addresses")
		content, err := os.ReadFile(addressFilePath)
		require.NoError(t, err)

		contentStr := string(content)
		assert.Contains(t, contentStr, "SERVER_EXTERNAL_WEB_URL=https://origin.example.com:9443")
		assert.Contains(t, contentStr, "ORIGIN_URL=https://origin.example.com:9444")
		// Should not contain cache URL
		assert.NotContains(t, contentStr, "CACHE_URL")
	})

	t.Run("WriteAddressFileDirectorOnly", func(t *testing.T) {
		// Reset and set up new test parameters
		viper.Reset()
		viper.Set("ConfigDir", tmpDir)
		setRuntimeDir(t)
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://director.example.com:8443"))

		// Create modules with only director enabled
		modules := server_structs.DirectorType

		// Write the address file
		err := WriteAddressFile(modules)
		require.NoError(t, err)

		// Check that the file was created
		addressFilePath := filepath.Join(tmpDir, "pelican.addresses")
		content, err := os.ReadFile(addressFilePath)
		require.NoError(t, err)

		contentStr := string(content)
		assert.Contains(t, contentStr, "SERVER_EXTERNAL_WEB_URL=https://director.example.com:8443")
		// Should not contain origin or cache URLs
		assert.NotContains(t, contentStr, "ORIGIN_URL")
		assert.NotContains(t, contentStr, "CACHE_URL")
	})

	t.Run("WriteAddressFileNoConfigDir", func(t *testing.T) {
		// Reset viper and don't set ConfigDir
		viper.Reset()

		modules := server_structs.DirectorType

		// This should return an error since the runtime directory is not configured
		err := WriteAddressFile(modules)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "runtime directory is not configured")
	})

	t.Run("AtomicWrite", func(t *testing.T) {
		// Reset and set up
		viper.Reset()
		viper.Set("ConfigDir", tmpDir)
		setRuntimeDir(t)
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://atomic.example.com:8443"))

		modules := server_structs.DirectorType

		// Write the address file
		err := WriteAddressFile(modules)
		require.NoError(t, err)

		// Verify that the temp file doesn't exist
		tempFilePath := filepath.Join(tmpDir, "pelican.addresses.tmp")
		_, err = os.Stat(tempFilePath)
		assert.True(t, os.IsNotExist(err), "Temporary file should not exist after atomic write")

		// Verify that the final file exists
		addressFilePath := filepath.Join(tmpDir, "pelican.addresses")
		_, err = os.Stat(addressFilePath)
		require.NoError(t, err, "Address file should exist")
	})

	t.Run("ParseableFormat", func(t *testing.T) {
		// Reset and set up
		viper.Reset()
		viper.Set("ConfigDir", tmpDir)
		setRuntimeDir(t)
		require.NoError(t, param.Set("Server.ExternalWebUrl", "https://parseable.example.com:8443"))
		require.NoError(t, param.Set("Origin.Url", "https://parseable.example.com:8444"))

		modules := server_structs.OriginType

		// Write the address file
		err := WriteAddressFile(modules)
		require.NoError(t, err)

		// Read the file
		addressFilePath := filepath.Join(tmpDir, "pelican.addresses")
		content, err := os.ReadFile(addressFilePath)
		require.NoError(t, err)

		// Parse the file as KEY=VALUE pairs
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		vars := make(map[string]string)
		for _, line := range lines {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			require.Len(t, parts, 2, "Each line should be a KEY=VALUE pair")
			vars[parts[0]] = parts[1]
		}

		// Verify the parsed values
		assert.Equal(t, "https://parseable.example.com:8443", vars["SERVER_EXTERNAL_WEB_URL"])
		assert.Equal(t, "https://parseable.example.com:8444", vars["ORIGIN_URL"])
	})
}
