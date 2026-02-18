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

package config

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestSaveConfigContentsToFile(t *testing.T) {
	t.Run("save-without-password", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "test-creds.pem")

		testConfig := &OSDFConfig{}
		testConfig.OSDF.OauthClient = []PrefixEntry{
			{
				Prefix:       "/test/namespace",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		}

		err := SaveConfigContentsToFile(testConfig, filePath, false)
		require.NoError(t, err)

		// Verify file exists and has correct permissions
		info, err := os.Stat(filePath)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		}

		// Read the file and verify PEM structure
		data, err := os.ReadFile(filePath)
		require.NoError(t, err)

		// Should have unencrypted PRIVATE KEY (not ENCRYPTED PRIVATE KEY)
		rest := data
		var foundPrivateKey, foundConfig bool
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "PRIVATE KEY" {
				foundPrivateKey = true
			}
			if block.Type == "ENCRYPTED CONFIG" {
				foundConfig = true
			}
		}
		assert.True(t, foundPrivateKey, "Expected to find PRIVATE KEY block")
		assert.True(t, foundConfig, "Expected to find ENCRYPTED CONFIG block")
	})

	t.Run("save-nil-config", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "test-creds.pem")

		err := SaveConfigContentsToFile(nil, filePath, false)
		require.NoError(t, err)

		// Verify file was created
		_, err = os.Stat(filePath)
		require.NoError(t, err)
	})

	t.Run("save-creates-directories", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "nested", "dir", "test-creds.pem")

		err := SaveConfigContentsToFile(&OSDFConfig{}, filePath, false)
		require.NoError(t, err)

		_, err = os.Stat(filePath)
		require.NoError(t, err)
	})

	t.Run("roundtrip-without-password", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "test-creds.pem")

		testConfig := &OSDFConfig{}
		testConfig.OSDF.OauthClient = []PrefixEntry{
			{
				Prefix:       "/test/roundtrip",
				ClientID:     "roundtrip-client-id",
				ClientSecret: "roundtrip-client-secret",
			},
		}

		err := SaveConfigContentsToFile(testConfig, filePath, false)
		require.NoError(t, err)

		// Now use the Client.CredentialFile param to read it back
		require.NoError(t, param.Set(param.Client_CredentialFile.GetName(), filePath))
		viper.Set("ConfigDir", tmpDir)

		readConfig, err := GetCredentialConfigContents()
		require.NoError(t, err)

		require.Len(t, readConfig.OSDF.OauthClient, 1)
		assert.Equal(t, "/test/roundtrip", readConfig.OSDF.OauthClient[0].Prefix)
		assert.Equal(t, "roundtrip-client-id", readConfig.OSDF.OauthClient[0].ClientID)
		assert.Equal(t, "roundtrip-client-secret", readConfig.OSDF.OauthClient[0].ClientSecret)
	})
}

func TestHasEncryptedPassword(t *testing.T) {
	t.Run("no-file-returns-false", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "nonexistent.pem")
		require.NoError(t, param.Set(param.Client_CredentialFile.GetName(), filePath))

		hasPassword, err := HasEncryptedPassword()
		require.NoError(t, err)
		assert.False(t, hasPassword)
	})

	t.Run("unencrypted-file-returns-false", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "unencrypted.pem")

		// Save without password
		testConfig := &OSDFConfig{}
		err := SaveConfigContentsToFile(testConfig, filePath, false)
		require.NoError(t, err)

		require.NoError(t, param.Set(param.Client_CredentialFile.GetName(), filePath))

		hasPassword, err := HasEncryptedPassword()
		require.NoError(t, err)
		assert.False(t, hasPassword)
	})
}

func TestGetEncryptedConfigNameOverride(t *testing.T) {
	t.Run("override-with-credential-file", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		expectedPath := "/custom/path/to/creds.pem"
		require.NoError(t, param.Set(param.Client_CredentialFile.GetName(), expectedPath))

		result, err := GetEncryptedConfigName()
		require.NoError(t, err)
		assert.Equal(t, expectedPath, result)
	})

	t.Run("no-override-uses-default", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(func() {
			ResetConfig()
		})

		tmpDir := t.TempDir()
		viper.Set("ConfigDir", tmpDir)

		result, err := GetEncryptedConfigName()
		require.NoError(t, err)
		// Should not be empty and should not be our custom path
		assert.NotEmpty(t, result)
		assert.NotEqual(t, "/custom/path/to/creds.pem", result)
	})
}
