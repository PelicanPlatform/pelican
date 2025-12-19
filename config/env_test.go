/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestOsdfEnvToPelican(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	hook := test.NewGlobal()

	t.Run("non-osdf-prefix-does-nothing", func(t *testing.T) {
		ResetConfig()
		testingPreferredPrefix = PelicanPrefix

		os.Setenv("OSDF_MOCK", "randomStr")
		t.Cleanup(func() {
			err := os.Unsetenv("OSDF_MOCK")
			require.NoError(t, err)
			validPrefixes[PelicanPrefix] = false
		})
		bindNonPelicanEnv()
		assert.False(t, viper.IsSet("MOCK"))
	})

	t.Run("one-osdf-env", func(t *testing.T) {
		ResetConfig()
		hook.Reset()
		testingPreferredPrefix = OsdfPrefix

		os.Setenv("OSDF_MOCK", "randomStr")
		t.Cleanup(func() {
			err := os.Unsetenv("OSDF_MOCK")
			require.NoError(t, err)
		})
		bindNonPelicanEnv()
		assert.Equal(t, "randomStr", viper.Get("mock")) // viper key is case-insensitive
		assert.Equal(t, "randomStr", viper.Get("MOCK"))
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Environment variables with OSDF prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.")
	})

	t.Run("one-stash-env", func(t *testing.T) {
		ResetConfig()
		hook.Reset()
		testingPreferredPrefix = StashPrefix

		os.Setenv("STASH_MOCK", "randomStr")
		t.Cleanup(func() {
			err := os.Unsetenv("STASH_MOCK")
			require.NoError(t, err)
		})
		bindNonPelicanEnv()
		assert.Equal(t, "randomStr", viper.Get("mock")) // viper key is case-insensitive
		assert.Equal(t, "randomStr", viper.Get("MOCK"))
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Environment variables with STASH prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.")
	})

	t.Run("complex-osdf-env", func(t *testing.T) {
		ResetConfig()
		hook.Reset()
		testingPreferredPrefix = OsdfPrefix

		os.Setenv("OSDF_FEDERATION_DIRECTORURL", "randomStr")
		t.Cleanup(func() {
			err := os.Unsetenv("OSDF_FEDERATION_DIRECTORURL")
			require.NoError(t, err)
		})
		bindNonPelicanEnv()
		assert.Equal(t, "randomStr", viper.Get("Federation.DirectorUrl"))
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Environment variables with OSDF prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.")
	})

	t.Run("pelican-env-still-works", func(t *testing.T) {
		ResetConfig()
		hook.Reset()
		testingPreferredPrefix = OsdfPrefix

		os.Setenv("OSDF_FEDERATION_DIRECTORURL", "randomStr")
		os.Setenv("PELICAN_FEDERATION_REGISTRYURL", "registry")
		t.Cleanup(func() {
			err := os.Unsetenv("OSDF_FEDERATION_DIRECTORURL")
			require.NoError(t, err)
			err = os.Unsetenv("PELICAN_FEDERATION_REGISTRYURL")
			require.NoError(t, err)
		})

		bindNonPelicanEnv()

		viper.SetEnvPrefix("pelican")
		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		assert.Equal(t, "randomStr", viper.Get("Federation.DirectorUrl"))
		assert.Equal(t, "registry", viper.Get("Federation.RegistryUrl"))
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Environment variables with OSDF prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.")
	})

	t.Run("pelican-env-overwrites-osdf", func(t *testing.T) {
		ResetConfig()
		hook.Reset()
		testingPreferredPrefix = OsdfPrefix

		os.Setenv("OSDF_FEDERATION_REGISTRYUR", "osdf-registry")
		os.Setenv("PELICAN_FEDERATION_REGISTRYURL", "pelican-registry")
		t.Cleanup(func() {
			err := os.Unsetenv("OSDF_FEDERATION_REGISTRYUR")
			require.NoError(t, err)
			err = os.Unsetenv("PELICAN_FEDERATION_REGISTRYURL")
			require.NoError(t, err)
		})

		bindNonPelicanEnv()

		viper.SetEnvPrefix("pelican")
		viper.AutomaticEnv()
		viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

		assert.Equal(t, "pelican-registry", viper.Get("Federation.RegistryUrl"))
		require.Equal(t, 1, len(hook.Entries))
		assert.Equal(t, log.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Environment variables with OSDF prefix will be deprecated in the next feature release. Please use PELICAN prefix instead.")
	})
}

func TestBindClassAdConfig(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	t.Run("no-job-ad-file", func(t *testing.T) {
		ResetConfig()

		// Ensure no job ad environment variable is set
		os.Unsetenv("_CONDOR_JOB_AD")

		bindClassAdConfig()
		// Refresh param cache to check if anything was set
		_, err := param.Refresh()
		require.NoError(t, err)

		// Should not set anything when no job ad file exists
		assert.Empty(t, param.Client_PreferredCaches.GetStringSlice())
	})

	t.Run("job-ad-with-pelican-cfg-attributes", func(t *testing.T) {
		ResetConfig()

		// Create a temporary job ad file
		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		// Write a ClassAd with PelicanCfg attributes (old format without brackets)
		jobAdContent := `PelicanCfg_Client_PreferredCaches = {"cache1.example.com", "cache2.example.com"}
PelicanCfg_Client_MinimumDownloadSpeed = 1024
PelicanCfg_Logging_Level = "debug"
PelicanCfg_Client_DisableHttpProxy = true
ProjectName = "testProject"
GlobalJobId = "12345"
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		// Set the environment variable to point to our test file
		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		// Refresh param cache
		_, err = param.Refresh()
		require.NoError(t, err)

		// Verify that the PelicanCfg attributes were converted and set
		preferredCaches := param.Client_PreferredCaches.GetStringSlice()
		assert.Equal(t, 2, len(preferredCaches))
		assert.Equal(t, "cache1.example.com", preferredCaches[0])
		assert.Equal(t, "cache2.example.com", preferredCaches[1])

		assert.Equal(t, 1024, param.Client_MinimumDownloadSpeed.GetInt())
		assert.Equal(t, "debug", param.Logging_Level.GetString())
		assert.Equal(t, true, param.Client_DisableHttpProxy.GetBool())
	})

	t.Run("job-ad-with-empty-list", func(t *testing.T) {
		ResetConfig()

		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		jobAdContent := `PelicanCfg_Client_PreferredCaches = {}
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		_, err = param.Refresh()
		require.NoError(t, err)

		// Verify empty list
		assert.Empty(t, param.Client_PreferredCaches.GetStringSlice())
	})

	t.Run("job-ad-with-type-mismatch-string-to-int", func(t *testing.T) {
		ResetConfig()

		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		// Try to set a string value where an int is expected
		jobAdContent := `PelicanCfg_Client_MinimumDownloadSpeed = "not-a-number"
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		_, err = param.Refresh()
		// The refresh should fail because the value can't be parsed as an int
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot parse")
	})

	t.Run("job-ad-with-int-where-bool-expected", func(t *testing.T) {
		ResetConfig()

		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		// Try to set an integer where a bool is expected
		jobAdContent := `PelicanCfg_Client_DisableHttpProxy = 1
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		_, err = param.Refresh()
		require.NoError(t, err)

		// Viper should handle the conversion from int to bool (1 -> true, 0 -> false)
		assert.Equal(t, true, param.Client_DisableHttpProxy.GetBool())
	})

	t.Run("job-ad-with-real-where-bool-expected", func(t *testing.T) {
		ResetConfig()

		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		// Try to set a real number where a bool is expected
		jobAdContent := `PelicanCfg_Client_DisableHttpProxy = 0.0
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		_, err = param.Refresh()
		require.NoError(t, err)

		// Viper should handle the conversion from float to bool (0.0 -> false)
		assert.Equal(t, false, param.Client_DisableHttpProxy.GetBool())
	})

	t.Run("job-ad-with-nested-classad", func(t *testing.T) {
		ResetConfig()

		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "test.job.ad")

		// Test with a nested ClassAd structure
		jobAdContent := `PelicanCfg_Origin_Exports = [FederationPrefix = "/test"; StoragePrefix = "/storage"; Capabilities = {"Reads", "Writes"}]
`
		err := os.WriteFile(jobAdFile, []byte(jobAdContent), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		bindClassAdConfig()
		_, err = param.Refresh()
		require.NoError(t, err)

		// Verify the nested structure is accessible and has the expected values
		// Origin.Exports is of type interface{}, so we need to use viper to access it
		exportsVal := viper.Get("Origin.Exports")
		require.NotNil(t, exportsVal)

		// The structure should be a map
		exportsMap, ok := exportsVal.(map[string]interface{})
		require.True(t, ok, "Origin.Exports should be a map[string]interface{}, got %T", exportsVal)

		// Verify the expected fields are present with correct values
		// Note: JSON unmarshalling converts keys to lowercase
		assert.Equal(t, "/test", exportsMap["federationprefix"])
		assert.Equal(t, "/storage", exportsMap["storageprefix"])

		// Verify the Capabilities list
		capabilities, ok := exportsMap["capabilities"].([]interface{})
		require.True(t, ok, "capabilities should be a list")
		require.Equal(t, 2, len(capabilities))
		assert.Equal(t, "Reads", capabilities[0])
		assert.Equal(t, "Writes", capabilities[1])
	})

	t.Run("invalid-job-ad-file", func(t *testing.T) {
		ResetConfig()

		// Create a temporary job ad file with invalid content
		tmpDir := t.TempDir()
		jobAdFile := filepath.Join(tmpDir, "invalid.job.ad")

		// Write invalid ClassAd content
		err := os.WriteFile(jobAdFile, []byte("this is not valid classad syntax [[["), 0644)
		require.NoError(t, err)

		os.Setenv("_CONDOR_JOB_AD", jobAdFile)
		t.Cleanup(func() {
			os.Unsetenv("_CONDOR_JOB_AD")
		})

		// Should not panic and should not set any values
		bindClassAdConfig()
		_, err = param.Refresh()
		require.NoError(t, err)

		assert.Empty(t, param.Client_PreferredCaches.GetStringSlice())
	})
}
