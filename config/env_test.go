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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// newGlobalHook installs a logrus hook that captures every entry emitted
// during the test and restores the logger's previous hooks afterwards.
func newGlobalHook(t *testing.T) *test.Hook {
	t.Helper()

	// Copy the per-level slices: test.NewGlobal() appends to the live
	// map, so saving the map alone would save the new hook along with
	// it.
	saved := make(log.LevelHooks, len(log.StandardLogger().Hooks))
	for level, hooks := range log.StandardLogger().Hooks {
		saved[level] = slices.Clone(hooks)
	}
	t.Cleanup(func() { log.StandardLogger().ReplaceHooks(saved) })

	return test.NewGlobal()
}

// setTestLogLevel sets the process log level for the duration of the
// test. ResetConfig does not restore the level, and InitConfigInternal
// changes it, so a bare SetLogging would leak into later tests.
func setTestLogLevel(t *testing.T, level log.Level) {
	t.Helper()

	previous := GetEffectiveLogLevel()
	t.Cleanup(func() { SetLogging(previous) })
	SetLogging(level)
}

// setTestTier overrides the behavior tier that GetPreferredPrefix
// reports for the duration of the test.
func setTestTier(t *testing.T, tier ConfigPrefix) {
	t.Helper()

	previous := testingPreferredPrefix
	t.Cleanup(func() { testingPreferredPrefix = previous })
	testingPreferredPrefix = tier
}

// scrubConfigEnv unsets every PELICAN_ variable and every variable that
// warnRemovedEnv reports on, for the duration of the test, so that the ambient
// environment cannot affect it.
func scrubConfigEnv(t *testing.T) {
	t.Helper()

	for _, env := range os.Environ() {
		name, value, _ := strings.Cut(env, "=")
		// isOsdf is true so that the OSDF-branded names are always
		// scrubbed regardless of the (effective) binary name.
		if !strings.HasPrefix(name, "PELICAN_") && !isRemovedEnv(name, true) {
			continue
		}
		require.NoError(t, os.Unsetenv(name))
		// assert, not require: FailNow in a cleanup skips
		// the remaining cleanups.
		t.Cleanup(func() { assert.NoError(t, os.Setenv(name, value)) })
	}
}

func TestBindClassAdConfig(t *testing.T) {
	setTestLogLevel(t, log.DebugLevel)

	t.Run("no-job-ad-file", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)

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

func TestBindLegacyServerEnv(t *testing.T) {
	setTestLogLevel(t, log.DebugLevel)
	hook := newGlobalHook(t)

	t.Run("pelican-maxmindkey-is-honored", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		t.Setenv("PELICAN_MAXMINDKEY", "/path/to/keyfile")
		hook.Reset()

		bindLegacyServerEnv()

		assert.Equal(t, "/path/to/keyfile", viper.GetString(param.Director_MaxMindKeyFile.GetName()))

		// The variable is deprecated, so honoring it must also say so.
		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Equal(t, log.WarnLevel, entries[0].Level)
		assert.Contains(t, entries[0].Message, "PELICAN_MAXMINDKEY")
		assert.Contains(t, entries[0].Message, param.Director_MaxMindKeyFile.GetName())
	})

	t.Run("config-wins-over-legacy-env", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		t.Setenv("PELICAN_MAXMINDKEY", "/path/to/keyfile")
		viper.Set(param.Director_MaxMindKeyFile.GetName(), "/existing/config/keyfile")

		bindLegacyServerEnv()

		assert.Equal(t, "/existing/config/keyfile", viper.GetString(param.Director_MaxMindKeyFile.GetName()))
	})

	t.Run("osdf-maxmindkey-is-ignored", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		t.Setenv("OSDF_MAXMINDKEY", "/path/to/keyfile")
		t.Setenv("STASH_MAXMINDKEY", "/path/to/keyfile")

		bindLegacyServerEnv()

		assert.False(t, viper.IsSet(param.Director_MaxMindKeyFile.GetName()))
	})
}
