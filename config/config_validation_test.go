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

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// assertNoUnknownKeyLogs validates that no log entry mentions unknown configuration keys.
// The logging callback can emit other messages (for example, when parsing log levels),
// so the checks target only the unknown-key warnings.
func assertNoUnknownKeyLogs(t *testing.T, entries []*logrus.Entry) {
	t.Helper()
	for _, entry := range entries {
		assert.NotContains(t, entry.Message, "Unknown configuration keys found")
	}
}

// Test that Pelican notifies users about unrecognized configuration keys.
func TestBadConfigKeys(t *testing.T) {
	t.Cleanup(func() { ResetConfig() })

	setupFunc := func() *test.Hook {
		ResetConfig()
		require.NoError(t, param.ConfigDir.Set(t.TempDir()))
		hook := test.NewLocal(logrus.StandardLogger())
		return hook
	}
	t.Run("testRecognizedViperKey", func(t *testing.T) {
		hook := setupFunc()
		require.NoError(t, param.Origin_FederationPrefix.Set("/a/prefix"))
		InitConfigInternal(logrus.DebugLevel)

		assertNoUnknownKeyLogs(t, hook.AllEntries())
	})

	t.Run("testRecognizedEnvKey", func(t *testing.T) {
		hook := setupFunc()
		os.Setenv("PELICAN_ORIGIN_FEDERATIONPREFIX", "/a/prefix")
		defer os.Unsetenv("PELICAN_ORIGIN_FEDERATIONPREFIX")
		InitConfigInternal(logrus.DebugLevel)

		assertNoUnknownKeyLogs(t, hook.AllEntries())
	})

	t.Run("testBadViperKey", func(t *testing.T) {
		hook := setupFunc()
		require.NoError(t, param.SetRaw("Origin.Bad.Key", "/a/prefix"))
		InitConfigInternal(logrus.DebugLevel)

		require.NotNil(t, hook.LastEntry())
		assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Unknown configuration keys found")
		assert.Contains(t, hook.LastEntry().Message, "origin.bad.key")
	})

	t.Run("testBadEnvKey", func(t *testing.T) {
		hook := setupFunc()
		os.Setenv("PELICAN_ORIGIN_BAD_KEY", "/a/prefix")
		defer os.Unsetenv("PELICAN_ORIGIN_BAD_KEY")
		InitConfigInternal(logrus.DebugLevel)

		require.NotNil(t, hook.LastEntry())
		assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Unknown configuration keys found")
		assert.Contains(t, hook.LastEntry().Message, "origin.bad.key")
	})
}

func TestValidateLogExportsConfig(t *testing.T) {
	t.Cleanup(func() { ResetConfig() })
	t.Run("no-op when disabled", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		// Logging.LogExports.Enabled defaults to false; no other config needed.
		err := ValidateLogExportsConfig()
		require.NoError(t, err)
	})

	t.Run("error when enabled but Sitename is empty", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		require.NoError(t, param.Logging_EnableLogExports.Set(true))
		// Xrootd.Sitename defaults to empty.
		err := ValidateLogExportsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), param.Xrootd_Sitename.GetName())
	})

	t.Run("error when enabled but LogLocation is empty", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		require.NoError(t, param.Logging_EnableLogExports.Set(true))
		require.NoError(t, param.Xrootd_Sitename.Set("test-origin"))
		// Logging.LogLocation defaults to empty string.
		err := ValidateLogExportsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), param.Logging_LogLocation.GetName())
	})

	t.Run("error when enabled but LogLocation is /dev/null", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		require.NoError(t, param.Logging_EnableLogExports.Set(true))
		require.NoError(t, param.Xrootd_Sitename.Set("test-origin"))
		require.NoError(t, param.Logging_LogLocation.Set("/dev/null"))
		err := ValidateLogExportsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), param.Logging_LogLocation.GetName())
	})

	t.Run("warning when enabled and LogLocation set but IssuerKeysDirectory empty", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		hook := test.NewGlobal()
		defer hook.Reset()

		logFile := filepath.Join(t.TempDir(), "pelican.log")
		f, err := os.Create(logFile)
		require.NoError(t, err)
		f.Close()

		require.NoError(t, param.Logging_EnableLogExports.Set(true))
		require.NoError(t, param.Xrootd_Sitename.Set("test-origin"))
		require.NoError(t, param.Logging_LogLocation.Set(logFile))
		// IssuerKeysDirectory is empty (default).

		err = ValidateLogExportsConfig()
		require.NoError(t, err)

		found := false
		for _, entry := range hook.Entries {
			if entry.Level == logrus.WarnLevel && strings.Contains(entry.Message, param.IssuerKeysDirectory.GetName()) {
				found = true
				break
			}
		}
		assert.True(t, found, "expected a warning about IssuerKeysDirectory not being configured")
	})

	t.Run("success when enabled with real LogLocation and IssuerKeysDirectory", func(t *testing.T) {
		t.Cleanup(func() { ResetConfig() })
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "pelican.log")
		f, err := os.Create(logFile)
		require.NoError(t, err)
		f.Close()

		require.NoError(t, param.Logging_EnableLogExports.Set(true))
		require.NoError(t, param.Xrootd_Sitename.Set("test-origin"))
		require.NoError(t, param.Logging_LogLocation.Set(logFile))
		require.NoError(t, param.IssuerKeysDirectory.Set(tmpDir))

		err = ValidateLogExportsConfig()
		require.NoError(t, err)
	})
}
