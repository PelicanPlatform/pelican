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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// Test that Pelican notifies users about unrecognized configuration keys.
func TestBadConfigKeys(t *testing.T) {
	t.Cleanup(func() { ResetConfig() })

	setupFunc := func() *test.Hook {
		ResetConfig()
		require.NoError(t, param.Set("ConfigDir", t.TempDir()))
		hook := test.NewLocal(logrus.StandardLogger())
		return hook
	}
	t.Run("testRecognizedViperKey", func(t *testing.T) {
		hook := setupFunc()
		require.NoError(t, param.Set("Origin.FederationPrefix", "/a/prefix"))
		InitConfigInternal(logrus.DebugLevel)

		require.Nil(t, hook.LastEntry())
	})

	t.Run("testRecognizedEnvKey", func(t *testing.T) {
		hook := setupFunc()
		os.Setenv("PELICAN_ORIGIN_FEDERATIONPREFIX", "/a/prefix")
		defer os.Unsetenv("PELICAN_ORIGIN_FEDERATIONPREFIX")
		InitConfigInternal(logrus.DebugLevel)

		require.Nil(t, hook.LastEntry())
	})

	t.Run("testBadViperKey", func(t *testing.T) {
		hook := setupFunc()
		require.NoError(t, param.Set("Origin.Bad.Key", "/a/prefix"))
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
