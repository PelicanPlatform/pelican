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
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsdfEnvToPelican(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	hook := test.NewGlobal()

	t.Run("non-osdf-prefix-does-nothing", func(t *testing.T) {
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
		viper.Reset()
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
