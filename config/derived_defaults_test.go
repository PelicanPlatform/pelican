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
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/param"
)

// recordUserValue simulates a value that came from a user config file: it sets
// the value as a viper override (the precedence level viper uses when merging a
// config file) and records its provenance as SourceConfigFile so that
// ApplyDerivedDefaults' isDefaultSource guard treats it as user-supplied.
func recordUserValue(v *viper.Viper, key string, value any) {
	v.Set(key, value)
	GetSourceTracker().Record(strings.ToLower(key), ConfigSource{Type: SourceConfigFile, Detail: "test.yaml"})
}

// TestApplyDerivedDefaults exercises the generated ApplyDerivedDefaults pass,
// which re-resolves interpolated defaults (e.g. "${Server.ExternalWebUrl}")
// after user config has been loaded. The interesting behaviors are:
//   - a user override to a referenced param flows into every default that
//     interpolates it, including transitively;
//   - a default that the user has explicitly set is never recomputed; and
//   - the pass is ordered so dependencies resolve before their dependents.
func TestApplyDerivedDefaults(t *testing.T) {
	t.Run("user-overridden web port flows through the derived URL chain", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		v := viper.New()
		SetBaseDefaultsInConfig(v)
		// Pin the hostname so the expected URLs are deterministic regardless of
		// the machine the test runs on.
		v.Set(param.Server_Hostname.GetName(), "example.com")

		// The user sets a non-default web port via their config file.
		recordUserValue(v, param.Server_WebPort.GetName(), 9999)

		ApplyDerivedDefaults(v, false, false)

		// Server.ExternalWebUrl = "https://${Server.Hostname}:${Server.WebPort}"
		assert.Equal(t, "https://example.com:9999",
			v.GetString(param.Server_ExternalWebUrl.GetName()))

		// Both of these default to "${Server.ExternalWebUrl}", so the override
		// must propagate one hop further (the generator emits ExternalWebUrl
		// before its dependents, which is what makes this resolve correctly).
		assert.Equal(t, "https://example.com:9999",
			v.GetString(param.Director_AdvertiseUrl.GetName()))
		assert.Equal(t, "https://example.com:9999",
			v.GetString(param.Issuer_IssuerClaimValue.GetName()))
	})

	t.Run("a user-set dependent is not clobbered by the derived value", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		v := viper.New()
		SetBaseDefaultsInConfig(v)
		v.Set(param.Server_Hostname.GetName(), "example.com")
		recordUserValue(v, param.Server_WebPort.GetName(), 9999)

		// Simulate the user explicitly setting Director.AdvertiseUrl. We model a
		// config-file value as a default-tier value tagged with a non-default
		// source: this is precisely the situation the isDefaultSource guard
		// exists to protect, so the derived pass must leave it untouched.
		const userAdvertise = "https://director.example.org"
		v.SetDefault(param.Director_AdvertiseUrl.GetName(), userAdvertise)
		GetSourceTracker().Record(strings.ToLower(param.Director_AdvertiseUrl.GetName()),
			ConfigSource{Type: SourceConfigFile, Detail: "test.yaml"})

		ApplyDerivedDefaults(v, false, false)

		// ExternalWebUrl still derives from the overridden port...
		assert.Equal(t, "https://example.com:9999",
			v.GetString(param.Server_ExternalWebUrl.GetName()))
		// ...but the user's explicit AdvertiseUrl is preserved, not overwritten
		// with the recomputed ExternalWebUrl.
		assert.Equal(t, userAdvertise,
			v.GetString(param.Director_AdvertiseUrl.GetName()))
		// A sibling default that the user did NOT set still tracks ExternalWebUrl.
		assert.Equal(t, "https://example.com:9999",
			v.GetString(param.Issuer_IssuerClaimValue.GetName()))
	})

	t.Run("Cache.StorageLocation override propagates to derived cache paths", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)

		v := viper.New()
		SetBaseDefaultsInConfig(v)

		recordUserValue(v, param.Cache_StorageLocation.GetName(), "/custom/storage")

		ApplyDerivedDefaults(v, false, false)

		assert.Equal(t, []string{"/custom/storage/data"},
			v.GetStringSlice(param.Cache_DataLocations.GetName()))
		assert.Equal(t, []string{"/custom/storage/meta"},
			v.GetStringSlice(param.Cache_MetaLocations.GetName()))
		assert.Equal(t, "/custom/storage/namespace",
			v.GetString(param.Cache_NamespaceLocation.GetName()))
	})
}
