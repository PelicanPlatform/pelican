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
	"runtime"
	"slices"
	"strconv"
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

// scrubConfigDirs points the directories that initialization searches for
// pelican.yaml at empty temporary ones for the duration of the test. An
// ambient config file could otherwise supply values or, if malformed, exit
// the test binary via cobra.CheckErr. Viper cannot unset a key, so the
// cleanup resets the whole config rather than restoring ConfigBase.
func scrubConfigDirs(t *testing.T) {
	t.Helper()

	require.NoError(t, param.ConfigBase.Set(t.TempDir()))
	t.Cleanup(ResetConfig)

	previousSysConfigLocation := sysConfigLocation
	sysConfigLocation = t.TempDir()
	t.Cleanup(func() { sysConfigLocation = previousSysConfigLocation })
}

// TestWarnRemovedEnv covers the warning about environment variables that
// Pelican no longer reads. Each case calls ResetConfig first to re-arm the
// warning's sync.Once.
func TestWarnRemovedEnv(t *testing.T) {
	setTestLogLevel(t, log.DebugLevel)
	hook := newGlobalHook(t)

	// The cases below iterate over these lists, so they cannot detect a
	// deleted entry. Pinning the lists does.
	t.Run("removed-lists-are-pinned", func(t *testing.T) {
		assert.Equal(t, "OSDF_", removedOsdfEnvPrefix)
		assert.Equal(t, []string{
			"STASH_DIRECTOR_URL",
			"STASH_DISABLE_HTTP_PROXY",
			"STASH_DISABLE_PROXY_FALLBACK",
			"STASH_MAXMINDKEY",
			"STASH_MINIMUM_DOWNLOAD_SPEED",
			"STASH_NAMESPACE_URL",
			"STASH_NEAREST_CACHE",
			"STASH_TOPOLOGY_NAMESPACE_URL",
			"OSDFCP_MINIMUM_DOWNLOAD_SPEED",
			"STASHCP_MINIMUM_DOWNLOAD_SPEED",
		}, removedOsdfEnvNames)
		assert.Equal(t, []string{
			"NEAREST_CACHE",
			"OSG_DISABLE_HTTP_PROXY",
			"OSG_DISABLE_PROXY_FALLBACK",
			"PELICANCP_MINIMUM_DOWNLOAD_SPEED",
		}, removedEnvNames)
	})

	// Every entry of both lists, and the prefix, must draw a warning.
	t.Run("every-removed-prefix-and-name-warns", func(t *testing.T) {
		names := make([]string, 0, 1+len(removedOsdfEnvNames)+len(removedEnvNames))
		names = append(names, removedOsdfEnvPrefix+"FEDERATION_DIRECTORURL")
		names = append(names, removedOsdfEnvNames...)
		names = append(names, removedEnvNames...)

		for _, name := range names {
			t.Run(name, func(t *testing.T) {
				ResetConfig()
				t.Cleanup(ResetConfig)
				scrubConfigEnv(t)
				// The OSDF-branded names are reported only under the OSDF tier.
				setTestTier(t, OsdfPrefix)
				t.Setenv(name, "some-value")
				hook.Reset()

				warnRemovedEnv()

				entries := hook.AllEntries()
				require.Len(t, entries, 1)
				assert.Equal(t, log.WarnLevel, entries[0].Level)
				assert.Contains(t, entries[0].Message, name)
			})
		}
	})

	t.Run("warns-with-sorted-names", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		t.Setenv("OSDF_FEDERATION_DIRECTORURL", "https://director.example.com")
		t.Setenv("NEAREST_CACHE", "https://cache.example.com")
		hook.Reset()

		warnRemovedEnv()

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Equal(t, log.WarnLevel, entries[0].Level)
		assert.Regexp(t, `"NEAREST_CACHE".*"OSDF_FEDERATION_DIRECTORURL"`, entries[0].Message)
		assert.Contains(t, entries[0].Message, "Please use the equivalent PELICAN_ variable instead.")
	})

	t.Run("pelican-prefixed-vars-are-silent", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		t.Setenv("PELICAN_FEDERATION_DIRECTORURL", "https://director.example.com")
		hook.Reset()

		warnRemovedEnv()

		assert.Empty(t, hook.AllEntries())
	})

	// Pelican-named binaries never read the OSDF-branded names, which may
	// belong to unrelated software, so they are not reported.
	t.Run("osdf-prefixes-ignored-under-pelican-binary", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		require.Equal(t, PelicanPrefix, GetPreferredPrefix())
		t.Setenv("OSDF_FEDERATION_DIRECTORURL", "https://director.example.com")
		t.Setenv("STASH_DIRECTOR_URL", "https://director.example.com")
		t.Setenv("OSDFCP_MINIMUM_DOWNLOAD_SPEED", "1024")
		t.Setenv("STASHCP_MINIMUM_DOWNLOAD_SPEED", "1024")
		hook.Reset()

		warnRemovedEnv()

		assert.Empty(t, hook.AllEntries())
	})

	// STASH_ and *CP_ variables outside removedOsdfEnvNames were never
	// read, so they are not reported.
	t.Run("unread-osdf-branded-names-are-silent", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		// STASH_USE_TOPOLOGY was read but never had an effect.
		t.Setenv("STASH_USE_TOPOLOGY", "1")
		t.Setenv("STASH_BASE_URL", "https://stash.example.com")
		t.Setenv("STASHCP_LOCATION", "/opt/stashcp")
		t.Setenv("OSDFCP_LOCATION", "/opt/osdfcp")
		hook.Reset()

		warnRemovedEnv()

		assert.Empty(t, hook.AllEntries())
	})

	// Names are quoted so that an embedded newline cannot forge a log
	// entry. Under the HTCondor plugin, the job submitter controls the
	// environment.
	t.Run("names-are-quoted", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		// os.Setenv rejects only "=" and NUL in names.
		t.Setenv("OSDF_X\nWARN forged entry", "1")
		hook.Reset()

		warnRemovedEnv()

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.NotContains(t, entries[0].Message, "\n")
		assert.Contains(t, entries[0].Message, `"OSDF_X\nWARN forged entry"`)
	})

	// The names that every binary read are reported under a Pelican-named
	// binary too.
	t.Run("individual-names-warn-under-pelican-binary", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		require.Equal(t, PelicanPrefix, GetPreferredPrefix())
		t.Setenv("OSG_DISABLE_PROXY_FALLBACK", "")
		t.Setenv("PELICANCP_MINIMUM_DOWNLOAD_SPEED", "1024")
		hook.Reset()

		warnRemovedEnv()

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Contains(t, entries[0].Message, "OSG_DISABLE_PROXY_FALLBACK")
		assert.Contains(t, entries[0].Message, "PELICANCP_MINIMUM_DOWNLOAD_SPEED")
	})

	// Windows environment variable names are case-insensitive, so there,
	// any spelling of a name is reported, as spelled. Elsewhere, only the
	// exact name is.
	t.Run("name-case-follows-platform", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		setTestTier(t, OsdfPrefix)
		names := []string{"nearest_cache", "Stash_Director_Url", "osdf_director_url"}
		for _, name := range names {
			t.Setenv(name, "some-value")
		}
		hook.Reset()

		warnRemovedEnv()

		entries := hook.AllEntries()
		if runtime.GOOS != "windows" {
			assert.Empty(t, entries)
			return
		}
		require.Len(t, entries, 1)
		for _, name := range names {
			assert.Contains(t, entries[0].Message, strconv.Quote(name))
		}
	})
}

// TestInitConfigInternalWarnsAboutRemovedEnv checks that initialization
// emits the warning, and late enough that the log level it configures,
// rather than the caller's, decides whether the warning is shown.
func TestInitConfigInternalWarnsAboutRemovedEnv(t *testing.T) {
	tests := []struct {
		name string
		// entryLevel is the log level on entry to InitConfigInternal.
		// initLevel is its argument, which sets the level that the
		// warning should be logged under.
		entryLevel log.Level
		initLevel  log.Level
	}{
		{
			name:       "verbose-caller",
			entryLevel: log.DebugLevel,
			initLevel:  log.DebugLevel,
		},
		{
			// stashcp sets the level to Error before calling InitClient,
			// which passes WarnLevel.
			name:       "caller-quieted-below-warn",
			entryLevel: log.ErrorLevel,
			initLevel:  log.WarnLevel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ResetConfig()
			t.Cleanup(ResetConfig)

			// The global filter hooks pin logrus to TraceLevel, which
			// would bypass the level gating under test.
			ResetGlobalLoggingHooks()

			setTestLogLevel(t, tc.entryLevel)
			hook := newGlobalHook(t)
			scrubConfigEnv(t)
			scrubConfigDirs(t)

			// NEAREST_CACHE is reported under either tier.
			t.Setenv("NEAREST_CACHE", "https://cache.example.com")
			hook.Reset()

			InitConfigInternal(tc.initLevel)

			// Match rather than count: initialization logs other entries.
			assert.True(t, slices.ContainsFunc(hook.AllEntries(), func(entry *log.Entry) bool {
				return entry.Level == log.WarnLevel &&
					strings.Contains(entry.Message, "Ignoring environment variable(s)") &&
					strings.Contains(entry.Message, "NEAREST_CACHE")
			}), "InitConfigInternal must warn about removed environment variables; got %v", hook.AllEntries())
		})
	}
}

// TestBindLegacyClientEnv checks that each legacy client variable is
// honored under the PELICAN_ prefix and no other.
func TestBindLegacyClientEnv(t *testing.T) {
	setTestLogLevel(t, log.DebugLevel)
	hook := newGlobalHook(t)

	const (
		directorUrl = "https://director.example.com"
		registryUrl = "https://registry.example.com"
		topologyUrl = "https://topology.example.com"
		cacheUrl    = "https://cache.example.com"

		// Stands in for a configured value in the preset cases.
		presetUrl = "https://preset.example.com"
	)

	tests := []struct {
		name string
		// osdfBinary runs the case under the OSDF tier, the only one
		// under which most of the removed variables were read.
		osdfBinary bool
		env        map[string]string
		// preset seeds viper with a configured value before the bind
		// runs. It must use viper.Set; with SetDefault, it would share a
		// layer with the bind's SetDefault calls, and the later write
		// would win.
		preset func(t *testing.T)
		check  func(t *testing.T)
	}{
		{
			name: "director-url/pelican-honored",
			env:  map[string]string{"PELICAN_DIRECTOR_URL": directorUrl},
			check: func(t *testing.T) {
				assert.Equal(t, directorUrl, viper.GetString(param.Federation_DirectorUrl.GetName()))
			},
		},
		{
			name:       "director-url/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_DIRECTOR_URL": directorUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_DirectorUrl.GetName()))
			},
		},
		{
			name:       "director-url/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_DIRECTOR_URL": directorUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_DirectorUrl.GetName()))
			},
		},
		{
			// Most legacy variables override a configured value, but
			// PELICAN_MINIMUM_DOWNLOAD_SPEED and PELICAN_MAXMINDKEY defer
			// to it. The cases pin each direction.
			name:   "director-url/env-overrides-config",
			env:    map[string]string{"PELICAN_DIRECTOR_URL": directorUrl},
			preset: func(t *testing.T) { viper.Set(param.Federation_DirectorUrl.GetName(), presetUrl) },
			check: func(t *testing.T) {
				assert.Equal(t, directorUrl, viper.GetString(param.Federation_DirectorUrl.GetName()))
			},
		},
		{
			name: "namespace-url/pelican-honored",
			env:  map[string]string{"PELICAN_NAMESPACE_URL": registryUrl},
			check: func(t *testing.T) {
				assert.Equal(t, registryUrl, viper.GetString(param.Federation_RegistryUrl.GetName()))
			},
		},
		{
			name:       "namespace-url/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_NAMESPACE_URL": registryUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_RegistryUrl.GetName()))
			},
		},
		{
			name:       "namespace-url/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_NAMESPACE_URL": registryUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_RegistryUrl.GetName()))
			},
		},
		{
			name:   "namespace-url/env-overrides-config",
			env:    map[string]string{"PELICAN_NAMESPACE_URL": registryUrl},
			preset: func(t *testing.T) { viper.Set(param.Federation_RegistryUrl.GetName(), presetUrl) },
			check: func(t *testing.T) {
				assert.Equal(t, registryUrl, viper.GetString(param.Federation_RegistryUrl.GetName()))
			},
		},
		{
			name: "topology-namespace-url/pelican-honored",
			env:  map[string]string{"PELICAN_TOPOLOGY_NAMESPACE_URL": topologyUrl},
			check: func(t *testing.T) {
				assert.Equal(t, topologyUrl, viper.GetString(param.Federation_TopologyNamespaceUrl.GetName()))
			},
		},
		{
			name:       "topology-namespace-url/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_TOPOLOGY_NAMESPACE_URL": topologyUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_TopologyNamespaceUrl.GetName()))
			},
		},
		{
			name:       "topology-namespace-url/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_TOPOLOGY_NAMESPACE_URL": topologyUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Federation_TopologyNamespaceUrl.GetName()))
			},
		},
		{
			name:   "topology-namespace-url/env-overrides-config",
			env:    map[string]string{"PELICAN_TOPOLOGY_NAMESPACE_URL": topologyUrl},
			preset: func(t *testing.T) { viper.Set(param.Federation_TopologyNamespaceUrl.GetName(), presetUrl) },
			check: func(t *testing.T) {
				assert.Equal(t, topologyUrl, viper.GetString(param.Federation_TopologyNamespaceUrl.GetName()))
			},
		},
		{
			// The variable is a flag: being set at all, even to the empty
			// string, turns the behavior on.
			name: "disable-http-proxy/pelican-honored",
			env:  map[string]string{"PELICAN_DISABLE_HTTP_PROXY": ""},
			check: func(t *testing.T) {
				assert.True(t, viper.GetBool(param.Client_DisableHttpProxy.GetName()))
			},
		},
		{
			// OSG_ was read under either tier.
			name: "disable-http-proxy/osg-ignored",
			env:  map[string]string{"OSG_DISABLE_HTTP_PROXY": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableHttpProxy.GetName()))
			},
		},
		{
			name:       "disable-http-proxy/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_DISABLE_HTTP_PROXY": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableHttpProxy.GetName()))
			},
		},
		{
			name:       "disable-http-proxy/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_DISABLE_HTTP_PROXY": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableHttpProxy.GetName()))
			},
		},
		{
			// The preset is false because the bind sets true.
			name:   "disable-http-proxy/env-overrides-config",
			env:    map[string]string{"PELICAN_DISABLE_HTTP_PROXY": ""},
			preset: func(t *testing.T) { viper.Set(param.Client_DisableHttpProxy.GetName(), false) },
			check: func(t *testing.T) {
				assert.True(t, viper.GetBool(param.Client_DisableHttpProxy.GetName()))
			},
		},
		{
			name: "disable-proxy-fallback/pelican-honored",
			env:  map[string]string{"PELICAN_DISABLE_PROXY_FALLBACK": ""},
			check: func(t *testing.T) {
				assert.True(t, viper.GetBool(param.Client_DisableProxyFallback.GetName()))
			},
		},
		{
			name: "disable-proxy-fallback/osg-ignored",
			env:  map[string]string{"OSG_DISABLE_PROXY_FALLBACK": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableProxyFallback.GetName()))
			},
		},
		{
			name:       "disable-proxy-fallback/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_DISABLE_PROXY_FALLBACK": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableProxyFallback.GetName()))
			},
		},
		{
			name:       "disable-proxy-fallback/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_DISABLE_PROXY_FALLBACK": ""},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_DisableProxyFallback.GetName()))
			},
		},
		{
			name:   "disable-proxy-fallback/env-overrides-config",
			env:    map[string]string{"PELICAN_DISABLE_PROXY_FALLBACK": ""},
			preset: func(t *testing.T) { viper.Set(param.Client_DisableProxyFallback.GetName(), false) },
			check: func(t *testing.T) {
				assert.True(t, viper.GetBool(param.Client_DisableProxyFallback.GetName()))
			},
		},
		{
			name: "minimum-download-speed/pelican-honored",
			env:  map[string]string{"PELICAN_MINIMUM_DOWNLOAD_SPEED": "1024"},
			check: func(t *testing.T) {
				assert.Equal(t, int64(1024), viper.GetInt64(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			name:       "minimum-download-speed/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_MINIMUM_DOWNLOAD_SPEED": "1024"},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			name:       "minimum-download-speed/stashcp-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASHCP_MINIMUM_DOWNLOAD_SPEED": "1024"},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			name:       "minimum-download-speed/osdfcp-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDFCP_MINIMUM_DOWNLOAD_SPEED": "1024"},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			// PELICANCP_ was read under either tier.
			name: "minimum-download-speed/pelicancp-ignored",
			env:  map[string]string{"PELICANCP_MINIMUM_DOWNLOAD_SPEED": "1024"},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			// See director-url/env-overrides-config.
			name:   "minimum-download-speed/config-wins-over-env",
			env:    map[string]string{"PELICAN_MINIMUM_DOWNLOAD_SPEED": "1024"},
			preset: func(t *testing.T) { viper.Set(param.Client_MinimumDownloadSpeed.GetName(), 2048) },
			check: func(t *testing.T) {
				assert.Equal(t, int64(2048), viper.GetInt64(param.Client_MinimumDownloadSpeed.GetName()))
			},
		},
		{
			name: "nearest-cache/pelican-honored",
			env:  map[string]string{"PELICAN_NEAREST_CACHE": cacheUrl + ",https://cache2.example.com"},
			check: func(t *testing.T) {
				assert.Equal(t, []string{cacheUrl, "https://cache2.example.com"},
					viper.GetStringSlice(param.Client_PreferredCaches.GetName()))
			},
		},
		{
			// NEAREST_CACHE was read under either tier.
			name: "nearest-cache/unprefixed-ignored",
			env:  map[string]string{"NEAREST_CACHE": cacheUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_PreferredCaches.GetName()))
			},
		},
		{
			name:       "nearest-cache/osdf-ignored",
			osdfBinary: true,
			env:        map[string]string{"OSDF_NEAREST_CACHE": cacheUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_PreferredCaches.GetName()))
			},
		},
		{
			name:       "nearest-cache/stash-ignored",
			osdfBinary: true,
			env:        map[string]string{"STASH_NEAREST_CACHE": cacheUrl},
			check: func(t *testing.T) {
				assert.False(t, viper.IsSet(param.Client_PreferredCaches.GetName()))
			},
		},
		{
			name:   "nearest-cache/env-overrides-config",
			env:    map[string]string{"PELICAN_NEAREST_CACHE": cacheUrl},
			preset: func(t *testing.T) { viper.Set(param.Client_PreferredCaches.GetName(), []string{presetUrl}) },
			check: func(t *testing.T) {
				assert.Equal(t, []string{cacheUrl}, viper.GetStringSlice(param.Client_PreferredCaches.GetName()))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ResetConfig()
			t.Cleanup(ResetConfig)
			scrubConfigEnv(t)
			if tc.osdfBinary {
				setTestTier(t, OsdfPrefix)
			}
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			// ResetConfig disabled AutomaticEnv, so the order relative to
			// tc.env is immaterial.
			if tc.preset != nil {
				tc.preset(t)
			}

			bindLegacyClientEnv()

			tc.check(t)
		})
	}

	// PELICAN_NEAREST_CACHE is itself deprecated in favor of
	// Client.PreferredCaches.
	t.Run("nearest-cache/warns-that-it-is-deprecated", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		t.Setenv("PELICAN_NEAREST_CACHE", cacheUrl)
		hook.Reset()

		bindLegacyClientEnv()

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Equal(t, log.WarnLevel, entries[0].Level)
		assert.Contains(t, entries[0].Message, "PELICAN_NEAREST_CACHE")
		assert.Contains(t, entries[0].Message, param.Client_PreferredCaches.GetName())
	})

	// An unparsable value is rejected rather than coerced to 0, which
	// would disable the slow-transfer check.
	t.Run("minimum-download-speed/unparsable-is-rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		t.Setenv("PELICAN_MINIMUM_DOWNLOAD_SPEED", "not-a-number")
		hook.Reset()

		bindLegacyClientEnv()

		assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Equal(t, log.ErrorLevel, entries[0].Level)
		assert.Contains(t, entries[0].Message, "PELICAN_MINIMUM_DOWNLOAD_SPEED")
	})

	// A negative value is rejected rather than clamped.
	t.Run("minimum-download-speed/negative-is-rejected", func(t *testing.T) {
		ResetConfig()
		t.Cleanup(ResetConfig)
		scrubConfigEnv(t)
		t.Setenv("PELICAN_MINIMUM_DOWNLOAD_SPEED", "-1")
		hook.Reset()

		bindLegacyClientEnv()

		assert.False(t, viper.IsSet(param.Client_MinimumDownloadSpeed.GetName()))

		entries := hook.AllEntries()
		require.Len(t, entries, 1)
		assert.Equal(t, log.ErrorLevel, entries[0].Level)
		assert.Contains(t, entries[0].Message, "PELICAN_MINIMUM_DOWNLOAD_SPEED")
	})
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
