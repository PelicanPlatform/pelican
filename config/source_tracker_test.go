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
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestSourceTracker_RecordAndGet(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}

	// Record a config file source.
	st.Record("foo", ConfigSource{Type: SourceConfigFile, Detail: "/path/to/file"})

	src, ok := st.Get("foo")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
	assert.Equal(t, "/path/to/file", src.Detail)

	// Unrecorded key returns false.
	_, ok = st.Get("bar")
	assert.False(t, ok)
}

func TestSourceTracker_LastWriterWins(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}

	st.Record("foo", ConfigSource{Type: SourceConfigFile, Detail: "/path/to/file"})
	st.Record("foo", ConfigSource{Type: SourceEnvVar, Detail: "PELICAN_FOO"})

	src, ok := st.Get("foo")
	require.True(t, ok)
	assert.Equal(t, SourceEnvVar, src.Type)
	assert.Equal(t, "PELICAN_FOO", src.Detail)
}

func TestSourceTracker_AllSources(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}

	st.Record("foo", ConfigSource{Type: SourceConfigFile, Detail: "a.yaml"})
	st.Record("bar", ConfigSource{Type: SourceEnvVar, Detail: "PELICAN_BAR"})

	all := st.AllSources()
	assert.Len(t, all, 2)
	assert.Equal(t, "a.yaml", all["foo"].Detail)

	// Returned map is a copy — mutating it doesn't affect the tracker.
	delete(all, "foo")
	_, ok := st.Get("foo")
	assert.True(t, ok)
}

func TestSourceTracker_Reset(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}
	st.Record("foo", ConfigSource{Type: SourceDefault})

	st.Reset()

	_, ok := st.Get("foo")
	assert.False(t, ok)
	assert.Empty(t, st.AllSources())
}

func TestRecordDefaultKeys(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}
	v := viper.New()
	v.SetDefault("foo", "info")
	v.SetDefault("bar", "8444")

	// A key with a pre-existing non-default source must not be reclassified.
	st.Record("bar", ConfigSource{Type: SourceConfigFile, Detail: "/path/to/file"})

	st.RecordDefaultKeys(v)

	// "foo" had no prior source → tagged default.
	src, ok := st.Get("foo")
	require.True(t, ok)
	assert.Equal(t, SourceDefault, src.Type)

	// "bar" already had a source → left untouched.
	src, ok = st.Get("bar")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
}

func TestRecordConfigFileKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	require.NoError(t, os.WriteFile(path,
		[]byte("Server:\n  WebHost: 1.2.3.4\nOrigin:\n  ExportVolumes:\n    - /a:/a\n    - /b:/b\n"), 0o600))

	st := &SourceTracker{sources: make(map[string]ConfigSource)}
	require.NoError(t, st.RecordConfigFileKeys(path, SourceConfigFile))

	// Scalar key recorded.
	src, ok := st.Get("server.webhost")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
	assert.Equal(t, path, src.Detail)

	// StringSlice key recorded too — the case a viper.GetString value-diff could
	// not detect (it collapses slices to "").
	src, ok = st.Get("origin.exportvolumes")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
	assert.Equal(t, path, src.Detail)

	// A key the file does NOT declare is not recorded.
	_, ok = st.Get("server.webport")
	assert.False(t, ok)
}

func TestRecordEnvVarSources(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}

	t.Setenv("PELICAN_LOGGING_LEVEL", "debug")

	st.RecordEnvVarSources()

	src, ok := st.Get("logging.level")
	require.True(t, ok)
	assert.Equal(t, SourceEnvVar, src.Type)
	assert.Equal(t, "PELICAN_LOGGING_LEVEL", src.Detail)

	// Non-PELICAN env vars should not be recorded.
	t.Setenv("HOME", "/root")
	_, ok = st.Get("home")
	assert.False(t, ok)
}

// TestSourceTrackerInitConfigIntegration exercises the source tracker through the
// real InitConfigInternal sequence (defaults → config files → continued configs →
// env vars), using on-disk YAML rather than synthetic keys on a hand-built viper.
// This is the wiring that the unit tests above cannot exercise: in particular the
// ExperimentalBindStruct + slice-typed behavior that a value-diff approach got
// wrong. It locks in the regressions called out in review of this PR.
func TestSourceTrackerInitConfigIntegration(t *testing.T) {
	ResetConfig()
	t.Cleanup(ResetConfig)

	// A continued-config directory with two files that set the SAME key to the
	// SAME value. The lexicographically-later file (b.yaml) is merged last and
	// must own the attribution ("last writer wins"). A value-diff approach left
	// this pinned to the first file.
	contDir := t.TempDir()
	dup := "Server:\n  ExternalWebUrl: https://dup.example.com\n"
	require.NoError(t, os.WriteFile(filepath.Join(contDir, "a.yaml"), []byte(dup), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(contDir, "b.yaml"), []byte(dup), 0o600))

	// Primary config: a scalar override, a stringSlice override (a slice param
	// that HAS a default), and a deprecated/replacement stringSlice pair set
	// together. The slice override and the deprecated pair are what a
	// viper.GetString value-diff mislabeled as "default".
	primary := "ConfigLocations:\n  - " + strings.ReplaceAll(contDir, "\\", "\\\\") + "\n" +
		"Server:\n  WebHost: 9.9.9.9\n" +
		"Origin:\n" +
		"  DefaultChecksumTypes:\n    - md5\n" +
		"  ExportVolumes:\n    - /user/A:/A\n    - /user/B:/B\n" +
		"  ExportVolume: /old:/old\n"
	cfg, err := os.CreateTemp("", "pelican-src-*.yaml")
	require.NoError(t, err)
	_, err = cfg.WriteString(primary)
	require.NoError(t, err)
	require.NoError(t, cfg.Close())
	require.NoError(t, param.SetRaw("config", cfg.Name()))

	// An env-var override must be tagged SourceEnvVar.
	t.Setenv("PELICAN_ORIGIN_PORT", "2718")

	InitConfigInternal(logrus.ErrorLevel)

	st := GetSourceTracker()
	require.Same(t, st, GetSourceTracker(), "GetSourceTracker should return the same singleton")

	// Scalar override → config file.
	src, ok := st.Get("server.webhost")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type, "scalar override should be tagged config-file")

	// StringSlice override → config file (regression: previously left "default"
	// because GetString collapses slices to "").
	src, ok = st.Get("origin.defaultchecksumtypes")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type, "stringSlice override should be tagged config-file, not default")

	// Env-var override → env.
	src, ok = st.Get("origin.port")
	require.True(t, ok)
	assert.Equal(t, SourceEnvVar, src.Type, "env override should be tagged env")
	assert.Equal(t, "PELICAN_ORIGIN_PORT", src.Detail)

	// Last-writer-wins across two continued-config files that set an identical
	// value: the later file (b.yaml) must own the source.
	src, ok = st.Get("server.externalweburl")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
	assert.True(t, strings.HasSuffix(src.Detail, "b.yaml"),
		"last writer (b.yaml) should win; got source %q", src.Detail)

	// Data-loss regression: with the deprecated Origin.ExportVolume and its
	// replacement Origin.ExportVolumes both set, the replacement must be seen as
	// user-set so the deprecation handler does NOT overwrite the user's list with
	// the deprecated scalar.
	assert.ElementsMatch(t, []string{"/user/A:/A", "/user/B:/B"},
		param.Origin_ExportVolumes.GetStringSlice(),
		"user's ExportVolumes list must survive deprecation handling")
}
