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
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestSnapshotViperKeys(t *testing.T) {
	v := viper.New()
	v.SetDefault("foo", "8444")
	v.SetDefault("bar", "info")

	snap := snapshotViperKeys(v)
	assert.Equal(t, "8444", snap["foo"])
	assert.Equal(t, "info", snap["bar"])
}

func TestRecordConfigFileDiff(t *testing.T) {
	st := &SourceTracker{sources: make(map[string]ConfigSource)}
	v := viper.New()
	v.SetDefault("foo", "info")
	v.SetDefault("bar", "8444")

	before := snapshotViperKeys(v)

	// Simulate a config file changing Logging.Level.
	v.Set("foo", "debug")

	st.RecordConfigFileDiff(before, v, "/path/to/file", SourceConfigFile)

	// Logging.Level changed → recorded.
	src, ok := st.Get("foo")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type)
	assert.Equal(t, "/path/to/file", src.Detail)

	// Server.WebPort unchanged → NOT recorded.
	_, ok = st.Get("bar")
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

// TestGlobalSourceTrackerIntegration exercises the global singleton through the
// full config initialization sequence: RecordDefaultKeys → RecordConfigFileDiff →
// RecordEnvVarSources, verifying that later stages correctly overwrite earlier ones.
func TestGlobalSourceTrackerIntegration(t *testing.T) {
	st := GetSourceTracker()
	st.Reset()
	t.Cleanup(func() { st.Reset() })

	// Verify GetSourceTracker returns the same singleton.
	require.Same(t, st, GetSourceTracker(), "GetSourceTracker should return the same instance")

	// Stage 1 — Simulate SetParameterDefaults by setting some defaults
	// and recording them via RecordDefaultKeys. "foo" and "bar" are pure
	// tracker keys; "origin.port" must be a real param so that
	// RecordEnvVarSources can resolve PELICAN_ORIGIN_PORT in Stage 3.
	v := viper.New()
	v.SetDefault("foo", "info")
	v.SetDefault("bar", "8444")
	v.SetDefault("origin.port", "8443")
	st.RecordDefaultKeys(v)

	src, ok := st.Get("foo")
	require.True(t, ok, "foo should be recorded after RecordDefaultKeys")
	assert.Equal(t, SourceDefault, src.Type)

	src, ok = st.Get("bar")
	require.True(t, ok)
	assert.Equal(t, SourceDefault, src.Type)

	// Stage 2 — Simulate a config file merge that changes "foo".
	before := snapshotViperKeys(v)
	v.Set("foo", "debug") // simulates MergeConfig
	st.RecordConfigFileDiff(before, v, "/etc/pelican/pelican.yaml", SourceConfigFile)

	src, ok = st.Get("foo")
	require.True(t, ok)
	assert.Equal(t, SourceConfigFile, src.Type, "Config file should overwrite default source")
	assert.Equal(t, "/etc/pelican/pelican.yaml", src.Detail)

	// "bar" was unchanged in Stage 2 → still SourceDefault.
	src, ok = st.Get("bar")
	require.True(t, ok)
	assert.Equal(t, SourceDefault, src.Type, "Unchanged key should remain as default")

	// Stage 3 — Simulate env var setting for origin.port.
	t.Setenv("PELICAN_ORIGIN_PORT", "9443")
	st.RecordEnvVarSources()

	src, ok = st.Get("origin.port")
	require.True(t, ok)
	assert.Equal(t, SourceEnvVar, src.Type, "Env var should overwrite default source")
	assert.Equal(t, "PELICAN_ORIGIN_PORT", src.Detail)

	// Verify the full state: 3 keys, each with the correct final source.
	all := st.AllSources()
	assert.Equal(t, SourceDefault, all["bar"].Type)
	assert.Equal(t, SourceConfigFile, all["foo"].Type)
	assert.Equal(t, SourceEnvVar, all["origin.port"].Type)
}
