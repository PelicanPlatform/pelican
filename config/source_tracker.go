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
	"strings"
	"sync"

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// ConfigSourceType describes where a config value came from.
type ConfigSourceType string

const (
	SourceDefault    ConfigSourceType = "default"     // Set by SetParameterDefaults (from parameters.yaml)
	SourceConfigFile ConfigSourceType = "config-file" // Loaded from a YAML config file
	SourceEnvVar     ConfigSourceType = "env"         // Set via a PELICAN_* (or OSDF_*/STASH_*) environment variable
	SourceWebConfig  ConfigSourceType = "web-config"  // Set via the web UI config file
	SourceDynamic    ConfigSourceType = "dynamic"     // Set programmatically at runtime (v.Set)
)

// ConfigSource records the provenance of a single config key's value.
type ConfigSource struct {
	Type ConfigSourceType
	// For SourceConfigFile / SourceWebConfig: the file path that set this key.
	// For SourceEnvVar: the environment variable name (e.g. "PELICAN_LOGGING_LEVEL").
	Detail string
}

// SourceTracker is a thread-safe map recording where each config key's value came from.
// It follows a "last writer wins" policy: later config loading stages overwrite earlier
// sources for the same key, which mirrors viper's own merge semantics.
type SourceTracker struct {
	mu      sync.RWMutex
	sources map[string]ConfigSource
}

var globalSourceTracker = &SourceTracker{sources: make(map[string]ConfigSource)}

func init() {
	// Track programmatic param.Set / param.MultiSet calls so handleDeprecatedConfig
	// can distinguish them from defaults. Without this hook, every key on this
	// branch is recorded as SourceDefault (the generated SetParameterDefaults
	// registers a default for nearly every key), making it impossible to tell
	// whether a deprecated key's replacement was set by the user.
	param.SetHook = func(key string) {
		globalSourceTracker.Record(strings.ToLower(key), ConfigSource{Type: SourceDynamic})
	}
}

// GetSourceTracker returns the global singleton source tracker.
func GetSourceTracker() *SourceTracker {
	return globalSourceTracker
}

// Record stores the source for a config key. If the key was already recorded,
// the new source overwrites the old one (later stages take precedence).
func (st *SourceTracker) Record(key string, source ConfigSource) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sources[key] = source
}

// Get retrieves the source for a config key. The second return value is false
// if the key has no recorded source.
func (st *SourceTracker) Get(key string) (ConfigSource, bool) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	src, ok := st.sources[key]
	return src, ok
}

// AllSources returns a copy of the full source map.
func (st *SourceTracker) AllSources() map[string]ConfigSource {
	st.mu.RLock()
	defer st.mu.RUnlock()
	result := make(map[string]ConfigSource, len(st.sources))
	for k, v := range st.sources {
		result[k] = v
	}
	return result
}

// Reset clears all recorded sources. Used in tests.
func (st *SourceTracker) Reset() {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.sources = make(map[string]ConfigSource)
}

// ResetPreservingDynamic clears all recorded sources except entries marked
// SourceDynamic. Dynamic entries come from programmatic param.Set / param.MultiSet
// calls made before InitConfig runs (typically by tests). They must survive
// re-initialization so that handleDeprecatedConfig can distinguish a user-set
// replacement key from a generator-emitted default.
func (st *SourceTracker) ResetPreservingDynamic() {
	st.mu.Lock()
	defer st.mu.Unlock()
	preserved := make(map[string]ConfigSource)
	for k, v := range st.sources {
		if v.Type == SourceDynamic {
			preserved[k] = v
		}
	}
	st.sources = preserved
}

// RecordConfigFileKeys records every key explicitly declared in the config file
// at filePath as originating from that file. Rather than diffing viper's merged
// state before and after a merge, it parses the file on its own and records the
// keys it actually contains.
//
// Recording by presence (rather than by value change) is what makes attribution
// correct in two cases a before/after value diff cannot handle:
//   - Complex types: viper.GetString collapses slices/maps/objects to "", so a
//     value diff cannot see a list or map the user set in a file, and the key is
//     left mislabeled as a default.
//   - "Last writer wins": when a later file re-declares a key with the same value
//     an earlier file already set, there is no value change to diff, so the source
//     would otherwise stay pinned to the earlier file.
//
// This is best-effort provenance metadata: the caller has already merged the file
// into viper, so a read error here does not affect the loaded configuration.
// Callers should log, not abort, on error.
func (st *SourceTracker) RecordConfigFileKeys(filePath string, sourceType ConfigSourceType) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Pelican config files are YAML; this matches how the caller merged the file
	// (InitConfigInternal sets viper's config type to yaml globally).
	tempV := viper.New()
	tempV.SetConfigType("yaml")
	if err := tempV.ReadConfig(f); err != nil {
		return err
	}
	for _, key := range tempV.AllKeys() {
		st.Record(key, ConfigSource{Type: sourceType, Detail: filePath})
	}
	return nil
}

// RecordEnvVarSources scans the environment for variables matching the
// active prefixes (determined by the binary name via GetAllPrefixes) and
// records those keys. For a "pelican" binary, only PELICAN_* is considered;
// for an "osdf" binary, OSDF_*, STASH_*, and PELICAN_* are all matched.
//
// Rather than reimplementing the env-var-to-config-key conversion, this uses
// param.LookupParam to resolve the canonical parameter name. OSDF_/STASH_
// env vars are normalized to the PELICAN_ equivalent before lookup, since
// the param package indexes env vars under the PELICAN_ prefix only.
func (st *SourceTracker) RecordEnvVarSources() {
	prefixes := make([]string, 0, 3)
	for _, p := range GetAllPrefixes() {
		prefixes = append(prefixes, p.String()+"_")
	}
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}
		envName := parts[0]
		for _, prefix := range prefixes {
			if strings.HasPrefix(envName, prefix) {
				// Normalize to PELICAN_ prefix for param.LookupParam,
				// which indexes env vars under PELICAN_ only.
				canonicalEnv := "PELICAN_" + envName[len(prefix):]
				if p, ok := param.LookupParam(canonicalEnv); ok {
					viperKey := strings.ToLower(p.GetName())
					st.Record(viperKey, ConfigSource{Type: SourceEnvVar, Detail: envName})
				}
				break
			}
		}
	}
}

// RecordDefaultKeys marks every key currently in viper that does not already
// have a recorded source as SourceDefault. Call this after SetParameterDefaults
// (and the seed params) have been registered but before config files or env
// vars are loaded, so that later loading stages naturally overwrite the
// default entries via the tracker's "last writer wins" policy.
func (st *SourceTracker) RecordDefaultKeys(v *viper.Viper) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, key := range v.AllKeys() {
		if _, exists := st.sources[key]; !exists {
			st.sources[key] = ConfigSource{Type: SourceDefault}
		}
	}
}
