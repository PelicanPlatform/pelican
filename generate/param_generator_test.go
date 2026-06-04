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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// indexOf returns the position of name in the sorted slice, or -1.
func indexOf(sorted []string, name string) int {
	for i, n := range sorted {
		if n == name {
			return i
		}
	}
	return -1
}

// param is a tiny helper to build a *paramDefault with a single "default" tier
// parsed the same way GenDefaults parses parameters.yaml, so the tests exercise
// the real parseTier ref-extraction path rather than hand-setting paramRefs.
func param(name, pType string, def any) *paramDefault {
	return &paramDefault{
		name:    name,
		varName: name, // varName isn't used by the helpers under test
		pType:   pType,
		def:     parseTier(def),
	}
}

func TestParseTier(t *testing.T) {
	t.Run("nil yields nil tier", func(t *testing.T) {
		assert.Nil(t, parseTier(nil))
	})

	t.Run("plain string has no refs", func(t *testing.T) {
		tier := parseTier("just a value")
		require.NotNil(t, tier)
		assert.Empty(t, tier.paramRefs)
		assert.Empty(t, tier.envRefs)
	})

	t.Run("param refs are extracted", func(t *testing.T) {
		tier := parseTier("https://${Server.Hostname}:${Server.WebPort}")
		require.NotNil(t, tier)
		assert.ElementsMatch(t, []string{"Server.Hostname", "Server.WebPort"}, tier.paramRefs)
		assert.Empty(t, tier.envRefs)
	})

	t.Run("env refs are extracted", func(t *testing.T) {
		tier := parseTier("$XDG_RUNTIME_DIR/pelican")
		require.NotNil(t, tier)
		assert.Empty(t, tier.paramRefs)
		assert.ElementsMatch(t, []string{"XDG_RUNTIME_DIR"}, tier.envRefs)
	})

	t.Run("param ref is not double-counted as env ref", func(t *testing.T) {
		// ${HOSTNAME} looks like an env ref ($HOSTNAME) but is a param ref.
		tier := parseTier("${HOSTNAME}/data")
		require.NotNil(t, tier)
		assert.ElementsMatch(t, []string{"HOSTNAME"}, tier.paramRefs)
		assert.Empty(t, tier.envRefs, "the $HOSTNAME inside ${HOSTNAME} must not be recorded as an env ref")
	})

	t.Run("refs inside string slices are extracted", func(t *testing.T) {
		tier := parseTier([]any{"${Cache.StorageLocation}/data", "${Cache.StorageLocation}/meta"})
		require.NotNil(t, tier)
		// Both elements reference the same param, so it appears twice.
		assert.Equal(t, []string{"Cache.StorageLocation", "Cache.StorageLocation"}, tier.paramRefs)
	})
}

func TestTopoSortParams_OrdersDependenciesFirst(t *testing.T) {
	// Server.ExternalWebUrl depends on Server.WebPort and the seed Server.Hostname.
	// Director.AdvertiseUrl depends (transitively) on Server.ExternalWebUrl.
	params := []*paramDefault{
		param("Director.AdvertiseUrl", "url", "${Server.ExternalWebUrl}"),
		param("Server.ExternalWebUrl", "url", "https://${Server.Hostname}:${Server.WebPort}"),
		param("Server.WebPort", "int", 8444),
	}

	sorted, err := topoSortParams(params)
	require.NoError(t, err)
	require.Len(t, sorted, 3)

	webPort := indexOf(sorted, "Server.WebPort")
	extUrl := indexOf(sorted, "Server.ExternalWebUrl")
	advUrl := indexOf(sorted, "Director.AdvertiseUrl")

	assert.Less(t, webPort, extUrl, "Server.WebPort must precede Server.ExternalWebUrl")
	assert.Less(t, extUrl, advUrl, "Server.ExternalWebUrl must precede Director.AdvertiseUrl")
}

func TestTopoSortParams_SeedDepsImposeNoOrdering(t *testing.T) {
	// A param that references only seed params (Server.Hostname) has in-degree 0
	// and must still be emitted; seeds are set externally.
	params := []*paramDefault{
		param("Server.ExternalWebUrl", "url", "https://${Server.Hostname}"),
	}
	sorted, err := topoSortParams(params)
	require.NoError(t, err)
	assert.Equal(t, []string{"Server.ExternalWebUrl"}, sorted)
}

func TestTopoSortParams_Deterministic(t *testing.T) {
	// Independent params (no refs) must come out in a stable, alphabetical order
	// regardless of input order, so the generated file doesn't churn.
	params := []*paramDefault{
		param("Zeta", "string", "z"),
		param("Alpha", "string", "a"),
		param("Mike", "string", "m"),
	}
	sorted, err := topoSortParams(params)
	require.NoError(t, err)
	assert.Equal(t, []string{"Alpha", "Mike", "Zeta"}, sorted)
}

func TestTopoSortParams_DetectsCycle(t *testing.T) {
	// A references B, B references A — unsatisfiable.
	params := []*paramDefault{
		param("A", "string", "${B}"),
		param("B", "string", "${A}"),
	}
	sorted, err := topoSortParams(params)
	assert.Nil(t, sorted)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
	// Both offending params should be named to aid debugging.
	assert.Contains(t, err.Error(), "A")
	assert.Contains(t, err.Error(), "B")
}

func TestValidateNoTierShadowing(t *testing.T) {
	t.Run("clean graph passes", func(t *testing.T) {
		params := []*paramDefault{
			param("Server.ExternalWebUrl", "url", "https://${Server.Hostname}:${Server.WebPort}"),
			param("Server.WebPort", "int", 8444),
		}
		byName := map[string]*paramDefault{}
		for _, p := range params {
			byName[p.name] = p
		}
		assert.NoError(t, validateNoTierShadowing(params, byName))
	})

	t.Run("server_default on a referenced param is rejected", func(t *testing.T) {
		// Dependent interpolates ${Dep}, but Dep is overridden by a server tier
		// that runs AFTER ApplyDerivedDefaults — the staleness hazard.
		dep := param("Dep", "string", "base")
		dep.serverDefault = parseTier("server-override")
		dependent := param("Dependent", "string", "${Dep}/child")

		params := []*paramDefault{dep, dependent}
		byName := map[string]*paramDefault{"Dep": dep, "Dependent": dependent}

		err := validateNoTierShadowing(params, byName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "server_default")
		assert.Contains(t, err.Error(), "Dependent")
		assert.Contains(t, err.Error(), "Dep")
	})

	t.Run("client_default on a referenced param is rejected", func(t *testing.T) {
		dep := param("Dep", "string", "base")
		dep.clientDefault = parseTier("client-override")
		dependent := param("Dependent", "string", "${Dep}/child")

		params := []*paramDefault{dep, dependent}
		byName := map[string]*paramDefault{"Dep": dep, "Dependent": dependent}

		err := validateNoTierShadowing(params, byName)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_default")
	})

	t.Run("a none-valued server tier does not trip the guard", func(t *testing.T) {
		// "none" means "no default", so it can't shadow anything.
		dep := param("Dep", "string", "base")
		dep.serverDefault = parseTier("none")
		dependent := param("Dependent", "string", "${Dep}/child")

		params := []*paramDefault{dep, dependent}
		byName := map[string]*paramDefault{"Dep": dep, "Dependent": dependent}

		assert.NoError(t, validateNoTierShadowing(params, byName))
	})

	t.Run("deprecated dependent is skipped", func(t *testing.T) {
		dep := param("Dep", "string", "base")
		dep.serverDefault = parseTier("server-override")
		dependent := param("Dependent", "string", "${Dep}/child")
		dependent.deprecated = true

		params := []*paramDefault{dep, dependent}
		byName := map[string]*paramDefault{"Dep": dep, "Dependent": dependent}

		assert.NoError(t, validateNoTierShadowing(params, byName))
	})
}

func TestIsNoneValue(t *testing.T) {
	tests := []struct {
		name  string
		pType string
		value any
		want  bool
	}{
		{"nil is none for any type", "string", nil, true},
		{"literal none string", "int", "none", true},
		{"empty string is none for string", "string", "", true},
		{"empty string is none for url", "url", "", true},
		{"empty string is none for filename", "filename", "", true},
		{"empty string is none for duration", "duration", "", true},
		{"empty string is none for byterate", "byterate", "", true},
		{"empty string is NOT none for bool-ish unknown type", "bogus", "", false},
		{"non-empty string is not none", "string", "value", false},
		{"int zero is a real default", "int", 0, false},
		{"bool false is a real default", "bool", false, false},
		{"bool true is a real default", "bool", true, false},
		{"empty slice is none for stringSlice", "stringSlice", []any{}, true},
		{"non-empty slice is not none for stringSlice", "stringSlice", []any{"a"}, false},
		{"empty slice is none for object", "object", []any{}, true},
		{"empty map is none for object", "object", map[string]any{}, true},
		{"non-empty map is not none for object", "object", map[string]any{"k": "v"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isNoneValue(tt.pType, tt.value))
		})
	}
}

func TestGoLiteral(t *testing.T) {
	assert.Equal(t, "nil", goLiteral(nil))
	assert.Equal(t, `"hello"`, goLiteral("hello"))
	assert.Equal(t, "true", goLiteral(true))
	assert.Equal(t, "42", goLiteral(42))
	// YAML integers frequently decode as float64; whole numbers render as ints.
	assert.Equal(t, "7", goLiteral(float64(7)))
	assert.Equal(t, `[]any{"a", "b"}`, goLiteral([]any{"a", "b"}))
	// Map keys are sorted for deterministic output.
	assert.Equal(t, `map[string]any{"a": 1, "b": 2}`,
		goLiteral(map[string]any{"b": 2, "a": 1}))
}

func TestHasBaseParamRefs(t *testing.T) {
	t.Run("base-tier ref counts", func(t *testing.T) {
		pd := param("X", "string", "${Y}/z")
		assert.True(t, pd.hasBaseParamRefs())
	})

	t.Run("no refs", func(t *testing.T) {
		pd := param("X", "string", "literal")
		assert.False(t, pd.hasBaseParamRefs())
	})

	t.Run("only an env ref does not count as a param ref", func(t *testing.T) {
		pd := param("X", "string", "$HOME/z")
		assert.False(t, pd.hasBaseParamRefs())
	})

	t.Run("client/server tier refs are excluded", func(t *testing.T) {
		// A ref that lives only in a client/server tier is applied via
		// ApplyClientDefaults/ApplyServerDefaults, not ApplyDerivedDefaults,
		// so it must NOT mark the param as having base refs.
		pd := param("X", "string", "literal")
		pd.clientDefault = parseTier("${Y}/z")
		assert.False(t, pd.hasBaseParamRefs())
	})
}
