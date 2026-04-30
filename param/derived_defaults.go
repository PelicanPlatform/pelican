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

package param

import (
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

// This file implements lazy resolution of "derived" parameter defaults —
// defaults whose value in docs/parameters.yaml contains ${Param.Name}
// placeholders that reference other parameters.
//
// Why lazy?
// ---------
// The generator used to substitute ${...} references at the moment
// SetParameterDefaults ran, baking in whatever value each dependency had at
// that instant. That approach broke whenever a dependency was modified
// later (e.g. tests pinning Server.WebPort to 0, then learning the OS
// chose port 45000): the derived default kept its stale baked-in value.
//
// With lazy resolution, SetParameterDefaults stores the *raw template*
// (e.g. "https://${Server.Hostname}:${Server.WebPort}") in viper and
// records (name, template) into the registry below via
// RegisterDerivedDefault. ResolveDerivedDefaults then walks the registry
// in topological dependency order and re-substitutes any entry the user
// hasn't overridden, calling v.SetDefault to update viper. Every code path
// that mutates viper (SetParameterDefaults, MultiSet, viper.MergeConfig
// callers) calls ResolveDerivedDefaults afterwards, so derived values
// always reflect the freshest dependency state.
//
// Maintainability
// ---------------
// The generator detects ${...} placeholders automatically. A new param in
// parameters.yaml whose default contains "${Foo}" is registered into
// derivedOrder and resolved at runtime with no manual hookup. Missing or
// cyclic references cause the generator to panic at code-gen time, so
// developers can't silently forget to wire something up.

// DerivedTemplate captures a parameter's "active" default template — the
// raw string (or string slice) that contains ${Param.Name} and/or
// $ENV_VAR placeholders to be resolved against current viper / process
// state. The generator emits one DerivedTemplate per templated tier and
// hands it to RegisterDerivedDefault from inside the generated
// SetParameterDefaults / ApplyClientDefaults / ApplyServerDefaults
// functions.
type DerivedTemplate struct {
	// Template is the raw template string with placeholders. For a
	// string-slice parameter, leave Template empty and populate
	// TemplateSlice instead.
	Template string

	// TemplateSlice is the raw per-element template for string-slice
	// parameters.
	TemplateSlice []string

	// EnvRefs lists the $ENV_VAR names referenced by the template (without
	// the leading $). They are resolved via os.Getenv at substitution time.
	// Plain ${Param.Name} references do NOT belong here — those are
	// discovered automatically by the regex matcher.
	EnvRefs []string
}

// derivedRefRe matches ${Param.Name} references inside a template string.
// It mirrors the regex the generator uses, but is duplicated here so the
// runtime resolver does not need to import the generator package.
var derivedRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// derivedState tracks both the raw template AND the most recently-resolved
// concrete value for a parameter. We need the resolved value to detect
// user overrides: viper.IsSet returns true for any key that has been
// touched by SetDefault, so we cannot use it to distinguish "still the
// default we computed" from "user set a value". Instead, on each Resolve
// pass we compare viper.Get(name) against lastResolved; if they match,
// the value is still ours to update; if they differ, the user (or some
// other code path) wrote over it and we leave it alone.
type derivedState struct {
	tmpl         DerivedTemplate
	lastResolved any  // most recent value we wrote via v.SetDefault, for override detection
	hasResolved  bool // false until the first ResolveDerivedDefaults pass writes a value
	// userPinned is set when an explicit caller (param.Set / param.MultiSet)
	// has written this key. Once pinned, the resolver will never overwrite
	// the value, even if a dependency changes. This is the explicit "I
	// know what I'm doing, leave it alone" opt-out — useful when test or
	// production code needs to freeze a derived value to match what was
	// captured by an external consumer (e.g. xrootd's scitokens.cfg).
	userPinned bool
}

var (
	derivedMu        sync.RWMutex
	derivedTemplates = map[string]*derivedState{}
)

// derivedOrder is the topological order in which derived defaults must be
// resolved so that each parameter sees its dependencies' freshly-resolved
// values when its own template is substituted.
//
// Populated by the generator via the file param/derived_defaults_gen.go
// (which assigns to this variable from an init() block).
var derivedOrder []string

// RegisterDerivedDefault records (or overrides) the active template for a
// parameter that the generator has identified as having a placeholder-bearing
// default. SetParameterDefaults, ApplyClientDefaults, and ApplyServerDefaults
// each call this for every templated tier they apply, so the most recently
// registered template always reflects the active environment (root, OSDF,
// client, server).
//
// Re-registering a parameter resets its hasResolved flag so the next
// ResolveDerivedDefaults pass treats it as fresh — important when
// ApplyClientDefaults / ApplyServerDefaults swap in a different tier
// after SetParameterDefaults already populated the base.
func RegisterDerivedDefault(name string, t DerivedTemplate) {
	derivedMu.Lock()
	defer derivedMu.Unlock()
	derivedTemplates[name] = &derivedState{tmpl: t}
}

// ResolveDerivedDefaults walks derivedOrder and, for any parameter whose
// current viper value still equals the value we last wrote (or whose
// template has not been resolved yet), substitutes the template against
// the freshest viper / environment state and reapplies it via v.SetDefault.
//
// Why we compare to lastResolved instead of using viper.IsSet: viper's
// IsSet returns true even for keys that have ONLY been touched by
// SetDefault, so it cannot distinguish "still the default value we
// computed" from "user explicitly overrode it". The lastResolved snapshot
// gives us that distinction — if the user (or any other code path) wrote
// a different value, viper.Get returns that other value and we skip
// re-resolution to preserve the override.
//
// Important properties:
//   - Idempotent: re-running with no dependency changes is a no-op.
//   - Safe after any mutation: callers should invoke this after
//     SetParameterDefaults, after viper.MergeConfig, and after every
//     viper.Set (handled by param.MultiSet) to keep derived values fresh.
//   - Skips user overrides: see lastResolved comparison above.
//   - Uses v.SetDefault, never v.Set: this preserves the "default-level"
//     status of derived values so callers that explicitly override later
//     still win, and so a future ResolveDerivedDefaults pass can re-resolve
//     after a dependency change.
func ResolveDerivedDefaults(v *viper.Viper) {
	if v == nil {
		return
	}

	derivedMu.Lock()
	defer derivedMu.Unlock()
	for _, name := range derivedOrder {
		st, ok := derivedTemplates[name]
		if !ok {
			continue
		}

		// If we already wrote a resolved value once, only re-resolve when
		// viper still holds that exact value. If anything else (user
		// config, env var, an explicit Set) wrote over it, leave it alone.
		if st.userPinned {
			continue
		}
		if st.hasResolved {
			cur := v.Get(name)
			if !equalValues(cur, st.lastResolved) {
				continue
			}
		}

		var resolved any
		if st.tmpl.TemplateSlice != nil {
			out := make([]string, len(st.tmpl.TemplateSlice))
			for i, s := range st.tmpl.TemplateSlice {
				out[i] = substituteDerivedTemplate(s, st.tmpl.EnvRefs, v)
			}
			resolved = out
		} else {
			resolved = substituteDerivedTemplate(st.tmpl.Template, st.tmpl.EnvRefs, v)
		}
		v.SetDefault(name, resolved)
		st.lastResolved = resolved
		st.hasResolved = true
	}
}

// equalValues compares two values that may be returned from viper.Get for
// a derived default. We only emit string and []string defaults from the
// generator, so a shallow equality check covers all real cases. Anything
// unexpected falls through to a conservative "treat as different", which
// is safer than "treat as equal" (we'd rather skip a re-resolution than
// stomp on a user override).
func equalValues(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case []string:
		bv, ok := b.([]string)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
		return true
	case []any:
		// viper sometimes returns []any for slice-typed values pulled out
		// of map[string]any; coerce to []string for comparison.
		bv, ok := b.([]string)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			s, ok := av[i].(string)
			if !ok || s != bv[i] {
				return false
			}
		}
		return true
	}
	return false
}

// substituteDerivedTemplate replaces ${Param.Name} occurrences with
// v.GetString(...) and $ENV occurrences with os.Getenv(...). It is the
// runtime counterpart to the strings.ReplaceAll chains the generator used
// to emit eagerly into SetParameterDefaults.
func substituteDerivedTemplate(s string, envRefs []string, v *viper.Viper) string {
	out := derivedRefRe.ReplaceAllStringFunc(s, func(match string) string {
		// match is e.g. "${Server.Hostname}"; strip ${ and }.
		return v.GetString(match[2 : len(match)-1])
	})
	for _, env := range envRefs {
		out = strings.ReplaceAll(out, "$"+env, os.Getenv(env))
	}
	return out
}

// ClearDerivedDefaults wipes the registry. This is intended for tests that
// need to reset global state between scenarios; production code should not
// call it.
func ClearDerivedDefaults() {
	derivedMu.Lock()
	defer derivedMu.Unlock()
	derivedTemplates = map[string]*derivedState{}
}

// MarkUserPinned flags the listed parameter names so the lazy resolver
// will never overwrite them on a future ResolveDerivedDefaults pass.
//
// Called by MultiSet for every key the caller explicitly Sets, so an
// explicit param.Set / param.MultiSet always wins over downstream
// re-resolution. Names that are not registered as derived defaults are
// silently ignored.
//
// This is the resolver's "explicit override" channel: it preserves the
// value the user just wrote even if a dependency later changes and the
// resolver would otherwise re-derive a different value. Without this,
// the lastResolved comparison would mistake a same-valued user Set for
// "still the resolver's value to update" and clobber it.
func MarkUserPinned(names ...string) {
	derivedMu.Lock()
	defer derivedMu.Unlock()
	for _, name := range names {
		if st, ok := derivedTemplates[name]; ok {
			st.userPinned = true
		}
	}
}
