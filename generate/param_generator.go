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

// This should not be included in any release of pelican, instead only the generated "parameters.go" and "parameters_struct.go" should packaged.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

type GoField struct {
	Name         string
	Type         string
	Tag          string
	NestedFields map[string]*GoField
}

type TemplateData struct {
	GeneratedConfig         string
	GeneratedConfigWithType string
	AllParamNames           []string
}

var requiredKeys = [3]string{"description", "default", "type"}
var deprecatedMap = make(map[string][]string)
var runtimeConfigurableMap = make(map[string]bool)

// paramRefRe matches ${Param.Name} references in default values (e.g.
// "${ConfigBase}/certificates/tls.crt"). parseTier uses this to populate
// defaultTier.paramRefs, which serve two purposes:
//   - They define edges in the dependency graph so Kahn's topological sort
//     processes the referenced parameter before the one that uses it.
//   - They tell writeSetDefault to emit strings.ReplaceAll interpolation
//     code that resolves the reference via v.GetString at startup.
var paramRefRe = regexp.MustCompile(`\$\{([^}]+)\}`)

// envRefRe matches $UPPER_CASE_VAR references in default values (e.g.
// "$XDG_RUNTIME_DIR/pelican"). Unlike ${Param.Name} refs, environment
// variable refs don't create ordering dependencies — they are resolved at
// startup via os.Getenv and cannot form cycles. parseTier's collectRefs
// skips any match that is actually part of a ${...} param ref to avoid
// double-counting (e.g. ${HOSTNAME} is a param ref, not an env ref).
var envRefRe = regexp.MustCompile(`\$([A-Z][A-Z0-9_]+)`)

// seedParams lists parameters whose defaults cannot be expressed as static
// YAML values — they require Go runtime calls (os.Hostname, the xdg package,
// etc.). SetBaseDefaultsInConfig in config/config.go sets these via
// v.SetDefault before calling the generated SetParameterDefaults function.
//
// The generator excludes seed params in two ways:
//   - GenDefaults skips emitting v.SetDefault calls for them.
//   - The topological sort treats them as pre-satisfied dependencies: other
//     params may reference ${ConfigBase} or ${Server.Hostname} freely without
//     creating a missing-node error or a false cycle.
var seedParams = map[string]bool{
	"ConfigBase":      true,
	"Server.Hostname": true,
	"RuntimeDir":      true,
}

// defaultTier holds a single default-value "tier" parsed from parameters.yaml.
//
// Each parameter in parameters.yaml may declare up to five tiers of defaults:
// default, root_default, osdf_default, client_default, and server_default.
// At runtime the generated code selects the appropriate tier based on context
// (e.g. isRoot, isOSDF). A tier's raw value may contain interpolation
// references — either ${Param.Name} refs to other config parameters, or
// $ENV_VAR refs to environment variables — which are resolved at startup.
// parseTier populates paramRefs and envRefs so that GenDefaults can:
//   - build a dependency graph and topologically sort parameters (paramRefs)
//   - emit the correct os.Getenv / v.GetString interpolation code (envRefs)
type defaultTier struct {
	raw       any      // the raw YAML value (string, bool, int, float64, or []any)
	paramRefs []string // ${Param.Name} references that create ordering dependencies
	envRefs   []string // $ENV_VAR references resolved via os.Getenv at startup
}

// paramDefault aggregates all default tiers for a single parameter from
// parameters.yaml. GenDefaults iterates over these in topologically-sorted
// order (via allDeps) and calls writeSetDefault for each non-nil tier to
// emit the appropriate v.SetDefault() call in the generated Go source.
// Deprecated parameters are tracked but skipped during code generation
// because setting their defaults would cause viper.IsSet to return true,
// breaking the migration logic in handleDeprecatedConfig.
type paramDefault struct {
	name          string
	varName       string // dots replaced with underscores for Go variable names
	pType         string // param type from parameters.yaml
	deprecated    bool   // whether this is a deprecated parameter
	def           *defaultTier
	rootDefault   *defaultTier
	osdfDefault   *defaultTier
	clientDefault *defaultTier
	serverDefault *defaultTier
}

// parseTier parses a single default-value tier from parameters.yaml into a
// defaultTier, extracting any ${Param.Name} and $ENV_VAR references. These
// references drive two downstream concerns:
//   - paramRefs feed into allDeps --> Kahn's topological sort, ensuring that
//     a parameter like Server.ExternalWebUrl (which references
//     ${Server.Hostname}) is processed after Server.Hostname.
//   - envRefs and paramRefs tell writeSetDefault to emit string interpolation
//     code (strings.ReplaceAll + os.Getenv) instead of a bare literal.
//
// Returns nil when the raw value is nil (i.e. the tier was absent in YAML),
// which signals to GenDefaults that this tier should be skipped.
func parseTier(raw any) *defaultTier {
	if raw == nil {
		return nil
	}
	t := &defaultTier{raw: raw}
	// Collect refs from string representations
	collectRefs := func(s string) {
		for _, m := range paramRefRe.FindAllStringSubmatch(s, -1) {
			t.paramRefs = append(t.paramRefs, m[1])
		}
		for _, m := range envRefRe.FindAllStringSubmatch(s, -1) {
			// Skip if this is actually part of a ${...} ref
			if strings.Contains(s, "${"+m[1]+"}") {
				continue
			}
			t.envRefs = append(t.envRefs, m[1])
		}
	}
	switch v := raw.(type) {
	case string:
		collectRefs(v)
	case []any:
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				collectRefs(s)
			}
		}
	}
	return t
}

// allDeps returns the union of ${Param.Name} references across all of this
// parameter's tiers. GenDefaults uses the result to build edges in the
// dependency graph for Kahn's topological sort: if param A references
// ${B} in any tier, then B must be processed before A so that
// v.GetString("B") returns the correct value when A's default is set.
// Seed params (ConfigBase, Server.Hostname, RuntimeDir) are excluded from
// the graph edges by the caller since they are set externally before the
// generated function runs.
func (pd *paramDefault) allDeps() map[string]bool {
	deps := make(map[string]bool)
	for _, t := range []*defaultTier{pd.def, pd.rootDefault, pd.osdfDefault, pd.clientDefault, pd.serverDefault} {
		if t == nil {
			continue
		}
		for _, r := range t.paramRefs {
			deps[r] = true
		}
	}
	return deps
}

// GenDefaults generates config/parameter_defaults.go, which contains three
// functions that replace the former defaults.yaml + osdf.yaml file-loading
// approach:
//
//   - SetParameterDefaults(v, isRoot, isOSDF): sets all base defaults in
//     dependency order, branching on isRoot/isOSDF for params that have
//     root_default or osdf_default tiers.
//   - ApplyClientDefaults(v): overrides base defaults with client_default
//     tier values. Called after SetParameterDefaults for client commands.
//   - ApplyServerDefaults(v): overrides base defaults with server_default
//     tier values. Called after SetParameterDefaults for server commands.
//
// The pipeline is:
//  1. Parse every YAML document in parameters.yaml into a paramDefault.
//  2. Build a dependency graph from ${Param.Name} refs (via allDeps).
//  3. Topologically sort with Kahn's algorithm (panic on cycles to create
//     a build error that developers will notice).
//  4. Iterate in sorted order, calling writeSetDefault to emit each
//     v.SetDefault call — with string interpolation code when the tier
//     contains param or env refs, or bare literals otherwise.
//  5. Write the formatted Go source to config/parameter_defaults.go.
func GenDefaults() {
	filename, _ := filepath.Abs("../docs/parameters.yaml")
	yamlFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer yamlFile.Close()

	decoder := yaml.NewDecoder(yamlFile)
	var allParams []*paramDefault

	for {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Errorf("document decode failed: %w", err))
		}
		name, _ := value["name"].(string)
		if name == "" {
			continue
		}
		pType, _ := value["type"].(string)

		pd := &paramDefault{
			name:    name,
			varName: strings.ReplaceAll(name, ".", "_"),
			pType:   pType,
		}
		if dep, ok := value["deprecated"].(bool); ok && dep {
			pd.deprecated = true
		}
		pd.def = parseTier(value["default"])
		pd.rootDefault = parseTier(value["root_default"])
		pd.osdfDefault = parseTier(value["osdf_default"])
		pd.clientDefault = parseTier(value["client_default"])
		pd.serverDefault = parseTier(value["server_default"])
		allParams = append(allParams, pd)
	}

	// Build name --> paramDefault lookup
	byName := make(map[string]*paramDefault, len(allParams))
	for _, pd := range allParams {
		byName[pd.name] = pd
	}

	// Build adjacency list and in-degree for Kahn's algorithm.
	// Edge: dep --> param (dep must be processed before param).
	inDegree := make(map[string]int, len(allParams))
	adj := make(map[string][]string)
	for _, pd := range allParams {
		inDegree[pd.name] = 0
	}
	for _, pd := range allParams {
		deps := pd.allDeps()
		// Only count deps on non-seed params (seeds are set externally)
		count := 0
		for dep := range deps {
			if !seedParams[dep] {
				adj[dep] = append(adj[dep], pd.name)
				count++
			}
		}
		inDegree[pd.name] = count
	}

	// Kahn's algorithm — topological sort.
	// We use sort.Strings(queue) after each insertion to maintain deterministic output
	// ordering. This is O(n² log n) total, which is suboptimal compared to a min-heap
	// (O(n log n)), but at ~400 parameters the difference is negligible for an offline
	// code generator. If the parameter count ever grows past ~2000, consider switching
	// to container/heap.
	var queue []string
	for _, pd := range allParams {
		if inDegree[pd.name] == 0 {
			queue = append(queue, pd.name)
		}
	}
	// Sort initial queue for deterministic output
	sort.Strings(queue)

	var sorted []string
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		sorted = append(sorted, n)
		neighbors := adj[n]
		sort.Strings(neighbors)
		for _, nb := range neighbors {
			inDegree[nb]--
			if inDegree[nb] == 0 {
				queue = append(queue, nb)
			}
		}
		// Re-sort queue for determinism after adding new items
		sort.Strings(queue)
	}
	if len(sorted) != len(allParams) {
		// Find the cycle
		var remaining []string
		for _, pd := range allParams {
			if inDegree[pd.name] != 0 {
				remaining = append(remaining, pd.name)
			}
		}
		panic(fmt.Sprintf("cycle detected in parameter defaults dependency graph; remaining params: %v", remaining))
	}

	// Generate the Go source file
	var buf bytes.Buffer
	buf.WriteString(`// Code generated by go generate; DO NOT EDIT.
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

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// Ensure imports are used.
var (
	_ = os.Getenv
	_ = strings.ReplaceAll
)

// SetParameterDefaults sets all parameter defaults from parameters.yaml in
// topologically-sorted dependency order. Seed values (ConfigBase,
// Server.Hostname, RuntimeDir) must already be set in viper via SetDefault
// before calling this function, as dependent params read them inline.
func SetParameterDefaults(v *viper.Viper, isRoot bool, isOSDF bool) {
`)

	// Collect which overrides are needed for client/server defaults
	var clientDefaults []*paramDefault
	var serverDefaults []*paramDefault

	for _, name := range sorted {
		if seedParams[name] {
			continue
		}
		pd := byName[name]

		// Skip object-type params — their defaults are complex structures
		// (nested maps/slices) that cannot be reliably serialized as Go literals.
		// They are typically "none" or "[]" and handled specially in Go code.
		if pd.pType == "object" {
			continue
		}

		// Skip deprecated params — their defaults should not be set via
		// SetParameterDefaults because viper.IsSet returns true for SetDefault
		// values, which would break the deprecation migration logic in
		// handleDeprecatedConfig. Deprecated params have their values migrated
		// to replacement keys at runtime.
		if pd.deprecated {
			continue
		}

		// Collect client/server defaults for separate functions
		if pd.clientDefault != nil {
			clientDefaults = append(clientDefaults, pd)
		}
		if pd.serverDefault != nil {
			serverDefaults = append(serverDefaults, pd)
		}

		// Determine which tiers are present
		hasRoot := pd.rootDefault != nil && !isNoneValue(pd.rootDefault.raw)
		hasOsdf := pd.osdfDefault != nil && !isNoneValue(pd.osdfDefault.raw)
		hasDef := pd.def != nil && !isNoneValue(pd.def.raw)

		if !hasDef && !hasRoot && !hasOsdf {
			continue
		}

		// Emit the v.SetDefault call(s) for this parameter.
		//
		// When a parameter has only a "default" tier, the generated code is
		// a single unconditional v.SetDefault call. But many parameters have
		// environment-specific tiers (root_default, osdf_default) that must
		// take precedence in certain contexts. For those, we emit an
		// if/else-if/else chain that selects the correct tier at runtime:
		//
		//   if isOSDF {
		//       v.SetDefault(param.X.GetName(), <osdf_default>)
		//   } else if isRoot {
		//       v.SetDefault(param.X.GetName(), <root_default>)
		//   } else {
		//       v.SetDefault(param.X.GetName(), <default>)
		//   }
		//
		// Not every parameter has all three tiers — the `first`
		// flag tracks whether we've already opened an `if` so we know whether
		// to emit `if` vs `} else if` for the next branch. If the fallback
		// "default" tier is absent (hasDef == false), the chain simply has no
		// else clause, meaning non-root/non-OSDF environments get no default
		// for that parameter (viper.IsSet will return false).
		fmt.Fprintf(&buf, "\t// %s\n", name)

		needsBranch := hasRoot || hasOsdf
		if needsBranch {
			first := true
			if hasOsdf {
				buf.WriteString("\tif isOSDF {\n")
				writeSetDefault(&buf, pd, pd.osdfDefault, "\t\t")
				first = false
			}
			if hasRoot {
				if first {
					buf.WriteString("\tif isRoot {\n")
				} else {
					buf.WriteString("\t} else if isRoot {\n")
				}
				writeSetDefault(&buf, pd, pd.rootDefault, "\t\t")
				first = false
			}
			if hasDef {
				buf.WriteString("\t} else {\n")
				writeSetDefault(&buf, pd, pd.def, "\t\t")
			}
			buf.WriteString("\t}\n")
		} else {
			writeSetDefault(&buf, pd, pd.def, "\t")
		}
	}

	buf.WriteString("}\n\n")

	// Generate ApplyClientDefaults
	buf.WriteString(`// ApplyClientDefaults overrides base defaults with client-specific values.
// Call after SetParameterDefaults.
func ApplyClientDefaults(v *viper.Viper) {
`)
	for _, pd := range clientDefaults {
		if isNoneValue(pd.clientDefault.raw) {
			continue
		}
		fmt.Fprintf(&buf, "\t// %s\n", pd.name)
		writeSetDefault(&buf, pd, pd.clientDefault, "\t")
	}
	buf.WriteString("}\n\n")

	// Generate ApplyServerDefaults
	buf.WriteString(`// ApplyServerDefaults overrides base defaults with server-specific values.
// Call after SetParameterDefaults.
func ApplyServerDefaults(v *viper.Viper) {
`)
	for _, pd := range serverDefaults {
		if isNoneValue(pd.serverDefault.raw) {
			continue
		}
		fmt.Fprintf(&buf, "\t// %s\n", pd.name)
		writeSetDefault(&buf, pd, pd.serverDefault, "\t")
	}
	buf.WriteString("}\n")

	// Write the file
	outPath, _ := filepath.Abs("../config/parameter_defaults.go")
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		panic(fmt.Errorf("failed to write parameter_defaults.go: %w", err))
	}
}

// isNoneValue returns true if the raw YAML value represents "no default".
// In parameters.yaml, "none" is the convention for params that have no
// meaningful default (e.g. optional file paths, URLs that must be set by
// the admin). GenDefaults skips emitting a v.SetDefault call for these
// so that viper.IsSet returns false, allowing downstream code to
// distinguish "not configured" from "configured to the default".
func isNoneValue(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return s == "none" || s == ""
	}
	return false
}

// writeSetDefault emits Go source code for a single v.SetDefault() call
// into buf. It is the lowest-level emitter in the code generation pipeline,
// called by GenDefaults once per (parameter, tier) pair.
//
// For tiers with no interpolation refs, it emits a simple literal:
//
//	v.SetDefault(param.Logging_Level.GetName(), "error")
//
// For tiers containing ${Param.Name} or $ENV_VAR refs, it emits a scoped
// block that builds the value via strings.ReplaceAll and os.Getenv:
//
//	{
//		val := "${ConfigBase}/certificates/tls.crt"
//		val = strings.ReplaceAll(val, "${ConfigBase}", v.GetString(param.ConfigBase.GetName()))
//		v.SetDefault(param.Server_TLSCertificateChain.GetName(), val)
//	}
//
// NOTE: The raw "${ConfigBase}/..." string that appears in the generated Go
// source is safe — it is NOT an unresolved template. It is a Go string
// literal copied verbatim from parameters.yaml's default field, and it is
// fully resolved by the strings.ReplaceAll call(s) immediately below it
// before the value ever reaches v.SetDefault. The ${...} syntax only has
// meaning inside this generator's pipeline; in the generated code it is
// just a substring being matched and replaced. Because the entire file is
// regenerated from parameters.yaml by `go generate`, these strings cannot
// drift out of sync with the YAML source.
//
// The type switch handles string, bool, int, float64, and []any (string
// slices). Object-type params are excluded upstream in GenDefaults.
func writeSetDefault(buf *bytes.Buffer, pd *paramDefault, tier *defaultTier, indent string) {
	paramVar := fmt.Sprintf("param.%s.GetName()", pd.varName)

	// Check if we need string interpolation
	hasParamRefs := len(tier.paramRefs) > 0
	hasEnvRefs := len(tier.envRefs) > 0
	needsInterp := hasParamRefs || hasEnvRefs

	switch raw := tier.raw.(type) {
	case string:
		if needsInterp {
			fmt.Fprintf(buf, "%s{\n", indent)
			fmt.Fprintf(buf, "%s\tval := %q\n", indent, raw)
			for _, ref := range tier.paramRefs {
				refVar := strings.ReplaceAll(ref, ".", "_")
				fmt.Fprintf(buf, "%s\tval = strings.ReplaceAll(val, \"${%s}\", v.GetString(%s.GetName()))\n",
					indent, ref, "param."+refVar)
			}
			for _, env := range tier.envRefs {
				fmt.Fprintf(buf, "%s\tval = strings.ReplaceAll(val, \"$%s\", os.Getenv(%q))\n",
					indent, env, env)
			}
			fmt.Fprintf(buf, "%s\tv.SetDefault(%s, val)\n", indent, paramVar)
			fmt.Fprintf(buf, "%s}\n", indent)
		} else {
			fmt.Fprintf(buf, "%sv.SetDefault(%s, %q)\n", indent, paramVar, raw)
		}
	case bool:
		fmt.Fprintf(buf, "%sv.SetDefault(%s, %t)\n", indent, paramVar, raw)
	case int:
		fmt.Fprintf(buf, "%sv.SetDefault(%s, %d)\n", indent, paramVar, raw)
	case float64:
		// YAML numbers may parse as float64
		if raw == float64(int(raw)) {
			fmt.Fprintf(buf, "%sv.SetDefault(%s, %d)\n", indent, paramVar, int(raw))
		} else {
			fmt.Fprintf(buf, "%sv.SetDefault(%s, %v)\n", indent, paramVar, raw)
		}
	case []any:
		// String slice — check if interpolation is needed
		if needsInterp {
			fmt.Fprintf(buf, "%s{\n", indent)
			fmt.Fprintf(buf, "%s\tvals := []string{", indent)
			for i, elem := range raw {
				if i > 0 {
					buf.WriteString(", ")
				}
				fmt.Fprintf(buf, "%q", fmt.Sprint(elem))
			}
			buf.WriteString("}\n")
			fmt.Fprintf(buf, "%s\tfor i, val := range vals {\n", indent)
			for _, ref := range tier.paramRefs {
				refVar := strings.ReplaceAll(ref, ".", "_")
				fmt.Fprintf(buf, "%s\t\tval = strings.ReplaceAll(val, \"${%s}\", v.GetString(%s.GetName()))\n",
					indent, ref, "param."+refVar)
			}
			for _, env := range tier.envRefs {
				fmt.Fprintf(buf, "%s\t\tval = strings.ReplaceAll(val, \"$%s\", os.Getenv(%q))\n",
					indent, env, env)
			}
			fmt.Fprintf(buf, "%s\t\tvals[i] = val\n", indent)
			fmt.Fprintf(buf, "%s\t}\n", indent)
			fmt.Fprintf(buf, "%s\tv.SetDefault(%s, vals)\n", indent, paramVar)
			fmt.Fprintf(buf, "%s}\n", indent)
		} else {
			fmt.Fprintf(buf, "%sv.SetDefault(%s, []string{", indent, paramVar)
			for i, elem := range raw {
				if i > 0 {
					buf.WriteString(", ")
				}
				fmt.Fprintf(buf, "%q", fmt.Sprint(elem))
			}
			buf.WriteString("})\n")
		}
	default:
		// For nil or unknown types, skip
		if raw != nil {
			fmt.Fprintf(buf, "%s// TODO: unhandled default type %T for %s\n", indent, raw, pd.name)
		}
	}
}

func GenParamEnum() {
	/*
	* This generated a file "config/parameters.go" that is based off of docs/parameters.yaml to be used
	* instead of explicit calls to viper.Get* It also generates a parameters.json file for website use
	 */
	filename, _ := filepath.Abs("../docs/parameters.yaml")
	yamlFile, err := os.Open(filename)
	fullJsonInt := []any{}

	if err != nil {
		panic(err)
	}

	// This decoder and for loop is needed because the yaml file has multiple '---' delineated docs
	decoder := yaml.NewDecoder(yamlFile)

	var values []any

	for {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Errorf("document decode failed: %w", err))
		}
		values = append(values, value)
	}

	stringParamMap := make(map[string]string)
	stringSliceParamMap := make(map[string]string)
	intParamMap := make(map[string]string)
	byteRateParamMap := make(map[string]string)
	boolParamMap := make(map[string]string)
	durationParamMap := make(map[string]string)
	objectParamMap := make(map[string]string)
	opaqueParamMap := make(map[string]string)
	allParamNames := make([]string, 0, 512)

	// Save the first parameter separately in order to do "<pname> Param = iota" for the enums

	// Parse and check the values of each parameter against the required Keys
	for idx, value := range values {
		entry := value.(map[string]any)
		entryName, ok := entry["name"]
		if !ok {
			panic(fmt.Sprintf("Parameter entry at position %d is missing the name attribute", idx))
		}
		for _, keyName := range requiredKeys {
			if _, ok := entry[keyName]; !ok {
				panic(fmt.Sprintf("Parameter entry '%s' is missing required key '%s'",
					entryName, keyName))
			}
		}

		// If `direct_access` is set to false, then we generate an OpaqueParam instead of the
		// normal typed param. OpaqueParam provides metadata methods (GetName, GetEnvVarName, etc.)
		// but no getters or setters, because the value is typically computed via some other
		// mechanism in the config module.
		isOpaque := false
		if entryDirectAccess, ok := entry["direct_access"]; ok {
			if entryVal, ok := entryDirectAccess.(bool); ok && !entryVal {
				isOpaque = true
			} else if !ok {
				panic(fmt.Sprintf("Parameter entry '%s' has direct_access set to non-boolean", entryName))
			}
		}

		// Each document must be converted to json on it's own and then the name
		// must be used as a key
		jsonBytes, _ := json.Marshal(entry)
		var j map[string]any
		err = json.Unmarshal(jsonBytes, &j)
		if err != nil {
			panic(err)
		}
		j2 := map[string]any{entry["name"].(string): j}
		fullJsonInt = append(fullJsonInt, j2)

		// Handle deprecated parameters
		if deprecated, ok := entry["deprecated"].(bool); ok && deprecated {
			if entry["replacedby"] == nil {
				panic(fmt.Sprintf("Parameter entry '%s' is deprecated but missing 'replacedby' key. If there is no replacement, use 'none'", entry["name"]))
			}
			var replacedBySlice []string
			// If the replaced by entry is a string, convert it to a slice
			if replacedBy, ok := entry["replacedby"].(string); ok {
				replacedBySlice = []string{replacedBy}
			} else if replacedBy, ok := entry["replacedby"].([]any); ok {
				// Convert each element to a string
				for _, v := range replacedBy {
					if vStr, ok := v.(string); ok {
						replacedBySlice = append(replacedBySlice, vStr)
					}
				}
			} else {
				panic(fmt.Sprintf("Parameter entry '%s' has invalid 'replacedby' key. It should be a string or a slice of strings", entry["name"]))
			}

			deprecatedMap[entry["name"].(string)] = replacedBySlice
		}

		// Handle runtime_configurable field
		rawName := entry["name"].(string)
		if runtimeConfigurable, ok := entry["runtime_configurable"].(bool); ok {
			runtimeConfigurableMap[rawName] = runtimeConfigurable
		} else {
			// Default to false if not specified
			runtimeConfigurableMap[rawName] = false
		}

		name := strings.ReplaceAll(rawName, ".", "_")
		if isOpaque {
			opaqueParamMap[name] = rawName
			allParamNames = append(allParamNames, rawName)
			continue
		}
		pType := entry["type"].(string)
		switch pType {
		case "url":
			fallthrough
		case "filename":
			fallthrough
		case "string":
			stringParamMap[name] = rawName
		case "stringSlice":
			stringSliceParamMap[name] = rawName
		case "int":
			intParamMap[name] = rawName
		case "byterate":
			byteRateParamMap[name] = rawName
		case "bool":
			boolParamMap[name] = rawName
		case "duration":
			durationParamMap[name] = rawName
		case "object":
			objectParamMap[name] = rawName
		default:
			errMsg := fmt.Sprintf("UnknownType '%s': add a new struct and return method to the generator, or "+
				"change the type in parameters.yaml to be an already-handled type", pType)
			panic(errMsg)
		}
		allParamNames = append(allParamNames, rawName)
	}

	sort.Strings(allParamNames)

	// Create the file to be generated
	f, err := os.Create("../param/parameters.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Generate the code based on the template
	err = packageTemplate.Execute(f, struct {
		StringMap              map[string]string
		StringSliceMap         map[string]string
		IntMap                 map[string]string
		ByteRateMap            map[string]string
		BoolMap                map[string]string
		DurationMap            map[string]string
		ObjectMap              map[string]string
		OpaqueMap              map[string]string
		DeprecatedMap          map[string][]string
		RuntimeConfigurableMap map[string]bool
		AllParamNames          []string
	}{StringMap: stringParamMap, StringSliceMap: stringSliceParamMap, IntMap: intParamMap, ByteRateMap: byteRateParamMap, BoolMap: boolParamMap, DurationMap: durationParamMap, ObjectMap: objectParamMap, OpaqueMap: opaqueParamMap, DeprecatedMap: deprecatedMap, RuntimeConfigurableMap: runtimeConfigurableMap, AllParamNames: allParamNames})

	if err != nil {
		panic(err)
	}

	// Write the json version of the yaml document to the file
	fullJsonBytes, err := json.Marshal(fullJsonInt)
	if err != nil {
		panic(err)
	}
	var prettyJSON bytes.Buffer
	err = json.Indent(&prettyJSON, fullJsonBytes, "", "\t")
	if err != nil {
		panic(err)
	}

	// Skip writing the file if it is the same as the existing file
	// This is so that the file is not updated if it is not changed making builds faster
	if _, err := os.Stat("../docs/parameters.json"); err == nil {
		existingJsonBytes, err := os.ReadFile("../docs/parameters.json")
		if err != nil {
			panic(err)
		}
		if bytes.Equal(existingJsonBytes, prettyJSON.Bytes()) {
			return
		}
	}

	// Create the json file to be generated (for the documentation website)
	fJSON, err := os.Create("../docs/parameters.json")
	if err != nil {
		panic(err)
	}
	_, err = fJSON.Write(prettyJSON.Bytes())
	if err != nil {
		panic(err)
	}
	// Copy the same json file ( for the web-ui )
	webUIPath := "../web_ui/frontend/public/data/parameters.json"
	// Create directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(webUIPath), 0755); err != nil {
		panic(err)
	}
	fJSON, err = os.Create("../web_ui/frontend/public/data/parameters.json")
	if err != nil {
		panic(err)
	}
	_, err = fJSON.Write(prettyJSON.Bytes())
	if err != nil {
		panic(err)
	}
}

// Recursively generate the struct code given the root of the GoField
func generateGoStructCode(field *GoField, indent string) string {
	// If it has type, it should be a leaf node as parent node
	// does not have a type
	if field.Type != "" {
		// Tack on a mapstructure value with the field's tag (ie the name of the field but lowercased). This
		// gets used to check viper keys against the struct fields, where Viper lowercases everything.
		return fmt.Sprintf("%s%s %s `mapstructure:\"%s\" yaml:\"%s\"`\n", indent, field.Name, field.Type, field.Tag, field.Name)
	}
	code := fmt.Sprintf("%s%s struct {\n", indent, field.Name)
	keys := make([]string, 0, len(field.NestedFields))
	for key := range field.NestedFields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		nested := field.NestedFields[key]
		code += generateGoStructCode(nested, indent+"	")
	}
	if field.Tag != "" {
		code += fmt.Sprintf("%s} `mapstructure:\"%s\" yaml:\"%s\"`\n", indent, field.Tag, field.Name)
	} else {
		code += fmt.Sprintf("%s}\n", indent)
	}
	return code
}

// Recursively generate the struct code given the root of the GoField
func generateGoStructWithTypeCode(field *GoField, indent string) string {
	// If it has type, it should be a leaf node as parent node
	// does not have a type
	if field.Type != "" {
		return fmt.Sprintf("%s%s struct { Type string; Value %s }\n", indent, field.Name, field.Type)
	}
	code := fmt.Sprintf("%s%s struct {\n", indent, field.Name)
	keys := make([]string, 0, len(field.NestedFields))
	for key := range field.NestedFields {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		nested := field.NestedFields[key]
		code += generateGoStructWithTypeCode(nested, indent+"	")
	}
	code += fmt.Sprintf("%s}\n", indent)
	return code
}

// This generates a file param/parameters_struct.go, a struct contains typed parameters
// that is based off of docs/parameters.yaml to be used for marshalling config to a JSON
func GenParamStruct() {
	// Same file-reading logic as GenParamEnum
	filename, _ := filepath.Abs("../docs/parameters.yaml")
	yamlFile, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer yamlFile.Close()

	decoder := yaml.NewDecoder(yamlFile)

	var values []any

	for {
		var value map[string]any
		if err := decoder.Decode(&value); err != nil {
			if err == io.EOF {
				break
			}
			panic(fmt.Errorf("document decode failed: %w", err))
		}
		values = append(values, value)
	}

	root := &GoField{
		NestedFields: make(map[string]*GoField),
	}

	// Convert YAML entries to a nested Go struct.
	for i := 0; i < len(values); i++ {
		entry := values[i].(map[string]any)

		// Skip required YAML field check as has been done in GenParamEnum
		pName := entry["name"].(string)
		pType := entry["type"].(string)
		goType := ""
		// Find the corresponding Go type
		switch pType {
		case "url":
			fallthrough
		case "filename":
			fallthrough
		case "string":
			goType = "string"
		case "stringSlice":
			goType = "[]string"
		case "int":
			goType = "int"
		case "byterate":
			goType = "byte_rate.ByteRate"
		case "bool":
			goType = "bool"
		case "duration":
			goType = "time.Duration"
		case "object":
			goType = "any"
		default:
			errMsg := fmt.Sprintf("UnknownType '%s': add a new struct and return method to the generator, or "+
				"change the type in parameters.yaml to be an already-handled type", pType)
			panic(errMsg)
		}

		parts := strings.Split(pName, ".")
		current := root
		for _, part := range parts {
			if current.NestedFields[part] == nil {
				current.NestedFields[part] = &GoField{
					Name:         part,
					Tag:          strings.ToLower(part),
					NestedFields: make(map[string]*GoField),
				}
			}
			current = current.NestedFields[part]
		}
		current.Type = goType
	}

	data := TemplateData{
		GeneratedConfig:         `type Config` + generateGoStructCode(root, ""),
		GeneratedConfigWithType: `type configWithType` + generateGoStructWithTypeCode(root, ""),
	}

	// Create the file to be generated
	f, err := os.Create("../param/parameters_struct.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// AllParameterNames is the list of all config keys generated from
	// docs/parameters.yaml. It is primarily used to bind environment variables
	// so that env-only overrides are included in viper.AllSettings().
	err = structTemplate.Execute(f, data)

	if err != nil {
		panic(err)
	}
}

// As more varied parameters get added to parameters.yaml with different paths and names, this may need to be
// altered to be more general
var packageTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
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
	"fmt"
	"strings"
	"time"

	"github.com/pelicanplatform/pelican/byte_rate"
)

type StringParam struct {
	name string
}

type StringSliceParam struct {
	name string
}

type BoolParam struct {
	name string
}

type IntParam struct {
	name string
}

type ByteRateParam struct {
	name string
}

type DurationParam struct {
	name string
}

type ObjectParam struct {
	name string
}

// OpaqueParam represents a parameter whose value is not directly accessible
// via the param package. It provides metadata methods (GetName, GetEnvVarName,
// IsSet, IsRuntimeConfigurable) but no getters or setters, because the value
// is typically computed via some other mechanism in the config module.
type OpaqueParam struct {
	name string
}

func GetDeprecated() map[string][]string {
    return map[string][]string{
        {{- range $key, $value := .DeprecatedMap}}
        "{{$key}}": {{"{"}}{{range $i, $v := $value}}{{if $i}}, {{end}}"{{$v}}"{{end}}},
        {{- end}}
    }
}

// runtimeConfigurableMap is a map of parameter names to their runtime configurability status.
// It is generated from docs/parameters.yaml and indicates whether a parameter can be reloaded
// at runtime without requiring a server restart.
var runtimeConfigurableMap = map[string]bool{
	{{- range $key, $value := .RuntimeConfigurableMap}}
	"{{$key}}": {{$value}},
	{{- end}}
}

func GetRuntimeConfigurable() map[string]bool {
	return runtimeConfigurableMap
}

// IsRuntimeConfigurable returns whether the given parameter name can be reloaded at runtime
func IsRuntimeConfigurable(paramName string) bool {
	if val, ok := runtimeConfigurableMap[paramName]; ok {
		return val
	}
	return false
}

// paramNameToEnvVar converts a parameter name (e.g., "Cache.Port") to its
// corresponding Pelican environment variable name (e.g., "PELICAN_CACHE_PORT").
func paramNameToEnvVar(paramName string) string {
	// Replace dots with underscores and convert to uppercase
	envVar := strings.ReplaceAll(paramName, ".", "_")
	envVar = strings.ToUpper(envVar)
	return "PELICAN_" + envVar
}

// stringAccessors maps parameter names to individual accessor functions.
// Using a map of closures instead of a switch statement prevents static analysis
// tools (e.g., CodeQL) from conflating all parameter accesses into a single
// data-flow path, which would cause every caller to be flagged whenever any
// single parameter refers to a sensitive value like a password location.
// The same logic applies to the other maps generated by this file.
var stringAccessors = map[string]func(*Config) string{
	{{- range $key, $value := .StringMap}}
	{{printf "%q" $value}}: func(c *Config) string { return c.{{$value}} },
	{{- end}}
}

func (sP StringParam) GetString() string {
	if accessor, ok := stringAccessors[sP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return ""
}

func (sP StringParam) GetName() string {
	return sP.name
}

func (sP StringParam) IsSet() bool {
	return viperIsSet(sP.name)
}

func (sP StringParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(sP.name)
}

func (sP StringParam) GetEnvVarName() string {
	return paramNameToEnvVar(sP.name)
}

// Set sets this string parameter's value.
func (sP StringParam) Set(value string) error {
	return MultiSet(map[string]any{sP.name: value})
}

var stringSliceAccessors = map[string]func(*Config) []string{
	{{- range $key, $value := .StringSliceMap}}
	{{printf "%q" $value}}: func(c *Config) []string { return c.{{$value}} },
	{{- end}}
}

func (slP StringSliceParam) GetStringSlice() []string {
	if accessor, ok := stringSliceAccessors[slP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return nil
}

func (slP StringSliceParam) GetName() string {
	return slP.name
}

func (slP StringSliceParam) IsSet() bool {
	return viperIsSet(slP.name)
}

func (slP StringSliceParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(slP.name)
}

func (slP StringSliceParam) GetEnvVarName() string {
	return paramNameToEnvVar(slP.name)
}

// Set sets this string slice parameter's value.
func (slP StringSliceParam) Set(value []string) error {
	return MultiSet(map[string]any{slP.name: value})
}

var intAccessors = map[string]func(*Config) int{
	{{- range $key, $value := .IntMap}}
	{{printf "%q" $value}}: func(c *Config) int { return c.{{$value}} },
	{{- end}}
}

func (iP IntParam) GetInt() int {
	if accessor, ok := intAccessors[iP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return 0
}

func (iP IntParam) GetName() string {
	return iP.name
}

func (iP IntParam) IsSet() bool {
	return viperIsSet(iP.name)
}

func (iP IntParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(iP.name)
}

func (iP IntParam) GetEnvVarName() string {
	return paramNameToEnvVar(iP.name)
}

// Set sets this integer parameter's value.
func (iP IntParam) Set(value int) error {
	return MultiSet(map[string]any{iP.name: value})
}

var byteRateAccessors = map[string]func(*Config) byte_rate.ByteRate{
	{{- range $key, $value := .ByteRateMap}}
	{{printf "%q" $value}}: func(c *Config) byte_rate.ByteRate { return c.{{$value}} },
	{{- end}}
}

func (bRP ByteRateParam) GetByteRate() byte_rate.ByteRate {
	if accessor, ok := byteRateAccessors[bRP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return 0
}

func (bRP ByteRateParam) GetName() string {
	return bRP.name
}

func (bRP ByteRateParam) IsSet() bool {
	return viperIsSet(bRP.name)
}

func (bRP ByteRateParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(bRP.name)
}

func (bRP ByteRateParam) GetEnvVarName() string {
	return paramNameToEnvVar(bRP.name)
}

// Set sets this byte rate parameter's value.
func (bRP ByteRateParam) Set(value byte_rate.ByteRate) error {
	return MultiSet(map[string]any{bRP.name: value})
}

// SetString parses a string (e.g. "10MB/s") and sets this byte rate parameter.
func (bRP ByteRateParam) SetString(value string) error {
	parsed, err := byte_rate.ParseRate(value)
	if err != nil {
		return fmt.Errorf("invalid byte rate %q for parameter %s: %w", value, bRP.name, err)
	}
	return MultiSet(map[string]any{bRP.name: parsed})
}

var boolAccessors = map[string]func(*Config) bool{
	{{- range $key, $value := .BoolMap}}
	{{printf "%q" $value}}: func(c *Config) bool { return c.{{$value}} },
	{{- end}}
}

func (bP BoolParam) GetBool() bool {
	if accessor, ok := boolAccessors[bP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return false
}

func (bP BoolParam) GetName() string {
	return bP.name
}

func (bP BoolParam) IsSet() bool {
	return viperIsSet(bP.name)
}

func (bP BoolParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(bP.name)
}

func (bP BoolParam) GetEnvVarName() string {
	return paramNameToEnvVar(bP.name)
}

// Set sets this boolean parameter's value.
func (bP BoolParam) Set(value bool) error {
	return MultiSet(map[string]any{bP.name: value})
}

var durationAccessors = map[string]func(*Config) time.Duration{
	{{- range $key, $value := .DurationMap}}
	{{printf "%q" $value}}: func(c *Config) time.Duration { return c.{{$value}} },
	{{- end}}
}

func (dP DurationParam) GetDuration() time.Duration {
	if accessor, ok := durationAccessors[dP.name]; ok {
		return accessor(getOrCreateConfig())
	}
	return 0
}

func (dP DurationParam) GetName() string {
	return dP.name
}

func (dP DurationParam) IsSet() bool {
	return viperIsSet(dP.name)
}

func (dP DurationParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(dP.name)
}

func (dP DurationParam) GetEnvVarName() string {
	return paramNameToEnvVar(dP.name)
}

// Set sets this duration parameter's value.
func (dP DurationParam) Set(value time.Duration) error {
	return MultiSet(map[string]any{dP.name: value})
}

// SetString parses a duration string (e.g. "1m", "30s") and sets this parameter.
func (dP DurationParam) SetString(value string) error {
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("invalid duration %q for parameter %s: %w", value, dP.name, err)
	}
	return MultiSet(map[string]any{dP.name: parsed})
}

func (oP ObjectParam) Unmarshal(rawVal any) error {
	return viperUnmarshalKey(oP.name, rawVal)
}

func (oP ObjectParam) GetName() string {
	return oP.name
}

func (oP ObjectParam) IsSet() bool {
	return viperIsSet(oP.name)
}

func (oP ObjectParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(oP.name)
}

func (oP ObjectParam) GetEnvVarName() string {
	return paramNameToEnvVar(oP.name)
}

// Set sets this object parameter's value.
func (oP ObjectParam) Set(value any) error {
	return MultiSet(map[string]any{oP.name: value})
}

func (oqP OpaqueParam) GetName() string {
	return oqP.name
}

func (oqP OpaqueParam) IsSet() bool {
	return viperIsSet(oqP.name)
}

func (oqP OpaqueParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(oqP.name)
}

func (oqP OpaqueParam) GetEnvVarName() string {
	return paramNameToEnvVar(oqP.name)
}

// allParameterNames is the list of all config keys generated from
// docs/parameters.yaml. It is primarily used to bind environment variables so
// that env-only overrides are included in viper.AllSettings().
var allParameterNames = []string{
	{{- range $i, $name := .AllParamNames}}
	{{printf "%q" $name}},
	{{- end}}
}

var ({{range $key, $value := .StringMap}}
	{{$key}} = StringParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .StringSliceMap}}
	{{$key}} = StringSliceParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .IntMap}}
	{{$key}} = IntParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .ByteRateMap}}
	{{$key}} = ByteRateParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .BoolMap}}
	{{$key}} = BoolParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .DurationMap}}
	{{$key}} = DurationParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .ObjectMap}}
	{{$key}} = ObjectParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .OpaqueMap}}
	{{$key}} = OpaqueParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

// paramByName maps canonical config key names (e.g. "Logging.Level") to their
// typed Param constant.  It is populated once at init time and never mutated,
// so concurrent reads are safe without a lock.
var paramByName map[string]Param

// paramByEnvVar maps environment variable names (e.g. "PELICAN_LOGGING_LEVEL")
// to the same typed Param constants.
var paramByEnvVar map[string]Param

func init() {
	paramByName = map[string]Param{
		{{- range $key, $value := .StringMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .StringSliceMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .IntMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .ByteRateMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .BoolMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .DurationMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .ObjectMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
		{{- range $key, $value := .OpaqueMap}}
		{{printf "%q" $value}}: {{$key}},
		{{- end}}
	}
	paramByEnvVar = make(map[string]Param, len(paramByName))
	for name, p := range paramByName {
		paramByEnvVar[paramNameToEnvVar(name)] = p
	}
}

// LookupParam returns the typed Param constant for a given configuration key
// name (e.g. "Logging.Level") or environment variable name
// (e.g. "PELICAN_LOGGING_LEVEL").  The second return value is false when
// the name does not correspond to any known parameter.
func LookupParam(name string) (Param, bool) {
	if p, ok := paramByName[name]; ok {
		return p, true
	}
	if p, ok := paramByEnvVar[name]; ok {
		return p, true
	}
	return nil, false
}
`))

var structTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
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
	"time"

	"github.com/pelicanplatform/pelican/byte_rate"
)

{{.GeneratedConfig}}

{{.GeneratedConfigWithType}}`))
