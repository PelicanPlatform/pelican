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

package main

// This should not be included in any release of pelican, instead only the generated "parameters.go" and "parameters_struct.go" should packaged.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func GenParamEnum() {
	/*
	* This generated a file "config/parameters.go" that is based off of docs/parameters.yaml to be used
	* instead of explicit calls to viper.Get* It also generates a parameters.json file for website use
	 */
	filename, _ := filepath.Abs("../docs/parameters.yaml")
	yamlFile, err := os.Open(filename)
	fullJsonInt := []interface{}{}

	if err != nil {
		panic(err)
	}

	// This decoder and for loop is needed because the yaml file has multiple '---' delineated docs
	decoder := yaml.NewDecoder(yamlFile)

	var values []interface{}

	for {
		var value map[string]interface{}
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
	allParamNames := make([]string, 0, 512)

	// Skip the first parameter (ConfigBase is special)
	// Save the first parameter separately in order to do "<pname> Param = iota" for the enums

	// Parse and check the values of each parameter against the required Keys
	for idx, value := range values {
		entry := value.(map[string]interface{})
		entryName, ok := entry["name"]
		if !ok {
			panic(fmt.Sprintf("Parameter entry at position %d is missing the name attribute", idx))
		}
		if entryName == "ConfigBase" {
			continue
		}
		for _, keyName := range requiredKeys {
			if _, ok := entry[keyName]; !ok {
				panic(fmt.Sprintf("Parameter entry '%s' is missing required key '%s'",
					entryName, keyName))
			}
		}

		// If `direct_access` is set to false, then we are not allowed to access the value via the
		// param module.  Typically, this indicates there's some other mechanism in the config module
		// that should be used instead (such as when there's a computed value).
		if entryDirectAccess, ok := entry["direct_access"]; ok {
			if entryVal, ok := entryDirectAccess.(bool); ok && !entryVal {
				// direct_access = false; do not generate parameter
				continue
			} else if !ok {
				panic(fmt.Sprintf("Parameter entry '%s' has direct_access set to non-boolean", entryName))
			}
		}

		// Each document must be converted to json on it's own and then the name
		// must be used as a key
		jsonBytes, _ := json.Marshal(entry)
		var j map[string]interface{}
		err = json.Unmarshal(jsonBytes, &j)
		if err != nil {
			panic(err)
		}
		j2 := map[string]interface{}{entry["name"].(string): j}
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
			} else if replacedBy, ok := entry["replacedby"].([]interface{}); ok {
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
		DeprecatedMap          map[string][]string
		RuntimeConfigurableMap map[string]bool
		AllParamNames          []string
	}{StringMap: stringParamMap, StringSliceMap: stringSliceParamMap, IntMap: intParamMap, ByteRateMap: byteRateParamMap, BoolMap: boolParamMap, DurationMap: durationParamMap, ObjectMap: objectParamMap, DeprecatedMap: deprecatedMap, RuntimeConfigurableMap: runtimeConfigurableMap, AllParamNames: allParamNames})

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

	var values []interface{}

	for {
		var value map[string]interface{}
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

	// Convert YAML entries to a nested Go struct. We intentionally skip
	// the first entry, i.e. ConfigBase as it's only a verbose parameter
	// for user to read but not being set in the code
	for i := 1; i < len(values); i++ {
		entry := values[i].(map[string]interface{})

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
			goType = "interface{}"
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

	// Manually added this config to reflect what ConfigBase was meant to be
	// Refer to where getConfigBase() is used in InitServer() in config/config.go
	// for details
	root.NestedFields["ConfigDir"] = &GoField{
		Name:         "ConfigDir",
		Tag:          "configdir",
		NestedFields: make(map[string]*GoField),
		Type:         "string",
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

package param

import (
	"strings"
	"time"

	"github.com/spf13/viper"

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

func (sP StringParam) GetString() string {
	config := getOrCreateConfig()
	switch sP.name {
		{{- range $key, $value := .StringMap}}
		case {{printf "%q" $value}}:
			return config.{{$value}}
		{{- end}}
	}
	return ""
}

func (sP StringParam) GetName() string {
	return sP.name
}

func (sP StringParam) IsSet() bool {
	return viper.IsSet(sP.name)
}

func (sP StringParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(sP.name)
}

func (sP StringParam) GetEnvVarName() string {
	return paramNameToEnvVar(sP.name)
}

func (slP StringSliceParam) GetStringSlice() []string {
	config := getOrCreateConfig()
	switch slP.name {
		{{- range $key, $value := .StringSliceMap}}
		case {{printf "%q" $value}}:
			return config.{{$value}}
		{{- end}}
	}
	return nil
}

func (slP StringSliceParam) GetName() string {
	return slP.name
}

func (slP StringSliceParam) IsSet() bool {
	return viper.IsSet(slP.name)
}

func (slP StringSliceParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(slP.name)
}

func (slP StringSliceParam) GetEnvVarName() string {
	return paramNameToEnvVar(slP.name)
}

func (iP IntParam) GetInt() int {
	config := getOrCreateConfig()
	switch iP.name {
		{{- range $key, $value := .IntMap}}
		case {{printf "%q" $value}}:
			return config.{{$value}}
		{{- end}}
	}
	return 0
}

func (iP IntParam) GetName() string {
	return iP.name
}

func (iP IntParam) IsSet() bool {
	return viper.IsSet(iP.name)
}

func (iP IntParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(iP.name)
}

func (iP IntParam) GetEnvVarName() string {
	return paramNameToEnvVar(iP.name)
}

func (bRP ByteRateParam) GetByteRate() byte_rate.ByteRate {
	config := getOrCreateConfig()
	switch bRP.name {
		case "Origin.TransferRateLimit":
			return config.Origin.TransferRateLimit
	}
	return 0
}

func (bRP ByteRateParam) GetName() string {
	return bRP.name
}

func (bRP ByteRateParam) IsSet() bool {
	return viper.IsSet(bRP.name)
}

func (bRP ByteRateParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(bRP.name)
}

func (bRP ByteRateParam) GetEnvVarName() string {
	return paramNameToEnvVar(bRP.name)
}

func (bP BoolParam) GetBool() bool {
	config := getOrCreateConfig()
	switch bP.name {
		{{- range $key, $value := .BoolMap}}
		case {{printf "%q" $value}}:
			return config.{{$value}}
		{{- end}}
	}
	return false
}

func (bP BoolParam) GetName() string {
	return bP.name
}

func (bP BoolParam) IsSet() bool {
	return viper.IsSet(bP.name)
}

func (bP BoolParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(bP.name)
}

func (bP BoolParam) GetEnvVarName() string {
	return paramNameToEnvVar(bP.name)
}

func (dP DurationParam) GetDuration() time.Duration {
	config := getOrCreateConfig()
	switch dP.name {
		{{- range $key, $value := .DurationMap}}
		case {{printf "%q" $value}}:
			return config.{{$value}}
		{{- end}}
	}
	return 0
}

func (dP DurationParam) GetName() string {
	return dP.name
}

func (dP DurationParam) IsSet() bool {
	return viper.IsSet(dP.name)
}

func (dP DurationParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(dP.name)
}

func (dP DurationParam) GetEnvVarName() string {
	return paramNameToEnvVar(dP.name)
}

func (oP ObjectParam) Unmarshal(rawVal any) error {
	return viper.UnmarshalKey(oP.name, rawVal)
}

func (oP ObjectParam) UnmarshalWithHook(rawVal any, decodeHook any) error {
	return viper.UnmarshalKey(oP.name, rawVal, viper.DecodeHook(decodeHook))
}

func (oP ObjectParam) GetName() string {
	return oP.name
}

func (oP ObjectParam) IsSet() bool {
	return viper.IsSet(oP.name)
}

func (oP ObjectParam) IsRuntimeConfigurable() bool {
	return IsRuntimeConfigurable(oP.name)
}

func (oP ObjectParam) GetEnvVarName() string {
	return paramNameToEnvVar(oP.name)
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
`))

var structTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
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

package param

import (
	"time"

	"github.com/pelicanplatform/pelican/byte_rate"
)

{{.GeneratedConfig}}

{{.GeneratedConfigWithType}}`))
