package main

// This should not be included in any release of pelican, instead only the generated "parameters.go" and "parameters_struct.go" should packaged.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

type GoField struct {
	Name         string
	Type         string
	NestedFields map[string]*GoField
}

type TemplateData struct {
	GeneratedCode string
}

func main() {
	GenParamEnum()
	GenParamStruct()
	GenPlaceholderPathForNext()
}

var requiredKeys = [4]string{"name", "description", "default", "type"}

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
	intParamMap := make(map[string]string)
	boolParamMap := make(map[string]string)
	durationParamMap := make(map[string]string)

	// Skip the first parameter (ConfigBase is special)
	// Save the first parameter seperately in order to do "<pname> Param = iota" for the enums

	// Parse and check the values of each parameter against the required Keys
	for i := 1; i < len(values); i++ {
		entry := values[i].(map[string]interface{})
		for j := 0; j < len(requiredKeys); j++ {
			_, ok := entry[requiredKeys[j]]
			if !ok {
				errMsg := "all entries require the " + requiredKeys[j] + " field to populated"
				panic(errMsg)
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

		rawName := entry["name"].(string)
		name := strings.ReplaceAll(rawName, ".", "_")
		pType := entry["type"].(string)
		switch pType {
		case "url":
			fallthrough
		case "filename":
			fallthrough
		case "string":
			stringParamMap[name] = rawName
		case "int":
			intParamMap[name] = rawName
		case "bool":
			boolParamMap[name] = rawName
		case "duration":
			durationParamMap[name] = rawName
		default:
			errMsg := "UnknownType, add a new struct and return method to the generator or add it to one of the already handles types"
			panic(errMsg)
		}
	}

	// Create the file to be generated
	f, err := os.Create("../param/parameters.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	// Generate the code based on the template
	err = packageTemplate.Execute(f, struct {
		StringMap   map[string]string
		IntMap      map[string]string
		BoolMap     map[string]string
		DurationMap map[string]string
	}{StringMap: stringParamMap, IntMap: intParamMap, BoolMap: boolParamMap, DurationMap: durationParamMap})

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
	// Create the json file to be generated (for the web ui)
	fJSON, err := os.Create("../docs/parameters.json")
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
		return fmt.Sprintf("%s%s %s\n", indent, field.Name, field.Type)
	}
	code := fmt.Sprintf("%s%s struct {\n", indent, field.Name)
	for _, nested := range field.NestedFields {
		code += generateGoStructCode(nested, indent+"	")
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
		case "int":
			goType = "int"
		case "bool":
			goType = "bool"
		case "duration":
			goType = "time.Duration"
		default:
			errMsg := "UnknownType, add a new struct and return method to the generator or add it to one of the already handles types"
			panic(errMsg)
		}

		parts := strings.Split(pName, ".")
		current := root
		for _, part := range parts {
			if current.NestedFields[part] == nil {
				current.NestedFields[part] = &GoField{
					Name:         part,
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
		NestedFields: make(map[string]*GoField),
		Type:         "string",
	}

	data := TemplateData{
		GeneratedCode: `type config` + generateGoStructCode(root, ""),
	}

	// Create the file to be generated
	f, err := os.Create("../param/parameters_struct.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = structTemplate.Execute(f, data)

	if err != nil {
		panic(err)
	}
}

// As more varied paramters get added to parameters.yaml with different paths and names, this may need to be
// altered to be more general
var packageTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.

package param

import (
	"time"

	"github.com/spf13/viper"
)

type StringParam struct {
	name string
}

type BoolParam struct {
	name string
}

type IntParam struct {
	name string
}

type DurationParam struct {
	name string
}

func (sP StringParam) GetString() string {
	return viper.GetString(sP.name)
}

func (iP IntParam) GetInt() int {
	return viper.GetInt(iP.name)
}

func (bP BoolParam) GetBool() bool {
	return viper.GetBool(bP.name)
}

func (bP DurationParam) GetDuration() time.Duration {
	return viper.GetDuration(bP.name)
}

var ({{range $key, $value := .StringMap}}
	{{$key}} = StringParam{{"{"}}{{printf "%q" $value}}{{"}"}}
	{{- end}}
)

var ({{range $key, $value := .IntMap}}
	{{$key}} = IntParam{{"{"}}{{printf "%q" $value}}{{"}"}}
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
`))

var structTemplate = template.Must(template.New("").Parse(`
// Code generated by go generate; DO NOT EDIT.
package param

import (
	"time"
)

{{.GeneratedCode}}
`))
