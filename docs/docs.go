package docs

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	ParsedParameters map[string]*ParameterDoc
	//go:embed parameters.yaml
	parametersYaml []byte
)

type ParameterDoc struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Default     interface{} `yaml:"default"`
	RootDefault interface{} `yaml:"root_default"`
	OsdfDefault interface{} `yaml:"osdf_default"`
	Type        string      `yaml:"type"`
	Components  []string    `yaml:"components"`
	Deprecated  bool        `yaml:"deprecated"`
	ReplacedBy  interface{} `yaml:"replacedby"`
	Hidden      bool        `yaml:"hidden"`
}

func init() {
	var err error
	ParsedParameters, err = parseParametersYAML()
	if err != nil {
		fmt.Printf("Error parsing parameters YAML: %v\n", err)
	}
}

func parseParametersYAML() (map[string]*ParameterDoc, error) {

	reader := bytes.NewReader(parametersYaml)

	parameters := make(map[string]*ParameterDoc)
	decoder := yaml.NewDecoder(reader)
	for {
		var param ParameterDoc
		err := decoder.Decode(&param)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse parameters file: %v", err)
		}
		if param.Name != "" {
			// Handle ["*"] in Components
			if len(param.Components) == 1 && param.Components[0] == "*" {
				param.Components = []string{"client", "registry", "director", "origin", "cache", "localcache"}
			}

			key := strings.ToLower(param.Name)
			parameters[key] = &param
		}
	}

	return parameters, nil
}
