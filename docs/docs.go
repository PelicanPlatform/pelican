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

package docs

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

var (
	// The terms "module" and "component" are used interchangeably.
	RecognizedComponents = []string{"client", "registry", "director", "origin", "cache", "localcache"}
	ParsedParameters     map[string]*ParameterDoc
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
		log.Errorf("Error parsing parameters YAML: %v\n", err)
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
				param.Components = RecognizedComponents
			}

			key := strings.ToLower(param.Name)
			parameters[key] = &param
		}
	}

	return parameters, nil
}
