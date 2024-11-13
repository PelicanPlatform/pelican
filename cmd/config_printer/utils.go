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

package config_printer

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// initClientAndServerConfig is used to initialize the values of a config instance.
//
// It takes a Viper instance, populates the client and server parameters, unmarshals it into
// a config struct, and returns it.
func initClientAndServerConfig(v *viper.Viper) *param.Config {
	if err := config.SetClientDefaults(v); err != nil {
		log.Errorf("Error setting client defaults: %v", err)
	}
	if err := config.SetServerDefaults(v); err != nil {
		log.Errorf("Error setting server defaults: %v", err)
	}

	if v == viper.GetViper() {
		globalFedInfo, globalFedErr := config.GetFederation(context.Background())
		if globalFedErr != nil {
			log.Errorf("Error getting federation info: %v", globalFedErr)
		}
		config.SetFederation(globalFedInfo)
	}

	exapandedConfig, err := param.UnmarshalConfig(v)
	if err != nil {
		log.Errorf("Error unmarshaling config: %v", err)
	}
	return exapandedConfig
}

// printConfig is used to print a config.
//
// It takes as input a config instance of type interface{} (not necessarily a full Config struct)
// and another parameter, format, which can be "yaml" or "json". It then prints the config in the
// corresponding format.
func printConfig(configData interface{}, format string) {
	switch format {
	case "yaml":
		if yamlData, err := yaml.Marshal(configData); err != nil {
			log.Errorf("Error marshaling config to YAML: %v", err)
		} else {
			fmt.Println(string(yamlData))
		}
	case "json":
		if jsonData, err := json.MarshalIndent(configData, "", "  "); err != nil {
			log.Errorf("Error marshaling config to JSON: %v", err)
		} else {
			fmt.Println(string(jsonData))
		}
	default:
		log.Errorf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}
}

// formatValue formats values appropriately for printing.
//
// It renders values of different kinds for printing. For example, a slice `[]int{1, 2, 3, 4}`
// would be formatted as "[1,2,3,4]".
func formatValue(value interface{}) string {
	if value == nil || value == "none" {
		return "none"
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		// Handle map[string]struct{} as a set
		if rv.Type().Key().Kind() == reflect.String && rv.Type().Elem().Kind() == reflect.Struct {
			var quotedKeys []string
			for _, key := range rv.MapKeys() {
				quotedKeys = append(quotedKeys, fmt.Sprintf("\"%s\"", key.String()))
			}
			return "[" + strings.Join(quotedKeys, ", ") + "]"
		}
		// Generic map handling (if needed)
		var elements []string
		for _, key := range rv.MapKeys() {
			formattedValue := formatValue(rv.MapIndex(key).Interface())
			elements = append(elements, fmt.Sprintf("%s: %s", key, formattedValue))
		}
		return "{" + strings.Join(elements, ", ") + "}"
	case reflect.Slice, reflect.Array:
		var elements []string
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i).Interface()
			elements = append(elements, formatValue(elem))
		}
		return "[" + strings.Join(elements, ", ") + "]"
	case reflect.String:
		// Surround string with double quotes
		return fmt.Sprintf("\"%s\"", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}
