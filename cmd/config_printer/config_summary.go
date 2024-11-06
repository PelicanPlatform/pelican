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
	"fmt"
	"reflect"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
)

func configSummary(cmd *cobra.Command, args []string) {
	defaultConfig := viper.New()
	config.SetBaseDefaultsInConfig(defaultConfig)
	err := config.InitConfigDir(defaultConfig)
	if err != nil {
		fmt.Printf("Error initializing config directory: %v\n", err)
	}

	defaultConfigMap := initClientAndServerConfig(defaultConfig)

	currentConfigMap := initClientAndServerConfig(viper.GetViper())

	diff := compareStructsAsym(currentConfigMap, defaultConfigMap)

	if diff != nil {
		printConfig(diff, format)
	}
}

// compareStructsAsym recursively iterates through the fields of two given config
// instances, `v1` and `v2`. It generates a nested structure containing the parameters
// in `v1` that have different corresponding values in `v2`.
func compareStructsAsym(v1, v2 interface{}) interface{} {
	val1 := reflect.ValueOf(v1)
	val2 := reflect.ValueOf(v2)

	if val1.Kind() == reflect.Ptr {
		if val1.IsNil() {
			val1 = reflect.Value{}
		} else {
			val1 = val1.Elem()
		}
	}
	if val2.Kind() == reflect.Ptr {
		if val2.IsNil() {
			val2 = reflect.Value{}
		} else {
			val2 = val2.Elem()
		}
	}

	val1IsValid := val1.IsValid()
	val2IsValid := val2.IsValid()

	if !val1IsValid && !val2IsValid {
		return nil
	}

	if !val1IsValid || !val2IsValid {
		return v1
	}

	var diff interface{}

	switch val1.Kind() {
	case reflect.Struct:
		diffMap := make(map[string]interface{})
		typeOfVal1 := val1.Type()
		for i := 0; i < val1.NumField(); i++ {
			fieldName := typeOfVal1.Field(i).Name
			fieldVal1 := val1.Field(i).Interface()

			var fieldVal2 interface{}
			field2 := val2.FieldByName(fieldName)
			if field2.IsValid() {
				fieldVal2 = field2.Interface()
			} else {
				fieldVal2 = nil
			}

			// Recursively compare the fields
			fieldDiff := compareStructsAsym(fieldVal1, fieldVal2)
			if fieldDiff != nil {
				diffMap[fieldName] = fieldDiff
			}
		}
		if len(diffMap) > 0 {
			diff = diffMap
		}

	case reflect.Slice, reflect.Array:
		if val1.IsNil() && val2.IsNil() {
			return nil
		}

		if val1.IsNil() != val2.IsNil() {
			diff = v1
			break
		}

		val1Len := val1.Len()
		val2Len := val2.Len()

		if val1Len != val2Len {
			diff = v1
			break
		}

		matched := make([]bool, val2Len)
		allMatch := true

		// Order-agnostic comparison
		for i := 0; i < val1Len; i++ {
			elem1 := val1.Index(i).Interface()
			found := false
			for j := 0; j < val2Len; j++ {
				if matched[j] {
					continue
				}
				elem2 := val2.Index(j).Interface()
				if compareStructsAsym(elem1, elem2) == nil {
					matched[j] = true
					found = true
					break
				}
			}
			if !found {
				allMatch = false
				break
			}
		}

		if !allMatch {
			diff = v1
		}

	default:
		if !reflect.DeepEqual(v1, v2) {
			diff = v1
		}
	}

	return diff
}
