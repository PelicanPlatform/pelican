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
	"reflect"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func configSummary(cmd *cobra.Command, args []string) {
	defaultConfig := viper.New()
	config.SetBaseDefaultsInConfig(defaultConfig)
	config.InitConfigDir(defaultConfig)

	defaultConfigMap := initClientAndServerConfig(defaultConfig)

	currentConfigMap := initClientAndServerConfig(viper.GetViper())

	diff := compareStructsAsym(currentConfigMap, defaultConfigMap)

	printConfig(diff, format)
}

func compareStructsAsym(v1, v2 interface{}) interface{} {
	val1 := reflect.ValueOf(v1)
	val2 := reflect.ValueOf(v2)

	if val1.Kind() == reflect.Ptr {
		val1 = val1.Elem()
	}
	if val2.Kind() == reflect.Ptr {
		val2 = val2.Elem()
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
			if val2.IsValid() {
				fieldVal2 = val2.FieldByName(fieldName).Interface()
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
		if !reflect.DeepEqual(v1, v2) {
			if !((val1.IsNil() && val2.Len() == 0) || (val2.IsNil() && val1.Len() == 0)) {
				diff = v1
			}
		}

	default:
		if !reflect.DeepEqual(v1, v2) {
			diff = v1

		}
	}

	return diff
}
