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

package config

import (
	"os"
	"reflect"
	"strings"

	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/param"
)

// findFieldByTag searches for a field in a struct by the value of a tag. This is used to
// check our Config struct against viper keys so we can warn the users if they feed the Pelican things
// it doesn't know how to eat.
func findFieldByTag(t reflect.Type, tagKey, tagValue string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get(tagKey)
		if tag == tagValue {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

// validateConfigKeys checks keys in the Viper config against fields in the Config struct
func validateConfigKeys() []string {
	possibleCfg := param.Config{}
	unknownKeys := []string{}
	// Get all currently-configured keys from Viper. This is a collection of default
	// configurations (both set internally and in defaults.yaml) and user-provided config.
	keys := viper.AllKeys()

	// Unfortunately viper.AllKeys() won't grab things that would otherwise be discovered as
	// env vars because of where we call the top-level function.
	envs := os.Environ()
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		// Until we fully deprecate OSDF and STASH prefixes, we'll check for them here
		if strings.HasPrefix(parts[0], "PELICAN_") || strings.HasPrefix(parts[0], "OSDF_") || strings.HasPrefix(parts[0], "STASH_") {
			// Strip off the prefix, convert to lower and replace _ with .
			key := strings.SplitN(parts[0], "_", 2)[1]
			key = strings.ToLower(key)
			key = strings.ReplaceAll(key, "_", ".")
			keys = append(keys, key)
		}
	}

	// Convert the config struct to a map
	configValue := reflect.ValueOf(possibleCfg)
	if configValue.Kind() == reflect.Ptr {
		configValue = configValue.Elem()
	}
	configType := configValue.Type()

	// Iterate over all keys
	for _, key := range keys {
		parts := strings.Split(key, ".")
		// Start with the top-level struct
		currentType := configType

		for idx, part := range parts {
			// Check if the part exists in the current struct
			if idx == 0 && part == "config" { // A special case for the top-level config struct
				continue
			}
			field, present := findFieldByTag(currentType, "mapstructure", part)
			if !present {
				unknownKeys = append(unknownKeys, key)
				break
			}

			// If the field is a struct, descend into it
			if field.Type.Kind() == reflect.Struct {
				currentType = field.Type
			} else {
				break
			}
		}
	}

	return unknownKeys
}
