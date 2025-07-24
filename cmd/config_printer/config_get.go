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
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/docs"
)

type Match struct {
	OriginalKey      string
	HighlightedKey   string
	HighlightedValue string
}

func configGet(cmd *cobra.Command, args []string) {
	currentConfig := initClientAndServerConfig(viper.GetViper())

	configValues := make(map[string]string)
	flattenConfig(currentConfig, "", configValues)

	var matches []Match

	containsComponent := func(components []string, c string) bool {
		for _, component := range components {
			//case-insensitive comparison
			if strings.EqualFold(component, c) {
				return true
			}
		}
		return false
	}

	for key, valueStr := range configValues {
		highlightedKey := key
		highlightedValue := valueStr
		matchesFound := false

		docParam, exists := docs.ParsedParameters[strings.ToLower(key)]

		if exists {
			if docParam.Hidden && !includeHidden {
				continue
			}

			if len(components) > 0 {
				componentsCheckFailed := true
				for _, c := range components {

					if containsComponent(docParam.Components, c) {
						componentsCheckFailed = false
						break
					}
				}
				if componentsCheckFailed {
					continue
				}
			}
		}

		if len(args) == 0 {
			matchesFound = true
		} else {
			for _, arg := range args {
				argLower := strings.ToLower(arg)

				if exactMatch {
					// Exact match comparison
					if strings.EqualFold(key, arg) {
						highlightedKey = highlightSubstring(key, arg, color.FgYellow)
						matchesFound = true
					}

					if strings.EqualFold(valueStr, arg) {
						highlightedValue = highlightSubstring(valueStr, arg, color.FgYellow)
						matchesFound = true
					}
				} else {
					// Substring match (existing behavior)
					if strings.Contains(strings.ToLower(key), argLower) {
						highlightedKey = highlightSubstring(key, arg, color.FgYellow)
						matchesFound = true
					}

					if strings.Contains(strings.ToLower(valueStr), argLower) {
						highlightedValue = highlightSubstring(valueStr, arg, color.FgYellow)
						matchesFound = true
					}
				}
			}
		}

		if matchesFound {
			// Check for deprecated parameter only when it matches the search criteria
			if exists && docParam.Deprecated && !includeDeprecated {
				fmt.Printf("%s: This parameter is DEPRECATED. If you still need to view it, run: pelican config get %s --include-deprecated\n", key, key)
				continue
			}

			matches = append(matches, Match{
				OriginalKey:      key,
				HighlightedKey:   highlightedKey,
				HighlightedValue: highlightedValue,
			})
		}

	}

	if len(matches) == 0 && len(args) > 0 {
		fmt.Println("No matching configuration parameters found.")
		return
	}

	sort.Slice(matches, func(i, j int) bool {
		return strings.ToLower(matches[i].OriginalKey) < strings.ToLower(matches[j].OriginalKey)
	})

	for _, match := range matches {
		fmt.Printf("%s: %s\n", match.HighlightedKey, match.HighlightedValue)
	}
}

// flattenConfig recursively flattens the config structure into a map[string]string.
func flattenConfig(config interface{}, parentKey string, result map[string]string) {
	v := reflect.ValueOf(config)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		key := strings.ToLower(field.Name)

		if parentKey != "" {
			key = parentKey + "." + key
		}

		// Handle different kinds of fields
		switch fieldValue.Kind() {
		case reflect.Struct:
			flattenConfig(fieldValue.Interface(), key, result)
		case reflect.Ptr:
			if !fieldValue.IsNil() {
				flattenConfig(fieldValue.Interface(), key, result)
			}
		default:
			result[key] = formatValue(fieldValue.Interface())
		}
	}
}

// highlightSubstring highlights all occurrences of the substring in the string
func highlightSubstring(s, substr string, colorAttr color.Attribute) string {
	sLower := strings.ToLower(s)
	substrLower := strings.ToLower(substr)
	substrLen := len(substr)

	var result strings.Builder
	start := 0

	for {
		idx := strings.Index(sLower[start:], substrLower)
		if idx == -1 {
			result.WriteString(s[start:])
			break
		}

		idx += start
		result.WriteString(s[start:idx])
		matchedText := s[idx : idx+substrLen]
		highlighted := color.New(colorAttr).Sprint(matchedText)
		result.WriteString(highlighted)
		start = idx + substrLen
	}

	return result.String()
}
