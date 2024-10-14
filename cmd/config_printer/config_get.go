package config_printer

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/pelicanplatform/pelican/docs"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/cobra"
)

type Match struct {
	OriginalKey      string
	HighlightedKey   string
	HighlightedValue string
}

func configGet(cmd *cobra.Command, args []string) {
	rawConfig, err := param.UnmarshalConfig()
	if err != nil {
		fmt.Println("Error unmarshalling config:", err)
		return
	}

	configValues := make(map[string]string)
	extractConfigValues(rawConfig, "", configValues)

	var matches []Match

	for key, valueStr := range configValues {
		highlightedKey := key
		highlightedValue := valueStr
		matchesFound := false

		docParam, exists := docs.ParsedParameters[strings.ToLower(key)]

		if exists {
			if docParam.Hidden && !includeHidden {
				continue
			}

			if docParam.Deprecated && !includeDeprecated {
				continue
			}

			if len(components) > 0 {
				componentsCheckFailed := true
				for _, c := range components {
					_, tagExists := docParam.Tags[strings.ToLower(c)]
					if tagExists {
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

		if matchesFound {
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

// extractConfigValues recursively extracts key-value pairs from a nested struct and returns a flattened map
func extractConfigValues(config interface{}, parentKey string, result map[string]string) {
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
			extractConfigValues(fieldValue.Interface(), key, result)
		case reflect.Ptr:
			if !fieldValue.IsNil() {
				extractConfigValues(fieldValue.Interface(), key, result)
			}
		case reflect.Slice, reflect.Array:
			// Convert slice elements to strings
			sliceValues := make([]string, fieldValue.Len())
			for j := 0; j < fieldValue.Len(); j++ {
				element := fieldValue.Index(j).Interface()
				sliceValues[j] = fmt.Sprintf("%v", element)
			}
			result[key] = "[" + strings.Join(sliceValues, ", ") + "]"
		case reflect.String:
			result[key] = fmt.Sprintf("\"%s\"", fieldValue.Interface())
		default:
			result[key] = fmt.Sprintf("%v", fieldValue.Interface())
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
