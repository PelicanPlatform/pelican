package config_printer

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func initClientAndServerConfig(v *viper.Viper) *param.Config {
	config.SetServerDefaults(v)
	config.SetClientDefaults(v)

	exapandedConfig, err := param.UnmarshalConfig(v)
	if err != nil {
		fmt.Println("Error:", err)
	}
	return exapandedConfig
}

func printConfig(configData interface{}, format string) {
	switch format {
	case "yaml":
		yamlData, err := yaml.Marshal(configData)
		if err != nil {
			fmt.Printf("Error marshaling config to YAML: %v", err)
		}
		fmt.Println(string(yamlData))
	case "json":
		jsonData, err := json.MarshalIndent(configData, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config to JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	default:
		fmt.Printf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}
}

func formatValue(value interface{}) string {
	if value == nil {
		return "none"
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		// Handle map[string]struct{} as a set
		if rv.Type().Key().Kind() == reflect.String && rv.Type().Elem().Kind() == reflect.Struct {
			var keys []string
			for _, key := range rv.MapKeys() {
				keys = append(keys, key.String())
			}
			return "[" + strings.Join(keys, ", ") + "]"
		}
		// Generic map handling (if needed)
		return fmt.Sprintf("%v", value)
	case reflect.Slice, reflect.Array:
		var elements []string
		for i := 0; i < rv.Len(); i++ {
			elem := rv.Index(i).Interface()
			elements = append(elements, fmt.Sprintf("%v", elem))
		}
		return "[" + strings.Join(elements, ", ") + "]"
	case reflect.String:
		// Surround string with double quotes
		return fmt.Sprintf("\"%s\"", value)
	default:
		return fmt.Sprintf("%v", value)
	}
}
