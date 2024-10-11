package config_printer

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/param"
)

func configDump(cmd *cobra.Command, args []string) {
	rawConfig, _ := param.UnmarshalConfig()

	switch format {
	case "yaml":
		yamlData, err := yaml.Marshal(rawConfig)
		if err != nil {
			fmt.Printf("Error marshaling config to YAML: %v", err)
		}
		fmt.Println(string(yamlData))
	case "json":
		jsonData, err := json.MarshalIndent(rawConfig, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config to JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	default:
		fmt.Printf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}
}
