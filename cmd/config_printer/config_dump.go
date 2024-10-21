package config_printer

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func configDump(cmd *cobra.Command, args []string) {
	currentConfig := InitServerClientConfig(viper.GetViper())

	switch format {
	case "yaml":
		yamlData, err := yaml.Marshal(currentConfig)
		if err != nil {
			fmt.Printf("Error marshaling config to YAML: %v", err)
		}
		fmt.Println(string(yamlData))
	case "json":
		jsonData, err := json.MarshalIndent(currentConfig, "", "  ")
		if err != nil {
			fmt.Printf("Error marshaling config to JSON: %v", err)
		}
		fmt.Println(string(jsonData))
	default:
		fmt.Printf("Unsupported format: %s. Use 'yaml' or 'json'.", format)
	}
}
