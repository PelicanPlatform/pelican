package main

import (
	"fmt"
	"os"
	config "github.com/htcondor/osdf-client/v6/config"
	"gopkg.in/yaml.v3"
)

func main() {

		// Dump prior config
	if len(os.Args) == 1 {
		config, err := config.GetConfigContents()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
			os.Exit(1)
		}
		config_b, err := yaml.Marshal(&config)
		if err != nil {
			fmt.Println(os.Stderr, "Failed to convert object to YAML:", err)
			os.Exit(1)
		}
		fmt.Println(string(config_b))
		os.Exit(0)
	}

	// Save the data we got from the input file
	input_config_b, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to to open file:", err)
		os.Exit(1)
	}

	input_config := config.OSDFConfig{}
	err = yaml.Unmarshal(input_config_b, &input_config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse config file:", err)
		os.Exit(1)
	}

	err = config.SaveConfigContents(&input_config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Unable to decrypt contents:", err)
		os.Exit(1)
	}
}
