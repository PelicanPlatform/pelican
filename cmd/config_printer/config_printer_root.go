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
	"strings"

	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/docs"
)

var (
	// ConfigCmd is the root command
	ConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "View and search for configuration parameters",
		Long:  "The 'config' command allows users to view, search, and see the documentation for various configuration parameters in the Pelican system.",
	}

	configDumpCmd = &cobra.Command{
		Use:   "dump [flags]",
		Short: "Dump all configuration parameters",
		Long:  "The 'dump' command outputs all current configuration parameters and their values to the console. This includes default values that have not been explicitly set.",
		Example: `# Dump all configuration parameters
pelican config dump`,
		Run: configDump,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if format != "yaml" && format != "json" {
				return fmt.Errorf("unsupported format: %s. Use 'yaml' or 'json'", format)
			}
			return nil
		},
	}

	configGetCmd = &cobra.Command{
		Use:   "get [arguments] [flags]",
		Short: "Retrieve config parameters that match any of the given arguments",
		Long: `The 'get' command retrieves and displays configuration parameters that contain any of the provided argument patterns in their name or value.
The search space can be narrowed or expanded using available flags. The matching is case-insensitive.
If no arguments are provided, all configuration parameters are retrieved.
The command outputs the results in a flattened format from the nested configuration, making it grep-friendly for easier searching.`,
		Example: `# Retrieve parameters that have either 'log' or 'monitor' in their name or value,
# and relate to either 'origin' or 'cache', including deprecated parameters in the search space
pelican config get log monitor -m origin -m cache --include-deprecated`,
		Run: configGet,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for _, comp := range components {
				found := false
				for _, recognized := range docs.RecognizedComponents {
					if strings.EqualFold(comp, recognized) {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("unsupported module: %s. Please use a recognized module: %v", comp, docs.RecognizedComponents)
				}
			}
			return nil
		},
	}

	configManCmd = &cobra.Command{
		Use:   "describe [parameter]",
		Short: "Print documentation for the specified config parameter",
		Long: `The 'describe' command prints detailed documentation for a specified configuration parameter,
including its type, default value, description, related components, and whether it is deprecated or hidden.`,
		Aliases: []string{"desc", "man", "doc"},
		Example: `# View documentation for the Server.WebPort parameter
pelican config describe server.webPort`,
		Run: configMan,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("please provide exactly one configuration parameter name")
			}
			return nil
		},
	}

	configSummaryCmd = &cobra.Command{
		Use:     "summary",
		Short:   "Print config parameters that differ from default values",
		Long:    "The 'summary' command outputs configuration parameters whose values differ from their default settings.",
		Aliases: []string{"sum"},
		Example: `# Show configuration parameters that are set differently from their default values
pelican config summary`,
		Run: configSummary,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if format != "yaml" && format != "json" {
				return fmt.Errorf("unsupported format: %s. Use 'yaml' or 'json'", format)
			}
			return nil
		},
	}

	format            string
	components        []string
	includeHidden     bool
	includeDeprecated bool
)

func init() {
	ConfigCmd.AddCommand(configDumpCmd)
	ConfigCmd.AddCommand(configGetCmd)
	ConfigCmd.AddCommand(configManCmd)
	ConfigCmd.AddCommand(configSummaryCmd)

	configDumpCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")

	configGetCmd.Flags().StringArrayVarP(&components, "module", "m", []string{},
		"Specify modules to filter the output of `config get`. The recognized modules are `client`, `registry`, `director`, `origin`, `cache`, and `localcache`. Multiple modules can be specified at the same time, for example: `config get -m cache -m origin`. If multiple modules are provided, parameters related to any of the modules will be retrieved. If no modules are specified, no module-based filter is applied to the search space.")
	configGetCmd.Flags().BoolVar(&includeHidden, "include-hidden", false, "Include hidden configuration parameters")
	configGetCmd.Flags().BoolVar(&includeDeprecated, "include-deprecated", false, "Include deprecated configuration parameters")

	configSummaryCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")

}
