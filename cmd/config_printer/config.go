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
	"github.com/spf13/cobra"

	_ "embed"
)

var (
	ConfigCmd = &cobra.Command{
		Use:   "config",
		Short: "View and search for configuration parameters",
	}

	configDumpCmd = &cobra.Command{
		Use:   "dump",
		Short: "Dump all configuration parameters",
		Run:   configDump,
	}

	configGetCmd = &cobra.Command{
		Use:   "get",
		Short: "Retrieve config parameters that match any of the given arguments",
		Run:   configGet,
	}

	configManCmd = &cobra.Command{
		Use:     "man",
		Short:   "Print documentation for the config parameter specified in the argument",
		Aliases: []string{"desc", "describe", "doc"},
		Run:     configMan,
	}

	configSummaryCmd = &cobra.Command{
		Use:     "summary",
		Short:   "Print config parameters that differ from the default values",
		Aliases: []string{"sum"},
		Run:     configSummary,
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

	configGetCmd.Flags().StringArrayVarP(&components, "component", "c", []string{}, "Specify components to filter the output of config get, if multiple components are provided, parameters related to any of the components will be retrieved")
	configGetCmd.Flags().BoolVar(&includeHidden, "include-hidden", false, "Include hidden configuration parameters")
	configGetCmd.Flags().BoolVar(&includeDeprecated, "include-deprecated", false, "Include deprecated configuration parameters")

	configSummaryCmd.Flags().StringVarP(&format, "format", "o", "yaml", "Output format (yaml or json)")

}
