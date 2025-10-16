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
	"github.com/spf13/viper"
)

func configDump(cmd *cobra.Command, args []string) {
	currentConfig := initClientAndServerConfig(viper.GetViper())

	// Use JSON format if either global --json flag is set or subcommand flag --format=json is specified
	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		format = "json"
	}

	printConfig(currentConfig, format)
}
