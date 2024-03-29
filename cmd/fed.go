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

package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	serveCmd = &cobra.Command{
		Use:    "serve",
		Hidden: true,
		Short:  "Starts pelican with a list of enabled modules",
		Long: `Starts pelican with a list of enabled modules [registry, director, cache, origin] to enable better
		 end-to-end and integration testing.

		 If the director or namespace registry are enabled, then ensure there is a corresponding url in the
		 pelican.yaml file.

		 This feature doesn't currently support the web UIs`,
		RunE: fedServeStart,
	}
)

func init() {
	serveCmd.Flags().StringSlice("module", []string{}, "Modules to be started.")
	if err := viper.BindPFlag("Server.Modules", serveCmd.Flags().Lookup("module")); err != nil {
		panic(err)
	}
	serveCmd.Flags().Uint16("origin-port", 8443, "Port for the origin")
	if err := viper.BindPFlag("Origin.Port", serveCmd.Flags().Lookup("origin-port")); err != nil {
		panic(err)
	}
	serveCmd.Flags().Uint16("cache-port", 8442, "Port for the cache")
	if err := viper.BindPFlag("Cache.Port", serveCmd.Flags().Lookup("cache-port")); err != nil {
		panic(err)
	}
	serveCmd.Flags().Uint16("port", 8444, "Port for Pelican server and web UI")
	if err := viper.BindPFlag("Server.WebPort", serveCmd.Flags().Lookup("port")); err != nil {
		panic(err)
	}
}
