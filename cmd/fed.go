/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

		 NOTE: This currently doesn't guarantee support for the web UIs`,
		RunE: fedServeStart,
	}
)

func init() {
	serveCmd.Flags().StringSlice("modules", []string{}, "Modules to be started.")
	serveCmd.Flags().Uint16("reg-port", 8446, "Port for the namespace registry")
	serveCmd.Flags().Uint16("director-port", 8445, "Port for the director")
	serveCmd.Flags().Uint16("origin-port", 8443, "Port for the origin")
	serveCmd.Flags().Uint16("cache-port", 8442, "Port for the cache")
}
