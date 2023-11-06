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
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	directorCmd = &cobra.Command{
		Use: "director",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := config.InitServer()
			return err
		},
		Short: "Launch a Pelican Director",
		Long: `Launch a Pelican Director service:

		The Pelican Director is the primary mechanism by which clients/caches
		can discover the source of a requested resource. It has two endpoints
		at /api/v1.0/director/origin/ and /api/v1.0/director/object/, where the
		former redirects to the closest origin supporting the object and the
		latter redirects to the closest cache. As a shortcut, requests to the
		director at /foo/bar will be treated as a request for the object from
		cache.`,
	}

	directorServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "serve the director service",
		RunE:         serveDirector,
		SilenceUsage: true,
	}
)

func init() {
	// Tie the directorServe command to the root CLI command
	directorCmd.AddCommand(directorServeCmd)

	// Set up flags for the command
	directorServeCmd.Flags().AddFlag(portFlag)

	directorServeCmd.Flags().StringP("default-response", "", "", "Set whether the default endpoint should redirect clients to caches or origins")
	err := viper.BindPFlag("Director.DefaultResponse", directorServeCmd.Flags().Lookup("default-response"))
	if err != nil {
		panic(err)
	}

	directorServeCmd.Flags().BoolP("enable-hostname-redirects", "", false, "Enabling host-aware redirects allows the director to bypass its default response for hosts specified via the Pelican configuration file")
	err = viper.BindPFlag("Director.HostAwareRedirects", directorServeCmd.Flags().Lookup("enable-hostname-redirects"))
	if err != nil {
		panic(err)
	}
}
