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
)

var (
	registryCmd = &cobra.Command{
		Use: "registry",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := initRegistry()
			return err
		},
		Short: "Interact with a Pelican registry service",
		Long: `Interact with a Pelican registry service:

		The namespace registry lies at the core of Pelican's security model
		by serving as the central point for clients to fetch the public keys
		associated with namespaced resources. When origins wish to claim a
		namespace prefix in their federation, they securely  associate the
		public key of their issuer with the namespace registry (many origins
		may act as their own issuer). Sometimes origins will provide
		additional OIDC metadata if the origins wish to be accessible to the
		OSDF's caching infrastructure. Services wishing to validate the
		authenticity of a token from an issuer can then reference the
		namespace registry's listed public key for that origin and verify
		that it was signed by the correct private key.
		`,
	}

	registryServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "serve the registry",
		RunE:         serveRegistry,
		SilenceUsage: true,
	}
)

func initRegistry() error {
	err := config.InitServer([]config.ServerType{config.RegistryType})
	cobra.CheckErr(err)

	return err
}

func init() {
	// Tie the registryServe command to the root CLI command
	registryCmd.AddCommand(registryServeCmd)
	// Set up flags for the command
	registryServeCmd.Flags().AddFlag(portFlag)
}
