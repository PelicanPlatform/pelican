/*
Copyright © 2023 Justin Hiemstra <jhiemstra@morgridge.org>
*/
package main

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	namespaceRegistryCmd = &cobra.Command{
		Use:   "registry",
		Short: "Interact with a Pelican namespace registry service",
		Long:  `Interact with a Pelican namespace registry service:
		
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
		Short:        "serve the namespace registry",
		RunE:         serveNamespaceRegistry,
		SilenceUsage: true,
	}
)

func init() {
	// Tie the registryServe command to the root CLI command
	namespaceRegistryCmd.AddCommand(registryServeCmd)

	// Set up flags for the command
	registryServeCmd.Flags().StringP("port", "p", "", "Set the port at which the namespace registry should be accessible.")
	err := viper.BindPFlag("WebPort", registryServeCmd.Flags().Lookup("port"))
	if err != nil {
		panic(err)
	}
}
