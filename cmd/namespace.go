package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These functions are just placeholders. You need to provide actual implementation.

var withIdentity bool
var prefix string
var host string
var jwks bool
var pubkeyPath string
var privkeyPath string

func registerANamespace(cmd *cobra.Command, args []string) {
	endpoint := host + "/registry"
	if prefix == "" {
		fmt.Println("Error: prefix is required")
		return
	}

	if withIdentity {
		namespace_register_with_identity(pubkeyPath, privkeyPath, endpoint, prefix)
	} else {
		namespace_register(pubkeyPath, privkeyPath, endpoint, "", prefix)
	}
}

func deleteANamespace(cmd *cobra.Command, args []string) {
	endpoint := host + "/" + prefix
	delete_namespace(endpoint)
}

func listAllNamespaces(cmd *cobra.Command, args []string) {
	endpoint := host
	list_namespaces(endpoint)
}

func getNamespace(cmd *cobra.Command, args []string) {
	if jwks {
		endpoint := host + "/" + prefix + "/issuer.jwks"
		get_namespace(endpoint)
	} else {
		fmt.Println("Get command is not yet implemented.")
	}
}

var namespaceCmd = &cobra.Command{
	Use:   "namespace",
	Short: "Work with namespaces",
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new namespace",
	Run:   registerANamespace,
}

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a namespace",
	Run:   deleteANamespace,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all namespaces",
	Run:   listAllNamespaces,
}

var getCmd = &cobra.Command{
	Use:   "get",
	Short: "Get a specific namespace",
	Run:   getNamespace,
}

func init() {
	registerCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for registering namespace")
	registerCmd.Flags().BoolVar(&withIdentity, "with-identity", false, "Register a namespace with an identity")
	getCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for get namespace")
	getCmd.Flags().BoolVar(&jwks, "jwks", false, "Get the jwks of the namespace")
	deleteCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for delete namespace")

	namespaceCmd.PersistentFlags().StringVar(&host, "host", "http://localhost:8443/cli-namespaces", "Host of the namespace registry")
	namespaceCmd.PersistentFlags().StringVar(&pubkeyPath, "pubkey", "/usr/src/app/pelican/cmd/cert/.well-known/client.jwks", "Path to the public key")
	namespaceCmd.PersistentFlags().StringVar(&privkeyPath, "privkey", "/usr/src/app/pelican/cmd/cert/client.key", "Path to the private key")
	namespaceCmd.AddCommand(registerCmd)
	namespaceCmd.AddCommand(deleteCmd)
	namespaceCmd.AddCommand(listCmd)
	namespaceCmd.AddCommand(getCmd)
}
