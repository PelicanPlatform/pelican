package main

import (
	"errors"
	"os"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	log "github.com/sirupsen/logrus"
)

// These functions are just placeholders. You need to provide actual implementation.

var withIdentity bool
var prefix string
var namespaceURL string
var jwks bool
var pubkeyPath string
var privkeyPath string

func getNamespaceEndpoint() (string, error) {
	namespaceEndpoint := namespaceURL
	if namespaceEndpoint == "" {
		namespaceEndpoint = viper.GetString("NamespaceURL")
	}
	if namespaceEndpoint == "" {
		return "", errors.New("No namespace registry specified; either give the federation name (-f) or specify the namespace API endpoint directly (e.g., --namespace-url=https://namespace.osg-htc.org/namespaces)")
	}
	return namespaceEndpoint, nil
}

func registerANamespace(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	privkey := privkeyPath
	if privkey == "" {
		privkey = viper.GetString("IssuerKey")
	}
	if privkey == "" {
		log.Error("Private key file is not set; specify its location with the --privkey option or by setting the IssuerKey configuration variable")
		os.Exit(1)
	}

	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	endpoint := namespaceEndpoint + "/registry"
	if prefix == "" {
		log.Error("Error: prefix is required")
		os.Exit(1)
	}

	if withIdentity {
		err := namespace_register_with_identity(privkey, endpoint, prefix)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
	} else {
		err := namespace_register(privkey, endpoint, "", prefix)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
	}
}

func deleteANamespace(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	endpoint := namespaceEndpoint + "/" + prefix
	err = delete_namespace(endpoint)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func listAllNamespaces(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	endpoint := namespaceEndpoint
	err = list_namespaces(endpoint)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func getNamespace(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	if jwks {
		namespaceEndpoint, err := getNamespaceEndpoint()
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}

		endpoint := namespaceEndpoint + "/" + prefix + "/issuer.jwks"
		err = get_namespace(endpoint)
		if err != nil {
			log.Error(err)
			os.Exit(1)
		}
	} else {
		log.Error("Error: get command requires --jwks flag")
		os.Exit(1)
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

	namespaceCmd.PersistentFlags().StringVar(&namespaceURL, "namespace-url", "", "Endpoint for the namespace registry")
	namespaceCmd.PersistentFlags().StringVar(&pubkeyPath, "pubkey", "", "Path to the public key")
	namespaceCmd.PersistentFlags().StringVar(&privkeyPath, "privkey", "", "Path to the private key")
	namespaceCmd.AddCommand(registerCmd)
	namespaceCmd.AddCommand(deleteCmd)
	namespaceCmd.AddCommand(listCmd)
	namespaceCmd.AddCommand(getCmd)
}
