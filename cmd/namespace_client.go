package main

import (
	"net/url"
	"os"

	"github.com/pelicanplatform/pelican/namespace-registry"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	log "github.com/sirupsen/logrus"
)

// Variables to which command line arguments will
// be bound, for using internally
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

	namespaceEndpointURL, err := url.Parse(namespaceEndpoint)
	if err != nil {
		return "", errors.Wrap(err, "Unable to parse namespace url")
	}

	// Return the string, as opposed to a pointer to the URL object
	return namespaceEndpointURL.String(), nil
}

func registerANamespace(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Errorln("Failed to initialize the client: ", err)
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
		log.Errorln("Failed to get NamespaceURL from config: ", err)
		os.Exit(1)
	}

	// Parse the namespace URL to make sure it's okay
	registrationEndpointURL, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		log.Errorf("Failed to construction registration endpoint URL: %v", err)
	}
	// registrationEndpoint := url.JoinPath(namespaceEndpoint, "/api/v1.0/registry/register").String()
	if prefix == "" {
		log.Error("Error: prefix is required")
		os.Exit(1)
	}

	if withIdentity {
		err := nsregistry.NamespaceRegisterWithIdentity(privkey, registrationEndpointURL, prefix)
		if err != nil {
			log.Errorf("Failed to register prefix %s with identity: %v", prefix, err)
			os.Exit(1)
		}
	} else {
		err := nsregistry.NamespaceRegister(privkey, registrationEndpointURL, "", prefix)
		if err != nil {
			log.Errorf("Failed to register prefix %s: %v", prefix, err)
			os.Exit(1)
		}
	}
}

func deleteANamespace(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Errorln("Failed to initialize the client: ", err)
		os.Exit(1)
	}

	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Errorln("Failed to get NamespaceURL from config: ", err)
		os.Exit(1)
	}

	deletionEndpointURL, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry", prefix)
	if err != nil {
		log.Errorf("Failed to construction deletion endpoint URL: %v", err)
	}

	err = nsregistry.NamespaceDelete(deletionEndpointURL)
	if err != nil {
		log.Errorf("Failed to delete prefix %s: %v", prefix, err)
		os.Exit(1)
	}
}

func listAllNamespaces(cmd *cobra.Command, args []string) {
	err := config.InitClient()
	if err != nil {
		log.Errorln("Failed to initialize the client: ", err)
		os.Exit(1)
	}

	namespaceEndpoint, err := getNamespaceEndpoint()
	if err != nil {
		log.Errorln("Failed to get NamespaceURL from config: ", err)
		os.Exit(1)
	}

	listEndpoint, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		log.Errorf("Failed to construction list endpoint URL: %v", err)
	}

	err = nsregistry.NamespaceList(listEndpoint)
	if err != nil {
		log.Errorf("Failed to list namespace information: %v", err)
		os.Exit(1)
	}
}

// Commenting until we're ready to use -- JH

// func getNamespace(cmd *cobra.Command, args []string) {
// 	err := config.InitClient()
// 	if err != nil {
// 		log.Errorln("Failed to initialize the client:", err)
// 		os.Exit(1)
// 	}

// 	if jwks {
// 		namespaceEndpoint, err := getNamespaceEndpoint()
// 		if err != nil {
// 			log.Errorln("Failed to get NamespaceURL from config:", err)
// 			os.Exit(1)
// 		}

// 		endpoint := url.JoinPath(namespaceEndpoint, prefix, "issuer.jwks")
// 		err = nsregistry.NamespaceGet(endpoint)
// 		if err != nil {
// 			log.Errorf("Failed to get jwks info for prefix %s: %v", prefix, err)
// 			os.Exit(1)
// 		}
// 	} else {
// 		log.Error("Error: get command requires --jwks flag")
// 		os.Exit(1)
// 	}
// }

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

// Commenting until we use -- JH
// var getCmd = &cobra.Command{
// 	Use:   "get",
// 	Short: "Get a specific namespace",
// 	Run:   getNamespace,
// }

func init() {
	registerCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for registering namespace")
	registerCmd.Flags().BoolVar(&withIdentity, "with-identity", false, "Register a namespace with an identity")
	//getCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for get namespace")
	//getCmd.Flags().BoolVar(&jwks, "jwks", false, "Get the jwks of the namespace")
	deleteCmd.Flags().StringVar(&prefix, "prefix", "", "prefix for delete namespace")

	namespaceCmd.PersistentFlags().StringVar(&namespaceURL, "namespace-url", "", "Endpoint for the namespace registry")
	namespaceCmd.PersistentFlags().StringVar(&pubkeyPath, "pubkey", "", "Path to the public key")
	namespaceCmd.PersistentFlags().StringVar(&privkeyPath, "privkey", "", "Path to the private key")
	namespaceCmd.AddCommand(registerCmd)
	namespaceCmd.AddCommand(deleteCmd)
	namespaceCmd.AddCommand(listCmd)
	// Commenting until we use -- JH
	//namespaceCmd.AddCommand(getCmd)
}
