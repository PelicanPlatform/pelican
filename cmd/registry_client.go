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

// The registry_client contains commands in Pelican CLI to register a namespace.
//
// You can access it through `./pelican namespace <command>`.
//
// Note that you need to have your registry server running either locally,
// or by setting Federation.RegistryUrl to the Url of your remote Pelican registry server
//
// Example: `./pelican namespace register --prefix /test`

package main

import (
	"context"
	"net/url"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/registry"
)

// Variables to which command line arguments will
// be bound, for using internally
var withIdentity bool
var prefix string
var pubkeyPath string

func getNamespaceEndpoint(ctx context.Context) (string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", err
	}
	namespaceEndpoint := fedInfo.NamespaceRegistrationEndpoint
	if namespaceEndpoint == "" {
		return "", errors.New("No namespace registry specified; either give the federation name (-f) or specify the namespace API endpoint directly (e.g., --namespace-url=https://namespace.osg-htc.org/namespaces)")
	}

	namespaceEndpointURL, err := url.Parse(namespaceEndpoint)
	if err != nil {
		return "", errors.Wrap(err, "Unable to parse namespace registry url")
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

	namespaceEndpoint, err := getNamespaceEndpoint(cmd.Context())
	if err != nil {
		log.Errorln("Failed to get RegistryUrl from config: ", err)
		os.Exit(1)
	}

	// Parse the namespace URL to make sure it's okay
	registrationEndpointURL, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		log.Errorf("Failed to construction registration endpoint URL: %v", err)
	}
	if prefix == "" {
		log.Error("Error: prefix is required")
		os.Exit(1)
	}

	publicKey, err := config.GetIssuerPublicJWKS()
	if err != nil {
		log.Error("Error: Failed to retrieve public key: ", err)
		os.Exit(1)
	}

	/*
	 * TODO: For now, we only allow namespace registration to occur with a single key, but
	 *       at some point we should expose an API for adding additional pubkeys to each
	 *       namespace. There is a similar TODO listed in registry.go, as the choices made
	 *       there mirror the choices made here.
	 * To enforce that we're only trying to register one key, we check the length here
	 */
	if publicKey.Len() > 1 {
		log.Errorf("Only one public key can be registered in this step, but %d were provided\n", publicKey.Len())
		os.Exit(1)
	}

	privateKeyRaw, err := config.LoadPrivateKey(param.IssuerKey.GetString(), false)
	if err != nil {
		log.Error("Failed to load private key", err)
		os.Exit(1)
	}
	privateKey, err := jwk.FromRaw(privateKeyRaw)
	if err != nil {
		log.Error("Failed to create JWK private key", err)
		os.Exit(1)
	}

	if withIdentity {
		err := registry.NamespaceRegisterWithIdentity(privateKey, registrationEndpointURL, prefix)
		if err != nil {
			log.Errorf("Failed to register prefix %s with identity: %v", prefix, err)
			os.Exit(1)
		}
	} else {
		err := registry.NamespaceRegister(privateKey, registrationEndpointURL, "", prefix)
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

	namespaceEndpoint, err := getNamespaceEndpoint(cmd.Context())
	if err != nil {
		log.Errorln("Failed to get RegistryUrl from config: ", err)
		os.Exit(1)
	}

	deletionEndpointURL, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry", prefix)
	if err != nil {
		log.Errorf("Failed to construction deletion endpoint URL: %v", err)
	}

	err = registry.NamespaceDelete(deletionEndpointURL, prefix)
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

	namespaceEndpoint, err := getNamespaceEndpoint(cmd.Context())
	if err != nil {
		log.Errorln("Failed to get RegistryUrl from config: ", err)
		os.Exit(1)
	}

	listEndpoint, err := url.JoinPath(namespaceEndpoint, "api", "v1.0", "registry")
	if err != nil {
		log.Errorf("Failed to construction list endpoint URL: %v", err)
	}

	err = registry.NamespaceList(listEndpoint)
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
// 			log.Errorln("Failed to get RegistryUrl from config:", err)
// 			os.Exit(1)
// 		}

// 		endpoint := url.JoinPath(namespaceEndpoint, prefix, "issuer.jwks")
// 		err = registry.NamespaceGet(endpoint)
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

	namespaceCmd.PersistentFlags().String("namespace-url", "", "Endpoint for the namespace registry")
	// Don't override Federation.RegistryUrl if the flag value is empty
	if namespaceCmd.PersistentFlags().Lookup("namespace-url").Value.String() != "" {
		if err := viper.BindPFlag("Federation.RegistryUrl", namespaceCmd.PersistentFlags().Lookup("namespace-url")); err != nil {
			panic(err)
		}
	}

	namespaceCmd.PersistentFlags().StringVar(&pubkeyPath, "pubkey", "", "Path to the public key")
	namespaceCmd.PersistentFlags().String("privkey", "", "Path to the private key")
	// Don't override IssuerKey if the flag value is empty
	if namespaceCmd.PersistentFlags().Lookup("privkey").Value.String() != "" {
		if err := viper.BindPFlag("IssuerKey", namespaceCmd.PersistentFlags().Lookup("privkey")); err != nil {
			panic(err)
		}
	}

	namespaceCmd.AddCommand(registerCmd)
	namespaceCmd.AddCommand(deleteCmd)
	namespaceCmd.AddCommand(listCmd)
	// Commenting until we use -- JH
	//namespaceCmd.AddCommand(getCmd)
}
