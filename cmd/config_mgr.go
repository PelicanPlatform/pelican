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
	"fmt"
	"net/url"
	"os"
	"path"

	"github.com/spf13/cobra"

	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
)

var (
	// Add the config and prefix commands
	rootConfigCmd = &cobra.Command{
		Use:   "credentials",
		Short: "Interact with the credential configuration file",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return config.InitClient()
		},
	}
)

func printConfig() {
	config, err := config.GetCredentialConfigContents()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get credential configuration contents:", err)
		os.Exit(1)
	}
	config_b, err := yaml.Marshal(&config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to convert object to YAML:", err)
		os.Exit(1)
	}
	fmt.Println(string(config_b))
}

func addConfigSubcommands(configCmd *cobra.Command) {

	configCmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the credential configuration file",
		Long:  "Print the credential configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			printConfig()
		},
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "replace <file>",
		Short: "Replace the credential configuration file",
		Long:  "Replace the credential configuration file",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config_b, err := os.ReadFile(args[0])
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to read config file:", err)
				os.Exit(1)
			}

			input_config := config.OSDFConfig{}
			err = yaml.Unmarshal(input_config_b, &input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to parse config file:", err)
				os.Exit(1)
			}

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

	configCmd.AddCommand(&cobra.Command{
		Use:   "reset-password",
		Short: "Reset the password for the current user",
		Long:  "Reset the password for the current user",
		Run: func(cmd *cobra.Command, args []string) {
			err := config.ResetPassword()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get reset password:", err)
				os.Exit(1)
			}
		},
	})

}

func printOauthConfig() {
	config, err := config.GetCredentialConfigContents()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
		os.Exit(1)
	}
	clientList := &config.OSDF.OauthClient
	config_b, err := yaml.Marshal(&clientList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to convert object to YAML:", err)
		os.Exit(1)
	}
	fmt.Println(string(config_b))

}

func addTokenSubcommands(tokenCmd *cobra.Command) {

	tokenCmd.AddCommand(&cobra.Command{
		Use:   "get <read|write> <prefix>",
		Short: "Get a new token for a given prefix",
		Long:  "Get a new token for a given prefix",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {

			isWrite := false
			switch args[0] {
			case "read":
			case "write":
				isWrite = true
			default:
				fmt.Fprintln(os.Stderr, "Unknown value for operation type (must be 'read' or 'write')", args[0])
				os.Exit(1)
			}
			dest := url.URL{Path: path.Clean("/" + args[1])}

			namespace, err := namespaces.MatchNamespace(cmd.Context(), args[1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get namespace for path:", err)
				os.Exit(1)
			}

			opts := config.TokenGenerationOpts{Operation: config.TokenRead}
			if isWrite {
				opts.Operation = config.TokenWrite
			}
			token, err := client.AcquireToken(&dest, namespace, opts)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get a token:", err)
				os.Exit(1)
			}

			fmt.Println(token)
		},
	})
}

func addPrefixSubcommands(prefixCmd *cobra.Command) {

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "print",
		Short: "Print the oauth client configuration file",
		Long:  "Print the oauth client configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			printOauthConfig()
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "add <prefix>",
		Short: "Add a new oauth client",
		Long:  "Add a new oauth client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetCredentialConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			hasPrefix := false
			for _, entry := range input_config.OSDF.OauthClient {
				if entry.Prefix == args[0] {
					hasPrefix = true
					break
				}
			}
			if !hasPrefix {
				newPrefix := config.PrefixEntry{Prefix: args[0]}
				input_config.OSDF.OauthClient = append(input_config.OSDF.OauthClient, newPrefix)
			} else {
				fmt.Fprintln(os.Stderr, "Prefix to add already exists")
				return
			}

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "set <prefix> <client_id|client_secret> <value>",
		Short: "Set the oauth client attributes",
		Long:  "Set the oauth client attributes (client_id or client_secret)",
		Args:  cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetCredentialConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			var existingPrefix *config.PrefixEntry
			existingPrefix = nil
			for idx := range input_config.OSDF.OauthClient {
				if input_config.OSDF.OauthClient[idx].Prefix == args[0] {
					existingPrefix = &input_config.OSDF.OauthClient[idx]
					break
				}
			}
			if existingPrefix == nil {
				fmt.Fprintln(os.Stderr, "Prefix to set was not present")
				os.Exit(1)
			}

			if args[1] == "client_id" {
				existingPrefix.ClientID = args[2]
			} else if args[1] == "client_secret" {
				existingPrefix.ClientSecret = args[2]
			} else {
				fmt.Fprintln(os.Stderr, "Unknown attribute to set:", args[1])
				os.Exit(1)
			}

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

	prefixCmd.AddCommand(&cobra.Command{
		Use:   "delete <prefix>",
		Short: "Delete the oauth client",
		Long:  "Delete the oauth client",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			input_config, err := config.GetCredentialConfigContents()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to get configuration contents:", err)
				os.Exit(1)
			}

			prefix_list := input_config.OSDF.OauthClient
			new_prefix_list := make([]config.PrefixEntry, 0, len(prefix_list)-1)
			for _, entry := range prefix_list {
				if entry.Prefix != args[0] {
					new_prefix_list = append(new_prefix_list, entry)
				}
			}
			input_config.OSDF.OauthClient = new_prefix_list

			err = config.SaveConfigContents(&input_config)
			if err != nil {
				fmt.Fprintln(os.Stderr, "Unable to save replaced configuration file:", err)
				os.Exit(1)
			}
		},
	})

}

func init() {

	// Define the config commands
	addConfigSubcommands(rootConfigCmd)

	// Define the prefix commands
	prefixCmd := &cobra.Command{
		Use:   "prefix",
		Short: "Manage the prefix configuration",
		Long:  "Manage the prefix configuration",
	}
	addPrefixSubcommands(prefixCmd)

	// Define the token commands
	tokenCmd := &cobra.Command{
		Use:   "token",
		Short: "Manage the available tokens",
		Long:  "Manage the available tokens",
	}
	addTokenSubcommands(tokenCmd)

	rootConfigCmd.CompletionOptions.DisableDefaultCmd = true
	rootConfigCmd.AddCommand(prefixCmd)
	rootConfigCmd.AddCommand(tokenCmd)
}
