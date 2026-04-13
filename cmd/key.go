//go:build server

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	keyCmd = &cobra.Command{
		Use:   "key",
		Short: "Manage Pelican issuer keys",
	}

	// `pelican key create` command aims to replace `pelican generate keygen` command in the future.
	// For now, they are both available and do the same thing to maintain backward compatibility.
	keyCreateCmd = &cobra.Command{
		Use:   "create",
		Short: "Generate a public-private key-pair for Pelican server",
		Long: `Generate a public-private key-pair for a Pelican server.
The private key is an ECDSA key with P256 curve. The corresponding public key
is a JSON Web Key Set (JWKS), which can be used for JWT signature verification.`,
		RunE:         keygenMain,
		SilenceUsage: true,
	}
)

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyCreateCmd)

	// Attach flags to the `create` sub-command
	keyCreateCmd.Flags().StringVar(&privateKeyPath, "private-key", "./private-key.pem", "The file path where the generated private key will be saved. If a key already exists at the provided path, it will not be overwritten but will be used to derive a public key")
	keyCreateCmd.Flags().StringVar(&publicKeyPath, "public-key", "./issuer-pub.jwks", "The file path where the generated public key (derived from the generated private key) will be saved.")
}
