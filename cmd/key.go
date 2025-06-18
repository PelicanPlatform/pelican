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
	keyCmd.AddCommand(keyCreateCmd)

	// Attach flags to the `create` sub-command
	keyCreateCmd.Flags().StringVar(&privateKeyPath, "private-key", "./private-key.pem", "The file path where the generated private key will be saved. If a key already exists at the provided path, it will not be overwritten but will be used to derive a public key")
	keyCreateCmd.Flags().StringVar(&publicKeyPath, "public-key", "./issuer-pub.jwks", "The file path where the generated public key (derived from the generated private key) will be saved.")
}
