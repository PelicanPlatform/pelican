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
		Short: "Generate a public-private key-pair for Pelican OIDC issuer",
		Long: `Generate a public-private key-pair for a Pelican server.
The private key is a ECDSA key with P256 curve. The corresponding public key
is a JWKS in JSON. The public key follows OIDC protocol and can be used
for JWT signature verification.`,
		RunE: keygenMain,
		// Note: no new tests are needed for this new command, because it reuses the `keygenMain` function,
		// which is already tested in `pelican/cmd/generate_keygen_test.go`.
		SilenceUsage: true,
	}
)

func init() {
	keyCmd.AddCommand(keyCreateCmd)

	// Attach flags to the `create` sub-command
	keyCreateCmd.Flags().StringVar(&privateKeyPath, "private-key", "", "The path to the generate private key file. Default: ./issuer.jwk")
	keyCreateCmd.Flags().StringVar(&publicKeyPath, "public-key", "", "The path to the generate public key file. Default: ./issuer-pub.jwks")
}
