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
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	tokenSetupNoPassword     bool
	tokenSetupCredentialFile string
	tokenSetupRead           bool
	tokenSetupWrite          bool
)

// addCredentialsTokenSetupCommand adds the "setup" subcommand to the given
// credentials token command.
func addCredentialsTokenSetupCommand(credentialsTokenCmd *cobra.Command) {
	setupCmd := &cobra.Command{
		Use:   "setup <pelican-url>",
		Short: "Set up a credential file containing tokens for a Pelican namespace",
		Long: `Acquire a token for the specified Pelican namespace and save it to a
credential file on disk. The credential file contains the access token,
refresh token, and OAuth2 client credentials needed to obtain fresh tokens
later without re-authenticating.

By default, the credential file is password-protected. Use --no-password to
save the file without encryption, which is useful for non-interactive contexts
where password prompts would fail.

Use --credential-file to specify an alternative path for the credential file.

Examples:
  # Set up credentials for reading from a namespace
  pelican credentials token setup --read pelican://federation.example.org/namespace/path

  # Set up credentials for reading and writing
  pelican credentials token setup --write pelican://federation.example.org/namespace/path

  # Set up credentials without password protection
  pelican credentials token setup --no-password --read pelican://federation.example.org/namespace/path

  # Set up credentials to a specific file
  pelican credentials token setup --credential-file /path/to/creds.pem --read pelican://federation.example.org/namespace/path`,
		RunE:         credentialsTokenSetupMain,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	setupCmd.Flags().BoolVar(&tokenSetupNoPassword, "no-password", false, "Save the credential file without password protection")
	setupCmd.Flags().BoolVarP(&tokenSetupRead, "read", "r", false, "Request a read token")
	setupCmd.Flags().BoolVarP(&tokenSetupWrite, "write", "w", false, "Request a write token (implies read)")

	setupCmd.Flags().StringVar(&tokenSetupCredentialFile, "credential-file", "", "Path to the credential file to write")
	if err := viper.BindPFlag("Client.CredentialFile", setupCmd.Flags().Lookup("credential-file")); err != nil {
		panic(err)
	}

	credentialsTokenCmd.AddCommand(setupCmd)
}

func credentialsTokenSetupMain(cmd *cobra.Command, args []string) error {
	err := config.InitClient()
	if err != nil {
		return errors.Wrap(err, "failed to initialize client configuration")
	}

	// Parse the Pelican URL
	rawUrl := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawUrl)
	if err != nil {
		return errors.Wrapf(err, "failed to parse URL: %s", rawUrl)
	}

	// Default to read if neither --read nor --write is specified
	if !tokenSetupRead && !tokenSetupWrite {
		tokenSetupRead = true
	}

	// Determine the HTTP method based on access mode
	httpMethod := http.MethodGet
	if tokenSetupWrite {
		httpMethod = http.MethodPut
	}

	// Get director info for the path
	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return errors.Wrapf(err, "failed to get director info for %s", rawUrl)
	}

	// Public prefixes don't require tokens
	if !dirResp.XPelNsHdr.RequireToken {
		fmt.Fprintln(os.Stderr, "The specified namespace does not require tokens; no credential file is needed.")
		return nil
	}

	// Determine the operation type.
	// --write implies read: request all scopes so the token works for both.
	var operation config.TokenOperation
	if tokenSetupWrite {
		operation.Set(config.TokenWrite)
		operation.Set(config.TokenDelete)
	}
	operation.Set(config.TokenRead)
	operation.Set(config.TokenList)

	// Acquire a token (this will also register the OAuth2 client and save
	// credentials to the credential file as a side effect)
	opts := config.TokenGenerationOpts{
		Operation: operation,
	}

	token, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts)
	if err != nil {
		return errors.Wrap(err, "failed to acquire token")
	}

	if token == "" {
		return errors.New("acquired token is empty")
	}

	// Now read the credential config that was just saved and optionally
	// re-save it as a passwordless file
	credFilePath, err := config.GetEncryptedConfigName()
	if err != nil {
		return errors.Wrap(err, "failed to determine credential file path")
	}

	if tokenSetupNoPassword {
		// Read the current config and re-save without password
		osdfConfig, err := config.GetCredentialConfigContents()
		if err != nil {
			return errors.Wrap(err, "failed to read credential configuration")
		}

		if err := config.SaveConfigContentsToFile(&osdfConfig, credFilePath, false); err != nil {
			return errors.Wrap(err, "failed to save passwordless credential file")
		}

		log.Infof("Credential file saved without password protection to %s", credFilePath)
	} else {
		log.Infof("Credential file saved to %s", credFilePath)
	}

	fmt.Fprintf(os.Stderr, "Successfully set up credentials for %s\n", dirResp.XPelNsHdr.Namespace)
	fmt.Fprintf(os.Stderr, "Credential file: %s\n", credFilePath)
	return nil
}
