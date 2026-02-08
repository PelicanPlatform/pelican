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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	rcloneTokenCmd = &cobra.Command{
		Use:    "token <pelican-url>",
		Short:  "Output a bearer token for rclone to use",
		Hidden: true,
		Long: `Output a fresh bearer token for use with rclone's bearer_token_command.

This command is designed to be called by rclone's bearer_token_command
configuration option. It fetches or generates a valid token for the
specified namespace and outputs it to stdout.

This command should generally not be called directly by users; it is
meant to be invoked automatically by rclone when a token is needed.

Examples:
  pelican rclone token --read pelican://federation.example.org/namespace/path
  pelican rclone token --write pelican://federation.example.org/namespace/path`,
		RunE:         rcloneTokenMain,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	rcloneTokenReadOnly       bool
	rcloneTokenReadWrite      bool
	rcloneTokenCredentialFile string
)

func init() {
	rcloneCmd.AddCommand(rcloneTokenCmd)

	rcloneTokenCmd.Flags().BoolVarP(&rcloneTokenReadOnly, "read", "r", false, "Request a read token")
	rcloneTokenCmd.Flags().BoolVarP(&rcloneTokenReadWrite, "write", "w", false, "Request a write token")
	rcloneTokenCmd.Flags().StringVar(&rcloneTokenCredentialFile, "credential-file", "", "Path to the credential file to use for token generation")

	rcloneTokenCmd.MarkFlagsOneRequired("read", "write")

	if err := viper.BindPFlag("Client.CredentialFile", rcloneTokenCmd.Flags().Lookup("credential-file")); err != nil {
		panic(err)
	}
}

func rcloneTokenMain(cmd *cobra.Command, args []string) error {
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

	// Determine the HTTP method based on access mode
	httpMethod := http.MethodGet
	if rcloneTokenReadWrite {
		httpMethod = http.MethodPut
	}

	// Get director info for the path
	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return errors.Wrapf(err, "failed to get director info for %s", rawUrl)
	}

	// Public prefixes don't require tokens. Output an empty string so rclone
	// gets a successful response and proceeds without authentication.
	if !dirResp.XPelNsHdr.RequireToken {
		return nil
	}

	// Determine the operation type.
	// --write implies read: request all scopes so the token works for both.
	var operation config.TokenOperation
	if rcloneTokenReadWrite {
		operation.Set(config.TokenWrite)
		operation.Set(config.TokenDelete)
	}
	operation.Set(config.TokenRead)
	operation.Set(config.TokenList)

	// Acquire a token
	opts := config.TokenGenerationOpts{
		Operation: operation,
	}

	token, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts)
	if err != nil {
		return errors.Wrap(err, "failed to acquire token")
	}

	// Output just the token (rclone expects the raw token string)
	fmt.Fprint(os.Stdout, token)
	return nil
}
