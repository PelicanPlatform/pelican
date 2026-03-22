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
	"fmt"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
)

var (
	objectEvictCmd = &cobra.Command{
		Use:   "evict {path}",
		Short: "Evict cached objects by path or prefix from the local cache",
		Long: `Evict one or more objects from the local Pelican cache.

All objects whose path starts with (or exactly matches) the given
path are selected.  By default the selected objects are marked for
priority eviction (purge-first) so they will be removed during the
next eviction cycle.  Use --immediate to delete them right away.

The path should be a pelican:// or osdf:// URL (or a schemeless
namespace path if federation discovery is configured).

Token bootstrapping follows the same logic as "pelican object get":
tokens are discovered from the environment, credential files, or
negotiated via OAuth when needed.  Use --token to provide a token
file explicitly.

Examples:
  pelican object evict pelican://fed.example.com/data/file.dat
  pelican object evict pelican://fed.example.com/data/project/
  pelican object evict --immediate pelican://fed.example.com/data/project/
  pelican object evict --token /path/to/token pelican://fed.example.com/data/file.dat`,
		Args:         cobra.ExactArgs(1),
		RunE:         objectEvictMain,
		SilenceUsage: true,
	}
)

func init() {
	flagSet := objectEvictCmd.Flags()
	flagSet.BoolP("immediate", "i", false, "Delete objects immediately instead of marking them for priority eviction")
	flagSet.StringP("token", "t", "", "Token file to use for authorization")
	objectCmd.AddCommand(objectEvictCmd)
}

func objectEvictMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	err := config.InitClient()
	if err != nil {
		log.Errorln(err)
		if client.IsRetryable(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

	tokenLocation, _ := cmd.Flags().GetString("token")
	immediate, _ := cmd.Flags().GetBool("immediate")
	source := args[0]

	options := []client.TransferOption{
		client.WithTokenLocation(tokenLocation),
	}

	message, err := client.DoEvict(ctx, source, immediate, options...)
	if err != nil {
		if handleCredentialPasswordError(err) {
			os.Exit(1)
		}
		errMsg := err.Error()
		var pe error_codes.PelicanError
		var te *client.TransferErrors
		if errors.As(err, &te) {
			errMsg = te.UserError()
		}
		if errors.Is(err, &pe) {
			errMsg = pe.Error()
			log.Errorln("Failure evicting " + source + ": " + errMsg)
			os.Exit(pe.ExitCode())
		}
		log.Errorln("Failure evicting " + source + ": " + errMsg)
		if client.ShouldRetry(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

	fmt.Println(message)
	return nil
}
