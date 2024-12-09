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
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	objectDeleteCmd = &cobra.Command{
		Use:   "delete {object}",
		Short: "Delete an object or a collection",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("no location provided for deletion")
			}
			if len(args) > 1 {
				return fmt.Errorf("too many arguments provided; only one argument is allowed")
			}
			return nil
		},
		RunE:   deleteMain,
		Hidden: true,
	}
)

func init() {
	flagSet := objectDeleteCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively delete a collection")

	objectCmd.AddCommand(objectDeleteCmd)
}

// deleteMain is the top-level function for executing the object delete command.
func deleteMain(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	err := config.InitClient()
	if err != nil {
		log.Errorln("Failed to initialize client:", err)

		if client.IsRetryable(err) {
			return fmt.Errorf("retryable error occurred: %v", err)
		}
		return fmt.Errorf("non-retryable error occurred: %v", err)
	}

	tokenLocation, _ := cmd.Flags().GetString("token")
	remoteDestination := args[len(args)-1]
	isRecursive, _ := cmd.Flags().GetBool("recursive")

	err = client.DoDelete(ctx, remoteDestination, isRecursive, client.WithTokenLocation(tokenLocation))

	if err != nil {
		log.Errorf("Failure deleting %s: %v", remoteDestination, err.Error())
		os.Exit(1)
	}

	return nil
}
