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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	objectDeleteCmd = &cobra.Command{
		Use:   "delete {object}",
		Short: "Delete an object from a namespace in a federation",
		RunE:  deleteMain,
	}
)

func init() {
	flagSet := objectDeleteCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")

	objectCmd.AddCommand(objectDeleteCmd)
}

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

	if len(args) < 1 {
		_ = cmd.Help()
		return fmt.Errorf("no location provided for deletion")
	}
	object := args[len(args)-1]
	log.Debugln("Object to be deleted:", object)

	err = client.DoDelete(ctx, object, client.WithTokenLocation(tokenLocation))
	// if err != nil {
	// 	if client.IsRetryable(err) {
	// 		return fmt.Errorf("temporary error deleting object: %s. Please try again later", object)
	// 	}
	// 	return fmt.Errorf("unexpected error while deleting object: %v", err)
	// }

	// Exit with failure
	if err != nil {
		// Print the list of errors
		errMsg := err.Error()
		var te *client.TransferErrors
		if errors.As(err, &te) {
			errMsg = te.UserError()
		}
		log.Errorln("Failure getting " + object + ": " + errMsg)
		if client.ShouldRetry(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

	log.Infoln("Successfully deleted object:", object)
	return nil
}
