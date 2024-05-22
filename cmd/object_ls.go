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
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	lsCmd = &cobra.Command{
		Use:   "ls {object}",
		Short: "List objects in a namespace from a federation",
		Run:   listMain,
	}
)

func init() {
	flagSet := lsCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("long", "L", false, "Include extended information")
	flagSet.BoolP("dironly", "D", false, "List directories only")
	flagSet.BoolP("objectonly", "O", false, "List objects only")
	flagSet.BoolP("json", "j", false, "Print results in JSON format")

	objectCmd.AddCommand(lsCmd)
}

func listMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()
	err := config.InitClient()
	if err != nil {
		log.Errorln(err)

		if client.IsRetryable(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		} else {
			os.Exit(1)
		}
	}

	tokenLocation, _ := cmd.Flags().GetString("token")

	if len(args) < 1 {
		log.Errorln("no object provided")
		err = cmd.Help()
		if err != nil {
			log.Errorln("failed to print out help:", err)
		}
		os.Exit(1)
	}
	object := args[len(args)-1]

	log.Debugln("Object:", object)

	long, _ := cmd.Flags().GetBool("long")
	dirOnly, _ := cmd.Flags().GetBool("dironly")
	objectOnly, _ := cmd.Flags().GetBool("objectonly")
	json, _ := cmd.Flags().GetBool("json")

	err = client.DoList(ctx, object, client.WithTokenLocation(tokenLocation), client.WithLongOption(long),
		client.WithDirOnlyOption(dirOnly), client.WithObjectOnlyOption(objectOnly), client.WithJsonOption(json))

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
}
