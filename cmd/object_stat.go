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

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	statCmd = &cobra.Command{
		Use:   "stat {object}",
		Short: "Stat objects in a namespace from a federation",
		Run:   statMain,
	}
)

func init() {
	flagSet := statCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("json", "j", false, "Print results in JSON format")
	objectCmd.AddCommand(statCmd)
}

func statMain(cmd *cobra.Command, args []string) {
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
	jsn, _ := cmd.Flags().GetBool("json")

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

	_, result := client.DoStat(ctx, object, client.WithTokenLocation(tokenLocation), client.WithJson(jsn))

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := result.Error()
		var te *client.TransferErrors
		if errors.As(result, &te) {
			errMsg = te.UserError()
		}
		log.Errorln("Failure getting " + object + ": " + errMsg)
		if client.ShouldRetry(result) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}
}
