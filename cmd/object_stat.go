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
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
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
		log.Errorln("No object provided")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}
	object := args[len(args)-1]

	log.Debugln("Object:", object)

	statInfo, err := client.DoStat(ctx, object, client.WithTokenLocation(tokenLocation))

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

	if jsn {
		// Print our stat info in JSON format:
		jsonData, err := json.Marshal(statInfo)
		if err != nil {
			log.Errorf("Failed to parse object/directory stat info to JSON format: %v", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
		return
	} else {
		// Print our stat info:
		fmt.Println("Name:", statInfo.Name)
		fmt.Println("Size:", statInfo.Size)
		fmt.Println("ModTime:", statInfo.ModTime)
		fmt.Println("IsDir:", statInfo.IsDir)
		return
	}
}
