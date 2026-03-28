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
	"strings"

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
	flagSet.StringArray(
		"checksums",
		[]string{},
		fmt.Sprintf("Checksums to request from the server.  Known values are: %s",
			strings.Join(client.KnownChecksumTypesAsHttpDigest(), ", "),
		),
	)
	objectCmd.AddCommand(statCmd)
}

func statMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	// Set up signal handlers to flush logs on SIGTERM
	client.SetupSignalHandlers()

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

	// Get the checksums to request
	checksums, _ := cmd.Flags().GetStringArray("checksums")
	checksumTypes := make([]client.ChecksumType, 0, len(checksums))
	if len(checksums) > 0 {
		// Convert the checksums to the correct type
		for _, checksum := range checksums {
			checksumType := client.ChecksumFromHttpDigest(checksum)
			if checksumType == client.AlgUnknown {
				log.Errorf("Unknown checksum type: %s", checksum)
				err = cmd.Help()
				if err != nil {
					log.Errorln("Failed to print out help:", err)
				}
				os.Exit(1)
			}
			checksumTypes = append(checksumTypes, checksumType)
		}
	}

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

	statInfo, err := client.DoStat(ctx, object, client.WithTokenLocation(tokenLocation), client.WithRequestChecksums(checksumTypes))

	// Exit with failure
	if err != nil {
		if handleCredentialPasswordError(err) {
			os.Exit(1)
		}
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
			log.Errorf("Failed to parse object/collection stat info to JSON format: %v", err)
			os.Exit(1)
		}
		fmt.Println(string(jsonData))
		return
	} else {
		// Print our stat info:
		fmt.Println("Name:", statInfo.Name)
		fmt.Println("Size:", statInfo.Size)
		fmt.Println("ModTime:", statInfo.ModTime)
		fmt.Println("IsCollection:", statInfo.IsCollection)
		if len(statInfo.Checksums) > 0 {
			fmt.Println("Checksums:")
			for alg, value := range statInfo.Checksums {
				fmt.Printf("  %s: %s\n", alg, value)
			}
		}
		return
	}
}
