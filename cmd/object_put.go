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
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	putCmd = &cobra.Command{
		Use:   "put {source ...} {destination}",
		Short: "Send a file to a Pelican federation",
		Run:   putMain,
	}
)

func init() {
	flagSet := putCmd.Flags()
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively upload a collection.  Forces methods to only be http to get the freshest collection contents")
	flagSet.String("checksum", "crc32c", "Checksum algorithm to use for upload and validation")
	objectCmd.AddCommand(putCmd)
}

func putMain(cmd *cobra.Command, args []string) {
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

	var options []client.TransferOption

	// Set the progress bars to the command line option
	tokenLocation, _ := cmd.Flags().GetString("token")

	// Add checksum options if requested
	checksumAlgorithm, _ := cmd.Flags().GetString("checksum")
	if checksumAlgorithm != "" {
		checksumType := client.ChecksumFromHttpDigest(checksumAlgorithm)
		if checksumType == client.AlgUnknown {
			log.Errorln("Unknown checksum algorithm:", checksumAlgorithm)
			var validAlgorithms []string
			for _, alg := range client.KnownChecksumTypes() {
				validAlgorithms = append(validAlgorithms, client.HttpDigestFromChecksum(alg))
			}
			log.Errorln("Valid algorithms are:", strings.Join(validAlgorithms, ", "))
			os.Exit(1)
		}
		options = append(options, client.WithRequestChecksums([]client.ChecksumType{checksumType}))
		options = append(options, client.WithRequireChecksum())
	}

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	log.Debugln("Len of source:", len(args))
	if len(args) < 2 {
		log.Errorln("No Source or Destination")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}
	source := args[:len(args)-1]
	dest := args[len(args)-1]

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)

	var result error
	lastSrc := ""

	options = append(options, client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation))

	for _, src := range source {
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		_, result = client.DoPut(ctx, src, dest, isRecursive, options...)
		if result != nil {
			lastSrc = src
			break
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := result.Error()
		var te *client.TransferErrors
		if errors.As(result, &te) {
			errMsg = te.UserError()
		}
		log.Errorln("Failure putting " + lastSrc + ": " + errMsg)
		if client.ShouldRetry(result) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

}
