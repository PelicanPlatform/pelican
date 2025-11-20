/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"net/url"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
)

var (
	getCmd = &cobra.Command{
		Use:   "get {source ...} {destination}",
		Short: "Get a file from a Pelican federation",
		Run:   getMain,
		PreRun: func(cmd *cobra.Command, args []string) {
			commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
		},
	}
)

func init() {
	flagSet := getCmd.Flags()
	flagSet.StringP("cache", "c", "", `A comma-separated list of preferred caches to try for the transfer, where a "+" in the list indicates
the client should fallback to discovered caches if all preferred caches fail.`)
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively download a collection.  Forces methods to only be http to get the freshest collection contents")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true
	flagSet.String("caches", "", "A JSON file containing the list of caches")
	flagSet.String("transfer-stats", "", "A path to a file to write transfer statistics to")
	flagSet.String("pack", "", "Package transfer using remote packing functionality (same as '?pack=' query). Options: auto, tar, tar.gz, tar.xz, zip. Default: auto when flag is provided without an explicit value")
	objectCmd.AddCommand(getCmd)
}

func getMain(cmd *cobra.Command, args []string) {
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

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	log.Debugln("Len of source:", len(args))
	if len(args) < 2 {
		log.Errorln("No Source or Destination\nTry 'pelican object get --help' for more information.")
		os.Exit(1)
	}
	source := args[:len(args)-1]
	dest := args[len(args)-1]

	// Handle --pack flag by appending the appropriate query parameter to each source URL
	packOption, _ := cmd.Flags().GetString("pack")
	if cmd.Flags().Changed("pack") {
		if packOption == "" {
			packOption = "auto"
		}
		if _, err := client.GetBehavior(packOption); err != nil {
			log.Errorln(err)
			os.Exit(1)
		}
		for i, src := range source {
			newSrc, err := addPackQuery(src, packOption)
			if err != nil {
				log.Errorln("Failed to process --pack option:", err)
				os.Exit(1)
			}
			source[i] = newSrc
		}
	}

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		log.Errorln("Failed to get preferred caches:", err)
		os.Exit(1)
	}

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil {
			log.Errorln("Destination does not exist")
			os.Exit(1)
		} else if !destStat.IsDir() {
			log.Errorln("Destination is not a directory")
			os.Exit(1)
		}
	}

	var attemptErr error
	lastSrc := ""

	finalResults := make([][]client.TransferResults, 0)

	for _, src := range source {
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		transferResults, err := client.DoGet(ctx, src, dest, isRecursive, client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation), client.WithCaches(caches...))
		if err != nil {
			attemptErr = err
			lastSrc = src
			break
		}
		finalResults = append(finalResults, transferResults)
	}

	// Exit with failure
	if attemptErr != nil {
		// Print the list of errors
		errMsg := attemptErr.Error()
		var pe error_codes.PelicanError
		var te *client.TransferErrors
		if errors.As(attemptErr, &te) {
			errMsg = te.UserError()
		}
		if errors.Is(attemptErr, &pe) {
			errMsg = pe.Error()
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			os.Exit(pe.ExitCode())
		} else { // For now, keeping this else here to catch any errors that are not classified PelicanErrors
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			if client.ShouldRetry(attemptErr) {
				log.Errorln("Errors are retryable")
				os.Exit(11)
			}
			os.Exit(1)
		}
	}

	// No failures so we can write the transfer stats
	transferStatsFile, _ := cmd.Flags().GetString("transfer-stats")
	if transferStatsFile != "" {
		transferStats, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			log.Errorln("Failed to marshal transfer results:", err)
		}
		err = os.WriteFile(transferStatsFile, transferStats, 0644)
		if err != nil {
			log.Errorln("Failed to write transfer stats to file:", err)
		}
	}
}

// addPackQuery appends or updates the "pack" query parameter on the provided URL string.
func addPackQuery(rawURL string, packOption string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("pack", packOption)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
