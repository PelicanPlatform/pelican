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
	"net/url"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	getCmd = &cobra.Command{
		Use:   "get {source ...} {destination}",
		Short: "Get a file from a Pelican federation",
		Run:   getMain,
	}
)

func init() {
	flagSet := getCmd.Flags()
	flagSet.StringP("cache", "c", "", "Cache to use")
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively download a directory.  Forces methods to only be http to get the freshest directory contents")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true
	flagSet.String("caches", "", "A JSON file containing the list of caches")
	objectCmd.AddCommand(getCmd)
}

func getMain(cmd *cobra.Command, args []string) {
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

	// Check for manually entered cache to use
	var preferredCache string
	if nearestCache, ok := os.LookupEnv("NEAREST_CACHE"); ok {
		preferredCache = nearestCache
	} else if cache, _ := cmd.Flags().GetString("cache"); cache != "" {
		preferredCache = cache
	}
	var caches []*url.URL
	caches, err = utils.GetPreferredCaches(preferredCache)
	if err != nil {
		log.Errorln(err)
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

	var result error
	lastSrc := ""

	for _, src := range source {
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		_, result = client.DoGet(ctx, src, dest, isRecursive, client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation), client.WithCaches(caches...))
		if result != nil {
			lastSrc = src
			break
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := result.Error()
		var pe error_codes.PelicanError
		var te *client.TransferErrors
		if errors.As(result, &te) {
			errMsg = te.UserError()
		}
		if errors.Is(result, &pe) {
			errMsg = pe.Error()
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			os.Exit(pe.ExitCode())
		} else { // For now, keeping this else here to catch any errors that are not classified PelicanErrors
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			if client.ShouldRetry(result) {
				log.Errorln("Errors are retryable")
				os.Exit(11)
			}
			os.Exit(1)
		}
	}
}
