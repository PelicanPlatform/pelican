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
	"strings"

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
	syncCmd = &cobra.Command{
		Use:   "sync {source ...} {destination}",
		Short: "Sync a directory to or from a Pelican federation",
		Run:   syncMain,
	}
)

func init() {
	flagSet := syncCmd.Flags()
	flagSet.StringP("cache", "c", "", "Cache to use")
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	objectCmd.AddCommand(syncCmd)
}

func getLastScheme(scheme string) string {
	idx := strings.LastIndex(scheme, "+")
	if idx == -1 {
		return scheme
	}
	return scheme[idx+1:]
}

// Returns true if the input is a url-like object that
// pelican can consume.
//
// Schemes we understand are "osdf", "pelican",
// "foo+osdf", or "foo+pelican" where "foo" is some arbitrary
// prefix not containing a "/"
func isPelicanUrl(input string) bool {
	prefix, _, found := strings.Cut(input, "://")
	if !found {
		return false
	}
	if strings.Contains(prefix, "/") {
		return false
	}
	scheme := getLastScheme(prefix)
	if scheme != "pelican" && scheme != "osdf" {
		return false
	}
	if _, err := url.Parse(input); err != nil {
		return false
	}
	return true
}

func syncMain(cmd *cobra.Command, args []string) {
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

	if len(args) < 2 {
		log.Errorln("No source or destination to sync")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}
	sources := args[:len(args)-1]
	dest := args[len(args)-1]
	doDownload := false
	if isPelicanUrl(dest) {
		for _, src := range sources {
			if isPelicanUrl(src) {
				log.Errorf("URL (%s) cannot be a source when synchronizing to a federation URL", src)
				os.Exit(1)
			}
		}
		log.Debugln("Synchronizing to a Pelican data federation")
	} else {
		if !isPelicanUrl(sources[0]) {
			log.Errorln("Either the first or last argument must be a pelican:// or osdf://-style URL specifying a remote destination")
			os.Exit(1)
		}
		for _, src := range sources {
			if !isPelicanUrl(src) {
				log.Errorln("When synchronizing to a local directory, all sources must be pelican URLs:", src)
				os.Exit(1)
			}
		}
		log.Debugln("Synchronizing from a Pelican data federation")
		doDownload = true
	}

	log.Debugln("Sources:", sources)
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

	if doDownload && len(sources) > 1 {
		if destStat, err := os.Stat(dest); err != nil {
			log.Errorln("Destination does not exist")
			os.Exit(1)
		} else if !destStat.IsDir() {
			log.Errorln("Destination is not a directory")
			os.Exit(1)
		}
	}

	lastSrc := ""

	if doDownload {
		for _, src := range sources {
			if _, err = client.DoGet(ctx, src, dest, true,
				client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation),
				client.WithCaches(caches...), client.WithSynchronize(client.SyncSize)); err != nil {
				lastSrc = src
				break
			}
		}
	} else {
		for _, src := range sources {
			if srcStat, err := os.Stat(src); err != nil {
				log.Errorln("Source does not exist")
				os.Exit(1)
			} else if !srcStat.IsDir() && string(dest[len(dest)-1]) == `/` {
				log.Warningln("Destination ends with '/', but the source is a file. If the destination does not exist, it will be treated as an object, not a collection.")
			}

			if _, err = client.DoPut(ctx, src, dest, true,
				client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation),
				client.WithCaches(caches...), client.WithSynchronize(client.SyncSize)); err != nil {
				lastSrc = src
				break
			}
		}
	}

	// Exit with failure
	if err != nil {
		// Print the list of errors
		errMsg := err.Error()
		var pe error_codes.PelicanError
		var te *client.TransferErrors
		if errors.As(err, &te) {
			errMsg = te.UserError()
		}
		if errors.Is(err, &pe) {
			errMsg = pe.Error()
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			os.Exit(pe.ExitCode())
		} else { // For now, keeping this else here to catch any errors that are not classified PelicanErrors
			log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
			if client.ShouldRetry(err) {
				log.Errorln("Errors are retryable")
				os.Exit(11)
			}
			os.Exit(1)
		}
	}
}
