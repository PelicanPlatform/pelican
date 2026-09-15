//go:build client

/***************************************************************
*
* Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

var (
	syncCmd = &cobra.Command{
		Use:   "sync {source ...} {destination}",
		Short: "Sync a directory to or from a Pelican federation",
		Run:   syncMain,
		PreRun: func(cmd *cobra.Command, args []string) {
			commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
		},
	}
)

func init() {
	flagSet := syncCmd.Flags()
	flagSet.StringP("cache", "c", "", `A comma-separated list of preferred caches to try for the transfer, where a "+" in the list indicates
the client should fallback to discovered caches if all preferred caches fail.`)
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.Bool("inplace", false, "Write files directly to destination (default: use temporary files)")
	flagSet.Bool("dry-run", false, "Show what would be synchronized without actually modifying the destination")
	flagSet.Bool("direct", false, "Read directly from an origin, bypassing any caches (same as '?directread' query)")
	objectCmd.AddCommand(syncCmd)
}

func syncMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	err := config.InitClient()
	if err != nil {
		reportError(err)

		if client.IsRetryable(err) {
			exitWithError(11, "Errors are retryable")
		} else {
			exitWithFlush(1)
		}
	}

	tokenLocation, _ := cmd.Flags().GetString("token")
	inPlace, _ := cmd.Flags().GetBool("inplace")

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_Client_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	if len(args) < 2 {
		reportError("No source or destination to sync")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		exitWithFlush(1)
	}
	sources := args[:len(args)-1]
	dest := args[len(args)-1]
	doDownload := false
	doTPC := false
	if pelican_url.IsPelicanURL(dest) {
		if pelican_url.IsPelicanURL(sources[0]) {
			// Both source and destination are remote: third-party-copy sync
			for _, src := range sources {
				if !pelican_url.IsPelicanURL(src) {
					exitWithError(1, "When synchronizing between federation URLs, all sources must be pelican URLs:", src)
				}
			}
			log.Debugln("Synchronizing between Pelican data federation endpoints (third-party-copy)")
			doTPC = true
		} else {
			for _, src := range sources {
				if pelican_url.IsPelicanURL(src) {
					exitWithErrorf(1, "URL (%s) cannot be a source when synchronizing to a federation URL from local files", src)
				}
			}
			log.Debugln("Synchronizing to a Pelican data federation")
		}
	} else {
		if !pelican_url.IsPelicanURL(sources[0]) {
			exitWithError(1, "Either the first or last argument must be a pelican:// or osdf://-style URL specifying a remote destination")
		}
		for _, src := range sources {
			if !pelican_url.IsPelicanURL(src) {
				exitWithError(1, "When synchronizing to a local directory, all sources must be pelican URLs:", src)
			}
		}
		log.Debugln("Synchronizing from a Pelican data federation")
		doDownload = true
	}

	// Handle --direct flag by appending the directread query parameter to each remote source URL
	directRead, _ := cmd.Flags().GetBool("direct")
	if directRead {
		if doDownload || doTPC {
			for i, src := range sources {
				// Check for conflicting prefercached parameter
				u, pErr := url.Parse(src)
				if pErr != nil {
					exitWithError(1, "Failed to parse URL:", pErr)
				}
				if u.Query().Has("prefercached") {
					exitWithError(1, "Cannot use --direct flag with URLs that have '?prefercached' query parameter")
				}

				newSrc, pErr := addQueryParam(src, "directread", "")
				if pErr != nil {
					exitWithError(1, "Failed to process --direct option:", pErr)
				}
				sources[i] = newSrc
			}
		} else {
			log.Warningln("The --direct flag is ignored for upload syncs (local to remote)")
		}
	}

	log.Debugln("Sources:", sources)
	log.Debugln("Destination:", dest)

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		exitWithError(1, "Failed to get preferred caches:", err)
	}

	if doDownload && len(sources) > 1 {
		if destStat, err := os.Stat(dest); err != nil {
			exitWithError(1, "Destination does not exist")
		} else if !destStat.IsDir() {
			exitWithError(1, "Destination is not a directory")
		}
	}

	lastSrc := ""

	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if doTPC {
		for _, src := range sources {
			options := []client.TransferOption{
				client.WithCallback(pb.callback),
				client.WithTokenLocation(tokenLocation),
				client.WithSynchronize(client.SyncSize),
				client.WithCaches(caches...),
				client.WithDryRun(dryRun),
			}
			if _, err = client.DoCopy(ctx, src, dest, true, options...); err != nil {
				lastSrc = src
				break
			}
		}
	} else if doDownload {
		for _, src := range sources {
			options := []client.TransferOption{
				client.WithCallback(pb.callback),
				client.WithTokenLocation(tokenLocation),
				client.WithSynchronize(client.SyncSize),
				client.WithCaches(caches...),
				client.WithInPlace(inPlace),
				client.WithDryRun(dryRun),
			}
			if _, err = client.DoGet(ctx, src, dest, true, options...); err != nil {
				lastSrc = src
				break
			}
		}
	} else {
		for _, src := range sources {
			if srcStat, err := os.Stat(src); err != nil {
				exitWithError(1, "Source: "+src+" does not exist")
			} else if !srcStat.IsDir() && string(dest[len(dest)-1]) == `/` {
				log.Warningln("Destination: " + dest + " ends with '/', but the source is a file. If the destination does not exist, it will be treated as an object, not a collection.")
			}

			options := []client.TransferOption{
				client.WithCallback(pb.callback),
				client.WithTokenLocation(tokenLocation),
				client.WithSynchronize(client.SyncSize),
				client.WithCaches(caches...),
				client.WithDryRun(dryRun),
			}
			if _, err = client.DoPut(ctx, src, dest, true, options...); err != nil {
				lastSrc = src
				break
			}
		}
	}

	// Exit with failure
	if err != nil {
		if handleCredentialPasswordError(err) {
			exitWithFlush(1)
		}
		// Print the list of errors
		exitTransferFailure(err, "Failure getting "+lastSrc)
	}
}
