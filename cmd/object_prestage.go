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
	prestageCmd = &cobra.Command{
		Use:    "prestage {source ...} {destination}",
		Short:  "Prestages a prefix to a Pelican cache",
		Hidden: true, // Until we decide how safe this approach is, keep the command hidden.
		Run:    prestageMain,
	}
)

func init() {
	flagSet := prestageCmd.Flags()
	flagSet.StringP("cache", "c", "", "Cache to use")
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	objectCmd.AddCommand(prestageCmd)
}

func prestageMain(cmd *cobra.Command, args []string) {
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

	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	if len(args) < 1 {
		log.Errorln("Prefix(es) to prestage must be specified")
		err = cmd.Help()
		if err != nil {
			log.Errorln("Failed to print out help:", err)
		}
		os.Exit(1)
	}

	log.Debugln("Prestage prefixes:", args)

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

	lastSrc := ""

	for _, src := range args {
		if !isPelicanUrl(src) {
			log.Errorln("Provided URL is not a valid Pelican URL:", src)
			os.Exit(1)
		}
		if _, err = client.DoPrestage(ctx, src,
			client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation),
			client.WithCaches(caches...)); err != nil {
			lastSrc = src
			break
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
			log.Errorln("Failure prestaging " + lastSrc + ": " + errMsg)
			os.Exit(pe.ExitCode())
		} else { // For now, keeping this else here to catch any errors that are not classified PelicanErrors
			log.Errorln("Failure prestaging " + lastSrc + ": " + errMsg)
			if client.ShouldRetry(err) {
				log.Errorln("Errors are retryable")
				os.Exit(11)
			}
			os.Exit(1)
		}
	}
}
