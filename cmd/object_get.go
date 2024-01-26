/***************************************************************
*
* Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"github.com/pelicanplatform/pelican/param"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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

	client.ObjectClientOptions.Version = version

	err := config.InitClient()
	if err != nil {
		log.Errorln(err)
		os.Exit(1)
	}

	// Set the progress bars to the command line option
	client.ObjectClientOptions.Token, _ = cmd.Flags().GetString("token")

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		client.ObjectClientOptions.ProgressBars = true
	} else {
		client.ObjectClientOptions.ProgressBars = false
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

	// Check for manually entered cache to use ??
	nearestCache, nearestCacheIsPresent := os.LookupEnv("NEAREST_CACHE")

	if nearestCacheIsPresent {
		client.NearestCache = nearestCache
		client.NearestCacheList = append(client.NearestCacheList, client.NearestCache)
		client.CacheOverride = true
	} else if cache, _ := cmd.Flags().GetString("cache"); cache != "" {
		client.NearestCache = cache
		client.NearestCacheList = append(client.NearestCacheList, cache)
		client.CacheOverride = true
	}

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil && destStat.IsDir() {
			log.Errorln("Destination is not a directory")
			os.Exit(1)
		}
	}

	var result error
	var downloaded int64 = 0
	lastSrc := ""
	for _, src := range source {
		var tmpDownloaded int64
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		client.ObjectClientOptions.Recursive = isRecursive
		tmpDownloaded, result = client.DoGet(src, dest, isRecursive)
		downloaded += tmpDownloaded
		if result != nil {
			lastSrc = src
			break
		} else {
			client.ClearErrors()
		}
	}

	// Exit with failure
	if result != nil {
		// Print the list of errors
		errMsg := client.GetErrors()
		if errMsg == "" {
			errMsg = result.Error()
		}
		log.Errorln("Failure getting " + lastSrc + ": " + errMsg)
		if client.ErrorsRetryable() {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}
}
