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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

var (
	execName string

	copyCmd = &cobra.Command{
		Use:   "copy {source ...} {destination}",
		Short: "Copy a file to/from a Pelican federation",
		Run:   copyMain,
	}
)

func init() {
	execName = filepath.Base(os.Args[0])
	// Take care of our Windows users
	execName = strings.TrimSuffix(execName, ".exe")
	// Being case-insensitive
	execName = strings.ToLower(execName)
	flagSet := copyCmd.Flags()
	flagSet.StringP("cache", "c", "", "Cache to use")
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively copy a directory.  Forces methods to only be http to get the freshest directory contents")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true
	// All the deprecated or hidden flags that are only relevant if we are in historical "stashcp mode"
	if strings.HasPrefix(execName, "stashcp") {
		copyCmd.Use = "stashcp {source ...} {destination}"
		copyCmd.Short = "Copy a file to/from the OSDF"
		flagSet.Lookup("cache-list-name").Hidden = false // Expose the help for this option
		flagSet.StringP("caches-json", "j", "", "A JSON file containing the list of caches")
		flagSet.Bool("closest", false, "Return the closest cache and exit")
		flagSet.BoolP("debug", "d", false, "Enable debug logs") // Typically set by the root command (which doesn't exist in stashcp mode)
		flagSet.Bool("list-names", false, "Return the names of pre-configured cache lists and exit")
		flagSet.String("methods", "http", "Comma separated list of methods to try, in order")
		flagSet.Bool("namespaces", false, "Print the namespace information and exit")
		flagSet.Bool("plugininterface", false, "Output in HTCondor plugin format.  Turned on if executable is named stash_plugin")
		flagSet.Lookup("plugininterface").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("progress", "p", false, "Show progress bars, turned on if run from a terminal")
		flagSet.Lookup("progress").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("version", "v", false, "Print the version and exit")
	} else {
		flagSet.String("caches", "", "A JSON file containing the list of caches")
		flagSet.String("methods", "http", "Comma separated list of methods to try, in order")
		objectCmd.AddCommand(copyCmd)
	}
}

func copyMain(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()

	// Need to check just stashcp since it does not go through root, the other modes get checked there
	if strings.HasPrefix(execName, "stashcp") {
		if val, err := cmd.Flags().GetBool("debug"); err == nil && val {
			config.SetLogging(log.DebugLevel)
		} else {
			config.SetLogging(log.ErrorLevel)
		}
	}

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

	if val, err := cmd.Flags().GetBool("version"); err == nil && val {
		config.PrintPelicanVersion(os.Stdout)
		os.Exit(0)
	}

	pb := newProgressBar()
	defer pb.shutdown()

	tokenLocation, _ := cmd.Flags().GetString("token")

	// Check if the program was executed from a terminal and does not specify a log location
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	if val, err := cmd.Flags().GetBool("namespaces"); err == nil && val {
		namespaces, err := namespaces.GetNamespaces(ctx)
		if err != nil {
			fmt.Println("Failed to get namespaces:", err)
			os.Exit(1)
		}
		fmt.Printf("%+v\n", namespaces)
		os.Exit(0)
	}

	// Just return all the caches that it knows about
	// Print out all of the caches and exit
	if val, err := cmd.Flags().GetBool("list-names"); err == nil && val {
		listName, _ := cmd.Flags().GetString("cache-list-name")
		cacheList, err := client.GetBestCache(listName)
		if err != nil {
			log.Errorln("Failed to get best caches:", err)
			os.Exit(1)
		}
		// Print the caches, comma separated,
		fmt.Println(strings.Join(cacheList[:], ","))
		os.Exit(0)
	}

	if val, err := cmd.Flags().GetBool("closest"); err == nil && val {
		listName, err := cmd.Flags().GetString("cache-list-name")
		if err != nil {
			log.Errorln("Failed to determine correct cache list")
			os.Exit(1)
		}
		cacheList, err := client.GetBestCache(listName)
		if err != nil {
			log.Errorln("Failed to get best cache: ", err)
		}
		fmt.Println(cacheList[0])
		os.Exit(0)
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
		_, result = client.DoCopy(ctx, src, dest, isRecursive, client.WithCallback(pb.callback), client.WithTokenLocation(tokenLocation), client.WithCaches(caches...))
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
		log.Errorln("Failure transferring " + lastSrc + ": " + errMsg)
		if client.ShouldRetry(err) {
			log.Errorln("Errors are retryable")
			os.Exit(11)
		}
		os.Exit(1)
	}

}
