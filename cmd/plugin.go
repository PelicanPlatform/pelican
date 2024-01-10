/***************************************************************
 *
 * Copyright (C) 2023, University of Nebraska-Lincoln
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
	"bufio"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"

	// Holds the various plugin commands
	rootPluginCmd = &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management for HTCSS",
	}
)

type Transfer struct {
	url       string
	localFile string
}

func init() {
	// Define the file transfer plugin command
	xferCmd := &cobra.Command{
		Use:                "transfer",
		Short:              "Run pelican CLI in HTCSS file transfer plugin mode",
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true, // We have custom flag handling to match HTCSS style.
		Run:                func(_ *cobra.Command, args []string) { stashPluginMain(args) },
	}

	rootPluginCmd.CompletionOptions.DisableDefaultCmd = true
	rootPluginCmd.AddCommand(xferCmd)
}

func stashPluginMain(args []string) {
	config.InitConfig()
	err := config.InitClient()
	if err != nil {
		log.Errorln(err)
		os.Exit(1)
	}

	// Parse command line arguments
	var upload bool = false
	// Set the options
	client.ObjectClientOptions.Recursive = false
	client.ObjectClientOptions.ProgressBars = false
	client.ObjectClientOptions.Version = version
	client.ObjectClientOptions.Plugin = true
	methods := []string{"http"}
	var infile, outfile, testCachePath string
	var useOutFile bool = false
	var getCaches bool = false

	// Pop the executable off the args list
	for len(args) > 0 {

		if args[0] == "-classad" {
			// Print classad and exit
			fmt.Println("MultipleFileSupport = true")
			fmt.Println("PluginVersion = \"" + version + "\"")
			fmt.Println("PluginType = \"FileTransfer\"")
			fmt.Println("SupportedMethods = \"stash, osdf\"")
			os.Exit(0)
		} else if args[0] == "-version" || args[0] == "-v" {
			fmt.Println("Version:", version)
			fmt.Println("Build Date:", date)
			fmt.Println("Build Commit:", commit)
			fmt.Println("Built By:", builtBy)
			os.Exit(0)
		} else if args[0] == "-upload" {
			log.Debugln("Upload detected")
			upload = true
		} else if args[0] == "-infile" {
			infile = args[1]
			args = args[1:]
			log.Debugln("Infile:", infile)
		} else if args[0] == "-outfile" {
			outfile = args[1]
			args = args[1:]
			useOutFile = true
			log.Debugln("Outfile:", outfile)
		} else if args[0] == "-d" {
			config.SetLogging(log.DebugLevel)
		} else if args[0] == "-get-caches" {
			if len(args) < 2 {
				log.Errorln("-get-caches requires an argument")
				os.Exit(1)
			}
			testCachePath = args[1]
			args = args[1:]
			getCaches = true
		} else if strings.HasPrefix(args[0], "-") {
			log.Errorln("Do not understand the option:", args[0])
			os.Exit(1)
		} else {
			// Must be the start of a source / destination
			break
		}
		// Pop off the args
		args = args[1:]
	}

	if getCaches {
		urls, err := client.GetCacheHostnames(testCachePath)
		if err != nil {
			log.Errorln("Failed to get cache URLs:", err)
			os.Exit(1)
		}

		cachesToTry := client.CachesToTry
		if cachesToTry > len(urls) {
			cachesToTry = len(urls)
		}

		for _, url := range urls[:cachesToTry] {
			fmt.Println(url)
		}
		os.Exit(0)
	}

	var source []string
	var dest string
	var result error
	//var downloaded int64 = 0
	var transfers []Transfer

	if len(args) == 0 && (infile == "" || outfile == "") {
		fmt.Fprint(os.Stderr, "No source or destination specified\n")
		os.Exit(1)
	}

	if len(args) == 0 {
		// Open the input and output files
		infileFile, err := os.Open(infile)
		if err != nil {
			log.Errorln("Failed to open infile:", err)
			os.Exit(1)
		}
		defer infileFile.Close()
		// Read in classad from stdin
		transfers, err = readMultiTransfers(*bufio.NewReader(infileFile))
		if err != nil {
			log.Errorln("Failed to read in from stdin:", err)
			os.Exit(1)
		}
	} else {
		source = args[:len(args)-1]
		dest = args[len(args)-1]
		for _, src := range source {
			transfers = append(transfers, Transfer{url: src, localFile: dest})
		}
	}

	// NOTE: HTCondor 23.3.0 and before would reuse the outfile names for multiple
	// transfers, meaning the results of prior plugin invocations would be present
	// by default in the outfile.  Combined with a bug that considered any exit code
	// besides `1` a success (note: a go panic is exit code `2`), this caused the starter
	// to incorrectly interpret plugin failures as successes, potentially leaving the user
	// with missing or truncated output files.
	//
	// By moving the truncation of the output file to a very early codepath, we reduce
	// the chances of hitting this problem.
	outputFile := os.Stdout
	if useOutFile {
		var err error
		outputFile, err = os.Create(outfile)
		if err != nil {
			log.Errorln("Failed to open outfile:", err)
			os.Exit(1)
		}
		defer outputFile.Close()
	}

	var resultAds []*classads.ClassAd
	retryable := false
	for _, transfer := range transfers {

		var tmpDownloaded int64
		if upload {
			source = append(source, transfer.localFile)
			log.Debugln("Uploading:", transfer.localFile, "to", transfer.url)
			tmpDownloaded, result = client.DoStashCPSingle(transfer.localFile, transfer.url, methods, false)
		} else {
			source = append(source, transfer.url)
			log.Debugln("Downloading:", transfer.url, "to", transfer.localFile)

			// When we want to auto-unpack files, we should do this to the containing directory, not the destination
			// file which HTCondor prepares
			url, err := url.Parse(transfer.url)
			if err != nil {
				result = errors.Wrap(err, "Unable to parse transfer source as a URL")
			} else {
				localFile := transfer.localFile
				if url.Query().Get("pack") != "" {
					localFile = filepath.Dir(localFile)
				}
				tmpDownloaded, result = client.DoStashCPSingle(transfer.url, localFile, methods, false)
			}
		}
		startTime := time.Now().Unix()
		resultAd := classads.NewClassAd()
		resultAd.Set("TransferStartTime", startTime)
		resultAd.Set("TransferEndTime", time.Now().Unix())
		hostname, _ := os.Hostname()
		resultAd.Set("TransferLocalMachineName", hostname)
		resultAd.Set("TransferProtocol", "stash")
		resultAd.Set("TransferUrl", transfer.url)
		resultAd.Set("TransferFileName", transfer.localFile)
		if upload {
			resultAd.Set("TransferType", "upload")
		} else {
			resultAd.Set("TransferType", "download")
		}
		if result == nil {
			resultAd.Set("TransferSuccess", true)
			resultAd.Set("TransferFileBytes", tmpDownloaded)
			resultAd.Set("TransferTotalBytes", tmpDownloaded)
		} else {
			resultAd.Set("TransferSuccess", false)
			if client.GetErrors() == "" {
				resultAd.Set("TransferError", result.Error())
			} else {
				errMsg := " Failure "
				if upload {
					errMsg += "uploading "
				} else {
					errMsg += "downloading "
				}
				errMsg += transfer.url + ": " + client.GetErrors()
				resultAd.Set("TransferError", errMsg)
				client.ClearErrors()
			}
			resultAd.Set("TransferFileBytes", 0)
			resultAd.Set("TransferTotalBytes", 0)
			if client.ErrorsRetryable() {
				resultAd.Set("TransferRetryable", true)
				retryable = true
			} else {
				resultAd.Set("TransferRetryable", false)
				retryable = false

			}
		}
		resultAds = append(resultAds, resultAd)

	}

	success := true
	for _, resultAd := range resultAds {
		_, err := outputFile.WriteString(resultAd.String() + "\n")
		if err != nil {
			log.Errorln("Failed to write to outfile:", err)
			os.Exit(1)
		}
		transferSuccess, err := resultAd.Get("TransferSuccess")
		if err != nil {
			log.Errorln("Failed to get TransferSuccess:", err)
			success = false
		}
		success = success && transferSuccess.(bool)
	}
	if err = outputFile.Sync(); err != nil {
		var perr *fs.PathError
		var serr syscall.Errno
		// Error code 1 (serr) is ERROR_INVALID_FUNCTION, the expected Windows syscall error
		// Error code EINVAL is returned on Linux
		// Error code ENODEV is returned on Mac OS X
		if errors.As(err, &perr) && errors.As(perr.Unwrap(), &serr) && (int(serr) == 1 || serr == syscall.EINVAL || serr == syscall.ENODEV) {
			log.Debugf("Error when syncing: %s; can be ignored\n", perr)
		} else {
			if errors.As(err, &perr) && errors.As(perr.Unwrap(), &serr) {
				log.Errorf("Failed to sync output file: %s (errno %d)", serr, int(serr))
			} else {
				log.Errorln("Failed to sync output file:", err)
			}
			os.Exit(1)
		}
	}

	if success {
		os.Exit(0)
	} else if retryable {
		os.Exit(11)
	} else {
		os.Exit(1)
	}
}

// readMultiTransfers reads the transfers from a Reader, such as stdin
func readMultiTransfers(stdin bufio.Reader) (transfers []Transfer, err error) {
	// Check stdin for a list of transfers
	ads, err := classads.ReadClassAd(&stdin)
	if err != nil {
		return nil, err
	}
	if ads == nil {
		return nil, errors.New("No transfers found")
	}
	for _, ad := range ads {
		url, err := ad.Get("Url")
		if err != nil {
			return nil, err
		}
		destination, err := ad.Get("LocalFileName")
		if err != nil {
			return nil, err
		}
		transfers = append(transfers, Transfer{url: url.(string), localFile: destination.(string)})
	}

	return transfers, nil
}
