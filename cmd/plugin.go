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
	"runtime/debug"
	"strings"
	"sync"
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

	// Need these for recovery function if we want to try to write our classAd outfile
	useOutFile bool = false
	outfile    string
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
	// Handler function to recover from panics
	defer func() {
		if r := recover(); r != nil {
			log.Debugln("Panic captured while attempting to perform transfer:", r)
			log.Debugln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in stashPluginMain(): %v", r)

			debugStack := strings.ReplaceAll(string(debug.Stack()), "\n", ";")
			client.AddError(errors.New(debugStack))

			// Attempt to add the panic to the error accumulator
			client.AddError(errors.New(ret))

			// Write our important classAds
			resultAd := classads.NewClassAd()
			var resultAds []*classads.ClassAd

			// Set as failure and add errors
			resultAd.Set("TransferSuccess", false)
			resultAd.Set("TransferError", client.GetErrors())
			resultAds = append(resultAds, resultAd)

			// Attempt to write our file and bail
			writeClassadOutputAndBail(1, resultAds)

			os.Exit(1) //exit here just in case
		}
	}()

	var isConfigErr = false
	config.InitConfig()
	err := config.InitClient()
	if err != nil {
		log.Errorf("Problem initializing the Pelican client config: %v", err)
		err = errors.Wrap(err, "Problem initializing the Pelican Client configuration")
		client.AddError(err)
		isConfigErr = true
	}

	// Parse command line arguments
	var upload bool = false
	// Set the options
	client.ObjectClientOptions.Recursive = false
	client.ObjectClientOptions.ProgressBars = false
	client.ObjectClientOptions.Version = version
	client.ObjectClientOptions.Plugin = true
	methods := []string{"http"}
	var infile, testCachePath string
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

	// Want to bail here for config fail to see if we want to write an outfile
	if isConfigErr {
		// Write our important classAds
		resultAd := classads.NewClassAd()
		var resultAds []*classads.ClassAd

		// Set as failure and add errors
		resultAd.Set("TransferSuccess", false)
		resultAd.Set("TransferError", client.GetErrors())
		resultAds = append(resultAds, resultAd)

		// Attempt to write our file and bail
		writeClassadOutputAndBail(1, resultAds)

		os.Exit(1) //exit here just in case
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
			os.Exit(3) // unique error code to give us info
		}
		defer outputFile.Close()
	}

	var wg sync.WaitGroup

	workChan := make(chan Transfer, len(transfers))
	results := make(chan *classads.ClassAd, len(transfers))

	// Start workers
	for i := 1; i <= 5; i++ {
		wg.Add(1)
		go moveObjects(source, methods, upload, &wg, workChan, results)
	}

	success := true
	var resultAds []*classads.ClassAd
	counter := 0
	done := false
	for !done {
		// Send to work channel the amount of transfers we have
		if counter < len(transfers) {
			workChan <- transfers[counter]
			counter++
		} else if counter == len(transfers) { // Once we sent all the work, close the channel
			close(workChan)
			// Increment counter so we no longer hit this case
			counter++
		}
		select {
		case resultAd := <-results:
			// Process results as soon as we get them
			transferSuccess, err := resultAd.Get("TransferSuccess")
			if err != nil {
				log.Errorln("Failed to get TransferSuccess:", err)
				success = false
			}
			// If we are not uploading and we fail, we want to abort
			if !upload && !transferSuccess.(bool) {
				success = false
				// Add the final (failed) result to the resultAds
				resultAds = append(resultAds, resultAd)
				done = true
				break
			} else { // Otherwise, we add to end result ads
				resultAds = append(resultAds, resultAd)
			}
		default:
			// We are either done or still downloading/uploading
			if len(resultAds) == len(transfers) {
				log.Debugln("Finished transfering objects! :)")
				done = true
				break
			}
		}
	}

	// Wait for transfers only if successful
	if success {
		wg.Wait()
	}

	close(results)

	success, retryable := writeOutfile(resultAds, outputFile)

	if success {
		os.Exit(0)
	} else if retryable {
		os.Exit(11)
	} else {
		os.Exit(1)
	}
}

// This function is used if we get some error requiring us to bail
// We attempt to write and output file and call an exit(1)
// In the future if we get more unique exit codes, we can change the passed in exit code
func writeClassadOutputAndBail(exitCode int, resultAds []*classads.ClassAd) {
	// Attempt to write out outfile:
	outputFile := os.Stdout
	if useOutFile {
		var err error
		outputFile, err = os.Create(outfile)
		if err != nil {
			log.Errorln("Failed to open outfile:", err)
			os.Exit(3) // Code of 3 to let us know that the outfile failed to be created
		}
		defer outputFile.Close()
	}

	// We'll exit 3 in here if anything fails to write the file
	writeOutfile(resultAds, outputFile)

	log.Errorln("Failure with pelican plugin. Exiting...")
	os.Exit(exitCode)
}

// moveObjects performs the appropriate download or upload functions for the plugin as well as
// writes the resultAds for each transfer
// Returns: resultAds and if an error given is retryable
func moveObjects(source []string, methods []string, upload bool, wg *sync.WaitGroup, workChan <-chan Transfer, results chan<- *classads.ClassAd) {
	defer wg.Done()
	var result error
	for transfer := range workChan {
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
			}
			resultAd.Set("TransferFileBytes", 0)
			resultAd.Set("TransferTotalBytes", 0)
			if client.ErrorsRetryable() {
				resultAd.Set("TransferRetryable", true)
			} else {
				resultAd.Set("TransferRetryable", false)
			}
			client.ClearErrors()
		}
		results <- resultAd
	}
}

// WriteOutfile takes in the result ads from the job and the file to be outputted, it returns a boolean indicating:
// true: all result ads indicate transfer success
// false: at least one result ad has failed
// As well as a boolean letting us know if errors are retryable
func writeOutfile(resultAds []*classads.ClassAd, outputFile *os.File) (bool, bool) {
	success := true
	retryable := false
	for _, resultAd := range resultAds {
		_, err := outputFile.WriteString(resultAd.String() + "\n")
		if err != nil {
			log.Errorln("Failed to write to outfile:", err)
			os.Exit(3)
		}
		transferSuccess, err := resultAd.Get("TransferSuccess")
		if err != nil {
			log.Errorln("Failed to get TransferSuccess:", err)
			success = false
		}
		success = success && transferSuccess.(bool)
		// If we do not get a success, check if it is retryable
		if !success {
			retryableTransfer, err := resultAd.Get("TransferRetryable")
			if err != nil {
				log.Errorln("Failed to see if ad is retryable", err)
			}
			if retryableTransfer != nil {
				retryable = retryableTransfer.(bool)
			}
		}
	}
	if err := outputFile.Sync(); err != nil {
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
			os.Exit(3) // Unique error code to let us know the outfile could not be created
		}
	}
	return success, retryable
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
