/***************************************************************
*
* Copyright (C) 2025, University of Nebraska-Lincoln
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
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	classad "github.com/PelicanPlatform/classad/classad"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

var (
	// Holds the various plugin commands
	rootPluginCmd = &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management for HTCSS",
	}

	// Need these for recovery function if we want to try to write our classAd outfile
	useOutFile bool = false
	outfile    string
)

type PluginTransfer struct {
	url       *url.URL
	localFile string
}

type ExitCode int

const (
	Success ExitCode = iota
	Error
	FailedOutfile = 3
	Retryable     = 11
)

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
	viper.Set(param.Client_IsPlugin.GetName(), true)

	// Set up signal handlers to flush logs on SIGTERM
	client.SetupSignalHandlers()

	// Handler function to recover from panics
	defer func() {
		if r := recover(); r != nil {
			log.Warningln("Panic captured while attempting to perform transfer:", r)
			log.Warningln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in stashPluginMain(): %v", r)

			resultAd := classad.New()
			var resultAds []*classad.ClassAd

			// Set as failure and add errors
			err := resultAd.Set("TransferSuccess", false)
			if err != nil {
				log.Errorf("Failed to set TransferSuccess: %s", err)
			}
			errMsg := writeTransferErrorMessage(ret+";"+strings.ReplaceAll(string(debug.Stack()), "\n", ";"), "")
			err = resultAd.Set("TransferError", errMsg)
			if err != nil {
				log.Errorf("Failed to set TransferError: %s", err)
			}
			err = resultAd.Set("TransferRetryable", false) // Panics are not retryable
			if err != nil {
				log.Errorf("Failed to set TransferRetryable: %s", err)
			}

			// Add DeveloperData and TransferErrorData for panic errors
			panicErr := errors.New(ret)
			addDataToClassAd(resultAd, nil, panicErr, 1, nil, nil)

			resultAds = append(resultAds, resultAd)

			// Attempt to write our file and bail
			writeClassadOutputAndBail(1, resultAds)

			os.Exit(1) //exit here just in case
		}
	}()

	var isConfigErr = false
	configErr := config.InitClient()
	if configErr != nil {
		log.Errorf("Problem initializing the Pelican client config: %v", configErr)
		configErr = errors.Wrap(configErr, "Problem initializing the Pelican Client configuration")
		isConfigErr = true
	}

	// Want to try to force logging to stderr because that is how we can see logging in condor starter log
	log.SetOutput(os.Stderr)

	// Parse command line arguments
	var upload bool = false
	// Set the options
	var infile, testCachePath string
	var getCaches bool = false

	// Pop the executable off the args list
	for len(args) > 0 {
		if args[0] == "-classad" {
			// Print classad and exit
			fmt.Println("MultipleFileSupport = true")
			fmt.Println("PelicanPluginVersion = \"" + config.GetVersion() + "\"")
			fmt.Println("PluginVersion = \"" + config.GetVersion() + "\"")
			fmt.Println("PluginType = \"FileTransfer\"")
			fmt.Println("ProtocolVersion = 2")
			fmt.Println("SupportedMethods = \"stash, osdf, pelican\"")
			fmt.Println("StartdAttrs = \"PelicanPluginVersion\"")
			os.Exit(0)
		} else if args[0] == "-version" || args[0] == "-v" {
			config.PrintPelicanVersion(os.Stdout)
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
		resultAd := classad.New()
		var resultAds []*classad.ClassAd

		// Set as failure and add errors
		err := resultAd.Set("TransferSuccess", false)
		if err != nil {
			log.Errorf("Failed to set TransferSuccess: %s", err)
		}
		errMsg := writeTransferErrorMessage(configErr.Error(), "")
		err = resultAd.Set("TransferError", errMsg)
		if err != nil {
			log.Errorf("Failed to set TransferError: %s", err)
		}
		err = resultAd.Set("TransferRetryable", client.ShouldRetry(configErr))
		if err != nil {
			log.Errorf("Failed to set TransferRetryable: %s", err)
		}
		addDataToClassAd(resultAd, nil, configErr, 1, nil, nil)
		resultAds = append(resultAds, resultAd)

		// Attempt to write our file and bail
		writeClassadOutputAndBail(1, resultAds)

		os.Exit(1) //exit here just in case
	}

	if getCaches {
		urls, err := client.GetObjectServerHostnames(context.Background(), testCachePath)
		if err != nil {
			log.Errorln("Failed to get object server URLs:", err)
			os.Exit(1)
		}

		serversToTry := client.ObjectServersToTry
		if serversToTry > len(urls) {
			serversToTry = len(urls)
		}

		for _, url := range urls[:serversToTry] {
			fmt.Println(url)
		}
		os.Exit(0)
	}

	var source []string
	var dest string
	var transfers []PluginTransfer

	if len(args) == 0 && (infile == "" || outfile == "") {
		fmt.Fprint(os.Stderr, "No source or destination specified\n")
		os.Exit(1)
	}

	var workChan chan PluginTransfer
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
		workChan = make(chan PluginTransfer, len(transfers))
		for _, transfer := range transfers {
			workChan <- transfer
		}
	} else if len(args) > 1 {
		source = args[:len(args)-1]
		dest = args[len(args)-1]
		workChan = make(chan PluginTransfer, len(args)-1)
		for _, src := range source {
			srcUrl, err := url.Parse(src)
			if err != nil {
				log.Errorf("Failed to parse input URL (%s): %s", src, err)
			}
			workChan <- PluginTransfer{url: srcUrl, localFile: dest}
		}
	} else {
		log.Errorln("Must provide both source and destination as argument")
		os.Exit(1)
	}
	close(workChan)

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
			os.Exit(FailedOutfile) // unique error code to give us info
		}
		defer outputFile.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	egrp, _ := errgroup.WithContext(ctx)
	defer func() {
		err := egrp.Wait()
		if err != context.Canceled {
			log.Errorln("Error when shutting down worker:", err)
		}
	}()
	defer cancel()

	results := make(chan *classad.ClassAd, 5)

	egrp.Go(func() error {
		return runPluginWorker(ctx, upload, workChan, results)
	})

	success := true
	var resultAds []*classad.ClassAd
	done := false
	for !done {
		select {
		case <-ctx.Done():
			done = true
		case resultAd, ok := <-results:
			if !ok {
				done = true
				break
			}
			// Process results as soon as we get them
			transferSuccess, ok := classad.GetAs[bool](resultAd, "TransferSuccess")
			if !ok {
				log.Errorln("Failed to get TransferSuccess: TransferSuccess is not a boolean")
				err := resultAd.Set("TransferSuccess", false)
				if err != nil {
					log.Errorf("Failed to set TransferSuccess: %s", err)
				}
				success = false
				transferSuccess = false
			}
			// If we are not uploading and we fail, we want to abort
			if !upload && !transferSuccess {
				success = false
				// Add the final (failed) result to the resultAds
				resultAds = append(resultAds, resultAd)
				done = true
			} else { // Otherwise, we add to end result ads
				resultAds = append(resultAds, resultAd)
			}
		}
	}

	// Ensure all our workers are shut down.
	cancel()
	var err error
	if waitErr := egrp.Wait(); waitErr != nil && waitErr != context.Canceled {
		log.Errorln("Error when shutting down worker:", waitErr)
		success = false
		err = waitErr
	}

	tmpSuccess, retryable, err := writeOutfile(err, resultAds, outputFile)
	if err != nil {
		os.Exit(FailedOutfile)
	}
	success = tmpSuccess && success

	if success {
		os.Exit(0)
	} else if retryable {
		os.Exit(Retryable)
	} else {
		os.Exit(1)
	}
}

// This function is used if we get some error requiring us to bail
// We attempt to write and output file and call an exit(1)
// In the future if we get more unique exit codes, we can change the passed in exit code
func writeClassadOutputAndBail(exitCode int, resultAds []*classad.ClassAd) {
	// Attempt to write out outfile:
	outputFile := os.Stdout
	if useOutFile {
		log.Debugln("Attempting to write classad output file... ")
		var err error
		outputFile, err = os.Create(outfile)
		if err != nil {
			log.Errorln("Failed to open outfile:", err)
			os.Exit(FailedOutfile) // Code of 3 to let us know that the outfile failed to be created
		}
		defer outputFile.Close()
	}

	// We'll exit 3 in here if anything fails to write the file
	_, retryable, err := writeOutfile(nil, resultAds, outputFile)
	if err != nil {
		exitCode = FailedOutfile
	}

	if retryable {
		exitCode = 11
	}

	log.Errorln("Failure with pelican plugin. Exiting...")
	os.Exit(exitCode)
}

// runPluginWorker performs the appropriate download or upload functions for the plugin as well as
// writes the resultAds for each transfer
// Returns: resultAds and if an error given is retryable
func runPluginWorker(ctx context.Context, upload bool, workChan <-chan PluginTransfer, results chan<- *classad.ClassAd) (err error) {
	te, err := client.NewTransferEngine(ctx)
	if err != nil {
		return
	}

	defer func() {
		if shutdownErr := te.Shutdown(); shutdownErr != nil && err == nil {
			err = shutdownErr
		}
	}()

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		return errors.Wrap(err, "unable to determine whether to use any preferred caches")
	}

	tc, err := te.NewClient(client.WithAcquireToken(false))
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			tc.Cancel()
		}
	}()
	defer close(results)

	resultsChan := tc.Results()
	jobMap := make(map[string]PluginTransfer)
	var recursive bool
	var tj *client.TransferJob

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case transfer, ok := <-workChan:
			if !ok {
				tc.Close()
				workChan = nil
				break
			}

			pUrl, err := pelican_url.Parse(transfer.url.String(), []pelican_url.ParseOption{pelican_url.ValidateQueryParams(true), pelican_url.AllowUnknownQueryParams(true)}, nil)
			if err != nil {
				failTransfer(transfer.url.String(), transfer.localFile, results, upload, err)
				return err
			}

			if transfer.url.Query().Has(pelican_url.QueryRecursive) {
				recursive = true
			} else {
				recursive = false
			}

			if upload {
				log.Debugln("Uploading:", transfer.localFile, "to", transfer.url)
			} else {
				transfer.localFile = parseDestination(transfer)
				log.Debugln("Downloading:", transfer.url, "to", transfer.localFile)
			}

			urlCopy := *(pUrl.GetRawUrl())
			tj, err = tc.NewTransferJob(context.Background(), &urlCopy, transfer.localFile, upload, recursive, client.WithAcquireToken(false), client.WithCaches(caches...))
			if err != nil {
				failTransfer(transfer.url.String(), transfer.localFile, results, upload, err)
				return errors.Wrap(err, "Failed to create new transfer job")
			}
			jobMap[tj.ID()] = transfer

			if err = tc.Submit(tj); err != nil {
				failTransfer(transfer.url.String(), transfer.localFile, results, upload, err)
				return err
			}
		case result, ok := <-resultsChan:
			if !ok {
				log.Debugln("Client has no more results")
				// Check to be sure we did not have a lookup error
				ok, err = tj.GetLookupStatus()
				// If we did not complete lookup, something went wrong
				if !ok {
					err = errors.New("error occurred during job lookup")
				}
				return
			}
			log.Debugln("Got result from transfer client")
			resultAd := classad.New()

			// Add comprehensive transfer data to ClassAd
			addDataToClassAd(resultAd, &result, result.Error, len(result.Attempts), result.ClientChecksums, result.ServerChecksums)

			err := resultAd.Set("TransferStartTime", result.TransferStartTime.Unix())
			if err != nil {
				log.Errorf("Failed to set TransferStartTime: %s", err)
			}
			err = resultAd.Set("TransferEndTime", time.Now().Unix())
			if err != nil {
				log.Errorf("Failed to set TransferEndTime: %s", err)
			}
			hostname, _ := os.Hostname()
			err = resultAd.Set("TransferLocalMachineName", hostname)
			if err != nil {
				log.Errorf("Failed to set TransferLocalMachineName: %s", err)
			}
			err = resultAd.Set("TransferProtocol", result.Scheme)
			if err != nil {
				log.Errorf("Failed to set TransferProtocol: %s", err)
			}
			transfer := jobMap[result.ID()]
			err = resultAd.Set("TransferUrl", transfer.url.String())
			if err != nil {
				log.Errorf("Failed to set TransferUrl: %s", err)
			}
			if upload {
				err = resultAd.Set("TransferType", "upload")
				if err != nil {
					log.Errorf("Failed to set TransferType: %s", err)
				}
				err = resultAd.Set("TransferFileName", path.Base(transfer.localFile))
				if err != nil {
					log.Errorf("Failed to set TransferFileName: %s", err)
				}
			} else {
				err = resultAd.Set("TransferType", "download")
				if err != nil {
					log.Errorf("Failed to set TransferType: %s", err)
				}
				err = resultAd.Set("TransferFileName", path.Base(transfer.url.String()))
				if err != nil {
					log.Errorf("Failed to set TransferFileName: %s", err)
				}
			}
			if result.Error == nil {
				err = resultAd.Set("TransferSuccess", true)
				if err != nil {
					log.Errorf("Failed to set TransferSuccess: %s", err)
				}
				err = resultAd.Set("TransferFileBytes", result.Attempts[len(result.Attempts)-1].TransferFileBytes)
				if err != nil {
					log.Errorf("Failed to set TransferFileBytes: %s", err)
				}
				err = resultAd.Set("TransferTotalBytes", result.Attempts[len(result.Attempts)-1].TransferFileBytes)
				if err != nil {
					log.Errorf("Failed to set TransferTotalBytes: %s", err)
				}
			} else {
				err = resultAd.Set("TransferSuccess", false)
				if err != nil {
					log.Errorf("Failed to set TransferSuccess: %s", err)
				}
				var te *client.TransferErrors
				errMsgInternal := result.Error.Error()
				if errors.As(result.Error, &te) {
					errMsgInternal = te.UserError()
				} else {
					// If we have a PelicanError, prefer the wrapped error message to avoid noisy prefixes
					var pe *error_codes.PelicanError
					if errors.As(result.Error, &pe) {
						if innerErr := pe.Unwrap(); innerErr != nil {
							errMsgInternal = innerErr.Error()
						} else {
							errMsgInternal = pe.Error()
						}
					}
				}
				errMsg := writeTransferErrorMessage(errMsgInternal, transfer.url.String())
				err = resultAd.Set("TransferError", errMsg)
				if err != nil {
					log.Errorf("Failed to set TransferError: %s", err)
				}
				err = resultAd.Set("TransferFileBytes", 0)
				if err != nil {
					log.Errorf("Failed to set TransferFileBytes: %s", err)
				}
				err = resultAd.Set("TransferTotalBytes", 0)
				if err != nil {
					log.Errorf("Failed to set TransferTotalBytes: %s", err)
				}
				if client.ShouldRetry(result.Error) {
					err = resultAd.Set("TransferRetryable", true)
					if err != nil {
						log.Errorf("Failed to set TransferRetryable: %s", err)
					}
				} else {
					err = resultAd.Set("TransferRetryable", false)
					if err != nil {
						log.Errorf("Failed to set TransferRetryable: %s", err)
					}
				}
			}
			results <- resultAd
		}
	}
}

// This function is to be called to populate the result ads for a failed transfer
// This ensures that the needed classads are populated and sent to the results channel
func failTransfer(remoteUrl string, localFile string, results chan<- *classad.ClassAd, upload bool, err error) {
	resultAd := classad.New()
	adErr := resultAd.Set("TransferUrl", remoteUrl)
	if adErr != nil {
		log.Errorf("Failed to set TransferUrl: %s", adErr)
	}
	if upload {
		adErr = resultAd.Set("TransferType", "upload")
		if adErr != nil {
			log.Errorf("Failed to set TransferType: %s", adErr)
		}
		adErr = resultAd.Set("TransferFileName", path.Base(localFile))
		if adErr != nil {
			log.Errorf("Failed to set TransferFileName: %s", adErr)
		}
	} else {
		adErr = resultAd.Set("TransferType", "download")
		if adErr != nil {
			log.Errorf("Failed to set TransferType: %s", adErr)
		}
		adErr = resultAd.Set("TransferFileName", path.Base(remoteUrl))
		if adErr != nil {
			log.Errorf("Failed to set TransferFileName: %s", adErr)
		}
	}
	adErr = resultAd.Set("TransferRetryable", client.IsRetryable(err))
	if adErr != nil {
		log.Errorf("Failed to set TransferRetryable: %s", adErr)
	}
	adErr = resultAd.Set("TransferSuccess", false)
	if adErr != nil {
		log.Errorf("Failed to set TransferSuccess: %s", adErr)
	}
	adErr = resultAd.Set("TransferError", err.Error())
	if adErr != nil {
		log.Errorf("Failed to set TransferError: %s", adErr)
	}

	// Add DeveloperData and TransferErrorData for early failures (e.g., director lookup failures)
	// This ensures errors can be properly classified even when they occur before transfer attempts
	addDataToClassAd(resultAd, nil, err, 1, nil, nil)

	results <- resultAd
}

// Gets the absolute path for the local destination. This is important
// especially for downloaded directories so that the downloaded files end up
// in the directory specified for download.
func parseDestination(transfer PluginTransfer) (parsedDest string) {
	// get absolute path
	destPath, _ := filepath.Abs(transfer.localFile)

	// When we want to auto-unpack files, we should do this to the containing directory, not the destination
	// file which HTCondor prepares
	isPack := transfer.url.Query().Get("pack") != ""
	if isPack {
		destPath = filepath.Dir(transfer.localFile)
	}

	// Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		return destPath
	} else if destStat.IsDir() && !isPack {
		// If we are a directory, add the source filename to the destination dir
		sourceFilename := path.Base(transfer.url.Path)
		parsedDest = path.Join(destPath, sourceFilename)
		return parsedDest
	}

	return destPath
}

// WriteOutfile takes in the result ads from the job and the file to be outputted, it returns a boolean indicating:
// true: all result ads indicate transfer success
// false: at least one result ad has failed
// As well as a boolean letting us know if errors are retryable
func writeOutfile(err error, resultAds []*classad.ClassAd, outputFile *os.File) (success bool, retryable bool, writeErr error) {

	if err != nil {
		alreadyFailed := false
		for _, ad := range resultAds {
			succeeded, ok := classad.GetAs[bool](ad, "TransferSuccess")
			if !ok || !succeeded {
				alreadyFailed = true
				break
			}
		}
		if !alreadyFailed {
			resultAd := classad.New()
			if adErr := resultAd.Set("TransferSuccess", false); adErr != nil {
				log.Errorf("Failed to set TransferSuccess: %s", adErr)
			}
			if adErr := resultAd.Set("TransferError", err.Error()); adErr != nil {
				log.Errorf("Failed to set TransferError: %s", adErr)
			}
			if adErr := resultAd.Set("TransferRetryable", client.ShouldRetry(err)); adErr != nil {
				log.Errorf("Failed to set TransferRetryable: %s", adErr)
			}
			addDataToClassAd(resultAd, nil, err, 1, nil, nil)
			resultAds = append(resultAds, resultAd)
		}
	}
	success = true
	retryable = false
	for _, resultAd := range resultAds {
		// Condor expects the plugin to always return a TransferUrl and TransferFileName. Therefore,
		// we should populate them even if they are empty. If empty, the url/filename is most likely
		// included in the error stack already or it is not relevant to the error
		if url, ok := classad.GetAs[string](resultAd, "TransferUrl"); !ok || url == "" {
			log.Debugln("No URL found in result ad")
			adErr := resultAd.Set("TransferUrl", "")
			if adErr != nil {
				log.Errorf("Failed to set TransferUrl: %s", adErr)
			}
		}
		if fileName, ok := classad.GetAs[string](resultAd, "TransferFileName"); !ok || fileName == "" {
			log.Debugln("No TransferFileName found in result ad")
			adErr := resultAd.Set("TransferFileName", "")
			if adErr != nil {
				log.Errorf("Failed to set TransferFileName: %s", adErr)
			}
		}

		_, adErr := outputFile.WriteString(resultAd.String() + "\n")
		if adErr != nil {
			return false, false, errors.Wrap(adErr, "failed to write to outfile")
		}
		transferSuccess, ok := classad.GetAs[bool](resultAd, "TransferSuccess")
		if !ok || !transferSuccess {
			success = false
			// If we do not get a success, check if it is retryable
			retryableTransfer, ok := classad.GetAs[bool](resultAd, "TransferRetryable")
			if !ok {
				log.Errorln("Failed to get TransferRetryable: TransferRetryable is not a boolean")
				retryable = false
			} else {
				retryable = retryableTransfer
			}
		}
	}
	if err := outputFile.Sync(); err != nil {
		var perr *fs.PathError
		var serr syscall.Errno
		// Error code 1 (serr) is ERROR_INVALID_FUNCTION, the expected Windows syscall error
		// Error code EINVAL is returned on Linux
		// Error code ENODEV (/dev/null) or ENOTTY (/dev/stdout) is returned on Mac OS X
		// Error code EBADF is returned on Mac OS X if /dev/stdout is redirected to a pipe in the shell
		if errors.As(err, &perr) && errors.As(perr.Unwrap(), &serr) && (int(serr) == 1 || serr == syscall.EINVAL || serr == syscall.ENODEV || serr == syscall.ENOTTY || serr == syscall.EBADF) {
			log.Debugf("Error when syncing: %s; can be ignored\n", perr)
		} else {
			if errors.As(err, &perr) && errors.As(perr.Unwrap(), &serr) {
				log.Errorf("Failed to sync output file (%s): %s (errno %d)", outputFile.Name(), serr, int(serr))
			} else {
				log.Errorf("Failed to sync output file (%s): %s", outputFile.Name(), err)
			}
			return false, false, errors.Wrap(err, "failed to sync output file")
		}
	}
	return success, retryable, nil
}

// readMultiTransfers reads the transfers from a Reader, such as stdin
func readMultiTransfers(stdin bufio.Reader) (transfers []PluginTransfer, err error) {
	// Check stdin for a list of transfers
	adsIter := classad.All(&stdin)
	for ad := range adsIter {
		adUrlStr, ok := ad.EvaluateAttrString("Url")
		if !ok || adUrlStr == "" {
			// If we don't find a URL, we are assuming it is a classad used for other purposes
			// so keep searching for URL
			log.Debugln("Url attribute not set for transfer, skipping...")
			continue
		}

		adUrl, err := url.Parse(adUrlStr)
		if err != nil {
			return nil, err
		}

		destination, ok := ad.EvaluateAttrString("LocalFileName")
		if !ok || destination == "" {
			// If we don't find a local filename, we are assuming it is a classad used for other purposes
			// so keep searching for local filename
			log.Debugln("LocalFileName attribute not set for transfer, skipping...")
			continue
		}
		transfers = append(transfers, PluginTransfer{url: adUrl, localFile: destination})
	}
	if len(transfers) == 0 {
		return nil, errors.New("No transfers found in infile")
	}

	return transfers, nil
}

// This function wraps the transfer error message into a more readable and user-friendly format.
func writeTransferErrorMessage(currentError string, transferUrl string) (errMsg string) {

	errMsg = "Pelican Client Error: "

	errMsg += currentError
	if tUrl, err := url.Parse(transferUrl); transferUrl != "" && err == nil {
		prefix := tUrl.Scheme + "://" + tUrl.Host
		urlRemainder := strings.TrimPrefix(transferUrl, prefix)
		errMsg = strings.ReplaceAll(errMsg, urlRemainder, "(...Path...)")
	}
	// HTCondor will already say whether it's an upload/download in its generated string;
	// save a few characters here
	errMsg = strings.ReplaceAll(errMsg, "failed download from", "from")

	errMsg += (" (Version: " + config.GetVersion())

	siteName, hostName := parseMachineAd()
	if siteName != "" {
		errMsg += "; Site: " + siteName
	}
	if hostName != "" {
		errMsg += "; Hostname: " + hostName + ")"
	} else {
		errMsg += ")"
	}

	return
}

// createTransferError creates a transfer error map with developer data
func createTransferError(err error) (transferError *classad.ClassAd) {
	transferError = classad.New()
	developerData := classad.New()

	isRetryable := client.IsRetryable(err)

	var pe *error_codes.PelicanError
	if errors.As(err, &pe) {
		err := developerData.Set("PelicanErrorCode", int64(pe.Code()))
		if err != nil {
			log.Errorf("Failed to set PelicanErrorCode: %s", err)
		}
		err = developerData.Set("Retryable", isRetryable)
		if err != nil {
			log.Errorf("Failed to set Retryable: %s", err)
		}
		err = developerData.Set("ErrorType", pe.ErrorType())
		if err != nil {
			log.Errorf("Failed to set ErrorType: %s", err)
		}

		// Use the wrapped error's message if available, otherwise use the PelicanError's full error message
		if innerErr := pe.Unwrap(); innerErr != nil {
			err = developerData.Set("ErrorMessage", innerErr.Error())
			if err != nil {
				log.Errorf("Failed to set ErrorMessage: %s", err)
			}
		} else {
			err = developerData.Set("ErrorMessage", pe.Error())
			if err != nil {
				log.Errorf("Failed to set ErrorMessage: %s", err)
			}
		}

		// Extract the high-level error category (first part before the dot)
		errorType := pe.ErrorType()
		if idx := strings.Index(errorType, "."); idx > 0 {
			err := transferError.Set("ErrorType", errorType[:idx])
			if err != nil {
				log.Errorf("Failed to set ErrorType: %s", err)
			}
		} else {
			err := transferError.Set("ErrorType", errorType)
			if err != nil {
				log.Errorf("Failed to set ErrorType: %s", err)
			}
		}
	} else {
		// Fallback for errors that aren't wrapped in PelicanError
		err = developerData.Set("PelicanErrorCode", 0)
		if err != nil {
			log.Errorf("Failed to set PelicanErrorCode: %s", err)
		}
		if err != nil {
			log.Errorf("Failed to set PelicanErrorCode: %s", err)
		}
		err = developerData.Set("ErrorType", "Unprocessed")
		if err != nil {
			log.Errorf("Failed to set ErrorType: %s", err)
		}
		err = developerData.Set("Retryable", isRetryable)
		if err != nil {
			log.Errorf("Failed to set Retryable: %s", err)
		}
		err = developerData.Set("ErrorMessage", "Unprocessed error type")
		if err != nil {
			log.Errorf("Failed to set ErrorMessage: %s", err)
		}
		err = transferError.Set("ErrorType", "Unprocessed")
		if err != nil {
			log.Errorf("Failed to set ErrorType: %s", err)
		}
	}
	err = transferError.Set("DeveloperData", developerData)
	if err != nil {
		log.Errorf("Failed to set DeveloperData: %s", err)
	}
	return transferError
}

// addDataToClassAd is a helper function that adds DeveloperData and TransferErrorData to a ClassAd
func addDataToClassAd(resultAd *classad.ClassAd, result *client.TransferResults, err error, attempts int, clientChecksums, serverChecksums []client.ChecksumInfo) {
	developerData := classad.New()
	var transferErrorData []*classad.ClassAd

	// Add duplicate fields into DeveloperData for backward compatibility
	adErr := developerData.Set("PelicanClientVersion", config.GetVersion())
	if adErr != nil {
		log.Errorf("Failed to set PelicanClientVersion: %s", adErr)
	}
	adErr = developerData.Set("Attempts", attempts)
	if adErr != nil {
		log.Errorf("Failed to set Attempts: %s", adErr)
	}

	// Handle per-attempt data if we have transfer results
	if result != nil {
		for _, attempt := range result.Attempts {
			adErr := developerData.Set(fmt.Sprintf("TransferFileBytes%d", attempt.Number), int64(attempt.TransferFileBytes))
			if adErr != nil {
				log.Errorf("Failed to set TransferFileBytes%d: %s", attempt.Number, adErr)
			}
			adErr = developerData.Set(fmt.Sprintf("TimeToFirstByte%d", attempt.Number), attempt.TimeToFirstByte.Round(time.Millisecond).Seconds())
			if adErr != nil {
				log.Errorf("Failed to set TimeToFirstByte%d: %s", attempt.Number, adErr)
			}
			adErr = developerData.Set(fmt.Sprintf("Endpoint%d", attempt.Number), attempt.Endpoint)
			if adErr != nil {
				log.Errorf("Failed to set Endpoint%d: %s", attempt.Number, adErr)
			}
			adErr = developerData.Set(fmt.Sprintf("TransferEndTime%d", attempt.Number), attempt.TransferEndTime.Unix())
			if adErr != nil {
				log.Errorf("Failed to set TransferEndTime%d: %s", attempt.Number, adErr)
			}
			adErr = developerData.Set(fmt.Sprintf("ServerVersion%d", attempt.Number), attempt.ServerVersion)
			if adErr != nil {
				log.Errorf("Failed to set ServerVersion%d: %s", attempt.Number, adErr)
			}
			adErr = developerData.Set(fmt.Sprintf("TransferTime%d", attempt.Number), attempt.TransferTime.Round(time.Millisecond).Seconds())
			if adErr != nil {
				log.Errorf("Failed to set TransferTime%d: %s", attempt.Number, adErr)
			}
			if attempt.CacheAge >= 0 {
				adErr = developerData.Set(fmt.Sprintf("DataAge%d", attempt.Number), attempt.CacheAge.Round(time.Millisecond).Seconds())
				if adErr != nil {
					log.Errorf("Failed to set DataAge%d: %s", attempt.Number, adErr)
				}
			}
			if attempt.Error != nil {
				adErr := developerData.Set(fmt.Sprintf("TransferError%d", attempt.Number), attempt.Error.Error())
				if adErr != nil {
					log.Errorf("Failed to set TransferError%d: %s", attempt.Number, adErr)
				}
				adErr = developerData.Set(fmt.Sprintf("IsRetryable%d", attempt.Number), client.IsRetryable(attempt.Error))
				if adErr != nil {
					log.Errorf("Failed to set IsRetryable%d: %s", attempt.Number, adErr)
				}
				transferError := createTransferError(attempt.Error)
				transferErrorData = append(transferErrorData, transferError)
			}
		}
	}

	// Handle early failures (simple error case or transfer results with no attempts)
	if err != nil && ((attempts == 1 && result == nil) || (result != nil && len(result.Attempts) == 0)) {
		adErr = developerData.Set("TransferError1", err.Error())
		if adErr != nil {
			log.Errorf("Failed to set TransferError1: %s", adErr)
		}
		adErr = developerData.Set("IsRetryable1", client.IsRetryable(err))
		if adErr != nil {
			log.Errorf("Failed to set IsRetryable1: %s", adErr)
		}
		transferError := createTransferError(err)
		transferErrorData = append(transferErrorData, transferError)
	}

	// Add checksum information if provided
	if len(clientChecksums) > 0 {
		clientChecksumsData := classad.New()
		for _, checksum := range clientChecksums {
			adErr = clientChecksumsData.Set(client.HttpDigestFromChecksum(checksum.Algorithm), hex.EncodeToString(checksum.Value))
			if adErr != nil {
				log.Errorf("Failed to set ClientChecksums: %s", adErr)
			}
		}
		adErr = developerData.Set("ClientChecksums", clientChecksumsData)
		if adErr != nil {
			log.Errorf("Failed to set ClientChecksums: %s", adErr)
		}
	}
	if len(serverChecksums) > 0 {
		serverChecksumsData := classad.New()
		for _, checksum := range serverChecksums {
			adErr = serverChecksumsData.Set(client.HttpDigestFromChecksum(checksum.Algorithm), hex.EncodeToString(checksum.Value))
			if adErr != nil {
				log.Errorf("Failed to set ServerChecksums: %s", adErr)
			}
		}
		adErr = developerData.Set("ServerChecksums", serverChecksumsData)
		if adErr != nil {
			log.Errorf("Failed to set ServerChecksums: %s", adErr)
		}
	}

	adErr = resultAd.Set("DeveloperData", developerData)
	if adErr != nil {
		log.Errorf("Failed to set DeveloperData: %s", adErr)
	}
	if len(transferErrorData) > 0 {
		adErr = resultAd.Set("TransferErrorData", transferErrorData)
		if adErr != nil {
			log.Errorf("Failed to set TransferErrorData: %s", adErr)
		}
	}
}

// This function parses the machine ad present with a condor job to get the site name and the physical hostname if run
// on a K8S setup.
// Only really needed on the ospool, otherwise this will return ""
func parseMachineAd() (string, string) {
	var filename string
	//Parse the .job.ad file for the Owner (username) and ProjectName of the callee.
	if _, err := os.Stat(".machine.ad"); err == nil {
		filename = ".machine.ad"
	} else {
		return "", ""
	}

	// https://stackoverflow.com/questions/28574609/how-to-apply-regexp-to-content-in-file-go

	b, err := os.ReadFile(filename)
	if err != nil {
		log.Warningln("Can not read .machine.ad file", err)
		return "", ""
	}

	// Get all matches from file
	// Note: This appears to be invalid regex but is the only thing that appears to work. This way it successfully finds our matches
	classadRegex, e := regexp.Compile(`^*\s*(GLIDEIN_Site)\s=\s"(.*)"`)
	if e != nil {
		log.Fatal(e)
	}

	siteMatchValue := ""
	matches := classadRegex.FindAll(b, -1)
	for _, match := range matches {
		matchString := strings.TrimSpace(string(match))

		if strings.HasPrefix(matchString, "GLIDEIN_Site") {
			matchParts := strings.Split(strings.TrimSpace(matchString), "=")

			if len(matchParts) == 2 { // just confirm we get 2 parts of the string
				siteMatchValue = strings.TrimSpace(matchParts[1])
				siteMatchValue = strings.Trim(siteMatchValue, "\"") //trim any "" around the match if present
				break
			}
		}
	}

	classadRegex, e = regexp.Compile(`^*\s*(K8SPhysicalHostName)\s=\s"(.*)"`)
	if e != nil {
		log.Fatal(e)
	}

	hostMatchValue := ""
	matches = classadRegex.FindAll(b, -1)
	for _, match := range matches {
		matchString := strings.TrimSpace(string(match))

		if strings.HasPrefix(matchString, "K8SPhysicalHostName") {
			matchParts := strings.Split(strings.TrimSpace(matchString), "=")

			if len(matchParts) == 2 { // just confirm we get 2 parts of the string
				hostMatchValue = strings.TrimSpace(matchParts[1])
				hostMatchValue = strings.Trim(hostMatchValue, "\"") //trim any "" around the match if present
				break
			}
		}
	}
	return siteMatchValue, hostMatchValue
}
