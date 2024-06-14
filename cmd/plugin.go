/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/classads"
	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/utils"
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
	// Handler function to recover from panics
	defer func() {
		if r := recover(); r != nil {
			log.Warningln("Panic captured while attempting to perform transfer:", r)
			log.Warningln("Panic caused by the following", string(debug.Stack()))
			ret := fmt.Sprintf("Unrecoverable error (panic) captured in stashPluginMain(): %v", r)

			resultAd := classads.NewClassAd()
			var resultAds []*classads.ClassAd

			// Set as failure and add errors
			resultAd.Set("TransferSuccess", false)
			errMsg := writeTransferErrorMessage(ret+";"+strings.ReplaceAll(string(debug.Stack()), "\n", ";"), "")
			resultAd.Set("TransferError", errMsg)
			resultAds = append(resultAds, resultAd)

			// Attempt to write our file and bail
			writeClassadOutputAndBail(1, resultAds)

			os.Exit(1) //exit here just in case
		}
	}()

	var isConfigErr = false
	config.InitConfig()
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
		resultAd := classads.NewClassAd()
		var resultAds []*classads.ClassAd

		// Set as failure and add errors
		resultAd.Set("TransferSuccess", false)
		errMsg := writeTransferErrorMessage(configErr.Error(), "")
		resultAd.Set("TransferError", errMsg)
		if client.ShouldRetry(configErr) {
			resultAd.Set("TransferRetryable", true)
		} else {
			resultAd.Set("TransferRetryable", false)
		}
		resultAds = append(resultAds, resultAd)

		// Attempt to write our file and bail
		writeClassadOutputAndBail(1, resultAds)

		os.Exit(1) //exit here just in case
	}

	if getCaches {
		urls, err := client.GetCacheHostnames(context.Background(), testCachePath)
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

	results := make(chan *classads.ClassAd, 5)

	egrp.Go(func() error {
		return runPluginWorker(ctx, upload, workChan, results)
	})

	success := true
	var resultAds []*classads.ClassAd
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
			transferSuccess, err := resultAd.Get("TransferSuccess")
			if err != nil {
				log.Errorln("Failed to get TransferSuccess:", err)
				resultAd.Set("TransferSuccess", false)
				success = false
				transferSuccess = false
			}
			// If we are not uploading and we fail, we want to abort
			if !upload && !transferSuccess.(bool) {
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
func writeClassadOutputAndBail(exitCode int, resultAds []*classads.ClassAd) {
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
func runPluginWorker(ctx context.Context, upload bool, workChan <-chan PluginTransfer, results chan<- *classads.ClassAd) (err error) {
	te, err := client.NewTransferEngine(ctx)
	if err != nil {
		return
	}

	defer func() {
		if shutdownErr := te.Shutdown(); shutdownErr != nil && err == nil {
			err = shutdownErr
		}
	}()

	// Check for local cache
	var caches []*url.URL
	if nearestCache, ok := os.LookupEnv("NEAREST_CACHE"); ok && nearestCache != "" {
		caches, err = utils.GetPreferredCaches(nearestCache)
		if err != nil {
			return
		}
	} else if nearestCache, ok := os.LookupEnv("PELICAN_NEAREST_CACHE"); ok && nearestCache != "" {
		caches, err = utils.GetPreferredCaches(nearestCache)
		if err != nil {
			return
		}
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

			// Check we have valid query parameters
			err := utils.CheckValidQuery(transfer.url)
			if err != nil {
				failTransfer(transfer.url.String(), transfer.localFile, results, upload, err)
				return err
			}

			if transfer.url.Query().Has("recursive") {
				recursive = true
			} else {
				recursive = false
			}

			if upload {
				log.Debugln("Uploading:", transfer.localFile, "to", transfer.url)
			} else {
				log.Debugln("Downloading:", transfer.url, "to", transfer.localFile)

				// When we want to auto-unpack files, we should do this to the containing directory, not the destination
				// file which HTCondor prepares
				if transfer.url.Query().Get("pack") != "" {
					transfer.localFile = filepath.Dir(transfer.localFile)
				}
				transfer.localFile = parseDestination(transfer)
			}

			urlCopy := *transfer.url
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
		case result, ok := <-tc.Results():
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
			resultAd := classads.NewClassAd()
			// Set our DeveloperData:
			developerData := make(map[string]interface{})
			developerData["PelicanClientVersion"] = config.GetVersion()
			developerData["Attempts"] = len(result.Attempts)
			for _, attempt := range result.Attempts {
				developerData[fmt.Sprintf("TransferFileBytes%d", attempt.Number)] = attempt.TransferFileBytes
				developerData[fmt.Sprintf("TimeToFirstByte%d", attempt.Number)] = attempt.TimeToFirstByte.Round(time.Millisecond).Seconds()
				developerData[fmt.Sprintf("Endpoint%d", attempt.Number)] = attempt.Endpoint
				developerData[fmt.Sprintf("TransferEndTime%d", attempt.Number)] = attempt.TransferEndTime.Unix()
				developerData[fmt.Sprintf("ServerVersion%d", attempt.Number)] = attempt.ServerVersion
				developerData[fmt.Sprintf("TransferTime%d", attempt.Number)] = attempt.TransferTime.Round(time.Millisecond).Seconds()
				if attempt.CacheAge >= 0 {
					developerData[fmt.Sprintf("DataAge%d", attempt.Number)] = attempt.CacheAge.Round(time.Millisecond).Seconds()
				}
				if attempt.Error != nil {
					developerData[fmt.Sprintf("TransferError%d", attempt.Number)] = attempt.Error.Error()
				}
			}

			resultAd.Set("DeveloperData", developerData)

			resultAd.Set("TransferStartTime", result.TransferStartTime.Unix())
			resultAd.Set("TransferEndTime", time.Now().Unix())
			hostname, _ := os.Hostname()
			resultAd.Set("TransferLocalMachineName", hostname)
			resultAd.Set("TransferProtocol", result.Scheme)
			transfer := jobMap[result.ID()]
			resultAd.Set("TransferUrl", transfer.url.String())
			if upload {
				resultAd.Set("TransferType", "upload")
				resultAd.Set("TransferFileName", path.Base(transfer.localFile))
			} else {
				resultAd.Set("TransferType", "download")
				resultAd.Set("TransferFileName", path.Base(transfer.url.String()))
			}
			if result.Error == nil {
				resultAd.Set("TransferSuccess", true)
				resultAd.Set("TransferFileBytes", result.Attempts[len(result.Attempts)-1].TransferFileBytes)
				resultAd.Set("TransferTotalBytes", result.Attempts[len(result.Attempts)-1].TransferFileBytes)
			} else {
				resultAd.Set("TransferSuccess", false)
				var te *client.TransferErrors
				errMsgInternal := result.Error.Error()
				if errors.As(result.Error, &te) {
					errMsgInternal = te.UserError()
				}
				errMsg := writeTransferErrorMessage(errMsgInternal, transfer.url.String())
				resultAd.Set("TransferError", errMsg)
				resultAd.Set("TransferFileBytes", 0)
				resultAd.Set("TransferTotalBytes", 0)
				if client.ShouldRetry(result.Error) {
					resultAd.Set("TransferRetryable", true)
				} else {
					resultAd.Set("TransferRetryable", false)
				}
			}
			results <- resultAd
		}
	}
}

// This function is to be called to populate the result ads for a failed transfer
// This ensures that the needed classads are populated and sent to the results channel
func failTransfer(remoteUrl string, localFile string, results chan<- *classads.ClassAd, upload bool, err error) {
	resultAd := classads.NewClassAd()
	resultAd.Set("TransferUrl", remoteUrl)
	if upload {
		resultAd.Set("TransferType", "upload")
		resultAd.Set("TransferFileName", path.Base(localFile))
	} else {
		resultAd.Set("TransferType", "download")
		resultAd.Set("TransferFileName", path.Base(remoteUrl))
	}
	if client.IsRetryable(err) {
		resultAd.Set("TransferRetryable", true)
	} else {
		resultAd.Set("TransferRetryable", false)
	}
	resultAd.Set("TransferSuccess", false)
	resultAd.Set("TransferError", err.Error())

	results <- resultAd
}

// Gets the absolute path for the local destination. This is important
// especially for downloaded directories so that the downloaded files end up
// in the directory specified for download.
func parseDestination(transfer PluginTransfer) (parsedDest string) {
	// get absolute path
	destPath, _ := filepath.Abs(transfer.localFile)
	// Check if path exists or if its in a folder
	if destStat, err := os.Stat(destPath); os.IsNotExist(err) {
		return destPath
	} else if destStat.IsDir() {
		// If we are a directory, add the source filename to the destination dir
		sourceFilename := path.Base(transfer.url.Path)
		parsedDest = path.Join(destPath, sourceFilename)
		return parsedDest
	}
	return transfer.localFile
}

// WriteOutfile takes in the result ads from the job and the file to be outputted, it returns a boolean indicating:
// true: all result ads indicate transfer success
// false: at least one result ad has failed
// As well as a boolean letting us know if errors are retryable
func writeOutfile(err error, resultAds []*classads.ClassAd, outputFile *os.File) (success bool, retryable bool, writeErr error) {

	if err != nil {
		alreadyFailed := false
		for _, ad := range resultAds {
			succeeded, getErr := ad.Get("TransferSuccess")
			if getErr != nil || !(succeeded.(bool)) {
				alreadyFailed = true
				break
			}
		}
		if !alreadyFailed {
			resultAd := classads.NewClassAd()
			resultAd.Set("TransferSuccess", false)
			resultAd.Set("TransferError", err.Error())
			if client.ShouldRetry(err) {
				resultAd.Set("TransferRetryable", true)
			} else {
				resultAd.Set("TransferRetryable", false)
			}
			resultAds = append(resultAds, resultAd)
		}
	}
	success = true
	retryable = false
	for _, resultAd := range resultAds {
		// Condor expects the plugin to always return a TransferUrl and TransferFileName. Therefore,
		// we should populate them even if they are empty. If empty, the url/filename is most likely
		// included in the error stack already or it is not relevant to the error
		if url, _ := resultAd.Get("TransferUrl"); url == nil {
			log.Debugln("No URL found in result ad")
			resultAd.Set("TransferUrl", "")
		}
		if fileName, _ := resultAd.Get("TransferFileName"); fileName == nil {
			log.Debugln("No TransferFileName found in result ad")
			resultAd.Set("TransferFileName", "")
		}

		_, err = outputFile.WriteString(resultAd.String() + "\n")
		if err != nil {
			return false, false, errors.Wrap(err, "failed to write to outfile")
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
	ads, err := classads.ReadClassAd(&stdin)
	if err != nil {
		return nil, err
	}
	if ads == nil {
		return nil, errors.New("No transfers found")
	}
	for _, ad := range ads {
		adUrlStr, err := ad.Get("Url")
		if err != nil {
			// If we don't find a URL, we are assuming it is a classad used for other purposes
			// so keep searching for URL
			log.Debugln("Url attribute not set for transfer, skipping...")
			continue
		}

		if adUrlStr == nil {
			log.Debugln("Url attribute not set for transfer, skipping...")
			continue
		}

		adUrl, err := url.Parse(adUrlStr.(string))
		if err != nil {
			return nil, err
		}

		destination, err := ad.Get("LocalFileName")
		if err != nil {
			// If we don't find a local filename, we are assuming it is a classad used for other purposes
			// so keep searching for local filename
			log.Debugln("LocalFileName attribute not set for transfer, skipping...")
			continue
		}

		if destination == nil {
			log.Debugln("LocalFileName attribute not set for transfer, skipping...")
			continue
		}
		transfers = append(transfers, PluginTransfer{url: adUrl, localFile: destination.(string)})
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
		prefix = tUrl.Scheme + "://" + tUrl.Host
		urlRemainder := strings.TrimPrefix(transferUrl, prefix)
		errMsg = strings.ReplaceAll(errMsg, urlRemainder, "(...Path...)")
	}
	// HTCondor will already say whether it's an upload/download in its generated string;
	// save a few characters here
	errMsg = strings.ReplaceAll(errMsg, "failed download from", "from")

	errMsg += (" (Version: " + config.GetVersion())

	siteName := parseMachineAd()
	if siteName != "" {
		errMsg += "; Site: " + siteName + ")"
	} else {
		errMsg += ")"
	}

	return
}

// This function parses the machine ad present with a condor job to get the site name.
// Only really needed on the ospool, otherwise this will return ""
func parseMachineAd() string {
	var filename string
	//Parse the .job.ad file for the Owner (username) and ProjectName of the callee.
	if _, err := os.Stat(".machine.ad"); err == nil {
		filename = ".machine.ad"
	} else {
		return ""
	}

	// https://stackoverflow.com/questions/28574609/how-to-apply-regexp-to-content-in-file-go

	b, err := os.ReadFile(filename)
	if err != nil {
		log.Warningln("Can not read .machine.ad file", err)
		return ""
	}

	// Get all matches from file
	// Note: This appears to be invalid regex but is the only thing that appears to work. This way it successfully finds our matches
	classadRegex, e := regexp.Compile(`^*\s*(GLIDEIN_Site)\s=\s"(.*)"`)
	if e != nil {
		log.Fatal(e)
	}

	matches := classadRegex.FindAll(b, -1)
	for _, match := range matches {
		matchString := strings.TrimSpace(string(match))

		if strings.HasPrefix(matchString, "GLIDEIN_Site") {
			matchParts := strings.Split(strings.TrimSpace(matchString), "=")

			if len(matchParts) == 2 { // just confirm we get 2 parts of the string
				matchValue := strings.TrimSpace(matchParts[1])
				matchValue = strings.Trim(matchValue, "\"") //trim any "" around the match if present
				return matchValue
			}
		}
	}
	return ""
}
