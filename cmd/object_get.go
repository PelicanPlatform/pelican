//go:build client

/***************************************************************
*
* Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	getCmd = &cobra.Command{
		Use:   "get {source ...} {destination}",
		Short: "Get a file from a Pelican federation",
		Run:   getMain,
		PreRun: func(cmd *cobra.Command, args []string) {
			commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
		},
	}
)

func init() {
	flagSet := getCmd.Flags()
	flagSet.StringP("cache", "c", "", `A comma-separated list of preferred caches to try for the transfer, where a "+" in the list indicates
the client should fallback to discovered caches if all preferred caches fail.`)
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.String("source-token", "", "Token file for the source (overrides --token for reads)")
	flagSet.BoolP("recursive", "r", false, "Recursively download a collection.  Forces methods to only be http to get the freshest collection contents")
	flagSet.Bool("inplace", false, "Write files directly to destination (default: use temporary files)")
	flagSet.Bool("dry-run", false, "Show what would be downloaded without actually downloading")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true
	flagSet.String("caches", "", "A JSON file containing the list of caches")
	flagSet.String("transfer-stats", "", "A path to a file to write transfer statistics to")
	flagSet.String("pack", "", "Package transfer using remote packing functionality (same as '?pack=' query). Options: auto, tar, tar.gz, tar.xz, zip. Default: auto when flag is provided without an explicit value")
	flagSet.Bool("direct", false, "Download directly from an origin, bypassing any caches (same as '?directread' query)")
	flagSet.Bool("async", false, "Run the transfer asynchronously through the client API server and return a job ID")
	flagSet.Bool("wait", false, "When used with --async, wait for the job to complete before returning")
	objectCmd.AddCommand(getCmd)
}

func getMain(cmd *cobra.Command, args []string) {
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

	// Check for async mode
	isAsync, _ := cmd.Flags().GetBool("async")
	if isAsync {
		// Validate arguments
		if len(args) < 2 {
			exitWithError(1, "No Source or Destination\nTry 'pelican object get --help' for more information.")
		}
		source := args[:len(args)-1]
		dest := args[len(args)-1]

		// Ensure server is running, starting it if necessary
		apiClient, err := ensureClientAgentRunning(cmd.Context(), 5)
		if err != nil {
			reportError("Failed to ensure API server is running:", err)
			exitWithError(1, "You can manually start it with 'pelican client-api serve --daemonize'")
		}

		// Get flags for transfer options
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		tokenLocation, _ := cmd.Flags().GetString("token")
		packOption, _ := cmd.Flags().GetString("pack")

		// Get preferred caches
		caches, err := getPreferredCaches()
		if err != nil {
			exitWithError(1, "Failed to get preferred caches:", err)
		}

		// Convert caches to strings
		cacheStrings := make([]string, len(caches))
		for i, cache := range caches {
			cacheStrings[i] = cache.String()
		}

		// Build transfer options
		options := client_agent.TransferOptions{
			Token:      tokenLocation,
			Caches:     cacheStrings,
			PackOption: packOption,
		}

		// Create transfers for each source
		transfers := make([]client_agent.TransferRequest, len(source))
		for i, src := range source {
			transfers[i] = client_agent.TransferRequest{
				Operation:   "get",
				Source:      src,
				Destination: dest,
				Recursive:   isRecursive,
			}
		}

		// Warm the wallet (interactively) and open the agent's wallet so the
		// agent can authorize the transfer non-interactively. Skipped when an
		// explicit token file was provided.
		if tokenLocation == "" {
			warmItems := make([]asyncWarmItem, len(source))
			for i, src := range source {
				warmItems[i] = asyncWarmItem{url: src, write: false}
			}
			if err := warmWalletForAsync(ctx, apiClient, warmItems); err != nil {
				exitWithError(1, "Failed to prepare credentials for async transfer:", err)
			}
		}

		// Create job
		jobID, err := apiClient.CreateJob(ctx, transfers, options)
		if err != nil {
			exitWithError(1, "Failed to create job:", err)
		}

		if outputJSON {
			result := map[string]interface{}{
				"job_id": jobID,
				"status": "created",
			}
			jsonBytes, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				exitWithError(1, "Failed to marshal JSON:", err)
			}
			fmt.Println(string(jsonBytes))
		} else {
			fmt.Printf("Job created: %s\n", jobID)
		}

		// Check if we should wait for completion
		shouldWait, _ := cmd.Flags().GetBool("wait")
		if shouldWait {
			if !outputJSON {
				fmt.Println("Waiting for job to complete...")
			}

			// Wait with a reasonable timeout (e.g., 1 hour)
			err := apiClient.WaitForJob(ctx, jobID, 1*time.Hour)
			if err != nil {
				exitWithError(1, "Error waiting for job:", err)
			}

			// Get final status
			finalStatus, err := apiClient.GetJobStatus(ctx, jobID)
			if err != nil {
				exitWithError(1, "Error getting final job status:", err)
			}

			if outputJSON {
				jsonBytes, err := json.MarshalIndent(finalStatus, "", "  ")
				if err != nil {
					exitWithError(1, "Failed to marshal JSON:", err)
				}
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("Job completed successfully\n")
				if finalStatus.Progress != nil {
					fmt.Printf("Transferred: %d bytes\n", finalStatus.Progress.BytesTransferred)
				}
			}
		} else {
			if !outputJSON {
				fmt.Printf("Check status with: pelican job status %s\n", jobID)
			}
		}
		return
	}

	tokenOpts := resolveTokenOptions(cmd)
	inPlace, _ := cmd.Flags().GetBool("inplace")

	pb := newProgressBar()
	defer pb.shutdown()

	// Check if the program was executed from a terminal
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_Client_DisableProgressBars.GetBool() {
		pb.launchDisplay(ctx)
	}

	log.Debugln("Len of source:", len(args))
	if len(args) < 2 {
		exitWithError(1, "No Source or Destination\nTry 'pelican object get --help' for more information.")
	}
	source := args[:len(args)-1]
	dest := args[len(args)-1]

	// Handle --pack flag by appending the appropriate query parameter to each source URL
	packOption, _ := cmd.Flags().GetString("pack")
	if cmd.Flags().Changed("pack") {
		if packOption == "" {
			packOption = "auto"
		}
		if _, err := client.GetBehavior(packOption); err != nil {
			exitWithError(1, err)
		}
		for i, src := range source {
			newSrc, err := addQueryParam(src, "pack", packOption)
			if err != nil {
				exitWithError(1, "Failed to process --pack option:", err)
			}
			source[i] = newSrc
		}
	}

	// Handle --direct flag by appending the directread query parameter to each source URL
	directRead, _ := cmd.Flags().GetBool("direct")
	if directRead {
		for i, src := range source {
			// Check for conflicting prefercached parameter
			u, err := url.Parse(src)
			if err != nil {
				exitWithError(1, "Failed to parse URL:", err)
			}
			if u.Query().Has("prefercached") {
				exitWithError(1, "Cannot use --direct flag with URLs that have '?prefercached' query parameter")
			}

			if u.RawQuery != "" {
				u.RawQuery += "&directread"
			} else {
				u.RawQuery = "directread"
			}
			source[i] = u.String()
		}
	}

	log.Debugln("Sources:", source)
	log.Debugln("Destination:", dest)

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		exitWithError(1, "Failed to get preferred caches:", err)
	}

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil {
			exitWithError(1, "Destination does not exist")
		} else if !destStat.IsDir() {
			exitWithError(1, "Destination is not a directory")
		}
	}

	var attemptErr error
	lastSrc := ""

	finalResults := make([][]client.TransferResults, 0)

	for _, src := range source {
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		options := []client.TransferOption{
			client.WithCallback(pb.callback),
			client.WithCaches(caches...),
			client.WithInPlace(inPlace),
			client.WithDryRun(dryRun),
			client.WithRejectCollections(!isRecursive),
		}
		options = append(options, tokenOpts...)
		transferResults, err := client.DoGet(ctx, src, dest, isRecursive, options...)
		if err != nil {
			attemptErr = err
			lastSrc = src
			break
		}
		finalResults = append(finalResults, transferResults)
	}

	// Exit with failure
	if attemptErr != nil {
		// Print the list of errors
		if handleCredentialPasswordError(attemptErr) {
			exitWithFlush(1)
		}
		exitTransferFailure(attemptErr, "Failure getting "+lastSrc)
	}

	// No failures so we can write the transfer stats
	transferStatsFile, _ := cmd.Flags().GetString("transfer-stats")
	if transferStatsFile != "" {
		transferStats, err := json.MarshalIndent(finalResults, "", "  ")
		if err != nil {
			log.Errorln("Failed to marshal transfer results:", err)
		}
		err = os.WriteFile(transferStatsFile, transferStats, 0644)
		if err != nil {
			log.Errorln("Failed to write transfer stats to file:", err)
		}
	}
}

// addQueryParam appends or updates a query parameter on the provided URL string.
func addQueryParam(rawURL string, key string, value string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if value == "" {
		// Valueless flag parameter: append without "=" so the URL
		// reads "?directread" instead of "?directread=".
		if u.RawQuery != "" {
			u.RawQuery += "&" + url.QueryEscape(key)
		} else {
			u.RawQuery = url.QueryEscape(key)
		}
	} else {
		q := u.Query()
		q.Set(key, value)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}
