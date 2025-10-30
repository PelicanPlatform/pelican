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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_api"
	"github.com/pelicanplatform/pelican/client_api/apiclient"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	execName string

	copyCmd = &cobra.Command{
		Use:   "copy {source ...} {destination}",
		Short: "Copy a file to/from a Pelican federation",
		Run:   copyMain,
		PreRun: func(cmd *cobra.Command, args []string) {
			commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
		},
	}
)

func init() {
	execName = filepath.Base(os.Args[0])
	// Take care of our Windows users
	execName = strings.TrimSuffix(execName, ".exe")
	// Being case-insensitive
	execName = strings.ToLower(execName)
	flagSet := copyCmd.Flags()
	flagSet.StringP("cache", "c", "", `A comma-separated list of preferred caches to try for the transfer, where a "+" in the list indicates
the client should fallback to discovered caches if all preferred caches fail.`)
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.BoolP("recursive", "r", false, "Recursively copy a collection.  Forces methods to only be http to get the freshest collection contents")
	flagSet.StringP("cache-list-name", "n", "xroot", "(Deprecated) Cache list to use, currently either xroot or xroots; may be ignored")
	flagSet.Lookup("cache-list-name").Hidden = true

	// All the deprecated or hidden flags that are only relevant if we are in historical "stashcp mode"
	if strings.HasPrefix(execName, "stashcp") {
		copyCmd.Use = "stashcp {source ...} {destination}"
		copyCmd.Short = "Copy a file to/from the OSDF"
		flagSet.Lookup("cache-list-name").Hidden = false // Expose the help for this option
		flagSet.StringP("caches-json", "j", "", "A JSON file containing the list of caches")
		flagSet.BoolP("debug", "d", false, "Enable debug logs") // Typically set by the root command (which doesn't exist in stashcp mode)
		flagSet.String("methods", "http", "Comma separated list of methods to try, in order")
		flagSet.Bool("namespaces", false, "Print the namespace information and exit")
		flagSet.Bool("plugininterface", false, "Output in HTCondor plugin format.  Turned on if executable is named stash_plugin")
		flagSet.Lookup("plugininterface").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("progress", "p", false, "Show progress bars, turned on if run from a terminal")
		flagSet.Lookup("progress").Hidden = true // This has been a no-op for quite some time.
		flagSet.BoolP("version", "v", false, "Print the version and exit")
		flagSet.Bool("async", false, "Run the transfer asynchronously through the client API server and return a job ID")
		flagSet.Bool("wait", false, "When used with --async, wait for the job to complete before returning")
	} else {
		flagSet.String("caches", "", "A JSON file containing the list of caches")
		flagSet.String("methods", "http", "Comma separated list of methods to try, in order")
		flagSet.Bool("async", false, "Run the transfer asynchronously through the client API server and return a job ID")
		flagSet.Bool("wait", false, "When used with --async, wait for the job to complete before returning")
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

	// Check for async mode
	isAsync, _ := cmd.Flags().GetBool("async")
	if isAsync {
		// Validate arguments
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

		// Create API client (empty string uses default socket path)
		apiClient, err := apiclient.NewAPIClient("")
		if err != nil {
			log.Errorln("Failed to create API client:", err)
			log.Errorln("Ensure the client API server is running with 'pelican client-api serve'")
			os.Exit(1)
		}

		// Check if server is running
		if !apiClient.IsServerRunning(ctx) {
			log.Errorln("Client API server is not running")
			log.Errorln("Start it with 'pelican client-api serve'")
			os.Exit(1)
		}

		// Get flags for transfer options
		isRecursive, _ := cmd.Flags().GetBool("recursive")
		tokenLocation, _ := cmd.Flags().GetString("token")

		// Get preferred caches
		caches, err := getPreferredCaches()
		if err != nil {
			log.Errorln("Failed to get preferred caches:", err)
			os.Exit(1)
		}

		// Convert caches to strings
		cacheStrings := make([]string, len(caches))
		for i, cache := range caches {
			cacheStrings[i] = cache.String()
		}

		// Build transfer options
		options := client_api.TransferOptions{
			Token:  tokenLocation,
			Caches: cacheStrings,
		}

		// Create transfers for each source
		transfers := make([]client_api.TransferRequest, len(source))
		for i, src := range source {
			transfers[i] = client_api.TransferRequest{
				Operation:   "copy",
				Source:      src,
				Destination: dest,
				Recursive:   isRecursive,
			}
		}

		// Create job
		jobID, err := apiClient.CreateJob(ctx, transfers, options)
		if err != nil {
			log.Errorln("Failed to create job:", err)
			os.Exit(1)
		}

		fmt.Printf("Job created: %s\n", jobID)

		// Check if we should wait for completion
		shouldWait, _ := cmd.Flags().GetBool("wait")
		if shouldWait {
			fmt.Println("Waiting for job to complete...")

			// Wait with a reasonable timeout (e.g., 1 hour)
			err := apiClient.WaitForJob(ctx, jobID, 1*time.Hour)
			if err != nil {
				log.Errorln("Error waiting for job:", err)
				os.Exit(1)
			}

			// Get final status
			finalStatus, err := apiClient.GetJobStatus(ctx, jobID)
			if err != nil {
				log.Errorln("Error getting final job status:", err)
				os.Exit(1)
			}

			fmt.Printf("Job completed successfully\n")
			if finalStatus.Progress != nil {
				fmt.Printf("Transferred: %d bytes\n", finalStatus.Progress.BytesTransferred)
			}
		} else {
			fmt.Printf("Check status with: pelican job status %s\n", jobID)
		}
		return
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
		// NOTE: The value returned by this no longer conforms to the old-style stashcp namespaces JSON.
		// Instead, it now returns the struct provided by the registry
		listAllNamespaces(cmd, args)
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

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		log.Errorln("Failed to get preferred caches:", err)
		os.Exit(1)
	}

	if len(source) > 1 {
		if destStat, err := os.Stat(dest); err != nil {
			log.Errorln("Destination does not exist")
			os.Exit(1)
		} else if !destStat.IsDir() {
			log.Errorln("Destination is not a collection")
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
		if handleCredentialPasswordError(result) {
			os.Exit(1)
		}
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
