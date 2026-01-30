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
	"os"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
)

var (
	prestageCmd = &cobra.Command{
		Use:    "prestage {source ...} {destination}",
		Short:  "Prestages a prefix to a Pelican cache",
		Hidden: true, // Until we decide how safe this approach is, keep the command hidden.
		Run:    prestageMain,
		PreRun: func(cmd *cobra.Command, args []string) {
			commaFlagsListToViperSlice(cmd, map[string]string{"cache": param.Client_PreferredCaches.GetName()})
		},
	}
)

func init() {
	flagSet := prestageCmd.Flags()
	flagSet.StringP("cache", "c", "", `A comma-separated list of preferred caches to try for the transfer, where a "+" in the list indicates
the client should fallback to discovered caches if all preferred caches fail.`)
	flagSet.StringP("token", "t", "", "Token file to use for transfer")
	flagSet.Bool("async", false, "Run the prestage asynchronously through the client API server and return a job ID")
	flagSet.Bool("wait", false, "When used with --async, wait for the job to complete before returning")
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

	// Check for async mode
	isAsync, _ := cmd.Flags().GetBool("async")
	if isAsync {
		// Validate arguments
		if len(args) < 1 {
			log.Errorln("Prefix(es) to prestage must be specified")
			err = cmd.Help()
			if err != nil {
				log.Errorln("Failed to print out help:", err)
			}
			os.Exit(1)
		}

		// Ensure server is running, starting it if necessary
		apiClient, err := ensureClientAgentRunning(cmd.Context(), 5)
		if err != nil {
			log.Errorln("Failed to ensure API server is running:", err)
			log.Errorln("You can manually start it with 'pelican client-api serve --daemonize'")
			os.Exit(1)
		}

		// Get flags for transfer options
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
		options := client_agent.TransferOptions{
			Token:  tokenLocation,
			Caches: cacheStrings,
		}

		// Create transfers for each source prefix
		transfers := make([]client_agent.TransferRequest, len(args))
		for i, src := range args {
			if !isPelicanUrl(src) {
				log.Errorln("Provided URL is not a valid Pelican URL:", src)
				os.Exit(1)
			}
			transfers[i] = client_agent.TransferRequest{
				Operation:   "prestage",
				Source:      src,
				Destination: "", // Prestage doesn't have a destination
				Recursive:   false,
			}
		}

		// Create job
		jobID, err := apiClient.CreateJob(ctx, transfers, options)
		if err != nil {
			log.Errorln("Failed to create job:", err)
			os.Exit(1)
		}

		if outputJSON {
			result := map[string]interface{}{
				"job_id": jobID,
				"status": "created",
			}
			jsonBytes, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				log.Errorln("Failed to marshal JSON:", err)
				os.Exit(1)
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
				log.Errorln("Error waiting for job:", err)
				os.Exit(1)
			}

			// Get final job status
			status, err := apiClient.GetJobStatus(ctx, jobID)
			if err != nil {
				log.Errorln("Failed to get job status:", err)
				os.Exit(1)
			}

			if outputJSON {
				jsonBytes, err := json.MarshalIndent(status, "", "  ")
				if err != nil {
					log.Errorln("Failed to marshal JSON:", err)
					os.Exit(1)
				}
				fmt.Println(string(jsonBytes))
			} else {
				fmt.Printf("Job completed successfully\n")
			}

			if status.Status != "completed" {
				os.Exit(1)
			}
		} else {
			if !outputJSON {
				fmt.Printf("Check status with: pelican job status %s\n", jobID)
			}
		}

		return
	}

	// Original synchronous behavior
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

	// Get any configured preferred caches, to be passed along to the client
	// as options.
	caches, err := getPreferredCaches()
	if err != nil {
		log.Errorln("Failed to get preferred caches:", err)
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
		if handleCredentialPasswordError(err) {
			os.Exit(1)
		}
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
