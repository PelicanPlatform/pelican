//go:build client

/***************************************************************
*
* Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
)

var (
	execName string

	copyCmd = &cobra.Command{
		Use:   "copy {source ...} {destination}",
		Short: "Copy a file to or from a Pelican federation or between two objects in a federation",
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
	flagSet.String("source-token", "", "Token file for the source (overrides --token for reads)")
	flagSet.String("dest-token", "", "Token file for the destination (overrides --token for writes)")
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
		flagSet.Bool("direct", false, "Read directly from an origin, bypassing any caches (same as '?directread' query)")
		flagSet.Bool("async", false, "Run the transfer asynchronously through the client API server and return a job ID")
		flagSet.Bool("wait", false, "When used with --async, wait for the job to complete before returning")
		flagSet.String("transfer-server", "", "Submit the transfer to a remote transfer server instead of running locally")
		flagSet.String("transfer-server-token", "", "Path to a file containing the token for authenticating with the transfer server")
		flagSet.String("source-credential-id", "", "Credential ID on the transfer server to use for the source")
		flagSet.String("dest-credential-id", "", "Credential ID on the transfer server to use for the destination")
		flagSet.String("dest-origin", "", "Use the transfer service at the given destination origin URL (pings it first to verify availability)")
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

		// Ensure server is running, starting it if necessary
		apiClient, err := ensureClientAgentRunning(cmd.Context(), 5)
		if err != nil {
			log.Errorln("Failed to ensure API server is running:", err)
			log.Errorln("You can manually start it with 'pelican client-api serve --daemonize'")
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
		options := client_agent.TransferOptions{
			Token:  tokenLocation,
			Caches: cacheStrings,
		}

		// Create transfers for each source
		transfers := make([]client_agent.TransferRequest, len(source))
		for i, src := range source {
			transfers[i] = client_agent.TransferRequest{
				Operation:   "copy",
				Source:      src,
				Destination: dest,
				Recursive:   isRecursive,
			}
		}

		// Warm the wallet (interactively) and open the agent's wallet so the
		// agent can authorize both sides of the copy non-interactively. The
		// sources need a read token and the destination a write token. Skipped
		// when an explicit token file was provided.
		if tokenLocation == "" {
			warmItems := make([]asyncWarmItem, 0, len(source)+1)
			for _, src := range source {
				warmItems = append(warmItems, asyncWarmItem{url: src, write: false})
			}
			warmItems = append(warmItems, asyncWarmItem{url: dest, write: true})
			if err := warmWalletForAsync(ctx, apiClient, warmItems); err != nil {
				log.Errorln("Failed to prepare credentials for async transfer:", err)
				os.Exit(1)
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

			// Get final status
			finalStatus, err := apiClient.GetJobStatus(ctx, jobID)
			if err != nil {
				log.Errorln("Error getting final job status:", err)
				os.Exit(1)
			}

			if outputJSON {
				jsonBytes, err := json.MarshalIndent(finalStatus, "", "  ")
				if err != nil {
					log.Errorln("Failed to marshal JSON:", err)
					os.Exit(1)
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

	// Check if user wants to submit to a remote transfer server.
	// --dest-origin pings the origin to discover whether its transfer
	// service is enabled and, if so, uses it as the transfer server.
	transferServer, _ := cmd.Flags().GetString("transfer-server")
	destOrigin, _ := cmd.Flags().GetString("dest-origin")
	if destOrigin != "" && transferServer != "" {
		log.Errorln("Cannot specify both --transfer-server and --dest-origin")
		os.Exit(1)
	}
	if destOrigin != "" {
		originURL := strings.TrimRight(destOrigin, "/")
		if err := pingTransferService(ctx, originURL); err != nil {
			log.Errorf("Transfer service not available at %s: %v", originURL, err)
			os.Exit(1)
		}
		transferServer = originURL
	}

	if transferServer != "" {
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

		isRecursive, _ := cmd.Flags().GetBool("recursive")
		srcCred, _ := cmd.Flags().GetString("source-credential-id")
		dstCred, _ := cmd.Flags().GetString("dest-credential-id")
		serverToken, _ := cmd.Flags().GetString("transfer-server-token")
		shouldWait, _ := cmd.Flags().GetBool("wait")

		err := submitToTransferServer(ctx, transferServer, serverToken, source, dest, isRecursive, srcCred, dstCred, shouldWait)
		if err != nil {
			log.Errorln("Transfer server submission failed:", err)
			os.Exit(1)
		}
		return
	}

	pb := newProgressBar()
	defer pb.shutdown()

	tokenOpts := resolveTokenOptions(cmd)

	// Check if the program was executed from a terminal and does not specify a log location
	// https://rosettacode.org/wiki/Check_output_device_is_a_terminal#Go
	if fileInfo, _ := os.Stdout.Stat(); (fileInfo.Mode()&os.ModeCharDevice) != 0 && param.Logging_LogLocation.GetString() == "" && !param.Logging_Client_DisableProgressBars.GetBool() {
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

	// Handle --direct flag by appending the directread query parameter to each source URL
	directRead, _ := cmd.Flags().GetBool("direct")
	if directRead {
		for i, src := range source {
			u, pErr := url.Parse(src)
			if pErr != nil {
				log.Errorln("Failed to parse URL:", pErr)
				os.Exit(1)
			}

			// --direct is only meaningful for pelican/osdf URLs
			if !pelican_url.IsPelicanScheme(u.Scheme) {
				log.Warnln("--direct flag is ignored for non-pelican source:", src)
				continue
			}

			// Check for conflicting prefercached parameter
			if u.Query().Has("prefercached") {
				log.Errorln("Cannot use --direct flag with URLs that have '?prefercached' query parameter")
				os.Exit(1)
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
		options := append([]client.TransferOption{client.WithCallback(pb.callback), client.WithCaches(caches...)}, tokenOpts...)
		_, result = client.DoCopy(ctx, src, dest, isRecursive, options...)
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

// submitToTransferServer submits a copy job to a remote transfer server via its API.
// If credential IDs are not specified, it will attempt to look them up from
// the local credential file or bootstrap new credentials.
// tokenFile is an optional path to a file containing a bearer token for the transfer server.
// If wait is true, the function polls the job status until a terminal state is reached.
func submitToTransferServer(ctx context.Context, serverURL, tokenFile string, sources []string, dest string, recursive bool, srcCred, dstCred string, wait bool) error {
	serverURL = strings.TrimRight(serverURL, "/")

	// Read the server token from the file, if provided
	serverToken, err := readTokenFile(tokenFile)
	if err != nil {
		return err
	}

	// Resolve credentials and authentication token
	var tokenValue string
	srcCred, dstCred, tokenValue, err = lookupOrBootstrapCredentials(ctx, serverURL, serverToken, srcCred, dstCred, sources, dest)
	if err != nil {
		return errors.Wrap(err, "credential resolution failed")
	}

	// If lookupOrBootstrap didn't produce a token but we have one from the flag, use it
	if tokenValue == "" && serverToken != "" {
		tokenValue = serverToken
	}

	transfers := make([]map[string]any, len(sources))
	for i, src := range sources {
		transfers[i] = map[string]any{
			"operation":   "copy",
			"source":      src,
			"destination": dest,
			"recursive":   recursive,
		}
	}

	reqBody := map[string]interface{}{
		"transfers": transfers,
	}
	if srcCred != "" {
		reqBody["source_credential_id"] = srcCred
	}
	if dstCred != "" {
		reqBody["dest_credential_id"] = dstCred
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "failed to marshal request")
	}

	transport := config.GetTransport()
	httpClient := &http.Client{Transport: transport}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		serverURL+"/api/v1.0/transfer/jobs", bytes.NewReader(bodyBytes))
	if err != nil {
		return errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")
	if tokenValue != "" {
		req.Header.Set("Authorization", "Bearer "+tokenValue)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to contact transfer server")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("transfer server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return errors.Wrap(err, "failed to parse transfer server response")
	}
	jobID, _ := result["job_id"].(string)

	if outputJSON && !wait {
		fmt.Println(string(respBody))
	} else if !wait {
		fmt.Printf("Transfer job submitted: %s (status: %s)\n", jobID, result["status"])
	}

	if !wait {
		return nil
	}

	if !outputJSON {
		fmt.Printf("Transfer job submitted: %s — waiting for completion...\n", jobID)
	}

	return pollTransferJob(ctx, httpClient, serverURL, jobID, tokenValue)
}

// pollTransferJob polls the transfer server for the status of a job until
// it reaches a terminal state (completed, error, or cancelled).
func pollTransferJob(ctx context.Context, httpClient *http.Client, serverURL, jobID, token string) error {
	pollURL := serverURL + "/api/v1.0/transfer/jobs/" + jobID
	pollInterval := 2 * time.Second
	maxInterval := 30 * time.Second

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollURL, nil)
		if err != nil {
			return errors.Wrap(err, "failed to create poll request")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			log.Warnf("Poll request failed: %v; retrying...", err)
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Warnf("Poll returned %d: %s; retrying...", resp.StatusCode, string(body))
			continue
		}

		var status map[string]any
		if err := json.Unmarshal(body, &status); err != nil {
			log.Warnf("Failed to parse poll response: %v; retrying...", err)
			continue
		}

		jobStatus, _ := status["status"].(string)
		switch jobStatus {
		case "completed":
			if outputJSON {
				fmt.Println(string(body))
			} else {
				fmt.Printf("Transfer job %s completed successfully.\n", jobID)
			}
			return nil
		case "error":
			if outputJSON {
				fmt.Println(string(body))
			}
			errMsg, _ := status["error"].(string)
			return fmt.Errorf("transfer job %s failed: %s", jobID, errMsg)
		case "cancelled":
			if outputJSON {
				fmt.Println(string(body))
			}
			return fmt.Errorf("transfer job %s was cancelled", jobID)
		default:
			// Still in progress — increase interval with backoff
			if pollInterval < maxInterval {
				pollInterval = pollInterval * 3 / 2
				if pollInterval > maxInterval {
					pollInterval = maxInterval
				}
			}
		}
	}
}

// pingTransferService checks whether the transfer API is enabled at the given
// origin URL by issuing a GET to /api/v1.0/transfer/ping.
func pingTransferService(ctx context.Context, originURL string) error {
	transport := config.GetTransport()
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	pingURL := originURL + "/api/v1.0/transfer/ping"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create ping request")
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to contact origin")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ping returned HTTP %d; transfer service may not be enabled", resp.StatusCode)
	}

	var result map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &result); err != nil {
		return errors.Wrap(err, "failed to parse ping response")
	}
	if result["service"] != "transfer" {
		return fmt.Errorf("unexpected ping response: %s", string(body))
	}

	return nil
}
