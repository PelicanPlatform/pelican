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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// downtimeDisplay struct helps in formatting time for output
type downtimeDisplay struct {
	server_structs.Downtime
	StartTimeStr string `json:"start_time_str" yaml:"start_time_str"`
	EndTimeStr   string `json:"end_time_str" yaml:"end_time_str"`
}

var (
	downtimeListCmd = &cobra.Command{
		Use:   "list",
		Short: "List server's scheduled downtime periods",
		Long: `List scheduled downtime periods for a Pelican server (Origin/Cache).
  Requires an administrative token for the server.
  Shows active and future downtimes ('incomplete') by default.`,
		Args:    cobra.NoArgs,
		RunE:    listDowntime,
		Aliases: []string{"ls"},
	}
)

func init() {
	// Add flags specific to the list command
	flags := downtimeListCmd.Flags()

	// Optional Flags
	flags.String("status", "incomplete", "Filter downtimes by status ('incomplete' shows active/future, 'all' shows all history)")

	// Add list command to the downtime group
	downtimeCmd.AddCommand(downtimeListCmd)
}

// Core logic for the 'pelican downtime list' command
func listDowntime(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	// Get additional flag Values
	statusFilter, _ := cmd.Flags().GetString("status")

	// Basic validation of the input
	targetURL, err := constructDowntimeApiURL(serverURLStr)
	if err != nil {
		return err
	}

	statusFilter = strings.ToLower(statusFilter)
	if statusFilter != "incomplete" && statusFilter != "all" {
		return errors.New("Invalid status filter: must be 'incomplete' or 'all'")
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(serverURLStr, tokenLocation)
	if err != nil {
		return err
	}

	// Prepare HTTP Request

	// Add query parameter
	query := targetURL.Query()
	query.Set("status", statusFilter)
	targetURL.RawQuery = query.Encode()

	log.Debugln("Requesting downtimes from:", targetURL.String())

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL.String(), nil)
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}

	req.Header.Set("Authorization", "Bearer "+tok)
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion()) // Assumes client.GetUserAgent is accessible
	req.Header.Set("Accept", "application/json")

	// Execute Request
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("Request cancelled")
		}
		return errors.Wrapf(err, "Failed to execute request to %s", targetURL.String())
	}
	defer resp.Body.Close()

	// Handle Response
	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		log.Debugf("Raw response body on error: %s", string(bodyBytes))
		return errors.Wrap(err, "Server request failed")
	}

	// Parse Response
	var downtimes []server_structs.Downtime
	if err := json.Unmarshal(bodyBytes, &downtimes); err != nil {
		log.Debugf("Raw response body on parse error: %s", string(bodyBytes))
		return errors.Wrap(err, "Failed to parse JSON response from server")
	}

	// Use JSON format if global --json flag is set, otherwise use YAML format
	outputFormat := "yaml"
	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		outputFormat = "json"
	}

	// Format and Print Output
	if err := printDowntimes(downtimes, outputFormat); err != nil {
		return errors.Wrap(err, "Failed to format or print output")
	}

	return nil
}

// Helper function to print downtimes in the specified format
func printDowntimes(downtimes []server_structs.Downtime, format string) error {
	if len(downtimes) == 0 {
		fmt.Println("No downtime periods found matching the criteria.")
		return nil
	}

	// Sort by start time for consistent output
	sort.Slice(downtimes, func(i, j int) bool {
		return downtimes[i].StartTime < downtimes[j].StartTime
	})

	// Prepare display data (format times)
	displayData := make([]downtimeDisplay, len(downtimes))
	for i, dt := range downtimes {
		// Convert Unix Milliseconds to human-readable time in UTC
		startTime := time.UnixMilli(dt.StartTime).UTC()
		displayData[i].StartTimeStr = startTime.Format(time.RFC3339) // ISO 8601 format

		if dt.EndTime > 0 {
			endTime := time.UnixMilli(dt.EndTime).UTC()
			displayData[i].EndTimeStr = endTime.Format(time.RFC3339)
		} else {
			displayData[i].EndTimeStr = "Indefinite"
		}
		displayData[i].Downtime = dt
	}

	switch format {
	case "yaml":
		yamlData, err := yaml.Marshal(displayData)
		if err != nil {
			return errors.Wrap(err, "Failed to marshal data to YAML")
		}
		fmt.Println(string(yamlData))
	case "json":
		fallthrough // Default to json
	default:
		jsonData, err := json.MarshalIndent(displayData, "", "  ")
		if err != nil {
			return errors.Wrap(err, "Failed to marshal data to JSON")
		}
		fmt.Println(string(jsonData))
	}

	return nil
}
