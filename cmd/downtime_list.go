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
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const (
	// The API path for downtime management
	serverDowntimeAPIPath = "/api/v1.0/downtime"
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
		RunE:    listDowntimeFunc,
		Aliases: []string{"ls"},
	}
)

func init() {
	// Add flags specific to the list command
	flags := downtimeListCmd.Flags()

	// Optional Flags
	flags.String("status", "incomplete", "Filter downtimes by status ('incomplete' shows active/future, 'all' shows all history)")
	flags.StringP("output", "o", "table", "Output format (table, json, yaml)")

	// Add list command to the downtime group
	downtimeCmd.AddCommand(downtimeListCmd)
}

// Core logic for the 'pelican downtime list' command
func listDowntimeFunc(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	// Get additional flag Values
	statusFilter, _ := cmd.Flags().GetString("status")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Basic validation of the input
	targetURL, err := constructDowntimeApiURL(serverURLStr)
	if err != nil {
		return err
	}

	statusFilter = strings.ToLower(statusFilter)
	if statusFilter != "incomplete" && statusFilter != "all" {
		return errors.New("Invalid status filter: must be 'incomplete' or 'all'")
	}

	outputFormat = strings.ToLower(outputFormat)
	if outputFormat != "table" && outputFormat != "json" && outputFormat != "yaml" {
		return errors.New("Invalid output format: must be 'table', 'json', or 'yaml'")
	}

	tok, err := getToken(serverURLStr, tokenLocation)
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

	// Format and Print Output
	if err := printDowntimes(downtimes, outputFormat); err != nil {
		return errors.Wrap(err, "Failed to format or print output")
	}

	return nil
}

// Helper function to validate the server URL and construct the full API endpoint URL
func constructDowntimeApiURL(serverURLStr string) (*url.URL, error) {
	if serverURLStr == "" {
		return nil, errors.New("The --server flag providing the server's web URL is required")
	}
	serverURLStr = strings.TrimSuffix(serverURLStr, "/") // Normalize URL
	baseURL, err := url.Parse(serverURLStr)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid server URL format: %s", serverURLStr)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.Errorf("Server URL must have an http or https scheme: %s", serverURLStr)
	}
	if baseURL.Host == "" {
		return nil, errors.Errorf("Server URL must include a hostname: %s", serverURLStr)
	}
	// Construct the full API endpoint URL
	targetURL, err := baseURL.Parse(serverDowntimeAPIPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct downtime API URL")
	}
	return targetURL, nil
}

// Helper function to load or generate token
func getToken(serverURLStr, tokenLocation string) (string, error) {
	var tok string
	// Prioritize using a token from a file if one is provided.
	if tokenLocation != "" {
		if _, err := os.Stat(tokenLocation); errors.Is(err, os.ErrNotExist) {
			return "", errors.Errorf("Token file not found at: %s", tokenLocation)
		} else if err != nil {
			return "", errors.Wrapf(err, "Error checking token file: %s", tokenLocation)
		}
		tokenBytes, err := os.ReadFile(tokenLocation)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to read token file: %s", tokenLocation)
		}
		tok = strings.TrimSpace(string(tokenBytes))
	}
	// If no token is provided, generate a new one with current issuer key
	if tok == "" {
		tc := token.NewWLCGToken()
		tc.Lifetime = 5 * time.Minute
		tc.Subject = "admin"
		tc.Issuer = serverURLStr
		tc.AddAudienceAny()
		tc.AddScopes(token_scopes.WebUi_Access)
		tok, err := tc.CreateToken()
		if err != nil {
			log.Debugln("Token Configuration (partial):")
			log.Debugln("  Issuer:", tc.Issuer)
			log.Debugln("  Subject:", tc.Subject)
			return "", errors.Wrap(err, "Failed to create the downtime operation token")
		}
		return tok, nil
	}
	return tok, nil
}

// handleAdminApiResponse checks the HTTP status code for API calls
// that requires server admin authorization.
// Returns the body bytes on success (2xx) or an error for non-2xx status codes.
// Attempts to parse standard Pelican error responses (SimpleApiResp).
func handleAdminApiResponse(resp *http.Response) ([]byte, error) {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read response body (status: %s)", resp.Status)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return bodyBytes, nil // Success
	}

	// Attempt to parse a standard error response
	var errorResp server_structs.SimpleApiResp
	errMsg := fmt.Sprintf("server responded with %s", resp.Status)
	if parseErr := json.Unmarshal(bodyBytes, &errorResp); parseErr == nil && errorResp.Msg != "" {
		errMsg = fmt.Sprintf("%s: %s", errMsg, errorResp.Msg)
	} else {
		// Fallback if parsing fails or message is empty
		if len(bodyBytes) > 0 && len(bodyBytes) < 512 { // Avoid logging huge bodies
			errMsg += fmt.Sprintf(" (body: %s)", string(bodyBytes))
		}
	}

	// Add specific messages for common auth errors
	if resp.StatusCode == http.StatusUnauthorized { // 401
		errMsg += " (check if token is valid or expired)"
	} else if resp.StatusCode == http.StatusForbidden { // 403
		errMsg += " (check if token has required admin privileges)"
	}

	return bodyBytes, errors.New(errMsg)
}

// Helper function to print downtimes in the specified format
func printDowntimes(downtimes []server_structs.Downtime, format string) error {
	if len(downtimes) == 0 {
		fmt.Println("No downtime periods found matching the criteria.")
		return nil
	}

	// Sort by start time for consistent table output
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
