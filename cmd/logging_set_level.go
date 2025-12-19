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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

var (
	loggingParameterName string

	serverSetLoggingLevelCmd = &cobra.Command{
		Use:   "set-logging-level <level> <duration-seconds>",
		Short: "Temporarily change the server's log level",
		Long: `Temporarily change the server's log level for a specified duration.
The log level will automatically revert to the configured level after the duration expires.

Valid log levels: debug, info, warn, error, fatal, panic

Examples:
  pelican server set-logging-level debug 300 -s https://my-origin.com:8447
	pelican server set-logging-level info 1800 -s https://my-cache.com:8447 -t /path/to/token
	pelican server set-logging-level debug 120 -s https://my-origin.com:8447 --param Logging.Origin.Xrootd`,
		Args: cobra.ExactArgs(2),
		RunE: setLogLevel,
	}
)

func init() {
	serverCmd.AddCommand(serverSetLoggingLevelCmd)
	serverSetLoggingLevelCmd.Flags().StringVarP(&loggingParameterName, "param", "p", "Logging.Level", "Target parameter for the log level (e.g., Logging.Level, Logging.Origin.Xrootd, Logging.Cache.Xrootd)")
	serverSetLoggingLevelCmd.Flags().StringVarP(&serverURLStr, "server", "s", "", "Web URL of the Pelican server (e.g. https://my-origin.com:8447)")
	serverSetLoggingLevelCmd.Flags().StringVarP(&tokenLocation, "token", "t", "", "Path to the admin token file")
}

func setLogLevel(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	level := args[0]
	durationStr := args[1]

	// Parse duration
	duration, err := strconv.Atoi(durationStr)
	if err != nil || duration <= 0 {
		return errors.New("Duration must be a positive integer (seconds)")
	}

	parameterName := strings.TrimSpace(loggingParameterName)
	if parameterName == "" {
		parameterName = "Logging.Level"
	}

	// Construct API URL - use config if server URL not provided
	srvURL := serverURLStr
	if srvURL == "" {
		srvURL = param.Server_ExternalWebUrl.GetString()
		if srvURL == "" {
			return errors.New("Server URL must be provided via --server flag or Server.ExternalWebUrl config")
		}
	}

	targetURL, err := constructLoggingApiURL(srvURL)
	if err != nil {
		return err
	}

	// Build request payload
	payload := map[string]interface{}{
		"level":         level,
		"duration":      duration,
		"parameterName": parameterName,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal request payload")
	}

	// Get admin token - use config for server URL if not provided
	srvURL = serverURLStr
	if srvURL == "" {
		srvURL = param.Server_ExternalWebUrl.GetString()
	}

	tok, err := fetchOrGenerateWebAPIAdminToken(srvURL, tokenLocation)
	if err != nil {
		return err
	}

	// Prepare and send the HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", targetURL.String(), bytes.NewBuffer(payloadBytes))
	if err != nil {
		return errors.Wrap(err, "Failed to create HTTP request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pelican-client/"+config.GetVersion())

	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "HTTP request failed")
	}
	defer resp.Body.Close()

	bodyBytes, err := handleAdminApiResponse(resp)
	if err != nil {
		return errors.Wrap(err, "Server request failed")
	}

	// Parse response
	type LogLevelChangeResponse struct {
		ChangeID      string    `json:"changeId"`
		Level         string    `json:"level"`
		ParameterName string    `json:"parameterName"`
		EndTime       time.Time `json:"endTime"`
		Remaining     int       `json:"remainingSeconds"`
	}

	var response LogLevelChangeResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		return errors.Wrap(err, "Failed to parse server response")
	}

	fmt.Printf("Log level for %s successfully changed to '%s' for %d seconds\n", response.ParameterName, response.Level, response.Remaining)
	fmt.Printf("Change ID: %s\n", response.ChangeID)
	fmt.Printf("Will revert at: %s\n", response.EndTime.Format(time.RFC3339))
	return nil
}

func constructLoggingApiURL(serverURLStr string) (*url.URL, error) {
	if serverURLStr == "" {
		return nil, errors.New("The --server flag providing the server's web URL is required")
	}
	serverURLStr = strings.TrimSuffix(serverURLStr, "/") // Normalize URL
	baseURL, err := url.Parse(serverURLStr)
	if err != nil {
		return nil, errors.Wrapf(err, "Invalid server URL format: %s", serverURLStr)
	}
	// A Pelican server must use HTTPS scheme
	if baseURL.Scheme != "https" {
		return nil, errors.Errorf("Server URL must have an https scheme: %s", serverURLStr)
	}
	if baseURL.Host == "" {
		return nil, errors.Errorf("Server URL must include a hostname: %s", serverURLStr)
	}
	// Construct the full API endpoint URL
	targetURL, err := baseURL.Parse(path.Join("/api/v1.0/logging/level"))
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct logging API URL")
	}
	return targetURL, nil
}
