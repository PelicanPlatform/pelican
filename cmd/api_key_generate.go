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
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/web_ui"
)

// ApiTokenResponse matches the response structure from the API
type apiTokenResponse struct {
	Token string `json:"token"`
}

var (
	apiKeyGenerateCmd = &cobra.Command{
		Use:   "generate",
		Short: "Generate a new API key for the server",
		Long: `Generate a new API key with specified scopes.

Common scopes for API keys:
  monitoring.query    Query the server's Prometheus endpoints
  monitoring.scrape   Scrape the server's /metrics endpoint

The --expiration flag accepts the following formats:
  - 'never'                       Token does not expire
  - RFC3339 in UTC                e.g. 2025-12-31T23:59:59Z
  - RFC3339 with timezone offset  e.g. 2025-12-31T18:59:59-05:00
  - Date only (ISO 8601)          e.g. 2025-12-31 (interpreted as midnight UTC)

Note: Use either 'Z' for UTC or a timezone offset like '-05:00', not both.

Examples:
  # Generate an API key that never expires
  pelican apikey generate --server https://my-origin.com:8447 --scopes "monitoring.query" --expiration never

  # Generate an API key expiring on a specific date
  pelican apikey generate --server https://my-origin.com:8447 --scopes "monitoring.query,monitoring.scrape" --expiration 2025-12-31

  # Generate an API key with a precise expiration in UTC
  pelican apikey generate --server https://my-origin.com:8447 --scopes "monitoring.query" --expiration 2025-12-31T23:59:59Z

  # Generate an API key with a timezone offset
  pelican apikey generate --server https://my-origin.com:8447 --scopes "monitoring.query" --expiration 2025-12-31T18:59:59-05:00`,
		RunE: generateApiKey,
	}

	apiKeyScopes     string
	apiKeyName       string
	apiKeyExpiration string
)

func init() {
	apiKeyCmd.AddCommand(apiKeyGenerateCmd)

	apiKeyGenerateCmd.Flags().StringVar(&apiKeyScopes, "scopes", "", "Comma-separated list of scopes (e.g., monitoring.query,monitoring.scrape) (required)")
	apiKeyGenerateCmd.Flags().StringVar(&apiKeyName, "name", "", "Name for the API key (defaults to cli-generated-{timestamp})")
	apiKeyGenerateCmd.Flags().StringVar(&apiKeyExpiration, "expiration", "", "Expiration: 'never', a date (2025-12-31), or RFC3339 (2025-12-31T23:59:59Z) (required)")

	// Mark scopes as required
	err := apiKeyGenerateCmd.MarkFlagRequired("scopes")
	if err != nil {
		log.Errorln("Failed to mark scopes flag as required:", err)
	}

	err = apiKeyGenerateCmd.MarkFlagRequired("expiration")
	if err != nil {
		log.Errorln("Failed to mark expiration flag as required:", err)
	}
}

// parseExpiration validates and normalizes the expiration flag value.
// It accepts "never", RFC3339 timestamps, or date-only strings (YYYY-MM-DD),
// which are interpreted as midnight UTC on that date.
// The returned string is either "never" or a valid RFC3339 timestamp.
func parseExpiration(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("--expiration flag is required")
	}
	if raw == "never" {
		return "never", nil
	}
	// Try RFC3339 first
	if _, err := time.Parse(time.RFC3339, raw); err == nil {
		return raw, nil
	}
	// Try date-only (ISO 8601: YYYY-MM-DD), interpreted as midnight UTC
	if t, err := time.Parse("2006-01-02", raw); err == nil {
		return t.UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("expiration must be 'never', a date (e.g., 2025-12-31), or RFC3339 (e.g., 2025-12-31T23:59:59Z or 2025-12-31T18:59:59-05:00)")
}

func generateApiKey(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	if err := config.InitClient(); err != nil {
		log.Errorln("Failed to initialize client:", err)
	}

	// Validate and parse scopes
	if apiKeyScopes == "" {
		return errors.New("--scopes flag is required")
	}
	scopesList := strings.Split(apiKeyScopes, ",")
	// Trim whitespace from each scope
	for i, scope := range scopesList {
		scopesList[i] = strings.TrimSpace(scope)
		if scopesList[i] == "" {
			return errors.New("scopes cannot contain empty values")
		}
	}

	// Generate default name if not provided
	name := apiKeyName
	if name == "" {
		name = fmt.Sprintf("cli-generated-%d", time.Now().Unix())
	}

	// Validate and normalize expiration
	expiration, err := parseExpiration(apiKeyExpiration)
	if err != nil {
		return err
	}

	// Construct API URL
	targetURL, err := constructApiKeyApiURL(apiKeyServerURLStr)
	if err != nil {
		return err
	}

	// Build request payload
	payload := web_ui.CreateApiTokenReq{
		Name:       name,
		Expiration: expiration,
		Scopes:     scopesList,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal API key request payload")
	}

	// Get token using the provided helper
	tok, err := fetchOrGenerateWebAPIAdminToken(apiKeyServerURLStr, apiKeyTokenLocation)
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
	req.AddCookie(&http.Cookie{Name: "login", Value: tok})
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

	// Parse response to extract token
	var tokenResp apiTokenResponse
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		// If parsing fails, just print the raw response
		fmt.Println("API key generated successfully:")
		fmt.Println(string(bodyBytes))
		return nil
	}

	// Check if JSON output is requested
	if jsonFlag, _ := cmd.Root().PersistentFlags().GetBool("json"); jsonFlag {
		// Output in JSON format with metadata
		output := map[string]interface{}{
			"key":        tokenResp.Token,
			"name":       name,
			"scopes":     scopesList,
			"expiration": expiration,
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return errors.Wrap(err, "Failed to marshal output to JSON")
		}
		fmt.Println(string(jsonData))
	} else {
		// Output the generated token (plain text)
		fmt.Println("Key: ", tokenResp.Token)
	}
	return nil
}
