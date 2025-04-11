/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

const (
	// The API path for downtime management
	serverDowntimeAPIPath = "/api/v1.0/downtime"
)

var (
	directorCmd = &cobra.Command{
		Use:   "director",
		Short: "Launch a Pelican Director",
		Long: `Launch a Pelican Director service:

		The Pelican Director is the primary mechanism by which clients/caches
		can discover the source of a requested resource. It has two endpoints
		at /api/v1.0/director/origin/ and /api/v1.0/director/object/, where the
		former redirects to the closest origin supporting the object and the
		latter redirects to the closest cache. As a shortcut, requests to the
		director at /foo/bar will be treated as a request for the object from
		cache.`,
	}

	directorServeCmd = &cobra.Command{
		Use:          "serve",
		Short:        "serve the director service",
		RunE:         serveDirector,
		SilenceUsage: true,
	}
)

func init() {
	// Tie the directorServe command to the root CLI command
	directorCmd.AddCommand(directorServeCmd)

	// Set up flags for the command
	directorServeCmd.Flags().AddFlag(portFlag)

	directorServeCmd.Flags().StringP("default-response", "", "", "Set whether the default endpoint should redirect clients to caches or origins")
	err := viper.BindPFlag("Director.DefaultResponse", directorServeCmd.Flags().Lookup("default-response"))
	if err != nil {
		panic(err)
	}
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
	// A Pelican server must use HTTPS scheme
	if baseURL.Scheme != "https" {
		return nil, errors.Errorf("Server URL must have an https scheme: %s", serverURLStr)
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

// Helper function to load or generate token that could access server's web API with admin privileges
func fetchOrGenerateWebAPIAdminToken(serverURLStr, tokenLocation string) (string, error) {
	var tok string
	var err error
	// Prioritize using a token from a file if one is provided.
	if tokenLocation != "" {
		if _, err := os.Stat(tokenLocation); errors.Is(err, os.ErrNotExist) {
			return "", errors.Errorf("Token file not found at: %s", tokenLocation)
		} else if err != nil {
			return "", errors.Wrapf(err, "Error checking token file: %s", tokenLocation)
		}
		tok, err = utils.GetTokenFromFile(tokenLocation)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to read token file: %s", tokenLocation)
		}
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
