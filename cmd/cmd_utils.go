//go:build client || server

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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

const (
	incorrectPasswordAccessMessage = "Failed to access local credential file - entered incorrect local decryption password"
	incorrectPasswordResetMessage  = "Failed to reset password - entered incorrect local decryption password"

	// The API path for downtime management
	serverDowntimeAPIPath = "/api/v1.0/downtime"
	// The API path for API key management
	serverApiKeyAPIPath = "/api/v1.0/tokens"
)

// Given an input map of flag-->viper config, convert any comma-delineated
// input lists and store them as a string slice with Viper
func commaFlagsListToViperSlice(cmd *cobra.Command, flags map[string]string) {
	for flagName, viperName := range flags {
		if flagValue, _ := cmd.Flags().GetString(flagName); flagValue != "" {
			trimmedValues := []string{}
			for _, value := range strings.Split(flagValue, ",") {
				trimmedValues = append(trimmedValues, strings.TrimSpace(value))
			}
			if err := param.SetRaw(viperName, trimmedValues); err != nil {
				cobra.CheckErr(err)
			}
		}
	}
}

// To be invoked by cmds that need to pass a slice of "preferred" caches
// as an option when invoking a new transfer job/client.
func getPreferredCaches() ([]*url.URL, error) {
	var caches []*url.URL
	for _, cacheStr := range param.Client_PreferredCaches.GetStringSlice() {
		cache, err := url.Parse(cacheStr)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse cache URL from preferred caches config: %s", cacheStr)
		}

		caches = append(caches, cache)
	}

	return caches, nil
}

// resolveTokenOptions reads the --token, --source-token, and --dest-token
// flags from cmd and returns the appropriate client.TransferOption slice.
//
// Precedence: --source-token / --dest-token override --token for their
// respective role.  --token is the fallback used when neither role-specific
// flag is set.
func resolveTokenOptions(cmd *cobra.Command) []client.TransferOption {
	var opts []client.TransferOption

	// Generic --token (fallback for both source and destination)
	if tokenLocation, _ := cmd.Flags().GetString("token"); tokenLocation != "" {
		opts = append(opts, client.WithTokenLocation(tokenLocation))
	}

	// --source-token overrides --token for reads / source side
	if srcToken, _ := cmd.Flags().GetString("source-token"); srcToken != "" {
		opts = append(opts, client.WithSourceTokenLocation(srcToken))
	}

	// --dest-token overrides --token for writes / destination side
	if destToken, _ := cmd.Flags().GetString("dest-token"); destToken != "" {
		opts = append(opts, client.WithDestinationTokenLocation(destToken))
	}

	return opts
}

func handleIncorrectPassword(err error, actionMessage string) bool {
	if err == nil || !errors.Is(err, config.ErrIncorrectPassword) {
		return false
	}
	fmt.Fprintln(os.Stderr, actionMessage)
	fmt.Fprintln(os.Stderr, "If you have forgotten your password, you can reset the local state (deleting all on-disk credentials)")
	fmt.Fprintf(os.Stderr, "by running '%s credentials reset-local'\n", os.Args[0])
	return true
}

func handleCredentialPasswordError(err error) bool {
	return handleIncorrectPassword(err, incorrectPasswordAccessMessage)
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

// Helper function to validate the server URL and construct the full API key API endpoint URL
func constructApiKeyApiURL(serverURLStr string) (*url.URL, error) {
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
	targetURL, err := baseURL.Parse(serverApiKeyAPIPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct API key API URL")
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
		// Use GetServerIssuerURL to determine the issuer.  When origin and
		// director are co-located, the local issuer URL is a sub-path
		// (e.g. .../api/v1.0/origin) that differs from the base server URL.
		// GetServerIssuerURL checks Server.IssuerUrl first (which may have
		// been set in the config file) and falls back to Server.ExternalWebUrl.
		issuerURL, issuerErr := config.GetServerIssuerURL()
		if issuerErr != nil || issuerURL == "" {
			issuerURL = serverURLStr
		}
		tc.Issuer = issuerURL
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

// inferGetDestination resolves the local destination for a CLI `pelican
// object get` invocation when the destination looks like a container.
// It layers `cp`-style semantics on top of client.DoGet's flat library
// behaviour:
//
//   - If the local destination is not an existing directory, or the
//     source URL has `?pack=...`, the destination string is returned
//     unchanged (DoGet decides what to do).
//   - Otherwise the remote source is stat'd once.  If it's a collection
//     and !recursive, an error is returned (row G4 -- symmetric with
//     the put-side directory guard).  If it's a collection and
//     recursive, the destination is rewritten to
//     `<localDest>/<basename(source)>` so a `cp -r` gesture nests the
//     tree under its source name (row G5).
//
// Stat errors are handled softly: ErrObjectNotFound is a normal
// signal (the transfer machinery will surface it with a clearer
// message); any other stat failure returns an error rather than
// silently building the wrong local layout.
//
// Callers other than the get CLI (`object sync`, client_agent, tests
// that exercise the library directly) do NOT go through this helper
// and therefore continue to see the pre-existing flat layout.
func inferGetDestination(ctx context.Context, remoteSource, localDest string, recursive bool, options ...client.TransferOption) (resolved string, err error) {
	resolved = localDest

	pUrl, err := client.ParseRemoteAsPUrl(ctx, remoteSource)
	if err != nil {
		return localDest, err
	}
	// Honor the pack override: an auto-pack request may legitimately
	// name a directory as the local destination.
	if pUrl.Query().Get("pack") != "" {
		return localDest, nil
	}

	absDest, absErr := filepath.Abs(localDest)
	if absErr != nil {
		absDest = localDest
	}
	destStat, statErr := os.Stat(absDest)
	if statErr != nil || !destStat.IsDir() {
		return localDest, nil
	}

	stat, err := client.DoStat(ctx, pUrl.GetRawUrl().String(), options...)
	if err != nil && !errors.Is(err, client.ErrObjectNotFound) {
		return localDest, errors.Wrapf(err,
			"failed to stat remote source %q while deciding destination layout", remoteSource)
	}
	isCollection := stat != nil && stat.IsCollection

	if isCollection && !recursive {
		return localDest, errors.Errorf(
			"remote object %q is a collection but recursive is not enabled", remoteSource)
	}
	if isCollection && recursive {
		return path.Join(absDest, path.Base(pUrl.Path)), nil
	}
	return localDest, nil
}
