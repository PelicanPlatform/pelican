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

// mintedAdminTokenIssuer records the issuer stamped into the admin token this
// process minted (empty when the operator supplied a token file instead).  A
// CLI invocation mints at most one such token, so a single package-level value
// is enough; it exists purely so that an authorization failure can name the
// issuer that was used.  See adminTokenIssuerHint.
var mintedAdminTokenIssuer string

// originAndDirectorColocated reports whether the server whose web API we are
// about to call runs the origin and director modules in the *same* process.
// That is the one topology where the server's local issuer URL is a sub-path
// of the web URL instead of the bare web URL itself.
//
// A CLI cannot simply ask config.IsServerEnabled(): that state is only ever
// populated by config.InitServer() inside the serving process.  A CLI runs
// InitClient (or, as with `cache introspect`, InitServer for the single module
// it is inspecting), so IsServerEnabled() reports the origin and director as
// disabled no matter what the server on this host is actually running.  We
// therefore re-derive the answer from configuration, which is the only channel
// a separate process shares with the server: Server.Modules is the parameter
// `pelican-server serve --module <name>` binds to, so a host that records its
// module list in the config file (or in PELICAN_SERVER_MODULES) is detected
// exactly.
//
// A host whose module list exists only in the serving process's argv leaves no
// artifact on disk for the CLI to read, so co-location there is *not*
// detectable from here.  Rather than guess, we report false and let
// handleAdminApiResponse turn the resulting 401 into a message that names both
// the issuer we used and the one a co-located server would demand.  (The
// durable fix is for the server to publish its local issuer URL in the address
// file it already writes at startup; see config.WriteAddressFile.)
func originAndDirectorColocated() bool {
	// If this process *is* the server (in-process callers and tests), its own
	// module registration is authoritative and matches what the verifier sees.
	if config.IsServerEnabled(server_structs.OriginType) && config.IsServerEnabled(server_structs.DirectorType) {
		return true
	}

	modules := server_structs.NewServerType()
	for _, name := range param.Server_Modules.GetStringSlice() {
		// Unknown names are ignored here; `serve` is the command that rejects
		// them, and a typo must not silently flip the issuer we mint against.
		_ = modules.SetString(strings.TrimSpace(name))
	}
	return modules.IsEnabled(server_structs.OriginType) && modules.IsEnabled(server_structs.DirectorType)
}

// webAPIAdminTokenIssuer returns the issuer string that the server's web API
// will require of a locally minted admin token, or "" if it cannot be
// determined at all.
//
// The verifying side is web_ui.extractUserFromBearerToken, reached through
// web_ui.AuthHandler -> web_ui.GetUserGroups.  It compares the token's `iss`
// against config.GetLocalIssuerUrl() twice (once before checking the signature,
// once inside jwt.Validate) and rejects every other value; there is no second
// bearer-token path that would accept a different spelling.  So the minting
// side has to reproduce GetLocalIssuerUrl(), *not* config.GetServerIssuerURL(),
// which is what this helper used to call.  The two diverge in two ways:
//
//   - GetServerIssuerURL() honors Server.IssuerUrl and Server.IssuerHostname;
//     GetLocalIssuerUrl() ignores both and always builds off
//     Server.ExternalWebUrl.  On a host that sets Server.IssuerUrl, the minted
//     token was rejected with a bare 401.
//   - When the origin and director run in one process, the local issuer is
//     "<Server.ExternalWebUrl>/api/v1.0/origin"; everywhere else it is
//     Server.ExternalWebUrl verbatim.  A CLI cannot learn that from
//     config.GetLocalIssuerUrl() either (see originAndDirectorColocated), so we
//     rebuild the sub-path here.
//
// Widening the verifier to accept both spellings was considered and rejected:
// that is an authorization path, and teaching it to trust a second issuer to
// paper over a minting bug trades a diagnosable failure for a permanently
// larger trusted set.  Fix the minter instead.
//
// config.GetLocalIssuerUrl() remains the authority for the format; this
// function must track it, and TestWebAPIAdminTokenIssuerMatchesVerifier pins
// the two together so a change on either side fails the build.
func webAPIAdminTokenIssuer(serverURLStr string) string {
	// A running server records the issuer it will accept in its address file.
	// That is authoritative and needs no inference, so prefer it: the module
	// set a server was started with may exist only in its argv, where nothing
	// this process can read will reveal it.  A server too old to write the key,
	// or one that is not running, falls through to the derivation below.
	if addr, err := config.ReadAddressFile(); err == nil && addr.LocalIssuerURL != "" {
		return addr.LocalIssuerURL
	}

	// Mirror GetLocalIssuerUrl(): build off Server.ExternalWebUrl and
	// deliberately do not consult Server.IssuerUrl.  Falling back to the URL
	// the caller is dialing keeps the case of a client-only configuration
	// (no local server config at all) working as it did before.
	base := param.Server_ExternalWebUrl.GetString()
	if base == "" {
		base = serverURLStr
	}
	if base == "" {
		return ""
	}
	if !originAndDirectorColocated() {
		return base
	}

	issuerURL, err := url.JoinPath(base, "/api/v1.0/origin")
	if err != nil {
		log.Warningf("Failed to construct the co-located origin issuer URL from %q: %v; falling back to %s", base, err, base)
		return base
	}
	return issuerURL
}

// adminTokenIssuerHint explains, for an authorization failure, which issuer the
// token this process minted carries and what the server may have wanted
// instead.  Returns "" when the operator supplied the token, since then the
// issuer is theirs to explain.
func adminTokenIssuerHint() string {
	if mintedAdminTokenIssuer == "" {
		return ""
	}
	hint := fmt.Sprintf("; this CLI minted its own admin token with issuer %q, and the server accepts only tokens whose issuer equals its local issuer URL",
		mintedAdminTokenIssuer)
	if !originAndDirectorColocated() {
		colocated, err := url.JoinPath(mintedAdminTokenIssuer, "/api/v1.0/origin")
		if err != nil {
			return hint
		}
		hint += fmt.Sprintf(". A server running the origin and director modules in one process expects %q instead; if that describes this host, list both modules under %s in the configuration this CLI reads, or pass a token file with --token",
			colocated, param.Server_Modules.GetName())
	}
	return hint
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
		// The issuer must be exactly what the server's web API verifies
		// against -- its local issuer URL -- or the request comes back 401.
		// webAPIAdminTokenIssuer documents why that is not the same thing as
		// config.GetServerIssuerURL(), which this used to call.
		issuerURL := webAPIAdminTokenIssuer(serverURLStr)
		if issuerURL == "" {
			return "", errors.Errorf("Cannot determine the issuer for an auto-generated admin token: neither %s nor a server URL is configured; set %s or supply a token file",
				param.Server_ExternalWebUrl.GetName(), param.Server_ExternalWebUrl.GetName())
		}

		tc := token.NewWLCGToken()
		tc.Lifetime = 5 * time.Minute
		tc.Subject = "admin"
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
		log.Debugf("Minted a short-lived web API admin token with issuer %q", issuerURL)
		mintedAdminTokenIssuer = issuerURL
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
		errMsg += adminTokenIssuerHint()
	} else if resp.StatusCode == http.StatusForbidden { // 403
		errMsg += " (check if token has required admin privileges)"
	}

	return bodyBytes, errors.New(errMsg)
}
