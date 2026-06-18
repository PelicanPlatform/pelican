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
	"net/http"
	"net/url"
	"os/user"
	"path"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils/registry_jwks"
)

var (
	tokenCmd = &cobra.Command{
		Use:   "token",
		Short: "Interact with tokens used to interact with objects in Pelican",
	}

	tokenCreateCmd = &cobra.Command{
		Use:   "create <pelican-url>",
		Short: "Create a token",
		Long: `Create a signed JWT for accessing Pelican resources.

The generated token is a Bearer token. To authorize requests with it, pass it to
other Pelican CLI commands via the --token flag or in the HTTP Authorization header.

SCOPES

Scopes control what the token permits. Use the flags below to set them, or
pass arbitrary values with --raw-scope.

  Flag        WLCG profile (default)    SciTokens2 profile (--profile scitokens2)
  ----        ----------------------    -----------------------------------------
  --read      storage.read:<path>       read:<path>
  --write     storage.create:<path>     write:<path>
  --modify    storage.modify:<path>     write:<path>
  --stage     storage.stage:<path>      write:<path>

The <path> in each scope is the object path with the namespace prefix stripped.
Use --scope-path to override it, or --raw-scope to supply scopes verbatim, e.g.:

    --raw-scope "storage.read:/ storage.create:/uploads"

ISSUER

The issuer (--issuer) is auto-discovered from the Director using the supplied
pelican URL. Provide --issuer manually when:
  - Director discovery is unavailable
  - The namespace has multiple issuers and you need a specific one

EXPIRATION

Set the token lifetime with --lifetime (seconds, default 1200) or with
--expiration (an absolute RFC3339 timestamp, e.g. 2026-12-31T23:59:59Z).
These two flags are mutually exclusive.`,
		Example: `  # Read/write token for a path in OSDF (issuer auto-discovered):
  pelican token create --read --write pelican://osg-htc.org/some/namespace/path

  # Token expiring at a specific time (RFC3339: YYYY-MM-DDTHH:MM:SSZ):
  pelican token create --read --expiration 2026-06-30T00:00:00Z \
    pelican://osg-htc.org/some/namespace/path

  # One-hour token with an explicit issuer:
  pelican token create --read --lifetime 3600 \
    --issuer https://my-origin.com:8443 \
    pelican://osg-htc.org/some/namespace/path

  # Token with custom raw scopes:
  pelican token create --raw-scope "storage.read:/ storage.create:/uploads" \
  pelican://osg-htc.org/some/namespace/path`,
		RunE:         createToken,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	tokenFetchCmd = &cobra.Command{
		Use:   "fetch <pelican-url>",
		Short: "Fetch a token",
		RunE:  fetchToken,
		Args:  cobra.ExactArgs(1),
		Example: "To fetch a write token for /some/namespace/path in OSDF: " +
			"pelican token fetch --write pelican://osg-htc.org/some/namespace/path." + "\n" +
			"Ensure that only one of --read, --write, or --modify is specified.",
		Hidden: true,
	}
)

func addScopeFlags(cmd *cobra.Command) {
	cmd.Flags().BoolP("read", "r", false, "Indicate the requested token should provide the ability to read the specified resource.")
	cmd.Flags().BoolP("write", "w", false, "Indicate the requested token should provide the ability to create/write the specified resource. "+
		"Does not grant the ability to overwrite/modify existing resources.")
	cmd.Flags().BoolP("modify", "m", false, "Indicate the requested token should provide the ability to modify/delete the specified resource.")
}

// addTokenCreateFlags registers every flag that the `token create` command and
// its createToken handler read. It is the single source of truth for that flag
// set, shared by init() and tests so the two cannot drift apart.
func addTokenCreateFlags(cmd *cobra.Command) {
	// Token capabilities
	addScopeFlags(cmd)

	cmd.Flags().BoolP("stage", "s", false, "Indicate the requested token should provide the ability to stage the specified resource.")
	cmd.Flags().String("scope-path", "", "Specify the path to use when creating the token's scopes. This should generally be "+
		"the object path without the namespace prefix.")

	// Additional token fields
	cmd.Flags().StringP("audience", "a", "", "Specify the token's 'audience/aud' claim. If not provided, the equivalent 'any' audience "+
		"for the selected profile will be used (e.g. 'https://wlcg.cern.ch/jwt/v1/any' for the 'wlcg' profile).")
	cmd.Flags().IntP("lifetime", "l", 1200, "Set the token's lifetime in seconds.")
	cmd.Flags().String("expiration", "", "Set the token's expiration as an absolute RFC3339 timestamp (e.g., 2026-12-31T23:59:59Z). Mutually exclusive with --lifetime.")
	cmd.MarkFlagsMutuallyExclusive("lifetime", "expiration")
	cmd.Flags().String("subject", "", "Set token's 'subject/sub' claim. If not provided, the current user will be used as the default subject.")
	cmd.Flags().StringP("issuer", "i", "", "Set the token's 'issuer/iss' claim. If not provided, the issuer will be discovered via the Director.")
	cmd.Flags().StringArray("raw-claim", []string{}, "Set claims to be added to the token. Format: <claim_key>=<claim_value>. ")
	cmd.Flags().StringArray("raw-scope", []string{}, "Set non-typical values for the token's 'scope' claim. Scopes should be space-separated, e.g. "+
		"'storage.read:/ storage.create:/'.")
	cmd.Flags().StringP("profile", "p", "wlcg", "Create a token with a specific JWT profile. Accepted values are scitokens2 and wlcg.")
	cmd.Flags().StringP("private-key", "k", "", fmt.Sprintf("Path to the private key used to sign the token. If not provided, Pelican will look for "+
		"the private key in the default location pointed to by the '%s' config parameter.", param.IssuerKeysDirectory))
}

func init() {
	rootCmd.AddCommand(tokenCmd)

	// Token create command setup
	tokenCmd.AddCommand(tokenCreateCmd)
	addTokenCreateFlags(tokenCreateCmd)

	// Token fetch command setup
	tokenCmd.AddCommand(tokenFetchCmd)
	addScopeFlags(tokenFetchCmd)

	// Token fetch requires exactly one of read, write or modify
	tokenFetchCmd.MarkFlagsMutuallyExclusive("read", "write", "modify")
	tokenFetchCmd.MarkFlagsOneRequired("read", "write", "modify")
}

func splitClaim(claim string) (string, string, error) {
	// Split by the first "=" delimiter
	parts := strings.SplitN(claim, "=", 2)
	if len(parts) < 2 {
		return "", "", errors.Errorf("the claim '%s' is invalid. Did you forget an '='?", claim)
	}
	key := parts[0]
	val := parts[1]
	if key == "" || val == "" {
		return "", "", errors.Errorf("the claim '%s' is invalid. Key and value must not be empty", claim)
	}
	return key, val, nil
}

// Given some issuer and a set of KIDs, determine whether the issuer's JWKS contains a key with a matching KID
func issuerMatchesKey(issuer string, kidSet map[string]struct{}) (bool, error) {
	remoteJWKS, err := registry_jwks.GetJWKSFromIssUrl(issuer)
	if err != nil {
		return false, err
	}

	for kid := range kidSet {
		if _, ok := (*remoteJWKS).LookupKeyID(kid); ok {
			log.Debugf("Found matching key ID %s in JWKS from issuer %s", kid, issuer)
			return true, nil
		}
	}

	return false, nil
}

// Given a Pelican resource and a set of KIDs, discover issuers from the Director
// and return the first whose JWKS contains a key matching one of the input KIDs
//
// This is used to handle multi-issuer namespaces where it may not be obvious to the user
// which issuer aligns with their signing key.
func getIssuer(directorInfo server_structs.DirectorResponse, kidSet map[string]struct{}) (string, error) {
	if len(directorInfo.XPelAuthHdr.Issuers) == 0 {
		return "", errors.Errorf("no issuers found for %s in the Director response", directorInfo.XPelNsHdr.Namespace)
	}

	// Comb through the JWKS from each issuer to find which matches the signing key
	for _, issuer := range directorInfo.XPelAuthHdr.Issuers {
		remoteJWKS, err := registry_jwks.GetJWKSFromIssUrl(issuer.String())
		if err != nil {
			log.Warningf("Unable to get JWKS from issuer URL %s: %v; skipping", issuer, err)
			continue
		}
		it := (*remoteJWKS).Keys(context.Background())
		for it.Next(context.Background()) {
			key := it.Pair().Value.(jwk.Key)
			if _, ok := kidSet[key.KeyID()]; ok {
				log.Debugf("Found matching key ID %s in JWKS from issuer %s", key.KeyID(), issuer.String())
				return issuer.String(), nil
			}

			log.Debugf("Key ID %s from issuer %s does not match any of the locally-provided signing keys: %v", key.KeyID(), issuer.String(), kidSet)
		}
	}

	combineUrls := func(urls []*url.URL) string {
		var combined []string
		for _, u := range urls {
			combined = append(combined, u.String())
		}
		return strings.Join(combined, ", ")
	}

	return "", errors.Errorf("none of the issuers discovered at the director match your signing key; issuers that were checked: %s",
		combineUrls(directorInfo.XPelAuthHdr.Issuers))
}

// Given a Director's redirect response, re-query the Director's UI endpoint to get the full namespace ad information.
// This can be used later to determine what capabilities the namespace supports in comparison with the requested
// token scopes.
func getNsAd(directorInfo server_structs.DirectorResponse) (server_structs.NamespaceAdV2Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return server_structs.NamespaceAdV2Response{}, errors.Wrap(err, "unable to get federation info from config")
	}

	client := config.GetClient()

	reqURL := strings.TrimRight(fedInfo.DirectorEndpoint, "/") + "/api/v1.0/director_ui/namespaces"

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return server_structs.NamespaceAdV2Response{}, errors.Wrapf(err,
			"failed to create request for Director server lookup at %s", reqURL)
	}

	response, err := client.Do(request)
	if err != nil {
		return server_structs.NamespaceAdV2Response{}, errors.Wrapf(err,
			"failed to query Director for server ads at %s", reqURL)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return server_structs.NamespaceAdV2Response{}, errors.Errorf(
			"Director server lookup at %s returned status code %d",
			reqURL,
			response.StatusCode,
		)
	}

	// Parse the response body into a slice of server ads
	var nsAds []server_structs.NamespaceAdV2Response
	err = json.NewDecoder(response.Body).Decode(&nsAds)
	if err != nil {
		return server_structs.NamespaceAdV2Response{}, errors.Wrapf(err,
			"failed to decode Director response for namespace ads at %s", reqURL)
	}

	namespace := directorInfo.XPelNsHdr.Namespace
	// Find the first server advertising this namespace
	for _, nsAd := range nsAds {
		if path.Clean(nsAd.Path) == path.Clean(namespace) {
			return nsAd, nil
		}
	}

	return server_structs.NamespaceAdV2Response{}, errors.Errorf(
		"no namespace advertisement found for namespace %s",
		namespace,
	)
}

// Create a token using the provided flags/args
func createToken(cmd *cobra.Command, args []string) error {
	err := config.InitClient()
	if err != nil {
		log.Warningf("Unable to initialize client config, issuer auto discovery may not work: %v", err)
	}

	profileStr, _ := cmd.Flags().GetString("profile")
	rawProfile, err := token.ParseProfile(profileStr)
	if err != nil {
		return errors.Wrap(err, "unable to parse token profile")
	}
	// Type assert to StorageTokenProfile for storage-specific methods
	tokenProfile, ok := rawProfile.(token.StorageTokenProfile)
	if !ok {
		return errors.Errorf("profile %q does not support storage operations (read/write/modify/stage)", profileStr)
	}

	tokenConfig, err := token.NewTokenConfig(rawProfile)
	if err != nil {
		return errors.Wrap(err, "unable to create token config")
	}

	// Validate --expiration early so the user gets fast feedback before any network calls.
	// --lifetime and --expiration are mutually exclusive (enforced by cobra), so only one
	// can be set. The actual tokenConfig.Lifetime assignment is done later after scope setup.
	expirationStr, err := cmd.Flags().GetString("expiration")
	if err != nil {
		return errors.Wrap(err, "unable to get expiration flag")
	}
	if expirationStr != "" {
		expirationTime, err := time.Parse(time.RFC3339, expirationStr)
		if err != nil {
			return errors.Errorf("--expiration must be in RFC3339 format (e.g., 2026-12-31T23:59:59Z); got: %q", expirationStr)
		}
		if time.Until(expirationTime) <= 0 {
			return errors.Errorf("--expiration %q is already in the past", expirationStr)
		}
	}

	// First arg contains the pelican URL of the resource
	// Cobra has already checked that we have exactly one arg
	rawUrl := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pUrl, pUrlErr := client.ParseRemoteAsPUrl(ctx, rawUrl)
	sPath, err := cmd.Flags().GetString("scope-path")
	if err != nil {
		return errors.Wrap(err, "unable to get scope path")
	}
	issuer, err := cmd.Flags().GetString("issuer")
	if err != nil {
		return errors.Wrap(err, "unable to get issuer flag")
	}

	// Query the director for information about the resource -- in particular, we want
	// to know the namespace prefix so we can strip it from the path because the token
	// must not already contain the 'base_path' prefix as it would appear in the
	// scitokens configuration at the cache/origin.
	// However, if pelican URL parsing or director info retrieval fails, we can still let
	// users proceed when they provide the --issuer and --scope-path flags, since these
	// values would be used regardless of the director's response.
	var directorInfo server_structs.DirectorResponse
	directorErr := error(nil)
	if pUrlErr == nil {
		directorInfo, directorErr = client.GetDirectorInfoForPath(ctx, pUrl, http.MethodGet, "")
		if directorErr != nil {
			log.Errorf("Unable to get director info for %s: %v", rawUrl, directorErr)
		}
	}

	// Grab the namespace ad from the Director -- we'll use this later to validate token scopes.
	// This is best-effort: if we can't retrieve it (e.g. transient Director error), we skip the
	// capability-based scope validation rather than driving it off a zero-value ad, which would
	// emit misleading warnings.
	nsAd, nsAdErr := getNsAd(directorInfo)
	if nsAdErr != nil {
		log.Warningf("Unable to retrieve namespace information from the Director; skipping validation of requested token scopes against namespace capabilities: %v", nsAdErr)
	}

	// Handle any raw scopes early -- may be useful for developers/admin who want to create arbitrarily-scoped tokens,
	// and early handling lets us use this as another mechanism to avoid scope paths.
	rawScopes, err := cmd.Flags().GetStringArray("raw-scope")
	if err != nil {
		return errors.Wrap(err, "unable to get provided scopes")
	}
	if len(rawScopes) > 0 {
		for _, rawScope := range rawScopes {
			tokenConfig.AddRawScope(rawScope)
		}
	}

	if pUrlErr != nil || directorErr != nil {
		if issuer == "" || (sPath == "" && len(rawScopes) == 0) {
			return errors.Errorf(
				"Failed to get director info. You can try re-running with --issuer <issuer URL> "+
					"and --scope-path <scope path> to specify needed information manually. "+
					"URL parsing error: %v, Director error: %v", pUrlErr, directorErr)
		}
		log.Warning("Proceeding with user-supplied --issuer and --scope-path due to discovery failures.")
	} else {
		if sPath == "" {
			sPath = path.Clean(strings.TrimPrefix(pUrl.Path, directorInfo.XPelNsHdr.Namespace))
			if sPath == "." {
				sPath = "/"
			}
		}
	}
	log.Debugf("Using path %s for token scopes", sPath)

	// Start constructing the token scopes early -- we'll validate the scopes requested by the user
	// against what we think the namespace supports later.
	read, _ := cmd.Flags().GetBool("read")
	write, _ := cmd.Flags().GetBool("write")
	modify, _ := cmd.Flags().GetBool("modify")
	stage, _ := cmd.Flags().GetBool("stage")

	scopes := []token_scopes.TokenScope{}

	// For each scope we want to add, check against the Director's opinion of which scopes are supported for this resource.
	// Log an error for any requested scopes that aren't supported, but still add them to the token in case the user knows something we don't.
	if read {
		if nsAdErr == nil {
			if nsAd.Caps.PublicReads {
				// Read access is not behind token auth
				log.Warningf("Director indicates that the resource at %s is publicly readable so a token is not actually required to read it, but the --read flag was provided; adding read scope to token anyway", rawUrl)
			} else if !nsAd.Caps.Reads {
				log.Warningf("Director indicates that the resource at %s does not support read operations, but --read flag was provided; adding read scope to token anyway", rawUrl)
			}
		}
		scopes = append(scopes, tokenProfile.ReadScope(sPath))
	}
	if write {
		if nsAdErr == nil && !nsAd.Caps.Writes {
			log.Warningf("Director indicates that the resource at %s does not support write/modify operations, but --write flag was provided; adding write scope to token anyway", rawUrl)
		}
		scopes = append(scopes, tokenProfile.WriteScope(sPath))
	}
	if modify {
		if nsAdErr == nil && !nsAd.Caps.Writes {
			log.Warningf("Director indicates that the resource at %s does not support write/modify operations, but --modify flag was provided; adding modify scope to token anyway", rawUrl)
		}
		scopes = append(scopes, tokenProfile.ModifyScope(sPath))
	}
	if stage {
		scopes = append(scopes, tokenProfile.StageScope(sPath))
	}
	tokenConfig.AddScopes(scopes...)

	if len(scopes)+len(rawScopes) == 0 {
		log.Warningf("Detected creation of a token without any capabilities. Use flags like --read, --write, --modify, or --stage to add capabilities to the token.")
	}

	// Load the local signing key's public JWKS. We use the key IDs (KIDs) later to
	// match our signing key against issuers discovered from the Director.
	var myJWKS jwk.Set
	keyPath, err := cmd.Flags().GetString("private-key")
	var keyLoadErr error
	if err != nil {
		return errors.Wrap(err, "unable to get private key path")
	} else if keyPath == "" {
		myJWKS, err = config.GetIssuerPublicJWKS()
		if err != nil {
			keyLoadErr = errors.Wrap(err, "unable to load signing key from default location")
		} else if myJWKS == nil {
			keyLoadErr = errors.New("internal error: config.GetIssuerPublicJWKS() returned nil")
		}
	} else {
		myJWKS, err = config.GetIssuerPublicJWKS(keyPath)
		if err != nil {
			keyLoadErr = errors.Wrapf(err, "unable to load signing key from %s", keyPath)
		}
	}

	if keyLoadErr != nil {
		// If the namespace doesn't require protected reads and doesn't support writes,
		// a token probably isn't needed at all — give the user a more helpful hint.
		if nsAdErr == nil && !(nsAd.Caps.Reads && !nsAd.Caps.PublicReads) && !nsAd.Caps.Writes {
			return errors.Wrapf(keyLoadErr, "failed to load a local signing key; note that the Director reports namespace '%s' does not require auth for reads and does not support writes, so you may not need a token", nsAd.Path)
		}
		return keyLoadErr
	}

	kidSet := make(map[string]struct{}, myJWKS.Len())
	it := myJWKS.Keys(context.Background())
	for it.Next(context.Background()) {
		key := it.Pair().Value.(jwk.Key)
		kidSet[key.KeyID()] = struct{}{}
	}

	if issuer == "" {
		// If no issuer is provided, try to discover it from the info we previously obtained
		// from the Director
		issuer, err = getIssuer(directorInfo, kidSet)
		if err != nil {
			// If the namespace doesn't require protected reads and it doesn't support writes, there will likely have been no issuer to discover.
			// In that case, we warn that the user probably doesn't need to create a token in the first place, but we provide instructions for
			// supplying an issuer if they know better than we do.
			if nsAdErr == nil && !(nsAd.Caps.Reads && !nsAd.Caps.PublicReads) && !nsAd.Caps.Writes {
				return errors.Wrapf(err, "unable to determine issuer for resource %s. This is likely because the Director reports that this namespace does not require token issuance for reads and does not support writes. Are you sure you need a token? You may need to re-run with '--issuer <issuer URL>' to specify an issuer", rawUrl)
			} else if len(directorInfo.XPelAuthHdr.Issuers) > 0 {
				// Issuers were discovered but none match the local signing key — the inner error already
				// describes this clearly; avoid the misleading "unable to determine issuer" phrasing.
				return errors.Wrapf(err, "no issuer for resource %s matches your signing key; re-run with '--issuer <issuer URL>' to specify one, or ensure you are using the correct private key", rawUrl)
			} else {
				return errors.Wrapf(err, "unable to determine issuer for resource %s; you may need to re-run with '--issuer <issuer URL>' to specify an issuer", rawUrl)
			}
		}
	} else {
		// If an issuer is provided, check whether it matches the signing key
		matches, err := issuerMatchesKey(issuer, kidSet)
		if err != nil {
			log.Errorf("unable to fetch public JWKS from provided issuer %s, using anyway: %v; ", issuer, err)
		} else if !matches {
			// If the user-provided issuer does not match the signing key, we should warn the user
			// but still allow them to use it -- maybe they're creating tokens before the infrastructure is set up
			log.Errorf("provided issuer %s does not match the signing key; using anyway", issuer)
		}
	}
	tokenConfig.Issuer = issuer

	// Set token lifetime — either via --expiration (RFC3339) or --lifetime (seconds).
	// expirationStr was already validated above; here we just compute the duration.
	if expirationStr != "" {
		expirationTime, _ := time.Parse(time.RFC3339, expirationStr)
		tokenConfig.Lifetime = time.Until(expirationTime)
	} else {
		lifetime, err := cmd.Flags().GetInt("lifetime")
		if err != nil {
			return errors.Wrap(err, "unable to get token lifetime")
		} else if lifetime < 0 {
			return errors.Errorf("token lifetime must be a positive integer but you provided %d", lifetime)
		}
		tokenConfig.Lifetime = time.Duration(lifetime) * time.Second
	}

	// Set token audience
	audience, _ := cmd.Flags().GetString("audience")
	if audience == "" {
		audience = tokenProfile.AnyAudience()
	}
	tokenConfig.AddAudiences(audience)

	// Set token subject
	subject, _ := cmd.Flags().GetString("subject")
	if subject == "" {
		// Use the current user as the first choice of default subject.
		// The "root" user may be a common user in some environments (like dev containers),
		// but it doesn't provide any useful information about the user, so fall back to "pelican_client"
		usr, err := user.Current()
		if err != nil || usr.Username == "" || usr.Username == "root" {
			log.Warningln("Unable to get current user, using 'pelican_client' as default token subject")
			subject = "pelican_client"
		} else {
			subject = usr.Username
		}
	}
	tokenConfig.Subject = subject

	// Handle arbitrary claims
	rawClaims, err := cmd.Flags().GetStringArray("raw-claim")
	if err != nil {
		return errors.Wrap(err, "unable to get provided claims")
	}
	if len(rawClaims) > 0 {
		claims := make(map[string]string)
		for _, rawClaim := range rawClaims {
			key, val, err := splitClaim(rawClaim)
			if err != nil {
				return errors.Wrapf(err, "unable to split claim '%s'", rawClaim)
			}
			claims[key] = val
		}
		tokenConfig.Claims = claims
	}

	tok, err := tokenConfig.CreateToken(keyPath)
	if err != nil {
		return errors.Wrap(err, "unable to create token")
	}

	fmt.Println(tok)
	return nil
}

// Fetch a token for a given Pelican URL using the TokenGenerator.
// Tokens are first fetched from the client's on-disk token cache,
// and if none are available an OAuth2 flow is initiated against the
// discovered issuer
func fetchToken(cmd *cobra.Command, args []string) error {
	err := config.InitClient()
	if err != nil {
		return errors.Wrapf(err, "unable to initialize client config")
	}

	rawUrl := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pUrl, pUrlErr := client.ParseRemoteAsPUrl(ctx, rawUrl)
	if pUrlErr != nil {
		return errors.Wrapf(pUrlErr, "failed to parse Pelican URL")
	}

	// Determine whether to fetch a write token
	write, _ := cmd.Flags().GetBool("write")
	modify, _ := cmd.Flags().GetBool("modify")
	read, _ := cmd.Flags().GetBool("read")

	var oper config.TokenOperation
	var method string
	if read {
		oper = config.TokenRead
		method = http.MethodGet
	}
	if write {
		oper = config.TokenWrite
		method = http.MethodPut
	}
	if modify {
		oper = config.TokenDelete
		method = http.MethodPut
	}

	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, method, "")
	if err != nil {
		return errors.Wrapf(err, "failed to get director info for %s", pUrl.String())
	}

	tokenGenerator := client.NewTokenGenerator(pUrl, &dirResp, oper, true)
	tokenContents, err := tokenGenerator.Get()
	if err != nil {
		return errors.Wrap(err, "failed to fetch token")
	}
	if tokenContents == "" {
		return errors.New("retrieved token is empty")
	}

	fmt.Println(tokenContents)
	return nil
}
