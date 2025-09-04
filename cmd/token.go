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
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	tokenCmd = &cobra.Command{
		Use:   "token",
		Short: "Interact with tokens used to interact with objects in Pelican",
	}

	tokenCreateCmd = &cobra.Command{
		Use:   "create <pelican-url>",
		Short: "Create a token",
		RunE:  createToken,
		Args:  cobra.ExactArgs(1),
		Example: "To create a read/write token for /some/namespace/path in OSDF: " +
			"pelican token create --read --write pelican://osg-htc.org/some/namespace/path",
	}

	tokenFetchCmd = &cobra.Command{
		Use:   "fetch <pelican-url>",
		Short: "Fetch a token",
		RunE:  fetchToken,
		Args:  cobra.ExactArgs(1),
		Example: "To fetch a write token for /some/namespace/path in OSDF: " +
			"pelican token fetch --write pelican://osg-htc.org/some/namespace/path " +
			"ensure that only one of --read, --write, or --modify is specified",
		Hidden: true,
	}
)

func init() {
	tokenCmd.AddCommand(tokenCreateCmd)
	tokenCmd.AddCommand(tokenFetchCmd)

	// Token capabilities
	tokenCmd.Flags().BoolP("read", "r", false, "Create or fetch a token with the ability to read the specified resource")
	tokenCmd.Flags().BoolP("write", "w", false, "Create or fetch a token with the ability to write to the specified resource")
	tokenCmd.Flags().BoolP("modify", "m", false, "Create or fetch a token with the ability to modify or delete the specified resource")

	tokenCreateCmd.Flags().BoolP("stage", "s", false, "Create a token with the ability to stage the specified resource.")
	tokenCreateCmd.Flags().String("scope-path", "", "Specify the path to use when creating the token's scopes. This should generally be "+
		"the object path without the namespace prefix.")

	// Additional token fields
	tokenCreateCmd.Flags().StringP("audience", "a", "", "Specify the token's 'audience/aud' claim. If not provided, the equivalent 'any' audience "+
		"for the selected profile will be used (e.g. 'https://wlcg.cern.ch/jwt/v1/any' for the 'wlcg' profile).")
	tokenCreateCmd.Flags().IntP("lifetime", "l", 1200, "Set the token's lifetime in seconds.")
	tokenCreateCmd.Flags().String("subject", "", "Set token's 'subject/sub' claim. If not provided, the current user will be used as the default subject.")
	tokenCreateCmd.Flags().StringP("issuer", "i", "", "Set the token's 'issuer/iss' claim. If not provided, the issuer will be discovered via the Director.")
	tokenCreateCmd.Flags().StringArray("raw-claim", []string{}, "Set claims to be added to the token. Format: <claim_key>=<claim_value>. ")
	tokenCreateCmd.Flags().StringArray("raw-scope", []string{}, "Set non-typical values for the token's 'scope' claim. Scopes should be space-separated, e.g. "+
		"'storage.read:/ storage.create:/'.")
	tokenCreateCmd.Flags().StringP("profile", "p", "wlcg", "Create a token with a specific JWT profile. Accepted values are scitokens2 and wlcg")
	tokenCreateCmd.Flags().StringP("private-key", "k", "", fmt.Sprintf("Path to the private key used to sign the token. If not provided, Pelican will look for "+
		"the private key in the default location pointed to by the '%s' config parameter.", param.IssuerKeysDirectory.GetName()))
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
	remoteJWKS, err := server_utils.GetJWKSFromIssUrl(issuer)
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
// This is use to handle multi-issuer namespaces where it may not be obvious to the user
// which issuer aligns with their signing key.
func getIssuer(directorInfo server_structs.DirectorResponse, kidSet map[string]struct{}) (string, error) {
	if len(directorInfo.XPelAuthHdr.Issuers) == 0 {
		return "", errors.Errorf("no issuers found for %s in the Director response", directorInfo.XPelNsHdr.Namespace)
	}

	// Comb through the JWKS from each issuer to find which matches the signing key
	for _, issuer := range directorInfo.XPelAuthHdr.Issuers {
		remoteJWKS, err := server_utils.GetJWKSFromIssUrl(issuer.String())
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
					"and either --scope-path <scope path> or --scope <scope> to specify them manually. "+
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

	// Load the key and create a set of KIDs; we'll later check it against any issuers we may discover/be provided
	var myJWKS jwk.Set
	keyPath, err := cmd.Flags().GetString("private-key")
	if err != nil {
		return errors.Wrap(err, "unable to get private key path")
	} else if keyPath == "" {
		myJWKS, err = config.GetIssuerPublicJWKS()
		if err != nil {
			return errors.Wrap(err, "unable to get issuer public JWKS from default locations")
		} else if myJWKS == nil {
			return errors.New("internal error: config.GetIssuerPublicJWKS() returned nil")
		}
	} else {
		myJWKS, err = config.GetIssuerPublicJWKS(keyPath)
		if err != nil {
			return errors.Wrapf(err, "unable to get issuer public JWKS from %s", keyPath)
		}
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
			return errors.Wrapf(err, "unable to determine issuer for resource %s; you may need to re-run with '--issuer <issuer URL>' to specify an issuer", rawUrl)
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

	// Add token scopes for object manipulation
	read, _ := cmd.Flags().GetBool("read")
	write, _ := cmd.Flags().GetBool("write")
	modify, _ := cmd.Flags().GetBool("modify")
	stage, _ := cmd.Flags().GetBool("stage")

	scopes := []token_scopes.TokenScope{}

	if read {
		scopes = append(scopes, tokenProfile.ReadScope(sPath))
	}
	if write {
		scopes = append(scopes, tokenProfile.WriteScope(sPath))
	}
	if modify {
		scopes = append(scopes, tokenProfile.ModifyScope(sPath))
	}
	if stage {
		scopes = append(scopes, tokenProfile.StageScope(sPath))
	}
	tokenConfig.AddScopes(scopes...)

	if len(scopes)+len(rawScopes) == 0 {
		log.Warningf("Detected creation of a token without any capabilities. Use flags like --read, --write, --modify, or --stage to add capabilities to the token.")
	}

	// Set token lifetime
	lifetime, err := cmd.Flags().GetInt("lifetime")
	if err != nil {
		return errors.Wrap(err, "unable to get token lifetime")
	} else if lifetime < 0 {
		return errors.Errorf("token lifetime must be a positive integer but you provided %d", lifetime)
	}
	tokenConfig.Lifetime = time.Duration(lifetime) * time.Second

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
	count := 0
	if read {
		oper = config.TokenRead
		method = http.MethodGet
		count++
	}
	if write {
		oper = config.TokenWrite
		method = http.MethodPut
		count++
	}
	if modify {
		oper = config.TokenDelete
		method = http.MethodPut
		count++
	}

	if count == 0 {
		return errors.New("no scope specified, please specify only one of --read, --write, or --modify")
	} else if count > 1 {
		return errors.New("multiple scopes specified, please specify only one of --read, --write, or --modify")
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
