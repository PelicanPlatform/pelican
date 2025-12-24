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

package client

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwt "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	oauth2_upstream "golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

type (

	// A token contents and its expiration time
	//
	// Meant to be used atomically as part of the token generator.
	tokenInfo struct {
		Contents string
		Expiry   time.Time
	}

	// An object that can fetch an appropriate token for a given transfer.
	//
	// Thread-safe and will auto-renew the token throughout the lifetime
	// of the process.
	tokenGenerator struct {
		DirResp                 *server_structs.DirectorResponse
		Destination             *pelican_url.PelicanURL
		TokenLocation           string
		TokenName               string
		Operation               config.TokenOperation
		EnableAcquire           bool
		Token                   atomic.Pointer[tokenInfo]
		Iterator                *tokenContentIterator
		Sync                    *singleflight.Group
		authFailureMu           sync.Mutex
		consecutiveAuthFailures int
	}

	// An object that iterates through the various possible tokens
	tokenContentIterator struct {
		Location         string
		Name             string
		CredLocations    []string
		Method           int
		CurrentTokenPath string // Tracks the path of the current token being returned
	}
)

func NewTokenGenerator(dest *pelican_url.PelicanURL, dirResp *server_structs.DirectorResponse, operation config.TokenOperation, enableAcquire bool) *tokenGenerator {
	return &tokenGenerator{
		DirResp:       dirResp,
		Destination:   dest,
		Operation:     operation,
		EnableAcquire: enableAcquire,
		Sync:          new(singleflight.Group),
	}
}

func newTokenContentIterator(loc string, name string) *tokenContentIterator {
	return &tokenContentIterator{
		Location: loc,
		Name:     name,
	}
}

// Force the token generator to read the token from a fixed location.
//
// Overrides any environment-based discovery logic.
func (tg *tokenGenerator) SetTokenLocation(tokenLocation string) {
	tg.TokenLocation = tokenLocation
}

// Force the token generator to use a specific named token instead of
// evaluating all possible tokens
func (tg *tokenGenerator) SetTokenName(name string) {
	tg.TokenName = name
}

// Force the use of a specific token for the lifetime of the generator
func (tg *tokenGenerator) SetToken(contents string) {
	info := tokenInfo{
		Contents: contents,
		Expiry:   time.Now().Add(100 * 365 * 24 * time.Hour), // 100 years should be enough for "forever"
	}
	tg.Token.Store(&info)
}

// Copy the contents
func (tg *tokenGenerator) Copy() *tokenGenerator {
	return &tokenGenerator{
		DirResp:       tg.DirResp,
		Destination:   tg.Destination,
		Operation:     tg.Operation,
		EnableAcquire: tg.EnableAcquire,
		Sync:          new(singleflight.Group),
	}
}

func (tg *tokenGenerator) recordAuthFailure(statusCode int) (bool, error) {
	tg.authFailureMu.Lock()
	defer tg.authFailureMu.Unlock()

	// Ensure any subsequent request fetches a fresh credential.
	tg.Token.Store(nil)
	tg.consecutiveAuthFailures++

	// Retry up to 3 times before giving up
	maxRetries := 3
	if tg.consecutiveAuthFailures <= maxRetries {
		return true, errors.Errorf("authorization failed with status %d; retrying with a fresh credential", statusCode)
	}

	return false, errors.Errorf("authentication failed for %d consecutive times (last status %d)", tg.consecutiveAuthFailures, statusCode)
}

func (tg *tokenGenerator) recordAuthSuccess() {
	tg.authFailureMu.Lock()
	tg.consecutiveAuthFailures = 0
	tg.authFailureMu.Unlock()
}

func (tci *tokenContentIterator) discoverHTCondorTokenLocations(tokenName string) (tokenLocations []string) {
	tokenLocations = make([]string, 0)

	// Tokens with dots in their name may need to have dots converted to underscores.
	if strings.Contains(tokenName, ".") {
		underscoreTokenName := strings.ReplaceAll(tokenName, ".", "_")
		// If we find a token after replacing dots, then we're already done.
		tokenLocations = tci.discoverHTCondorTokenLocations(underscoreTokenName)
		if len(tokenLocations) > 0 {
			return
		}
	}

	credsDir, isCondorCredsSet := os.LookupEnv("_CONDOR_CREDS")
	if !isCondorCredsSet {
		credsDir = ".condor_creds"
	}

	if len(tokenName) > 0 {
		tokenLocation := filepath.Join(credsDir, tokenName+".use")
		// Token was explicitly requested; warn if it doesn't exist.
		if _, err := os.Stat(filepath.Join(credsDir, tokenName)); err != nil {
			log.Warningln("Environment variable _CONDOR_CREDS is set, but the credential file is not readable:", err)
		} else {
			tokenLocations = append(tokenLocations, tokenLocation)
			return
		}
	} else {
		tokenLocation := filepath.Join(credsDir, "scitokens.use")
		// Just prefer the scitokens.use first by convention; do not warn if it is missing
		if _, err := os.Stat(tokenLocation); err == nil {
			tokenLocations = append(tokenLocations, tokenLocation)
		}
	}

	// Walk through all available credentials in the directory; scitokens.use was already
	// put first, if available, above.
	err := filepath.Walk(credsDir, func(path string, info fs.FileInfo, err error) error {
		if path == credsDir {
			return nil
		} else if info.IsDir() {
			return filepath.SkipDir
		}
		baseName := filepath.Base(path)
		if baseName == "scitokens.use" {
			return nil
		}
		if len(baseName) > 0 && baseName[0] == '.' {
			return nil
		}
		tokenLocations = append(tokenLocations, path)
		return nil
	})
	if err != nil {
		log.Warningln("Failure when iterating through directory to look through tokens:", err)
	}
	return
}

func (tci *tokenContentIterator) next() (string, bool) {
	/*
		Search for the location of the authentication token.  It can be set explicitly on the command line,
		with the environment variable "BEARER_TOKEN", or it can be searched in the standard HTCondor directory pointed
		to by the environment variable "_CONDOR_CREDS".
	*/
	switch tci.Method {
	case 0:
		tci.Method += 1
		if tci.Location != "" {
			log.Debugln("Using API-specified token location", tci.Location)
			if _, err := os.Stat(tci.Location); err != nil {
				log.Warningln("Client was asked to read token from location", tci.Location, "but it is not readable:", err)
			} else if jwtSerialized, err := utils.GetTokenFromFile(tci.Location); err == nil {
				tci.CurrentTokenPath = tci.Location
				return jwtSerialized, true
			}
		}
		fallthrough
	// WLCG Token Discovery
	case 1:
		tci.Method += 1
		if bearerToken, isBearerTokenSet := os.LookupEnv("BEARER_TOKEN"); isBearerTokenSet {
			log.Debugln("Using token from BEARER_TOKEN environment variable")
			tci.CurrentTokenPath = "BEARER_TOKEN"
			return bearerToken, true
		}
		fallthrough
	case 2:
		tci.Method += 1
		if bearerTokenFile, isBearerTokenFileSet := os.LookupEnv("BEARER_TOKEN_FILE"); isBearerTokenFileSet {
			log.Debugln("Using token from BEARER_TOKEN_FILE environment variable")
			if _, err := os.Stat(bearerTokenFile); err != nil {
				log.Warningln("Environment variable BEARER_TOKEN_FILE is set, but file being point to does not exist:", err)
			} else if jwtSerialized, err := utils.GetTokenFromFile(bearerTokenFile); err == nil {
				tci.CurrentTokenPath = bearerTokenFile
				return jwtSerialized, true
			}
		}
		fallthrough
	case 3:
		tci.Method += 1
		if xdgRuntimeDir, xdgRuntimeDirSet := os.LookupEnv("XDG_RUNTIME_DIR"); xdgRuntimeDirSet {
			// Get the uid
			uid := os.Getuid()
			tmpTokenPath := filepath.Join(xdgRuntimeDir, "bt_u"+strconv.Itoa(uid))
			if _, err := os.Stat(tmpTokenPath); err == nil {
				log.Debugln("Using token from XDG_RUNTIME_DIR")
				if jwtSerialized, err := utils.GetTokenFromFile(tmpTokenPath); err == nil {
					tci.CurrentTokenPath = tmpTokenPath
					return jwtSerialized, true
				}
			}
		}
		fallthrough
	case 4:
		tci.Method += 1
		// Check for /tmp/bt_u<uid>
		uid := os.Getuid()
		tmpTokenPath := "/tmp/bt_u" + strconv.Itoa(uid)
		if _, err := os.Stat(tmpTokenPath); err == nil {
			log.Debugln("Using token from", tmpTokenPath)
			if jwtSerialized, err := utils.GetTokenFromFile(tmpTokenPath); err == nil {
				tci.CurrentTokenPath = tmpTokenPath
				return jwtSerialized, true
			}
		}
		fallthrough
	case 5:
		tci.Method += 1
		// Backwards compatibility for getting token; TOKEN env var is not standardized
		// but some of the oldest use cases may utilize them.
		if tokenFile, isTokenSet := os.LookupEnv("TOKEN"); isTokenSet {
			if _, err := os.Stat(tokenFile); err != nil {
				log.Warningln("Environment variable TOKEN is set, but file being point to does not exist:", err)
			} else if jwtSerialized, err := utils.GetTokenFromFile(tokenFile); err == nil {
				log.Debugln("Using token from TOKEN environment variable")
				tci.CurrentTokenPath = tokenFile
				return jwtSerialized, true
			}
		}
		fallthrough
	case 6:
		tci.Method += 1
		// Finally, look in the HTCondor runtime
		tci.CredLocations = tci.discoverHTCondorTokenLocations(tci.Name)
		fallthrough
	default:
		for {
			idx := tci.Method - 7
			tci.Method += 1
			if idx < 0 || idx >= len(tci.CredLocations) {
				log.Debugln("Out of token locations to search")
				return "", false
			}
			if jwtSerialized, err := utils.GetTokenFromFile(tci.CredLocations[idx]); err == nil {
				tci.CurrentTokenPath = tci.CredLocations[idx]
				return jwtSerialized, true
			}
		}
	}
}

// getToken returns the token to use for the given destination after searching through
// the environment.
//
// Do not use directly -- invoke `get` instead.  Intended to be invoked from a singleflight
// context.
func (tg *tokenGenerator) getToken() (token interface{}, err error) {

	{ // Check to see if the cached token was refreshed prior to the function call
		info := tg.Token.Load()
		if info != nil && time.Until(info.Expiry) > 0 && info.Contents != "" {
			token = info.Contents
			return
		}
	}

	potentialTokens := make([]tokenInfo, 0)
	var lastTokenLocation string

	if tg.TokenName == "" {
		tg.TokenName = tg.Destination.GetTokenName()
	}

	opts := config.TokenGenerationOpts{
		Operation: tg.Operation,
	}

	if tg.Iterator == nil {
		tg.Iterator = newTokenContentIterator(tg.TokenLocation, tg.TokenName)
	}
	for {
		contents, cont := tg.Iterator.next()
		if !cont {
			tg.Iterator = nil
			break
		}
		valid, expiry := tokenIsValid(contents)
		info := tokenInfo{contents, expiry}
		if valid && (tg.DirResp == nil || tokenIsAcceptable(contents, tg.Destination.Path, *tg.DirResp, opts)) {
			tg.Token.Store(&info)
			log.Debugln("Using token:", info.Contents)
			return contents, nil
		} else if contents != "" {
			potentialTokens = append(potentialTokens, info)
			// Track the location of the last token we found
			if tg.Iterator.CurrentTokenPath != "" {
				lastTokenLocation = tg.Iterator.CurrentTokenPath
			}
		}
	}

	// If _any_ potential token is found, even though it's not thought to be acceptable,
	// return that instead of failing outright under the theory the user knows better.
	if len(potentialTokens) > 0 {
		// Use the tracked location, or fall back to TokenLocation if available
		tokenLoc := lastTokenLocation
		if tokenLoc == "" {
			tokenLoc = tg.TokenLocation
		}
		log.Warningf("Using provided token %q even though it does not appear to be acceptable to perform transfer", tokenLoc)
		tg.Token.Store(&potentialTokens[0])
		token = potentialTokens[0].Contents
		err = nil
		return
	}

	if tg.EnableAcquire && tg.Destination != nil && tg.DirResp != nil {
		opts := config.TokenGenerationOpts{Operation: tg.Operation}
		var contents string
		contents, err = AcquireToken(tg.Destination.GetRawUrl(), *tg.DirResp, opts)
		if err == nil && contents != "" {
			valid, expiry := tokenIsValid(contents)
			info := tokenInfo{contents, expiry}
			if !tokenIsAcceptable(contents, tg.Destination.Path, *tg.DirResp, opts) {
				log.Warningln("Token was acquired from issuer but it does not appear valid for transfer; trying anyway")
			} else if !valid {
				log.Warningln("Token was acquired from issuer but it appears to be expired; trying anyway")
			}
			tg.Token.Store(&info)
			token = contents
			return
		}
		log.Errorln("Failed to generate a new authorization token for this transfer: ", err)
		log.Errorln("This transfer requires authorization to complete and no token is available")
		err = errors.Wrap(err, "failed to find or generate a token as required for "+tg.Destination.String())
		return
	}

	log.Errorln("Credential is required, but currently missing")
	return "", errors.New("credential is required for " + tg.Destination.String() + " but was not discovered")
}

// Return the token contents associated with the generator
//
// Thread-safe
func (tg *tokenGenerator) Get() (token string, err error) {
	// First, see if the existing token is valid
	info := tg.Token.Load()
	if info != nil && time.Until(info.Expiry) > 0 && info.Contents != "" {
		// if AcquireToken is enabled and the token is unacceptable, clear the cache and force a new token to be generated
		if tg.EnableAcquire && tg.DirResp != nil && !tokenIsAcceptable(info.Contents, tg.Destination.Path, *tg.DirResp, config.TokenGenerationOpts{Operation: tg.Operation}) {
			tg.Token.Store(nil) // clear the cache and force a new token to be generated
			log.Debugln("Token is not acceptable; clearing cache")
		} else {
			return info.Contents, nil
		}
	}

	// If not, always invoke the synchronized "Do".  It will
	// re-check the cache and, if still invalid, regenerate the token
	tokenGeneric, err, _ := tg.Sync.Do("", tg.getToken)
	if err != nil {
		return
	}
	if tokenStr, ok := tokenGeneric.(string); ok {
		token = tokenStr
		return
	}
	// Should be impossible -- getToken should always return a string
	err = errors.Errorf("token generator failed by returning object of type %T", tokenGeneric)
	return
}

// Given jwtSerialized, a serialized JWT, return whether or not the scopes
// would authorize the given objectName based on the information in dirResp.
func tokenIsAcceptable(jwtSerialized string, objectName string, dirResp server_structs.DirectorResponse, opts config.TokenGenerationOpts) bool {
	tok, err := jwt.Parse([]byte(jwtSerialized), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		log.Warningln("Failed to parse token:", err)
		return false
	}

	// Accept either a WLCG token (wlcg.ver) or a SciToken (ver starting “scitokens:”)
	var isWLCG, isSci bool

	if wlcgVer, ok := tok.Get("wlcg.ver"); ok && wlcgVer != nil {
		isWLCG = true
	}
	if ver, ok := tok.Get("ver"); ok {
		// Based on the scitoken official docs(https://scitokens.org/technical_docs/Verification),
		// the correct behavior for the `ver` claim is `scitoken:2.0` (singular). However, to maintain
		// backward compatibility and typo tolerance, Pelican should keep accepting `scitokens:2.0` too.
		// This implementation is inspired by the scitoken check in scitokens-cpp library.
		if s, ok2 := ver.(string); ok2 && (strings.HasPrefix(s, "scitoken:2.0") || strings.HasPrefix(s, "scitokens:2.0")) {
			isSci = true
		}
	}
	if !isWLCG && !isSci {
		return false
	}

	// Ensure the token issuer matches one of the issuers in the director response, if provided
	if len(dirResp.XPelTokGenHdr.Issuers) > 0 {
		issVal, ok := tok.Get("iss")
		if !ok {
			return false
		}
		issStr, ok := issVal.(string)
		if !ok {
			return false
		}
		foundIssuer := false
		for _, u := range dirResp.XPelTokGenHdr.Issuers {
			if u != nil && issStr == u.String() {
				foundIssuer = true
				break
			}
		}
		if !foundIssuer {
			return false
		}
	}

	osdfPathCleaned := path.Clean(objectName)
	if !strings.HasPrefix(osdfPathCleaned, dirResp.XPelNsHdr.Namespace) {
		return false
	}

	// For some issuers, the token base path is distinct from the OSDF base path.
	// Example:
	// - Issuer base path: `/chtc`
	// - Namespace path: `/chtc/PROTECTED`
	// In this case, we want to strip out the issuer base path, not the
	// namespace one, in order to see if the token has the right privs.

	// TODO: Come back and figure out how to resolve this in the case that there are multiple issuers or multiple base paths.
	targetResource := path.Clean("/" + osdfPathCleaned[len(dirResp.XPelNsHdr.Namespace):])
	if len(dirResp.XPelTokGenHdr.Issuers) >= 0 && len(dirResp.XPelTokGenHdr.BasePaths) > 0 && dirResp.XPelTokGenHdr.BasePaths[0] != "" {
		targetResource = path.Clean("/" + osdfPathCleaned[len(dirResp.XPelTokGenHdr.BasePaths[0]):])
	}

	scopesIface, ok := tok.Get("scope")
	if !ok {
		return false
	}
	scopes, ok := scopesIface.(string)
	if !ok {
		return false
	}

	return hasAcceptableScope(scopes, isWLCG, isSci, targetResource, opts)
}

// parseScope splits a scope string into authorization and resource parts.
// If no colon is present, returns the entire scope as authz with empty resource.
func parseScope(scope string) (authz, resource string, hasResource bool) {
	parts := strings.SplitN(scope, ":", 2)
	if len(parts) == 1 {
		return parts[0], "", false
	}
	return parts[0], parts[1], true
}

// hasAcceptableScope checks if any scope in the space-separated scope string
// is acceptable for the given operation and resource.
func hasAcceptableScope(scopes string, isWLCG, isSci bool, targetResource string, opts config.TokenGenerationOpts) bool {
	for _, scope := range strings.Fields(scopes) {
		authz, resource, hasResource := parseScope(scope)
		if authz == "" {
			continue
		}

		// Check if the authorization scope is valid for WLCG or Sci tokens
		scopeValid := (isWLCG && isValidWLCGScope(authz, opts.Operation)) || (isSci && isValidSciScope(authz, opts.Operation))
		if !scopeValid {
			continue
		}

		// If scope has no resource part, accept it
		if !hasResource {
			return true
		}

		// If scope has a resource part, check if it matches (exact for shared URLs, prefix otherwise)
		if matchesResource(targetResource, resource, opts.Operation) {
			return true
		}
	}
	return false
}

// matchesResource checks if the target resource matches the scope resource.
// For shared URLs, exact matches are preferred, but prefix matching is also acceptable.
func matchesResource(targetResource, scopeResource string, operation config.TokenOperation) bool {
	isSharedOperation := operation.IsEnabled(config.TokenSharedWrite) || operation.IsEnabled(config.TokenSharedRead)

	// Normalize paths for comparison: remove trailing slashes (except for root "/")
	// A scope like "/gluex/" should match both "/gluex/something" and "/gluex"
	targetNorm := targetResource
	if len(targetNorm) > 1 && strings.HasSuffix(targetNorm, "/") {
		targetNorm = strings.TrimSuffix(targetNorm, "/")
	}
	scopeNorm := scopeResource
	if len(scopeNorm) > 1 && strings.HasSuffix(scopeNorm, "/") {
		scopeNorm = strings.TrimSuffix(scopeNorm, "/")
	}

	// For shared operations, exact match is preferred; otherwise, prefix matching is acceptable.
	// However, prefix matching is always acceptable as a fallback.
	// Check exact match on normalized paths, or prefix match on original paths
	return (isSharedOperation && targetNorm == scopeNorm) ||
		strings.HasPrefix(targetResource, scopeResource) ||
		strings.HasPrefix(targetNorm, scopeNorm)
}

func isValidWLCGScope(authz string, operation config.TokenOperation) bool {
	switch {
	case operation.IsEnabled(config.TokenWrite) || operation.IsEnabled(config.TokenSharedWrite):
		return authz == token_scopes.Wlcg_Storage_Modify.String() || authz == token_scopes.Wlcg_Storage_Create.String()
	case operation.IsEnabled(config.TokenDelete):
		return authz == token_scopes.Wlcg_Storage_Modify.String()
	case operation.IsEnabled(config.TokenRead) || operation.IsEnabled(config.TokenSharedRead):
		return authz == token_scopes.Wlcg_Storage_Read.String()
	default:
		return false
	}
}

func isValidSciScope(authz string, operation config.TokenOperation) bool {
	switch {
	case operation.IsEnabled(config.TokenWrite) || operation.IsEnabled(config.TokenSharedWrite):
		return authz == token_scopes.Scitokens_Write.String()
	case operation.IsEnabled(config.TokenDelete):
		return authz == token_scopes.Scitokens_Write.String()
	case operation.IsEnabled(config.TokenRead) || operation.IsEnabled(config.TokenSharedRead):
		return authz == token_scopes.Scitokens_Read.String()
	default:
		return false
	}
}

// Return whether the JWT represented by jwtSerialized is valid.
//
// Valid means that the current time is after the `nbf` ("not before")
// claim and before the `exp` ("expiration") claim.
//
// If valid, then the function also returns the expiration time.
func tokenIsValid(jwtSerialized string) (valid bool, expiry time.Time) {
	token, err := jwt.Parse([]byte(jwtSerialized), jwt.WithVerify(false))
	if err != nil {
		log.Warningln("Failed to parse token:", err)
		return
	}

	if err := jwt.Validate(token); err != nil {
		log.Warningln("Token is invalid:", err)
		return false, token.Expiration()
	}

	valid = true
	expiry = token.Expiration()
	return
}

func tokenIsExpired(jwtSerialized string) (expired bool, expiry time.Time, err error) {
	token, err := jwt.Parse([]byte(jwtSerialized), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return
	}
	return token.Expiration().Before(time.Now()), token.Expiration(), nil
}

func registerClient(dirResp server_structs.DirectorResponse) (*config.PrefixEntry, error) {
	issuers := dirResp.XPelTokGenHdr.Issuers
	if len(issuers) == 0 {
		return nil, fmt.Errorf("no issuer information for prefix '%s' is provided", dirResp.XPelNsHdr.Namespace)
	}
	issuerUrl := issuers[0].String()
	issuer, err := config.GetIssuerMetadata(issuerUrl)
	if err != nil {
		return nil, err
	}
	if issuer.RegistrationURL == "" {
		return nil, errors.Errorf("issuer %s does not support dynamic client registration", issuerUrl)
	}

	drcp := oauth2.DCRPConfig{ClientRegistrationEndpointURL: issuer.RegistrationURL, Transport: config.GetTransport(), Metadata: oauth2.Metadata{
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "OSDF Command Line Client",
		Scopes:                  []string{"offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"},
	}}

	resp, err := drcp.Register()
	if err != nil {
		return nil, err
	}
	newEntry := config.PrefixEntry{
		Prefix:       dirResp.XPelNsHdr.Namespace,
		ClientID:     resp.ClientID,
		ClientSecret: resp.ClientSecret,
	}
	return &newEntry, nil
}

// Given a URL and a director Response, attempt to acquire a valid
// token for that URL.
func AcquireToken(destination *url.URL, dirResp server_structs.DirectorResponse, opts config.TokenGenerationOpts) (string, error) {

	log.Debugln("Acquiring a token from configuration and OAuth2")

	nsPrefix := dirResp.XPelNsHdr.Namespace

	switch tokStrategy := dirResp.XPelTokGenHdr.Strategy; tokStrategy {
	case server_structs.OAuthStrategy:
	case server_structs.VaultStrategy:
		return "", fmt.Errorf("vault credential generation strategy is not supported")
	default:
		return "", fmt.Errorf("unknown credential generation strategy (%s) for prefix %s",
			tokStrategy, nsPrefix)
	}

	issuers := dirResp.XPelTokGenHdr.Issuers
	if len(issuers) == 0 {
		return "", fmt.Errorf("no issuer information for prefix '%s' is provided", nsPrefix)
	}

	issuer := issuers[0].String()
	if len(issuer) == 0 {
		return "", fmt.Errorf("issuer URL for prefix %s is unknown", nsPrefix)
	}

	osdfConfig, err := config.GetCredentialConfigContents()
	if err != nil {
		return "", err
	}

	prefixIdx := -1
	for idx, entry := range osdfConfig.OSDF.OauthClient {
		if entry.Prefix == nsPrefix {
			prefixIdx = idx
			break
		}
	}
	var prefixEntry *config.PrefixEntry
	newEntry := false
	tryTokenGen := false
	if prefixIdx < 0 {
		// We prefer to generate a token over registering a new client.
		if token, err := generateToken(destination, dirResp, opts); err == nil && token != "" {
			log.Debugln("Successfully generated a new token from a local key")
			return token, nil
		}
		tryTokenGen = true

		log.Infof("Prefix configuration for %s not in configuration file; will request new client", nsPrefix)
		prefixEntry, err = registerClient(dirResp)
		if err != nil {
			return "", err
		}
		osdfConfig.OSDF.OauthClient = append(osdfConfig.OSDF.OauthClient, *prefixEntry)
		prefixEntry = &osdfConfig.OSDF.OauthClient[len(osdfConfig.OSDF.OauthClient)-1]
		newEntry = true
	} else {
		prefixEntry = &osdfConfig.OSDF.OauthClient[prefixIdx]
		if len(prefixEntry.ClientID) == 0 || len(prefixEntry.ClientSecret) == 0 {

			// Similarly, here, generate a token before registering a new client.
			if token, err := generateToken(destination, dirResp, opts); err == nil && token != "" {
				log.Debugln("Successfully generated a new token from a local key")
				return token, nil
			}
			tryTokenGen = true

			log.Infof("Prefix configuration for %s missing OAuth2 client information", nsPrefix)
			prefixEntry, err = registerClient(dirResp)
			if err != nil {
				return "", err
			}
			osdfConfig.OSDF.OauthClient[prefixIdx] = *prefixEntry
			newEntry = true
		}
	}
	if newEntry {
		if err = config.SaveConfigContents(&osdfConfig); err != nil {
			log.Warningln("Failed to save new token to configuration file:", err)
		}
	}

	// First search for an acceptable and unexpired token.
	for _, token := range prefixEntry.Tokens {
		if tokenIsAcceptable(token.AccessToken, destination.Path, dirResp, opts) {
			if valid, _ := tokenIsValid(token.AccessToken); valid {
				log.Debugln("Returning an unexpired token from cache")
				return token.AccessToken, nil
			}
		}
	}

	// If no acceptable and unexpired token is found, search for an acceptable token to refresh.
	var tokenToRefresh *config.TokenEntry = nil
	for idx, token := range prefixEntry.Tokens {
		if tokenIsAcceptable(token.AccessToken, destination.Path, dirResp, opts) {
			tokenToRefresh = &prefixEntry.Tokens[idx]
			break
		}
	}

	if tokenToRefresh != nil {
		// We have a reasonable token; let's try refreshing it.
		upstreamToken := oauth2_upstream.Token{
			AccessToken:  tokenToRefresh.AccessToken,
			RefreshToken: tokenToRefresh.RefreshToken,
			Expiry:       time.Unix(0, 0),
		}
		issuerInfo, err := config.GetIssuerMetadata(issuer)
		if err == nil {
			upstreamConfig := oauth2_upstream.Config{
				ClientID:     prefixEntry.ClientID,
				ClientSecret: prefixEntry.ClientSecret,
				Endpoint: oauth2_upstream.Endpoint{
					AuthURL:  issuerInfo.AuthURL,
					TokenURL: issuerInfo.TokenURL,
				}}
			client := &http.Client{Transport: config.GetTransport()}
			ctx := context.WithValue(context.Background(), oauth2_upstream.HTTPClient, client)
			source := upstreamConfig.TokenSource(ctx, &upstreamToken)
			newToken, err := source.Token()
			if err != nil {
				log.Warningln("Failed to renew an expired token:", err)
			} else {
				tokenToRefresh.AccessToken = newToken.AccessToken
				tokenToRefresh.Expiration = newToken.Expiry.Unix()
				if len(newToken.RefreshToken) != 0 {
					tokenToRefresh.RefreshToken = newToken.RefreshToken
				}
				if err = config.SaveConfigContents(&osdfConfig); err != nil {
					log.Warningln("Failed to save new token to configuration file:", err)
				}
				return newToken.AccessToken, nil
			}
		}
	}

	// If here, we've got a valid OAuth2 client credential but didn't have any luck refreshing -
	// try generating the token before requiring a potentially user-interactive flow.
	if !tryTokenGen {
		if token, err := generateToken(destination, dirResp, opts); err == nil && token != "" {
			log.Debugln("Successfully generated a new token from a local key")
			return token, nil
		}
	}

	token, err := oauth2.AcquireToken(issuer, prefixEntry, dirResp, destination.Path, opts)
	if errors.Is(err, oauth2.ErrUnknownClient) {
		// We use anonymously-registered clients; OA4MP can periodically garbage collect these to prevent DoS
		// In this case, we register a new client and try to acquire again.
		log.Infof("Identity provider does not know the client for %s; registering a new one", nsPrefix)
		prefixEntry, err = registerClient(dirResp)
		if err != nil {
			return "", errors.Wrap(err, "re-registration error (identity provider does not recognize our client)")
		}
		osdfConfig.OSDF.OauthClient[prefixIdx] = *prefixEntry
		if err = config.SaveConfigContents(&osdfConfig); err != nil {
			log.Warningln("Failed to save new token to configuration file:", err)
		}

		if token, err = oauth2.AcquireToken(issuer, prefixEntry, dirResp, destination.Path, opts); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	if token == nil {
		return "", fmt.Errorf("issuer %s returned an empty token response", issuer)
	}

	// At this point, we have a freshly acquired credential. tokenIsAcceptable can still fail only if:
	//  - the token lacks the storage scope required for the requested operation; or
	//  - the token is not valid for the director-provided namespace/base-path.
	// Issuer mismatches are handled earlier by oauth2.AcquireToken and will not reach this check.
	if !tokenIsAcceptable(token.AccessToken, destination.Path, dirResp, opts) {
		return "", error_codes.NewAuthorizationError(fmt.Errorf("acquired token not valid for %s (missing scope or namespace/base-path mismatch)", destination.Path))
	}

	Tokens := &prefixEntry.Tokens
	*Tokens = append(*Tokens, *token)

	if err = config.SaveConfigContents(&osdfConfig); err != nil {
		log.Warningln("Failed to save new token to configuration file:", err)
	}

	return token.AccessToken, nil
}

// Given a URL and a known public key, determine whether the public key
// is valid for the issuer URL.
//
// If valid, returns the corresponding keyId and sets found to true.
func findKeyId(url string, ecPubKey *ecdsa.PublicKey) (keyid string, found bool) {
	// Next, download the public keys for the issuer
	ctx := context.Background()
	issuerInfo, err := config.GetIssuerMetadata(url)
	if err != nil {
		log.Debugln("Failed to get metadata for", url, ":", err)
		return
	}
	client := &http.Client{Transport: config.GetTransport()}
	fetchOption := jwk.WithHTTPClient(client)
	jwks, err := jwk.Fetch(ctx, issuerInfo.JwksUri, fetchOption)
	if err != nil {
		log.Debugln("Failed to fetch the JWKS:", err)
		return
	}
	keyIter := jwks.Keys(ctx)
	for keyIter.Next(ctx) {
		pair := keyIter.Pair()
		key, ok := pair.Value.(jwk.Key)
		if !ok {
			log.Debugln("Decode of JWK in return JWKS failed")
			continue
		}
		var ecPubKey2 ecdsa.PublicKey
		if err = key.Raw(&ecPubKey2); err != nil {
			log.Debugln("Failed to convert public key:", err)
			continue
		}
		if ecPubKey2.Equal(ecPubKey) {
			return key.KeyID(), true
		}
	}
	return
}

// Check to see if there's a copy of the issuer's pubkey locally; if so, generate an appropriate token directly.
func generateToken(destination *url.URL, dirResp server_structs.DirectorResponse, opts config.TokenGenerationOpts) (tkn string, err error) {
	// Check to see if a private key is installed locally
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		log.Debugln("Cannot generate a token locally as private key is not present:", err)
		return
	}
	log.Debugln("Trying to generate a token locally from issuer private key")
	pubKey, err := key.PublicKey()
	if err != nil {
		log.Debugln("Cannot generate a token locally as the public key cannot be generated:", err)
		return
	}
	var ecPubKey ecdsa.PublicKey
	if err = pubKey.Raw(&ecPubKey); err != nil {
		log.Debugln("Failed to convert JWT pub key to ECDSA:", err)
		return
	}

	log.Debugln("Searching issuer public keys for matching key")
	// Next, download the public keys for the issuer
	var found bool
	var keyId, issuer string
	for _, issuerUrl := range dirResp.XPelAuthHdr.Issuers {
		if issuerUrl == nil {
			continue
		}
		issuer = issuerUrl.String()
		keyId, found = findKeyId(issuer, &ecPubKey)
		if found {
			break
		}
	}
	if !found {
		log.Debugln("Failed to find public key at issuer corresponding to local public key")
		return
	}

	tc, err := token.NewTokenConfig(token.WlcgProfile{})
	if err != nil {
		return
	}
	tc.AddAudienceAny()
	tc.Issuer = issuer
	tc.Lifetime = time.Hour
	tc.Subject = "client_token"
	scopes := []token_scopes.ResourceScope{}
	base := path.Clean(dirResp.XPelNsHdr.Namespace)
	dest := path.Clean(destination.Path)

	after, found := strings.CutPrefix(dest, base)
	if !found {
		err = errors.New("Destination resource not inside director-provided namespace")
		return
	}

	ops := []struct {
		enabled bool
		scope   token_scopes.TokenScope
	}{
		{opts.Operation.IsEnabled(config.TokenRead) || opts.Operation.IsEnabled(config.TokenSharedRead), token_scopes.Wlcg_Storage_Read},
		{opts.Operation.IsEnabled(config.TokenWrite) || opts.Operation.IsEnabled(config.TokenSharedWrite), token_scopes.Wlcg_Storage_Create},
		{opts.Operation.IsEnabled(config.TokenDelete), token_scopes.Wlcg_Storage_Modify},
		{opts.Operation.IsEnabled(config.TokenList), token_scopes.Wlcg_Storage_Read},
	}

	for _, op := range ops {
		if op.enabled {
			scopes = append(scopes, token_scopes.NewResourceScope(op.scope, after))
		}
	}
	tc.AddResourceScopes(scopes...)

	err = key.Set("kid", keyId)
	if err != nil {
		return
	}
	tkn, err = tc.CreateTokenWithKey(key)
	return
}
