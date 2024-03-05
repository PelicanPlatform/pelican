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

package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	TokenSource int
	TokenIssuer int
	AuthOption  struct {
		Sources   []TokenSource
		Issuers   []TokenIssuer
		Scopes    []token_scopes.TokenScope
		AllScopes bool
	}
	AuthChecker interface {
		FederationCheck(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScopes bool) error
		IssuerCheck(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScopes bool) error
	}
	AuthCheckImpl     struct{}
	DiscoveryResponse struct { // This is a duplicate from director/authentication to ensure we don't have cyclic import
		Issuer  string `json:"issuer"`
		JwksUri string `json:"jwks_uri"`
	}
)

const (
	Header TokenSource = iota // "Authorization" header
	Cookie                    // "login" cookie
	Authz                     // "authz" query parameter
)

const (
	Federation TokenIssuer = iota
	Issuer
)

var (
	federationJWK    *jwk.Cache
	directorJWK      *jwk.Cache
	directorMetadata *httprc.Cache
	authChecker      AuthChecker
)

func init() {
	authChecker = &AuthCheckImpl{}
}

// [Deprecated] This function is expected to be removed very soon, after
// https://github.com/PelicanPlatform/pelican/issues/559 is implemented
//
// Return director's public JWK for token verification. This function can be called
// on any server (director/origin/registry) as long as the Federation_DirectorUrl is set
//
// The director's metadata discovery endpoint and JWKS endpoint are cached
func LoadDirectorPublicKey() (jwk.Key, error) {
	directorUrlStr := param.Federation_DirectorUrl.GetString()
	if len(directorUrlStr) == 0 {
		return nil, errors.Errorf("Director URL is unset; Can't load director's public key")
	}
	log.Debugln("Director's discovery URL:", directorUrlStr)
	directorUrl, err := url.Parse(directorUrlStr)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Invalid director URL:", directorUrlStr))
	}
	directorUrl.Scheme = "https"
	directorUrl.Path = directorUrl.Path + "/.well-known/openid-configuration"

	directorMetadataCtx := context.Background()
	if directorMetadata == nil {
		client := &http.Client{Transport: config.GetTransport()}
		directorMetadata = httprc.NewCache(directorMetadataCtx)
		if err := directorMetadata.Register(directorUrl.String(), httprc.WithMinRefreshInterval(15*time.Minute), httprc.WithHTTPClient(client)); err != nil {
			return nil, errors.Wrap(err, "Failed to register httprc cache for director's metadata")
		}
	}

	payload, err := directorMetadata.Get(directorMetadataCtx, directorUrl.String())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get director's metadata")
	}

	metadata := DiscoveryResponse{}

	err = json.Unmarshal(payload.([]byte), &metadata)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when parsing director metadata at: ", directorUrl))
	}

	jwksUri := metadata.JwksUri

	directorJwkCtx := context.Background()
	if directorJWK == nil {
		client := &http.Client{Transport: config.GetTransport()}
		directorJWK = jwk.NewCache(directorJwkCtx)
		if err := directorJWK.Register(jwksUri, jwk.WithRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
			return nil, errors.Wrap(err, "Failed to register internal JWKS cache for director's public JWKS")
		}
	}

	jwks, err := directorJWK.Get(directorJwkCtx, jwksUri)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to get director's public JWKS")
	}
	key, ok := jwks.Key(0)
	if !ok {
		return nil, errors.Wrap(err, fmt.Sprintln("Failure when getting director's first public key: ", jwksUri))
	}

	return key, nil
}

// Checks that the given token was signed by the federation jwk and also checks that the token has the expected scope
func (a AuthCheckImpl) FederationCheck(c *gin.Context, strToken string, expectedScopes []token_scopes.TokenScope, allScopes bool) error {
	fedURL := param.Federation_DiscoveryUrl.GetString()
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))

	if err != nil {
		return err
	}

	if fedURL != token.Issuer() {
		return errors.New(fmt.Sprint("Issuer is not a federation: ", token.Issuer()))
	}

	fedURIFile := param.Federation_JwkUrl.GetString()
	ctx := context.Background()
	if federationJWK == nil {
		client := &http.Client{Transport: config.GetTransport()}
		federationJWK = jwk.NewCache(ctx)
		if err := federationJWK.Register(fedURIFile, jwk.WithRefreshInterval(15*time.Minute), jwk.WithHTTPClient(client)); err != nil {
			return errors.Wrap(err, "Failed to register cache for federation's public JWKS")
		}
	}

	jwks, err := federationJWK.Get(ctx, fedURIFile)
	if err != nil {
		return errors.Wrap(err, "Failed to get federation's public JWKS")
	}

	parsed, err := jwt.Parse([]byte(strToken), jwt.WithKeySet(jwks))

	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by federation's key")
	}

	scopeValidator := token_scopes.CreateScopeValidator(expectedScopes, allScopes)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Federation")
	return nil
}

// Checks that the given token was signed by the issuer jwk (the one from the server itself) and also checks that
// the token has the expected scope
//
// Note that this means the issuer jwk MUST be the one server created. It can't be provided by
// the user if they want to use a different issuer than the server. This can be changed in the future.
func (a AuthCheckImpl) IssuerCheck(c *gin.Context, strToken string, expectedScopes []token_scopes.TokenScope, allScopes bool) error {
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))
	if err != nil {
		return errors.Wrap(err, "Invalid JWT")
	}

	serverURL := param.Server_ExternalWebUrl.GetString()
	if serverURL != token.Issuer() {
		if param.Origin_Url.GetString() == token.Issuer() {
			return errors.New(fmt.Sprint("Wrong issuer; expect the issuer to be the server's web address but got Origin.URL, " + token.Issuer()))
		} else {
			return errors.New(fmt.Sprint("Issuer is not server itself: ", token.Issuer()))
		}
	}

	// Since whenever this function is called, the IssuerCheck is checking token signature
	// against the server's public key, we can directly get the public key
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return errors.Wrap(err, "Failed to load issuer server's public key")
	}

	parsed, err := jwt.Parse([]byte(strToken), jwt.WithKeySet(jwks))

	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by issuer's key")
	}

	scopeValidator := token_scopes.CreateScopeValidator(expectedScopes, allScopes)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Origin")
	return nil
}

// Check token authentication with token obtained from authOption.Sources, found the first
// token available and proceed to check against a list of authOption.Issuers with
// authOption.Scopes, return true and set "User" context to the issuer if any of the issuer check succeed
//
// Scope check will pass if your token has ANY of the scopes in authOption.Scopes
func CheckAnyAuth(ctx *gin.Context, authOption AuthOption) bool {
	token := ""
	errMsg := ""
	// Find token from the provided sources list, stop when found the first token
	tokenFound := false
	for _, opt := range authOption.Sources {
		if tokenFound {
			break
		}
		switch opt {
		case Cookie:
			cookieToken, err := ctx.Cookie("login")
			if err != nil || cookieToken == "" {
				errMsg += fmt.Sprintln("No 'login' cookie present: ", err)
				continue
			} else {
				token = cookieToken
				tokenFound = true
				break
			}
		case Header:
			headerToken := ctx.Request.Header["Authorization"]
			if len(headerToken) <= 0 {
				errMsg += fmt.Sprintln("No Authorization header present")
				continue
			} else {
				token = strings.TrimPrefix(headerToken[0], "Bearer ")
				tokenFound = true
				break
			}
		case Authz:
			authzToken := ctx.Request.URL.Query()["authz"]
			if len(authzToken) <= 0 {
				errMsg += fmt.Sprintln("No Authz query parameter present")
				continue
			} else {
				token = authzToken[0]
				tokenFound = true
				break
			}
		default:
			log.Info("Authentication failed. Invalid/unsupported token source")
			return false
		}
	}

	if token == "" {
		log.Info("Authentication failed. No token is present from the list of potential token positions")
		return false
	}

	for _, iss := range authOption.Issuers {
		switch iss {
		case Federation:
			err := authChecker.FederationCheck(ctx, token, authOption.Scopes, authOption.AllScopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Token validation failed with federation issuer: ", err)
				log.Debug("Token validation failed with federation issuer: ", err)
				break
			} else {
				log.Debug("Token validation succeeded with federation issuer")
				return exists
			}
		case Issuer:
			err := authChecker.IssuerCheck(ctx, token, authOption.Scopes, authOption.AllScopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Token validation failed with server issuer: ", err)
				log.Debug("Token validation failed with server issuer: ", err)
				break
			} else {
				log.Debug("Token validation succeeded with server issuer")
				return exists
			}
		default:
			log.Info("Authentication failed. Invalid/unsupported token issuer")
			return false
		}
	}

	// If the function reaches here, it means no token check passed
	log.Info("Authentication failed. Didn't pass the chain of checking:\n", errMsg)
	return false
}

// Given a request, try to get a token from its "authz" query parameter or "Authorization" header
func GetAuthzEscaped(ctx *gin.Context) (authzEscaped string) {
	if authzQuery := ctx.Request.URL.Query()["authz"]; len(authzQuery) > 0 {
		authzEscaped = authzQuery[0]
		// if the authz URL query is coming from XRootD, it probably has a "Bearer " tacked in front
		// even though it's coming via a URL
		authzEscaped = strings.TrimPrefix(authzEscaped, "Bearer ")
	} else if authzHeader := ctx.Request.Header["Authorization"]; len(authzHeader) > 0 {
		authzEscaped = strings.TrimPrefix(authzHeader[0], "Bearer ")
		authzEscaped = url.QueryEscape(authzEscaped)
	} else if authzCookie, err := ctx.Cookie("login"); err == nil && len(authzCookie) > 0 {
		authzEscaped = url.QueryEscape(authzCookie)
	}
	return
}

// For a given prefix, get the prefix's issuer URL, where we consider that the openid endpoint
// we use to look up a key location. Note that this is NOT the same as the issuer key -- to
// find that, follow openid-style discovery using the issuer URL as a base.
func GetNSIssuerURL(prefix string) (string, error) {
	if prefix == "" || !strings.HasPrefix(prefix, "/") {
		return "", errors.New(fmt.Sprintf("the prefix \"%s\" is invalid", prefix))
	}
	registryUrlStr := param.Federation_RegistryUrl.GetString()
	if registryUrlStr == "" {
		return "", errors.New("federation registry URL is not set and was not discovered")
	}
	registryUrl, err := url.Parse(registryUrlStr)
	if err != nil {
		return "", err
	}

	registryUrl.Path, err = url.JoinPath(registryUrl.Path, "api", "v1.0", "registry", prefix)

	if err != nil {
		return "", errors.Wrapf(err, "failed to construct openid-configuration lookup URL for prefix %s", prefix)
	}
	return registryUrl.String(), nil
}

// Given an issuer url, lookup the JWKS URL from the openid-configuration
// For example, if the issuer URL is https://registry.com:8446/api/v1.0/registry/test-namespace,
// this function will return the key indicated by the openid-configuration JSON hosted at
// https://registry.com:8446/api/v1.0/registry/test-namespace/.well-known/openid-configuration.
func GetJWKSURLFromIssuerURL(issuerUrl string) (string, error) {
	// Get/parse the openid-configuration JSON to lookup key location
	issOpenIDUrl, err := url.Parse(issuerUrl)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse issuer URL")
	}
	issOpenIDUrl.Path, _ = url.JoinPath(issOpenIDUrl.Path, ".well-known", "openid-configuration")

	client := &http.Client{Transport: config.GetTransport()}
	openIDCfg, err := client.Get(issOpenIDUrl.String())
	if err != nil {
		return "", errors.Wrapf(err, "failed to lookup openid-configuration for issuer %s", issuerUrl)
	}
	defer openIDCfg.Body.Close()

	// If we hit an old registry, it may not have the openid-configuration. In that case, we fallback to the old
	// behavior of looking for the key directly at the issuer URL.
	if openIDCfg.StatusCode == http.StatusNotFound {
		oldKeyLoc, err := url.JoinPath(issuerUrl, ".well-known", "issuer.jwks")
		if err != nil {
			return "", errors.Wrapf(err, "failed to construct key lookup URL for issuer %s", issuerUrl)
		}
		return oldKeyLoc, nil
	}

	body, err := io.ReadAll(openIDCfg.Body)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read response body from %s", issuerUrl)
	}

	var openIDCfgMap map[string]string
	err = json.Unmarshal(body, &openIDCfgMap)
	if err != nil {
		return "", errors.Wrapf(err, "failed to unmarshal openid-configuration for issuer %s", issuerUrl)
	}

	if keyLoc, ok := openIDCfgMap["jwks_uri"]; ok {
		return keyLoc, nil
	} else {
		return "", errors.New(fmt.Sprintf("no key found in openid-configuration for issuer %s", issuerUrl))
	}
}

func GetJWKSFromIssUrl(issuer string) (*jwk.Set, error) {
	// Make sure our URL is solid
	issuerUrl, err := url.Parse(issuer)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintln("Invalid issuer URL: ", issuerUrl))
	}

	// Discover the JWKS URL from the issuer
	pubkeyUrlStr, err := GetJWKSURLFromIssuerURL(issuerUrl.String())
	if err != nil {
		return nil, errors.Wrap(err, "Error getting JWKS URL from issuer URL")
	}

	fmt.Printf("\n\n\nPUBKEY URL: %s\n\n\n", pubkeyUrlStr)

	// Query the JWKS URL for the public keys
	httpClient := &http.Client{Transport: config.GetTransport()}
	req, err := http.NewRequest("GET", pubkeyUrlStr, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating request to issuer's JWKS URL")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrapf(err, "Error querying issuer's key endpoint (%s)", pubkeyUrlStr)
	}
	defer resp.Body.Close()
	// Check the response code, make sure it's not in the error ranges (400-500)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, errors.Errorf("The issuer's JWKS endpoint returned an unexpected status: %s", resp.Status)
	}

	// Read the response body and parse the JWKs from it
	jwksStr, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "Error reading response body from %s", pubkeyUrlStr)
	}
	kSet, err := jwk.ParseString(string(jwksStr))
	if err != nil {
		return nil, errors.Wrapf(err, "Error parsing JWKs from %s", pubkeyUrlStr)
	}

	return &kSet, nil
}
