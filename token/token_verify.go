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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	TokenSource string
	TokenIssuer string
	AuthOption  struct {
		Sources   []TokenSource
		Issuers   []TokenIssuer
		Scopes    []token_scopes.TokenScope
		AllScopes bool
	}
	AuthChecker interface {
		federationIssuerCheck(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScopes bool) error
		localIssuerCheck(ctx *gin.Context, token string, expectedScopes []token_scopes.TokenScope, allScopes bool) error
	}
	AuthCheckImpl     struct{}
	DiscoveryResponse struct { // This is a duplicate from director/authentication to ensure we don't have cyclic import
		Issuer  string `json:"issuer"`
		JwksUri string `json:"jwks_uri"`
	}
)

const (
	Header TokenSource = "AuthorizationHeader" // "Authorization" header
	Cookie TokenSource = "Cookie"              // "login" cookie
	Authz  TokenSource = "AuthzQueryParameter" // "authz" query parameter
)

const (
	FederationIssuer TokenIssuer = "FederationIssuer"
	LocalIssuer      TokenIssuer = "LocalIssuer"
)

var (
	federationJWK *jwk.Cache
	authChecker   AuthChecker
)

func init() {
	authChecker = &AuthCheckImpl{}
}

// Checks that the given token was signed by the federation jwk and also checks that the token has the expected scope
func (a AuthCheckImpl) federationIssuerCheck(c *gin.Context, strToken string, expectedScopes []token_scopes.TokenScope, allScopes bool) error {
	fedURL := param.Federation_DiscoveryUrl.GetString()
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))

	if err != nil {
		return err
	}

	if fedURL != token.Issuer() {
		return errors.New(fmt.Sprintf("Token issuer %s does not match the issuer from the federation. Expecting the issuer to be %s", token.Issuer(), fedURL))
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
		return errors.Wrap(err, fmt.Sprintf("Failed to verify the scope of the token. Require %v", expectedScopes))
	}

	c.Set("User", "Federation")
	return nil
}

// Checks that the given token was signed by the local issuer on the server
func (a AuthCheckImpl) localIssuerCheck(c *gin.Context, strToken string, expectedScopes []token_scopes.TokenScope, allScopes bool) error {
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))
	if err != nil {
		return errors.Wrap(err, "Invalid JWT")
	}

	serverURL := param.Server_ExternalWebUrl.GetString()
	if serverURL != token.Issuer() {
		if param.Origin_Url.GetString() == token.Issuer() {
			return errors.New(fmt.Sprintf("Wrong issuer %s; expect the issuer to be the server's web address but got Origin.URL", token.Issuer()))
		} else {
			return errors.New(fmt.Sprintf("Token issuer %s does not match the local issuer on the current server. Expecting %s", token.Issuer(), serverURL))
		}
	}

	// Since whenever this function is called, the localIssuerCheck is checking token signature
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
		return errors.Wrap(err, fmt.Sprintf("Failed to verify the scope of the token. Require %v", expectedScopes))
	}

	c.Set("User", "Origin")
	return nil
}

// Check token authentication with token obtained from authOption.Sources, found the first
// token available and proceed to check against a list of authOption.Issuers with
// authOption.Scopes, return true and set "User" context to the issuer if any of the issuer check succeed
//
// Scope check will pass if your token has ANY of the scopes in authOption.Scopes
func Verify(ctx *gin.Context, authOption AuthOption) (status int, verified bool, err error) {
	token := ""
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
				continue
			} else {
				token = cookieToken
				tokenFound = true
			}
		case Header:
			headerToken := ctx.Request.Header["Authorization"]
			if len(headerToken) <= 0 {
				continue
			} else {
				var found bool
				token, found = strings.CutPrefix(headerToken[0], "Bearer ")
				if found {
					tokenFound = true
				}
			}
		case Authz:
			authzToken := ctx.Request.URL.Query()["authz"]
			if len(authzToken) <= 0 {
				continue
			} else {
				token = authzToken[0]
				tokenFound = true
			}
		default:
			log.Error("Invalid/unsupported token source")
			return http.StatusInternalServerError, false, errors.New("Cannot verify token due to bad server configuration. Invalid/unsupported token source")
		}
	}

	if token == "" {
		log.Debugf("Unauthorized. No token is present from the list of potential token positions: %v", authOption.Sources)
		return http.StatusForbidden, false, errors.New("Authentication is required but no token is present.")
	}

	errMsg := ""
	for _, iss := range authOption.Issuers {
		switch iss {
		case FederationIssuer:
			if err := authChecker.federationIssuerCheck(ctx, token, authOption.Scopes, authOption.AllScopes); err != nil {
				errMsg += fmt.Sprintln("Cannot verify token with federation issuer: ", err)
			} else {
				return http.StatusOK, true, nil
			}
		case LocalIssuer:
			if err := authChecker.localIssuerCheck(ctx, token, authOption.Scopes, authOption.AllScopes); err != nil {
				errMsg += fmt.Sprintln("Cannot verify token with server issuer: ", err)
			} else {
				return http.StatusOK, true, nil
			}
		default:
			log.Error("Invalid/unsupported token issuer")
			return http.StatusInternalServerError, false, errors.New("Cannot verify token due to bad server configuration. Invalid/unsupported token issuer")
		}
	}

	// If the function reaches here, it means no token check passed
	log.Debug("Cannot verify token:\n", errMsg)
	return http.StatusForbidden, false, errors.New("Cannot verify token: " + errMsg)
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
