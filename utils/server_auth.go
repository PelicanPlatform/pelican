/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
package utils

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	TokenSource int
	TokenIssuer int
	AuthOption  struct {
		Sources   []TokenSource
		Issuers   []TokenIssuer
		Scopes    []string
		AllScopes bool
	}
	AuthChecker interface {
		FederationCheck(ctx *gin.Context, token string, expectedScopes []string, allScopes bool) error
		DirectorCheck(ctx *gin.Context, token string, expectedScopes []string, allScopes bool) error
		IssuerCheck(ctx *gin.Context, token string, expectedScopes []string, allScopes bool) error
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
	Director
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

// Return if expectedScopes contains the tokenScope and it's case-insensitive.
// If all=false, it checks if the tokenScopes have any one scope in expectedScopes;
// If all=true, it checks if tokenScopes is the same set as expectedScopes
func scopeContains(tokenScopes []string, expectedScopes []string, all bool) bool {
	if !all { // Any tokenScope in desiredScopes is OK
		for _, tokenScope := range tokenScopes {
			for _, sc := range expectedScopes {
				if strings.EqualFold(sc, tokenScope) {
					return true
				}
			}
		}
		return false
	} else { // All tokenScope must be in desiredScopes
		if len(tokenScopes) != len(expectedScopes) {
			return false
		}
		sort.Strings(tokenScopes)
		sort.Strings(expectedScopes)
		for i := 0; i < len(tokenScopes); i++ {
			if tokenScopes[i] != expectedScopes[i] {
				return false
			}
		}
		return true
	}
}

// Creates a validator that checks if a token's scope matches the given scope: expectedScopes.
// See `scopeContains` for detailed checking mechanism
func createScopeValidator(expectedScopes []string, all bool) jwt.ValidatorFunc {

	return jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		// If no scope is present, always return true
		if len(expectedScopes) == 0 {
			return nil
		}
		scope_any, present := tok.Get("scope")
		if !present {
			return jwt.NewValidationError(errors.New("No scope is present; required for authorization"))
		}
		scope, ok := scope_any.(string)
		if !ok {
			return jwt.NewValidationError(errors.New("scope claim in token is not string-valued"))
		}
		if scopeContains(strings.Split(scope, " "), expectedScopes, all) {
			return nil
		}
		return jwt.NewValidationError(errors.New(fmt.Sprint("Token does not contain any of the scopes: ", expectedScopes)))
	})
}

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
func (a AuthCheckImpl) FederationCheck(c *gin.Context, strToken string, expectedScopes []string, allScopes bool) error {
	var bKey *jwk.Key

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
	key, ok := jwks.Key(0)
	if !ok {
		return errors.Wrap(err, "Failed to get the first key of federation's public JWKS")
	}
	bKey = &key
	var raw ecdsa.PrivateKey
	if err = (*bKey).Raw(&raw); err != nil {
		return errors.Wrap(err, "Failed to get raw key of the federation JWK")
	}

	parsed, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, raw.PublicKey))

	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by federation's key")
	}

	scopeValidator := createScopeValidator(expectedScopes, allScopes)
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
func (a AuthCheckImpl) IssuerCheck(c *gin.Context, strToken string, expectedScopes []string, allScopes bool) error {
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

	bKey, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return errors.Wrap(err, "Failed to load issuer server's private key")
	}

	var raw ecdsa.PrivateKey
	if err = bKey.Raw(&raw); err != nil {
		return errors.Wrap(err, "Failed to get raw key of the issuer's JWK")
	}

	parsed, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, raw.PublicKey))

	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by issuer's key")
	}

	scopeValidator := createScopeValidator(expectedScopes, allScopes)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Origin")
	return nil
}

// Check if a JWT string was issued by the director and has the correct scope
func (a AuthCheckImpl) DirectorCheck(c *gin.Context, strToken string, expectedScopes []string, allScopes bool) error {
	directorURL := param.Federation_DirectorUrl.GetString()
	if directorURL == "" {
		return errors.New("Failed to check director; director URL is empty")
	}
	token, err := jwt.Parse([]byte(strToken), jwt.WithVerify(false))
	if err != nil {
		return errors.Wrap(err, "Invalid JWT")
	}

	if directorURL != token.Issuer() {
		return errors.New(fmt.Sprint("Issuer is not a director: ", token.Issuer()))
	}

	key, err := LoadDirectorPublicKey()
	if err != nil {
		return errors.Wrap(err, "Failed to load director's public JWK")
	}
	tok, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, key), jwt.WithValidate(true))
	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by director's key")
	}

	scopeValidator := createScopeValidator(expectedScopes, allScopes)
	if err = jwt.Validate(tok, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Director")
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
		case Director:
			err := authChecker.DirectorCheck(ctx, token, authOption.Scopes, authOption.AllScopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Token validation failed with director issuer: ", err)
				log.Debug("Token validation failed with director issuer: ", err)
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
