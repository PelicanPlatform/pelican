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
func Verify(ctx *gin.Context, authOption AuthOption) (status int, verfied bool, err error) {
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
				break
			}
		case Header:
			headerToken := ctx.Request.Header["Authorization"]
			if len(headerToken) <= 0 {
				continue
			} else {
				token = strings.TrimPrefix(headerToken[0], "Bearer ")
				tokenFound = true
				break
			}
		case Authz:
			authzToken := ctx.Request.URL.Query()["authz"]
			if len(authzToken) <= 0 {
				continue
			} else {
				token = authzToken[0]
				tokenFound = true
				break
			}
		default:
			log.Error("Invalid/unsupported token source")
			return http.StatusInternalServerError, false, errors.New("Cannot verify token due to bad server configuration. Invalid/unsupported token source")
		}
	}

	if token == "" {
		log.Debug("Unauthorized. No token is present from the list of potential token positions")
		return http.StatusUnauthorized, false, errors.New("Authentication is required but no token is present.")
	}

	errMsg := ""
	for _, iss := range authOption.Issuers {
		switch iss {
		case Federation:
			if err := authChecker.FederationCheck(ctx, token, authOption.Scopes, authOption.AllScopes); err != nil {
				errMsg += fmt.Sprintln("Cannot verify token with federation issuer: ", err)
				break
			} else {
				return http.StatusOK, true, nil
			}
		case Issuer:
			if err := authChecker.IssuerCheck(ctx, token, authOption.Scopes, authOption.AllScopes); err != nil {
				errMsg += fmt.Sprintln("Cannot verify token with server issuer: ", err)
				break
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
