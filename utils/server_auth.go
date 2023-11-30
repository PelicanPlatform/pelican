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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type (
	TokenSource int
	TokenIssuer int
	AuthOption  struct {
		Sources []TokenSource
		Issuers []TokenIssuer
		Scopes  []string
	}
	AuthChecker interface {
		FederationCheck(ctx *gin.Context, token string, scopes []string) error
		DirectorCheck(ctx *gin.Context, token string, scopes []string) error
		IssuerCheck(ctx *gin.Context, token string, scopes []string) error
	}
	AuthCheckImpl struct{}
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
	federationJWK *jwk.Cache
	authChecker   AuthChecker
)

func init() {
	authChecker = &AuthCheckImpl{}
}

// Return if desiredScopes contains the tokenScope and it's case-insensitive
func scopeContains(tokenScope string, desiredScopes []string) bool {
	for _, sc := range desiredScopes {
		if strings.EqualFold(sc, tokenScope) {
			return true
		}
	}
	return false
}

// Creates a validator that checks if a token's scope matches the given scope: matchScope.
// Will pass the check if no "anyScopes".
// Will pass the check if one token scope matches ANY item in "anyScopes"
func createScopeValidator(anyScopes []string) jwt.ValidatorFunc {

	return jwt.ValidatorFunc(func(_ context.Context, tok jwt.Token) jwt.ValidationError {
		// If no scope is present, always return true
		if len(anyScopes) == 0 {
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

		for _, tokenScope := range strings.Split(scope, " ") {
			// As long as there's one scope in the token that matches the pool of desriedScopes
			// we say it's valid
			if scopeContains(tokenScope, anyScopes) {
				return nil
			}
		}
		return jwt.NewValidationError(errors.New(fmt.Sprint("Token does not contain any of the scopes: ", anyScopes)))
	})
}

// Checks that the given token was signed by the federation jwk and also checks that the token has the expected scope
func (a AuthCheckImpl) FederationCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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

	scopeValidator := createScopeValidator(anyOfTheScopes)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Federation")
	return nil
}

// Checks that the given token was signed by the issuer jwk (the one from the server itself) and also checks that
// the token has the expected scope
func (a AuthCheckImpl) IssuerCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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

	scopeValidator := createScopeValidator(anyOfTheScopes)
	if err = jwt.Validate(parsed, jwt.WithValidator(scopeValidator)); err != nil {
		return errors.Wrap(err, "Failed to verify the scope of the token")
	}

	c.Set("User", "Origin")
	return nil
}

// Check if a JWT string was issued by the director and has the correct scope
func (a AuthCheckImpl) DirectorCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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

	key, err := director.LoadDirectorPublicKey()
	if err != nil {
		return errors.Wrap(err, "Failed to load director's public JWK")
	}
	tok, err := jwt.Parse([]byte(strToken), jwt.WithKey(jwa.ES256, key), jwt.WithValidate(true))
	if err != nil {
		return errors.Wrap(err, "Failed to verify JWT by director's key")
	}

	scopeValidator := createScopeValidator(anyOfTheScopes)
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
			err := authChecker.FederationCheck(ctx, token, authOption.Scopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Federation Check failed: ", err)
				log.Debug("Federation Check failed: ", err)
				break
			} else {
				log.Debug("Federation Check succeed")
				return exists
			}
		case Director:
			err := authChecker.DirectorCheck(ctx, token, authOption.Scopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Director Check failed: ", err)
				log.Debug("Director Check failed: ", err)
				break
			} else {
				log.Debug("Director Check succeed")
				return exists
			}
		case Issuer:
			err := authChecker.IssuerCheck(ctx, token, authOption.Scopes)
			if _, exists := ctx.Get("User"); err != nil || !exists {
				errMsg += fmt.Sprintln("Issuer Check failed: ", err)
				log.Debug("Issuer Check failed: ", err)
				break
			} else {
				log.Debug("Issuer Check succeed")
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
