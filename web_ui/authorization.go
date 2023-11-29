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
package web_ui

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
	pelican_config "github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/director"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var federationJWK *jwk.Cache

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
func FederationCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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
func IssuerCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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

	bKey, err := pelican_config.GetIssuerPrivateJWK()
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
func DirectorCheck(c *gin.Context, strToken string, anyOfTheScopes []string) error {
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

// Create a token for accessing Prometheus /metrics endpoint on
// the server itself
func CreatePromMetricToken() (string, error) {
	serverURL := param.Server_ExternalWebUrl.GetString()
	tokenExpireTime := param.Monitoring_TokenExpiresIn.GetDuration()

	tok, err := jwt.NewBuilder().
		Claim("scope", "pelican.promMetric").
		Issuer(serverURL).
		Audience([]string{serverURL}).
		Subject(serverURL).
		Expiration(time.Now().Add(tokenExpireTime)).
		Build()
	if err != nil {
		return "", err
	}

	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "failed to load the director's private JWK")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// Check if a valid token is present for most of the server's internal
// API endpoints and Web API endpoints. It checkes if a JWT is present in
// either authz query param, Authorization header (Bearer), and cookie's "login" key
// and was issued by either the federation/director/or a server itself
// For token scopes, it checks if the token has ANY of the scopes provided in anyScopes
func checkAPIToken(ctx *gin.Context, anyScopes []string) bool {
	strToken := ""
	errMsg := ""

	if authzQuery := ctx.Request.URL.Query()["authz"]; len(authzQuery) > 0 {
		strToken = authzQuery[0]
	} else if authzHeader := ctx.Request.Header["Authorization"]; len(authzHeader) > 0 {
		strToken = strings.TrimPrefix(authzHeader[0], "Bearer ")
	}

	hasCredential := false
	if strToken != "" {
		hasCredential = true
		err := FederationCheck(ctx, strToken, anyScopes)
		if _, exists := ctx.Get("User"); err != nil || !exists {
			errMsg += fmt.Sprintln("Federation Check failed; continue to issuer check: ", err)
			log.Debug("Federation Check failed; continue to issuer check: ", err)
		} else {
			log.Debug("Federation Check succeed")
			return exists
		}
		err = IssuerCheck(ctx, strToken, anyScopes)
		if _, exists := ctx.Get("User"); err != nil || !exists {
			errMsg += fmt.Sprintln("Issuer Check failed; continue to director check: ", err)
			log.Debug("Issuer Check failed; continue to director check: ", err)
		} else {
			log.Debug("Issuer Check succeed")
			return exists
		}
		err = DirectorCheck(ctx, strToken, anyScopes)
		if _, exists := ctx.Get("User"); err != nil || !exists {
			errMsg += fmt.Sprintln("Director Check failed; continue to see if token is for user login: ", err)
			log.Debug("Director Check failed; continue to see if token is for user login: ", err)
		} else {
			log.Debug("Director Check succeed")
			return exists
		}
	}

	strToken, err := ctx.Cookie("login")
	if err == nil && strToken != "" {
		hasCredential = true
		if err = IssuerCheck(ctx, strToken, anyScopes); err != nil {
			errMsg += fmt.Sprintln("Issuer check from cookie's token failed: ", err)
			log.Debug("Issuer check from cookie's token failed: ", err)
		}
	} else {
		errMsg += fmt.Sprintln("No cookie present for token: ", err)
	}

	// It will only check if the token is valid and set this context key-pair.
	// Futher steps requried to finish the auth process (i.e. return 401)
	_, exists := ctx.Get("User")
	if !exists && hasCredential {
		log.Info("Authentication failed. Didn't pass chain of checking:\n", errMsg)
	}
	return exists
}

// Handle the authorization of Prometheus /metrics endpoint by checking
// if a valid token is present with correct scope
func promMetricAuthHandler(ctx *gin.Context) {
	if strings.HasPrefix(ctx.Request.URL.Path, "/metrics") {
		authRequired := param.Monitoring_MetricAuthorization.GetBool()
		if !authRequired {
			ctx.Next()
			return
		}
		// For /metrics endpoint, auth is granted if the request is from either
		// 1.director scraper 2.server scraper 3.authenticated user (through web)
		valid := checkAPIToken(ctx, []string{"pelican.directorScrape", "pelican.promMetric", "prometheus.read"})
		if !valid {
			ctx.AbortWithStatusJSON(403, gin.H{"error": "Authentication required to access this endpoint."})
		}
		// Valid director/self request, pass to the next handler
		ctx.Next()
	}
	// We don't care about other routes for this handler
	ctx.Next()
}
