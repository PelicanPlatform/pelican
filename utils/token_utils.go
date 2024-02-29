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

package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	TokenProfile string
	TokenConfig  struct {
		TokenProfile TokenProfile
		Lifetime     time.Duration     // Lifetime is used to set 'exp' claim from now
		Issuer       string            // Issuer is 'iss' claim
		Audience     []string          // Audience is 'aud' claim
		Version      string            // Version is the version for different profiles. 'wlcg.ver' for WLCG profile and 'ver' for scitokens2
		Subject      string            // Subject is 'sub' claim
		Claims       map[string]string // Additional claims
		scope        string            // scope is a string with space-delimited list of scopes. To enforce type check, use AddRawScope or AddScopes to add scopes to your token
	}
)

const (
	WLCG       TokenProfile = "wlcg"
	Scitokens2 TokenProfile = "scitokens2"
	None       TokenProfile = "none"
)

func (p TokenProfile) String() string {
	return string(p)
}

// Validate a TokenConfig given its profile and checks if the required claims are present per profile requirement
// and if provided config values are legal.
func (config *TokenConfig) Validate() (bool, error) {
	if config.Lifetime.Seconds() <= 0 {
		return false, errors.New(fmt.Sprint("Invalid lifetime, lifetime must be positive number: ", config.Lifetime))
	}
	if _, err := url.Parse(config.Issuer); err != nil {
		return false, errors.Wrap(err, "Invalid issuer, issuer is not a valid Url")
	}
	switch config.TokenProfile {
	case Scitokens2:
		if err := config.verifyCreateSciTokens2(); err != nil {
			return false, err
		}
	case WLCG:
		if err := config.verifyCreateWLCG(); err != nil {
			return false, err
		}
	case None:
		return true, nil // we don't have profile specific check for None type
	default:
		return false, errors.New(fmt.Sprint("Unsupported token profile: ", config.TokenProfile.String()))
	}
	return true, nil
}

// Verify if the token matches scitoken2 profile requirement
func (config *TokenConfig) verifyCreateSciTokens2() error {
	// required fields: aud, ver, scope
	if len(config.Audience) == 0 {
		errMsg := "The 'audience' claim is required for the scitokens2 profile, but it could not be found."
		return errors.New(errMsg)
	}

	if config.scope == "" {
		errMsg := "The 'scope' claim is required for the scitokens2 profile, but it could not be found."
		return errors.New(errMsg)
	}

	if config.Version == "" {
		config.Version = "scitokens:2.0"
	} else {
		verPattern := `^scitokens:2\.[0-9]+$`
		re := regexp.MustCompile(verPattern)

		if !re.MatchString(config.Version) {
			errMsg := "The provided version '" + config.Version +
				"' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x"
			return errors.New(errMsg)
		}
	}
	return nil
}

// Verify if the token matches WLCG profile requirement
func (config *TokenConfig) verifyCreateWLCG() error {
	// required fields: sub, wlcg.ver, aud
	if len(config.Audience) == 0 {
		errMsg := "The 'audience' claim is required for the scitokens2 profile, but it could not be found."
		return errors.New(errMsg)
	}

	if config.Subject == "" {
		errMsg := "The 'subject' claim is required for the scitokens2 profile, but it could not be found."
		return errors.New(errMsg)
	}

	if config.Version == "" {
		config.Version = "1.0"
	} else {
		verPattern := `^1\.[0-9]+$`
		re := regexp.MustCompile(verPattern)
		if !re.MatchString(config.Version) {
			errMsg := "The provided version '" + config.Version + "' is not valid. It must be of the form '1.x'"
			return errors.New(errMsg)
		}
	}
	return nil
}

// AddScopes appends a list of token_scopes.TokenScope to the Scope field.
func (config *TokenConfig) AddScopes(scopes []token_scopes.TokenScope) {
	if config.scope == "" {
		config.scope = token_scopes.GetScopeString(scopes)
	} else {
		scopeStr := token_scopes.GetScopeString(scopes)
		if scopeStr != "" {
			config.scope += " " + scopeStr
		}
	}
}

// AddRawScope appends a space-delimited, case-sensitive scope string to the Scope field.
//
// Examples for valid scopes:
//   - "storage:read"
//   - "storage:read storage:write"
func (config *TokenConfig) AddRawScope(scope string) {
	if config.scope == "" {
		config.scope = scope
	} else {
		if scope != "" {
			config.scope += " " + scope
		}
	}
}

// GetScope returns a list of space-delimited, case-sensitive strings from TokenConfig.scope
func (config *TokenConfig) GetScope() string {
	return config.scope
}

// CreateToken validates a JWT TokenConfig and if it's valid, create and sign a token based on the TokenConfig.
func (tokenConfig *TokenConfig) CreateToken() (string, error) {

	// Now that we have a token, it needs signing. Note that GetIssuerPrivateJWK
	// will get the private key passed via the command line because that
	// file path has already been bound to IssuerKey
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "Failed to load signing keys. Either generate one at the default "+
			"location by serving an origin, or provide one via the --private-key flag")
	}

	return tokenConfig.CreateTokenWithKey(key)
}

// Variant of CreateToken with a JWT provided by the caller
func (tokenConfig *TokenConfig) CreateTokenWithKey(key jwk.Key) (string, error) {
	if ok, err := tokenConfig.Validate(); !ok || err != nil {
		return "", errors.Wrap(err, "Invalid tokenConfig")
	}

	jti_bytes := make([]byte, 16)
	if _, err := rand.Read(jti_bytes); err != nil {
		return "", err
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	issuerUrl := ""
	if tokenConfig.Issuer != "" {
		url, err := url.Parse(tokenConfig.Issuer)
		if err != nil {
			return "", errors.Wrap(err, "Failed to parse the configured IssuerUrl")
		}
		issuerUrl = url.String()
	} else {
		issuerUrlStr := viper.GetString("IssuerUrl")
		url, err := url.Parse(issuerUrlStr)
		if err != nil {
			return "", errors.Wrap(err, "Failed to parse the configured IssuerUrl")
		}
		issuerUrl = url.String()
	}

	if issuerUrl == "" {
		return "", errors.New("No issuer was found in the configuration file, and none was provided as a claim")
	}

	now := time.Now()
	builder := jwt.NewBuilder()
	builder.Issuer(issuerUrl).
		IssuedAt(now).
		Expiration(now.Add(tokenConfig.Lifetime)).
		NotBefore(now).
		Audience(tokenConfig.Audience).
		Subject(tokenConfig.Subject).
		JwtID(jti)

	if tokenConfig.scope != "" {
		builder.Claim("scope", tokenConfig.scope)
	}

	if tokenConfig.TokenProfile == Scitokens2 {
		builder.Claim("ver", tokenConfig.Version)
	} else if tokenConfig.TokenProfile == WLCG {
		builder.Claim("wlcg.ver", tokenConfig.Version)
	}

	if tokenConfig.Claims != nil {
		for key, val := range tokenConfig.Claims {
			builder.Claim(key, val)
		}
	}

	tok, err := builder.Build()
	if err != nil {
		return "", errors.Wrap(err, "Failed to generate token")
	}

	// Get/assign the kid, needed for verification by the client
	err = jwk.AssignKeyID(key)
	if err != nil {
		return "", errors.Wrap(err, "Failed to assign kid to the token")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	if err != nil {
		return "", errors.Wrap(err, "Failed to sign the deletion token")
	}

	return string(signed), nil
}
