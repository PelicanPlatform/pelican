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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type (
	TokenProfile string
	TokenConfig  struct {
		tokenProfile TokenProfile
		Lifetime     time.Duration     // Lifetime is used to set 'exp' claim from now
		Issuer       string            // Issuer is 'iss' claim
		audience     []string          // Audience is 'aud' claim
		version      string            // Version is the version for different profiles. 'wlcg.ver' for WLCG profile and 'ver' for scitokens2
		Subject      string            // Subject is 'sub' claim
		Claims       map[string]string // Additional claims
		scope        string            // scope is a string with space-delimited list of scopes. To enforce type check, use AddRawScope or AddScopes to add scopes to your token
	}

	openIdConfiguration struct {
		Issuer  string `json:"issuer"`
		JwksUri string `json:"jwks_uri"`
	}
)

var (
	scitokensVerPattern *regexp.Regexp = regexp.MustCompile(`^scitokens:2\.[0-9]+$`)
	wlcgVerPattern      *regexp.Regexp = regexp.MustCompile(`^1\.[0-9]+$`)
)

const (
	TokenProfileWLCG       TokenProfile = "wlcg"
	TokenProfileScitokens2 TokenProfile = "scitokens2"
	TokenProfileNone       TokenProfile = "none"
	tokenProfileEmpty      TokenProfile = ""

	wlcgAny      string = "https://wlcg.cern.ch/jwt/v1/any"
	scitokensAny string = "ANY"
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
	switch config.tokenProfile {
	case TokenProfileScitokens2:
		if err := config.verifyCreateSciTokens2(); err != nil {
			return false, err
		}
	case TokenProfileWLCG:
		if err := config.verifyCreateWLCG(); err != nil {
			return false, err
		}
	case TokenProfileNone:
		return true, nil // we don't have profile specific check for None type
	case tokenProfileEmpty:
		return false, errors.New("token profile is not set")
	default:
		return false, errors.Errorf("unsupported token profile: %s", config.tokenProfile.String())
	}
	return true, nil
}

func NewTokenConfig(tokenProfile TokenProfile) (tc TokenConfig, err error) {
	switch tokenProfile {
	case TokenProfileScitokens2:
		fallthrough
	case TokenProfileWLCG:
		fallthrough
	case TokenProfileNone:
		tc.tokenProfile = tokenProfile
	case tokenProfileEmpty:
		err = errors.New("token profile is not set")
	default:
		err = errors.Errorf("unsupported token profile: %s", tokenProfile.String())
	}
	return
}

func NewWLCGToken() (tc TokenConfig) {
	tc.tokenProfile = TokenProfileWLCG
	return
}

func NewScitoken() (tc TokenConfig) {
	tc.tokenProfile = TokenProfileScitokens2
	return
}

func (config *TokenConfig) GetVersion() string {
	return config.version
}

func (config *TokenConfig) SetVersion(ver string) error {
	if config.tokenProfile == TokenProfileScitokens2 {
		if ver == "" {
			ver = "scitokens:2.0"
		} else if !scitokensVerPattern.MatchString(ver) {
			return errors.New("the provided version '" + config.version +
				"' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x")
		}
	} else if config.tokenProfile == TokenProfileWLCG {
		if ver == "" {
			ver = "1.0"
		} else if !wlcgVerPattern.MatchString(config.version) {
			return errors.New("the provided version '" + config.version + "' is not valid. It must be of the form '1.x'")
		}
	}
	config.version = ver
	return nil
}

func (config *TokenConfig) AddAudienceAny() {
	newAud := ""
	switch config.tokenProfile {
	case TokenProfileScitokens2:
		newAud = string(scitokensAny)
	case TokenProfileWLCG:
		newAud = string(wlcgAny)
	}
	if newAud != "" {
		config.audience = append(config.audience, newAud)
	}
}

func (config *TokenConfig) AddAudiences(audiences ...string) {
	config.audience = append(config.audience, audiences...)
}

func (config *TokenConfig) GetAudiences() []string {
	return config.audience
}

// Verify if the token matches scitoken2 profile requirement
func (config *TokenConfig) verifyCreateSciTokens2() error {
	// required fields: aud, ver, scope
	if len(config.audience) == 0 {
		return errors.New("the 'audience' claim is required for the scitokens2 profile, but it could not be found")
	}

	if config.scope == "" {
		return errors.New("the 'scope' claim is required for the scitokens2 profile, but it could not be found")
	}

	if config.version == "" {
		config.version = "scitokens:2.0"
	} else if !scitokensVerPattern.MatchString(config.version) {
		return errors.New("the provided version '" + config.version +
			"' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x")
	}
	return nil
}

// Verify if the token matches WLCG profile requirement
func (config *TokenConfig) verifyCreateWLCG() error {
	// required fields: sub, wlcg.ver, aud
	if len(config.audience) == 0 {
		errMsg := "the 'audience' claim is required for the WLCG profile, but it could not be found"
		return errors.New(errMsg)
	}

	if config.Subject == "" {
		errMsg := "the 'subject' claim is required for the WLCG profile, but it could not be found"
		return errors.New(errMsg)
	}

	if config.version == "" {
		config.version = "1.0"
	} else if !wlcgVerPattern.MatchString(config.version) {
		return errors.New("the provided version '" + config.version + "' is not valid. It must be of the form '1.x'")
	}
	return nil
}

// AddScopes appends multiple token_scopes.TokenScope to the Scope field.
func (config *TokenConfig) AddScopes(scopes ...token_scopes.TokenScope) {
	config.AddRawScope(token_scopes.GetScopeString(scopes))
}

// AddResourceScopes appends multiple token_scopes.TokenScope to the Scope field.
func (config *TokenConfig) AddResourceScopes(scopes ...token_scopes.ResourceScope) {
	config.AddRawScope(token_scopes.GetScopeString(scopes))
}

// AddRawScope appends a space-delimited, case-sensitive scope string to the Scope field.
//
// Examples for valid scopes:
//   - "storage:read"
//   - "storage:read storage:write"
func (config *TokenConfig) AddRawScope(scope string) {
	if config.scope == "" {
		config.scope = scope
	} else if scope != "" {
		config.scope += " " + scope
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
		return "", errors.Wrap(err, "invalid tokenConfig")
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
		issuerUrlStr, err := config.GetServerIssuerURL()
		if err != nil {
			return "", errors.Wrap(err, "unable to generate token issuer URL")
		}
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
		Audience(tokenConfig.audience).
		Subject(tokenConfig.Subject).
		JwtID(jti)

	if tokenConfig.scope != "" {
		builder.Claim("scope", tokenConfig.scope)
	}

	if tokenConfig.tokenProfile == TokenProfileScitokens2 {
		builder.Claim("ver", tokenConfig.version)
	} else if tokenConfig.tokenProfile == TokenProfileWLCG {
		builder.Claim("wlcg.ver", tokenConfig.version)
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

// Given an issuer URL, lookup the corresponding JWKS URL using OAuth2 metadata discovery
func LookupIssuerJwksUrl(ctx context.Context, issuerUrlStr string) (jwksUrl *url.URL, err error) {
	issuerUrl, err := url.Parse(issuerUrlStr)
	if err != nil {
		err = errors.Wrap(err, "failed to parse issuer as URL")
		return
	}
	wellKnownUrl := *issuerUrl
	wellKnownUrl.Path = path.Join(wellKnownUrl.Path, ".well-known/openid-configuration")

	client := &http.Client{Transport: config.GetTransport()}

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnownUrl.String(), nil)
	if err != nil {
		err = errors.Wrap(err, "failed to generate new request to the remote issuer")
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		err = errors.Wrapf(err, "failed to get metadata from %s", issuerUrlStr)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		err = errors.Errorf("issuer %s returned error %s (HTTP %d) for its OpenID auto-discovery configuration", issuerUrlStr, resp.Status, resp.StatusCode)
		return
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrapf(err, "failed to read HTTP response when looking up OpenID auto-discovery configuration for issuer %s", issuerUrlStr)
		return
	}

	var conf openIdConfiguration
	if err = json.Unmarshal(respBytes, &conf); err != nil {
		err = errors.Wrapf(err, "failed to parse the OpenID auto-discovery configuration for issuer %s", issuerUrl)
		return
	}
	if conf.JwksUri == "" {
		err = errors.Errorf("issuer %s provided no JWKS URL in its OpenID auto-discovery configuration", issuerUrl)
		return
	}
	jwksUrl, err = url.Parse(conf.JwksUri)
	if err != nil {
		err = errors.Wrapf(err, "issuer %s provided an invalid JWKS URL in its OpenID auto-discovery configuration", issuerUrl)
		return
	}
	return
}
