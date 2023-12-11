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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
)

type (
	TokenProfile string
	TokenConfig  struct {
		TokenProfile TokenProfile
		Lifetime     time.Duration     // Lifetime is used to set 'exp' claim from now
		Issuer       string            // Issuer is 'iss' claim
		Audience     []string          // Audience is 'aud' claim
		Scope        string            // Scope is a space separated list of scopes
		Version      string            // Version is the version for different profiles. 'wlcg.ver' for WLCG profile and 'ver' for scitokens2
		Subject      string            // Subject is 'sub' claim
		Claims       map[string]string // Additional claims
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

func (config *TokenConfig) verifyCreateSciTokens2() error {
	// required fields: aud, ver, scope
	if len(config.Audience) == 0 {
		errMsg := "The 'audience' claim is required for the scitokens2 profile, but it could not be found."
		return errors.New(errMsg)
	}

	if config.Scope == "" {
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

// The verifyCreate* funcs only act on the provided claims maps, because they attempt
// to verify certain aspects of the token before it is created for simplicity. To verify
// an actual token object, use the analagous "verifyToken"
func verifyCreateSciTokens2(claimsMap *map[string]string) error {
	/*
		Don't check for the following claims because ALL base tokens have them:
		- iat
		- exp
		- nbf
		- iss
		- jti
	*/
	if len(*claimsMap) == 0 {
		return errors.New("To create a valid SciToken, the 'aud' and 'scope' claims must be passed, but none were found.")
	}
	requiredClaims := []string{"aud", "ver", "scope"}
	for _, reqClaim := range requiredClaims {
		if val, exists := (*claimsMap)[reqClaim]; !exists {
			// we can set ver because we know what it should be
			if reqClaim == "ver" {
				(*claimsMap)["ver"] = "scitokens:2.0"
			} else {
				// We can't set scope or aud, however
				errMsg := "The claim '" + reqClaim + "' is required for the scitokens2 profile, but it could not be found."
				return errors.New(errMsg)
			}
		} else {
			// The claim exists. While we're okay setting ver if it's not included, it
			// feels wrong to correct an explicitly-provided version that isn't correct,
			// so in that event, fail.
			if reqClaim == "ver" {
				verPattern := `^scitokens:2\.[0-9]+$`
				re := regexp.MustCompile(verPattern)

				if !re.MatchString(val) {
					errMsg := "The provided version '" + val +
						"' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x"
					return errors.New(errMsg)
				}
			}
		}
	}

	return nil
}

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

func verifyCreateWLCG(claimsMap *map[string]string) error {
	/*
		Don't check for the following claims because ALL base tokens have them:
		- iat
		- exp
		- nbf
		- iss
		- jti
	*/
	if len(*claimsMap) == 0 {
		return errors.New("To create a valid wlcg, the 'aud' and 'sub' claims must be passed, but none were found.")
	}

	requiredClaims := []string{"sub", "wlcg.ver", "aud"}
	for _, reqClaim := range requiredClaims {
		if val, exists := (*claimsMap)[reqClaim]; !exists {
			// we can set wlcg.ver because we know what it should be
			if reqClaim == "wlcg.ver" {
				(*claimsMap)["wlcg.ver"] = "1.0"
			} else {
				// We can't set the rest
				errMsg := "The claim '" + reqClaim +
					"' is required for the wlcg profile, but it could not be found."
				return errors.New(errMsg)
			}
		} else {
			if reqClaim == "wlcg.ver" {
				verPattern := `^1\.[0-9]+$`
				re := regexp.MustCompile(verPattern)
				if !re.MatchString(val) {
					errMsg := "The provided version '" + val + "' is not valid. It must be of the form '1.x'"
					return errors.New(errMsg)
				}
			}
		}
	}

	return nil
}

func CreateEncodedToken(claimsMap map[string]string, profile TokenProfile, lifetime int) (string, error) {
	var err error
	if profile != "" {
		if profile == Scitokens2 {
			err = verifyCreateSciTokens2(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to scitokens2 requirements")
			}
		} else if profile == WLCG {
			err = verifyCreateWLCG(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to wlcg requirements")
			}
		} else {
			errMsg := "The provided profile '" + profile.String() +
				"' is not recognized. Valid options are 'scitokens2' or 'wlcg'"
			return "", errors.New(errMsg)
		}
	}

	lifetimeDuration := time.Duration(lifetime)
	// Create a json token identifier (jti). This will be added to all tokens.
	jti_bytes := make([]byte, 16)
	if _, err := rand.Read(jti_bytes); err != nil {
		return "", err
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	issuerUrlStr := viper.GetString("IssuerUrl")
	issuerUrl, err := url.Parse(issuerUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse the configured IssuerUrl")
	}
	// issuer might be empty if not configured, so we need to be careful as it's required
	issuerFound := true
	if issuerUrl.String() == "" {
		issuerFound = false
	}

	// We allow the audience to be passed in the map, but we need to convert it to a list of strings
	extractAudFromClaims := func(claimsMap *map[string]string) []string {
		audience, exists := (*claimsMap)["aud"]
		if !exists {
			return nil
		}
		audienceSlice := strings.Split(audience, " ")
		delete(*claimsMap, "aud")
		return audienceSlice
	}(&claimsMap)

	now := time.Now()
	builder := jwt.NewBuilder()
	builder.Issuer(issuerUrl.String()).
		IssuedAt(now).
		Expiration(now.Add(time.Second * lifetimeDuration)).
		NotBefore(now).
		Audience(extractAudFromClaims).
		JwtID(jti)

	// Add cli-passed claims after setting up the basic token so that we
	// expose a method to override anything we already set.
	for key, val := range claimsMap {
		builder.Claim(key, val)
		if key == "iss" && val != "" {
			issuerFound = true
		}
	}

	if !issuerFound {
		return "", errors.New("No issuer was found in the configuration file, and none was provided as a claim")
	}

	tok, err := builder.Build()
	if err != nil {
		return "", errors.Wrap(err, "Failed to generate token")
	}

	// Now that we have a token, it needs signing. Note that GetIssuerPrivateJWK
	// will get the private key passed via the command line because that
	// file path has already been bound to IssuerKey
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "Failed to load signing keys. Either generate one at the default "+
			"location by serving an origin, or provide one via the --private-key flag")
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

// CreateToken validate a JWT TokenConfig and if it's valid, create and sign a token based on the TokenConfig.
func (tokenConfig *TokenConfig) CreateToken() (string, error) {
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
		Claim("scope", tokenConfig.Scope).
		JwtID(jti)

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

	// Now that we have a token, it needs signing. Note that GetIssuerPrivateJWK
	// will get the private key passed via the command line because that
	// file path has already been bound to IssuerKey
	key, err := config.GetIssuerPrivateJWK()
	if err != nil {
		return "", errors.Wrap(err, "Failed to load signing keys. Either generate one at the default "+
			"location by serving an origin, or provide one via the --private-key flag")
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
