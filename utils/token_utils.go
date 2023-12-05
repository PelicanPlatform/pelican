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
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/config"
)

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

func parseClaims(claims []string) (map[string]string, error) {
	claimsMap := make(map[string]string)
	for _, claim := range claims {
		// Split by the first "=" delimiter
		parts := strings.SplitN(claim, "=", 2)
		if len(parts) < 2 {
			errMsg := "The claim '" + claim + "' is invalid. Did you forget an '='?"
			return nil, errors.New(errMsg)
		}
		key := parts[0]
		val := parts[1]

		if existingVal, exists := claimsMap[key]; exists {
			claimsMap[key] = existingVal + " " + val
		} else {
			claimsMap[key] = val
		}
	}
	return claimsMap, nil
}

func CreateEncodedToken(claimsMap map[string]string, profile string, lifetime int) (string, error) {
	var err error
	if profile != "" {
		if profile == "scitokens2" {
			err = verifyCreateSciTokens2(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to scitokens2 requirements")
			}
		} else if profile == "wlcg" {
			err = verifyCreateWLCG(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to wlcg requirements")
			}
		} else {
			errMsg := "The provided profile '" + profile +
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

// Take an input slice and append its claim name
func parseInputSlice(rawSlice *[]string, claimPrefix string) []string {
	if len(*rawSlice) == 0 {
		return nil
	}
	slice := []string{}
	for _, val := range *rawSlice {
		slice = append(slice, claimPrefix+"="+val)
	}

	return slice
}

func CliTokenCreate(cmd *cobra.Command, args []string) error {
	// Additional claims can be passed via the --claims flag, or
	// they can be passed as args. We join those two slices here
	claimsSlice, err := cmd.Flags().GetStringSlice("claim")
	if err != nil {
		return errors.Wrap(err, "Failed to load claims passed via --claim flag")
	}
	args = append(args, claimsSlice...)

	// Similarly for scopes. Scopes could be passed like --scope "read:/storage write:/storage"
	// or they could be pased like --scope read:/storage --scope write:/storage. However, because
	// we already know the name of these claims and don't expect naming via the cli, we parse the
	// claims to name them here
	rawScopesSlice, err := cmd.Flags().GetStringSlice("scope")
	if err != nil {
		return errors.Wrap(err, "Failed to load scopes passed via --scope flag")
	}
	scopesSlice := parseInputSlice(&rawScopesSlice, "scope")
	if len(scopesSlice) > 0 {
		args = append(args, scopesSlice...)
	}

	// Like scopes, we allow multiple audiences and we need to add the claim name.
	rawAudSlice, err := cmd.Flags().GetStringSlice("audience")
	if err != nil {
		return errors.Wrap(err, "Failed to load audience passed via --audience flag")
	}
	audSlice := parseInputSlice(&rawAudSlice, "aud")
	if len(audSlice) > 0 {
		args = append(args, audSlice...)
	}

	claimsMap, err := parseClaims(args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse token claims")
	}

	// Get flags used for auxiliary parts of token creation that can't be fed directly to claimsMap
	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		return errors.Wrapf(err, "Failed to get profile '%s' from input", profile)
	}

	lifetime, err := cmd.Flags().GetInt("lifetime")
	if err != nil {
		return errors.Wrapf(err, "Failed to get lifetime '%d' from input", lifetime)
	}

	// Flags to populate claimsMap
	// Note that we don't get the issuer here, because that's bound to viper
	subject, err := cmd.Flags().GetString("subject")
	if err != nil {
		return errors.Wrapf(err, "Failed to get subject '%s' from input", subject)
	}
	if subject != "" {
		claimsMap["sub"] = subject
	}

	// Finally, create the token
	token, err := CreateEncodedToken(claimsMap, profile, lifetime)
	if err != nil {
		return errors.Wrap(err, "Failed to create the token")
	}

	fmt.Println(token)
	return nil
}

func VerifyToken(cmd *cobra.Command, args []string) error {
	return errors.New("Token verification not yet implemented")
}
