package main

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"net/url"
	"regexp"
	"time"

	"strconv"
	"strings"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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
					errMsg := "The provided version '" + val + "' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x"
					return errors.New(errMsg)
				}
			}
		}
	}

	return nil
}

func verifyCreateWLCG1(claimsMap *map[string]string) error {
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
				errMsg := "The claim '" + reqClaim + "' is required for the wlcg1 profile, but it could not be found."
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
	// We assume each claim has exactly one "=" delimiter
	for _, claim := range claims {
		parts := strings.Split(claim, "=")
		if len(parts) != 2 {
			if len(parts) < 2 {
				errMsg := "The claim '" + claim + "' is invalid. Did you forget an '='?"
				return nil, errors.New(errMsg)
			} else {
				errMsg := "The claim '" + claim + "' is invalid. Does it contain more than one '='?"
				return nil, errors.New(errMsg)
			}
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

func createEncodedToken(claimsMap map[string]string, profile string, lifetime int) (string, error) {
	var err error
	if profile != "" {
		if profile == "scitokens2" {
			err = verifyCreateSciTokens2(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to scitokens2 requirements")
			}
		} else if profile == "wlcg1" {
			err = verifyCreateWLCG1(&claimsMap)
			if err != nil {
				return "", errors.Wrap(err, "Token does not conform to wlcg1 requirements")
			}
		} else {
			errMsg := "The provided profile '" + profile + "' is not recognized. Valid options are 'scitokens2' or 'wlcg1'"
			return "", errors.New(errMsg)
		}
	}

	lifetimeDuration := time.Duration(lifetime)
	// Create a jti using uuid4. This will be added to all tokens.
	u, err := uuid.NewRandom()
	if err != nil {
		return "", errors.Wrap(err, "Failed to generate uuid4 for token jti")
	}

	issuerUrlStr := viper.GetString("IssuerUrl")
	issuerUrl, err := url.Parse(issuerUrlStr)
	if err != nil {
		return "", errors.Wrap(err, "Failed to parse the configured IssuerUrl")
	}

	now := time.Now()
	builder := jwt.NewBuilder()
	builder.Issuer(issuerUrl.String()).
		IssuedAt(now).
		Expiration(now.Add(time.Second * lifetimeDuration)).
		NotBefore(now).
		JwtID(u.String())

	// Add cli-passed claims after setting up the basic token so that we
	// expose a method to override anything we already set.
	for key, val := range claimsMap {
		builder.Claim(key, val)
	}

	tok, err := builder.Build()
	if err != nil {
		return "", errors.Wrap(err, "Failed to generate token")
	}

	// Now that we have a token, it needs signing. Note that GetOriginJWK
	// will get the private key passed via the command line because that
	// file path has already been bound to IssuerKey
	key, err := config.GetOriginJWK()
	if err != nil {
		return "", errors.Wrap(err, "Failed to load signing keys. Either generate one at the default location by serving an origin, or provide one via the --private-key flag")
	}

	// Get/assign the kid, needed for verification by the client
	err = jwk.AssignKeyID(*key)
	if err != nil {
		return "", errors.Wrap(err, "Failed to assign kid to the token")
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, *key))
	if err != nil {
		return "", errors.Wrap(err, "Failed to sign the deletion token")
	}

	return string(signed), nil
}

func cliTokenCreate( /*cmd*/ cmd *cobra.Command /*args*/, args []string) error {
	claimsMap, err := parseClaims(args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse token claims")
	}

	// Check if a profile was provided and verify what we need to from the claimsMap
	profile := cmd.Flags().Lookup("profile").Value.String()

	lifetime, err := strconv.Atoi(cmd.Flags().Lookup("lifetime").Value.String())
	if err != nil {
		return errors.Wrapf(err, "Failed to parse lifetime '%d' as an integer", lifetime)
	}

	token, err := createEncodedToken(claimsMap, profile, lifetime)
	if err != nil {
		return errors.Wrap(err, "Failed to create the token")
	}

	fmt.Println(token)
	return nil
}

func verifyToken( /*cmd*/ cmd *cobra.Command /*args*/, args []string) error {
	return errors.New("Token verification not yet implemented")
}
