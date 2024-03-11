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

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/token"
)

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

// Parse claims to tokenConfig, excluding "sub". `claims` should be in the form of
// <claim_key>=<claim=value>
func parseClaimsToTokenConfig(profile string, claims []string) (*token.TokenConfig, error) {
	tokenConfig, err := token.NewTokenConfig(token.TokenProfile(profile))
	if err != nil {
		return nil, err
	}
	for _, claim := range claims {
		// Split by the first "=" delimiter
		parts := strings.SplitN(claim, "=", 2)
		if len(parts) < 2 {
			errMsg := "The claim '" + claim + "' is invalid. Did you forget an '='?"
			return nil, errors.New(errMsg)
		}
		key := parts[0]
		val := parts[1]

		switch key {
		case "aud":
			tokenConfig.AddAudiences(val)
		case "scope":
			tokenConfig.AddRawScope(val)
		case "ver":
			fallthrough
		case "wlcg.ver":
			if err = tokenConfig.SetVersion(val); err != nil {
				return nil, err
			}
		case "iss":
			tokenConfig.Issuer = val
		default:
			if tokenConfig.Claims == nil {
				tokenConfig.Claims = map[string]string{}
			}
			if existingVal, exists := tokenConfig.Claims[key]; exists {
				tokenConfig.Claims[key] = existingVal + " " + val
			} else {
				tokenConfig.Claims[key] = val
			}
		}
	}

	return &tokenConfig, nil
}

func cliTokenCreate(cmd *cobra.Command, args []string) error {
	// Although we don't actually run any server stuff, we need access to the Origin's configuration
	// to know where private keys live for token signing, so we still need to call InitServer()
	ctx := context.Background()
	err := config.InitServer(ctx, config.OriginType)
	if err != nil {
		return errors.Wrap(err, "Cannot create token, failed to initialize configuration")
	}

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

	// Get flags used for auxiliary parts of token creation that can't be fed directly to claimsMap
	profile, err := cmd.Flags().GetString("profile")
	if err != nil {
		return errors.Wrapf(err, "Failed to get profile '%s' from input", profile)
	}

	tokenConfig, err := parseClaimsToTokenConfig(profile, args)
	if err != nil {
		return errors.Wrap(err, "Failed to parse token claims")
	}

	lifetime, err := cmd.Flags().GetInt("lifetime")
	if err != nil {
		return errors.Wrapf(err, "Failed to get lifetime '%d' from input", lifetime)
	}
	tokenConfig.Lifetime = time.Duration(lifetime) * time.Second

	// Flags to populate claimsMap
	// Note that we don't get the issuer here, because that's bound to viper
	subject, err := cmd.Flags().GetString("subject")
	if err != nil {
		return errors.Wrapf(err, "Failed to get subject '%s' from input", subject)
	}
	tokenConfig.Subject = subject

	// Finally, create the token
	token, err := tokenConfig.CreateToken()
	if err != nil {
		return errors.Wrap(err, "Failed to create the token")
	}

	fmt.Println(token)
	return nil
}

func verifyToken(cmd *cobra.Command, args []string) error {
	return errors.New("Token verification not yet implemented")
}
