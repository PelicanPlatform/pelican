package main

import (
	"fmt"
	"strings"

	"github.com/pelicanplatform/pelican/utils"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
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

func cliTokenCreate(cmd *cobra.Command, args []string) error {
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
	token, err := utils.CreateEncodedToken(claimsMap, utils.TokenProfile(profile), lifetime)
	if err != nil {
		return errors.Wrap(err, "Failed to create the token")
	}

	fmt.Println(token)
	return nil
}

func verifyToken(cmd *cobra.Command, args []string) error {
	return errors.New("Token verification not yet implemented")
}
