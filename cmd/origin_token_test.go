//go:build server

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"testing"

	"github.com/pelicanplatform/pelican/token"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// The message for a missing flag names the profile that was chosen, not
// always scitokens (#3835).
func TestMissingProfileFlagsNamesTheChosenProfile(t *testing.T) {
	newCmd := func(args ...string) *cobra.Command {
		cmd := &cobra.Command{Use: "create"}
		cmd.Flags().String("profile", "wlcg", "")
		cmd.Flags().String("subject", "", "")
		cmd.Flags().StringSlice("audience", []string{}, "")
		cmd.Flags().StringSlice("scope", []string{}, "")
		assert.NoError(t, cmd.Flags().Parse(args))
		return cmd
	}

	assert.Equal(t, []string{
		"The --audience flag must be populated for the wlcg profile",
	}, missingProfileFlags(newCmd("--profile", "wlcg", "--subject", "someone")))

	assert.Equal(t, []string{
		"The --subject flag must be populated for the wlcg profile",
		"The --audience flag must be populated for the wlcg profile",
	}, missingProfileFlags(newCmd()))

	assert.Equal(t, []string{
		"The --audience flag must be populated for the scitokens2 profile",
		"The --scope flag must be populated for the scitokens2 profile",
	}, missingProfileFlags(newCmd("--profile", "scitokens2")))

	assert.Empty(t, missingProfileFlags(newCmd("--profile", "wlcg", "--subject", "someone", "--audience", "https://example.org")))
}

func TestParseClaimsToTokenConfig(t *testing.T) {
	// Should parse basic fields correctly
	claims := []string{"aud=foo", "scope=baz", "ver=1.0", "iss=http://random.org"}
	tokenConfig, err := parseClaimsToTokenConfig(token.WlcgProfile{}.String(), claims)
	assert.NoError(t, err)
	assert.Equal(t, "http://random.org", tokenConfig.Issuer)
	assert.Equal(t, []string{"foo"}, tokenConfig.GetAudiences())
	assert.Equal(t, "baz", tokenConfig.GetScope())
	assert.Equal(t, "1.0", tokenConfig.GetVersion())

	// Give it something valid
	claims = []string{"foo=boo", "bar=baz"}
	tokenConfig, err = parseClaimsToTokenConfig(token.WlcgProfile{}.String(), claims)
	assert.NoError(t, err)
	assert.Equal(t, "boo", tokenConfig.Claims["foo"])
	assert.Equal(t, "baz", tokenConfig.Claims["bar"])
	assert.Equal(t, len(tokenConfig.Claims), 2)

	// Give it something with multiple of the same claim key
	claims = []string{"foo=boo", "foo=baz"}
	tokenConfig, err = parseClaimsToTokenConfig(token.WlcgProfile{}.String(), claims)
	assert.NoError(t, err)
	assert.Equal(t, "boo baz", tokenConfig.Claims["foo"])
	assert.Equal(t, 1, len(tokenConfig.Claims))

	// Give it something without = delimiter
	claims = []string{"foo=boo", "barbaz"}
	_, err = parseClaimsToTokenConfig(token.WlcgProfile{}.String(), claims)
	assert.EqualError(t, err, "The claim 'barbaz' is invalid. Did you forget an '='?")
}

func TestParseInputSlice(t *testing.T) {
	// A quick test, just to make sure this gets what it needs to
	rawSlice := []string{"https://my-issuer.com"}
	parsedSlice := parseInputSlice(&rawSlice, "iss")
	assert.Equal(t, []string{"iss=https://my-issuer.com"}, parsedSlice)
}
