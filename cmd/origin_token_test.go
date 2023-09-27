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

package main

import (
	// "net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestVerifyCreateSciTokens2(t *testing.T) {
	// Start by feeding it a valid claims map
	claimsMap := map[string]string{"aud": "foo", "ver": "scitokens:2.0", "scope": "read:/storage"}
	err := verifyCreateSciTokens2(&claimsMap)
	assert.NoError(t, err)

	// Fail to give it audience
	claimsMap = map[string]string{"ver": "scitokens:2.0", "scope": "read:/storage"}
	err = verifyCreateSciTokens2(&claimsMap)
	assert.EqualError(t, err, "The claim 'aud' is required for the scitokens2 profile, but it could not be found.")

	// Fail to give it scope
	claimsMap = map[string]string{"aud": "foo", "ver": "scitokens:2.0"}
	err = verifyCreateSciTokens2(&claimsMap)
	assert.EqualError(t, err, "The claim 'scope' is required for the scitokens2 profile, but it could not be found.")

	// Give it bad version
	claimsMap = map[string]string{"aud": "foo", "scope": "bar", "ver": "scitokens:2.xxxx"}
	err = verifyCreateSciTokens2(&claimsMap)
	assert.EqualError(t, err, "The provided version 'scitokens:2.xxxx' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x")

	// Don't give it a version and make sure it gets set correctly
	claimsMap = map[string]string{"aud": "foo", "scope": "bar"}
	err = verifyCreateSciTokens2(&claimsMap)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["ver"], "scitokens:2.0")

	// Give it a non-required claim to make sure it makes it through
	claimsMap = map[string]string{"aud": "foo", "scope": "bar", "sub": "origin"}
	err = verifyCreateSciTokens2(&claimsMap)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["sub"], "origin")
}

func TestVerifyCreateWLCG1(t *testing.T) {
	// Start by feeding it a valid claims map
	claimsMap := map[string]string{"sub": "foo", "wlcg.ver": "1.0", "jti": "1234", "aud": "director"}
	err := verifyCreateWLCG1(&claimsMap)
	assert.NoError(t, err)

	// Fail to give it a sub
	claimsMap = map[string]string{"wlcg.ver": "1.0", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG1(&claimsMap)
	assert.EqualError(t, err, "The claim 'sub' is required for the wlcg1 profile, but it could not be found.")

	// Fail to give it an aud
	claimsMap = map[string]string{"wlcg.ver": "1.0", "jti": "1234", "sub": "foo"}
	err = verifyCreateWLCG1(&claimsMap)
	assert.EqualError(t, err, "The claim 'aud' is required for the wlcg1 profile, but it could not be found.")

	// Give it bad version
	claimsMap = map[string]string{"sub": "foo", "wlcg.ver": "1.xxxx", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG1(&claimsMap)
	assert.EqualError(t, err, "The provided version '1.xxxx' is not valid. It must be of the form '1.x'")

	// Don't give it a version and make sure it gets set correctly
	claimsMap = map[string]string{"sub": "foo", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG1(&claimsMap)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["wlcg.ver"], "1.0")

	// Give it a non-required claim to make sure it makes it through
	claimsMap = map[string]string{"sub": "foo", "wlcg.ver": "1.0", "jti": "1234", "aud": "director", "anotherClaim": "bar"}
	err = verifyCreateWLCG1(&claimsMap)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["anotherClaim"], "bar")
}

func TestParseClaims(t *testing.T) {
	// Give it something valid
	claims := []string{"foo=boo", "bar=baz"}
	claimsMap, err := parseClaims(claims)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["foo"], "boo")
	assert.Equal(t, claimsMap["bar"], "baz")
	assert.Equal(t, len(claimsMap), 2)

	// Give it something with multiple of the same claim key
	claims = []string{"foo=boo", "foo=baz"}
	claimsMap, err = parseClaims(claims)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["foo"], "boo baz")
	assert.Equal(t, len(claimsMap), 1)

	// Give it something without = delimiter
	claims = []string{"foo=boo", "barbaz"}
	_, err = parseClaims(claims)
	assert.EqualError(t, err, "The claim 'barbaz' is invalid. Did you forget an '='?")

	// Give it something with extra =
	claims = []string{"foo=boo", "bar==baz"}
	_, err = parseClaims(claims)
	assert.EqualError(t, err, "The claim 'bar==baz' is invalid. Does it contain more than one '='?")
}

func TestCreateToken(t *testing.T) {
	// For now, the test doesn't actually test for token validity

	// Redirect stdout to a buffer to prevent printing the token during tests
	// In theory, we could use this to grab the actual tokens as well.
	// TODO: Figure out how to generate consistent tokens
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	// Create temp dir for the origin key file
	viper.Reset()
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	// Generate a private key to use for the test
	_, err := config.LoadPublicKey("", kfile)
	assert.NoError(t, err)

	// Create a profile-less token
	cmd := &cobra.Command{}
	cmd.Flags().Int("lifetime", 1200, "Lifetime")
	cmd.Flags().String("profile", "", "creation profile")
	cmd.Flags().String("private-key", kfile, "private key path")
	// Here, we pin various time-related values so we can get a consistent token
	testArgs := []string{"scope=foo", "aud=bar", "iat=12345", "exp=12345", "nbf=12345"}
	err = cliTokenCreate(cmd, testArgs)
	assert.NoError(t, err)

	// Create a scitokens token
	cmd = &cobra.Command{}
	cmd.Flags().Int("lifetime", 1200, "Lifetime")
	cmd.Flags().String("profile", "scitokens2", "creation profile")
	testArgs = []string{"aud=foo", "scope=read:/storage", "iat=12345", "exp=12345", "nbf=12345"}
	err = cliTokenCreate(cmd, testArgs)
	assert.NoError(t, err)

	// Create a wlcg token
	cmd = &cobra.Command{}
	cmd.Flags().Int("lifetime", 1200, "Lifetime")
	cmd.Flags().String("profile", "wlcg1", "creation profile")
	testArgs = []string{"sub=foo", "wlcg.ver=1.0", "jti=1234", "aud=director"}
	err = cliTokenCreate(cmd, testArgs)
	assert.NoError(t, err)

	// Pass an invalid profile
	cmd = &cobra.Command{}
	cmd.Flags().Int("lifetime", 1200, "Lifetime")
	cmd.Flags().String("profile", "foobar", "creation profile")
	testArgs = []string{"sub=foo", "wlcg.ver=1.0", "jti=1234", "aud=director"}
	err = cliTokenCreate(cmd, testArgs)
	assert.EqualError(t, err, "Failed to create the token: The provided profile 'foobar' is not recognized. Valid options are 'scitokens2' or 'wlcg1'")

	w.Close()
	os.Stdout = old
}
