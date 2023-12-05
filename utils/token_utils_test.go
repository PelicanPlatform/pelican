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
	"path/filepath"
	"testing"

	"github.com/pelicanplatform/pelican/config"
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

func TestVerifyCreateWLCG(t *testing.T) {
	// Start by feeding it a valid claims map
	claimsMap := map[string]string{"sub": "foo", "wlcg.ver": "1.0", "jti": "1234", "aud": "director"}
	err := verifyCreateWLCG(&claimsMap)
	assert.NoError(t, err)

	// Fail to give it a sub
	claimsMap = map[string]string{"wlcg.ver": "1.0", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG(&claimsMap)
	assert.EqualError(t, err, "The claim 'sub' is required for the wlcg profile, but it could not be found.")

	// Fail to give it an aud
	claimsMap = map[string]string{"wlcg.ver": "1.0", "jti": "1234", "sub": "foo"}
	err = verifyCreateWLCG(&claimsMap)
	assert.EqualError(t, err, "The claim 'aud' is required for the wlcg profile, but it could not be found.")

	// Give it bad version
	claimsMap = map[string]string{"sub": "foo", "wlcg.ver": "1.xxxx", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG(&claimsMap)
	assert.EqualError(t, err, "The provided version '1.xxxx' is not valid. It must be of the form '1.x'")

	// Don't give it a version and make sure it gets set correctly
	claimsMap = map[string]string{"sub": "foo", "jti": "1234", "aud": "director"}
	err = verifyCreateWLCG(&claimsMap)
	assert.NoError(t, err)
	assert.Equal(t, claimsMap["wlcg.ver"], "1.0")

	// Give it a non-required claim to make sure it makes it through
	claimsMap = map[string]string{"sub": "foo", "wlcg.ver": "1.0", "jti": "1234", "aud": "director", "anotherClaim": "bar"}
	err = verifyCreateWLCG(&claimsMap)
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
}

func TestCreateEncodedToken(t *testing.T) {
	// Some viper pre-requisites
	viper.Reset()
	viper.Set("IssuerUrl", "https://my-issuer.com")
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	// Generate a private key to use for the test
	_, err := config.GetIssuerPublicJWKS()
	assert.NoError(t, err)

	// Test that the wlcg profile works
	claims := map[string]string{
		"aud": "foo",
		"sub": "bar",
	}
	_, err = CreateEncodedToken(claims, "wlcg", 1200)
	assert.NoError(t, err)

	// Test that the wlcg profile fails if neither sub or aud not found
	claims = map[string]string{}
	_, err = CreateEncodedToken(claims, "wlcg", 1200)
	assert.EqualError(t, err, "Token does not conform to wlcg requirements: To create a valid wlcg, "+
		"the 'aud' and 'sub' claims must be passed, but none were found.")

	// Test that the scitokens2 profile works
	claims = map[string]string{
		"aud":   "foo",
		"scope": "bar",
	}
	_, err = CreateEncodedToken(claims, "scitokens2", 1200)
	assert.NoError(t, err)

	// Test that the scitokens2 profile fails if claims not found
	claims = map[string]string{}
	_, err = CreateEncodedToken(claims, "scitokens2", 1200)
	assert.EqualError(t, err, "Token does not conform to scitokens2 requirements: To create a valid SciToken, "+
		"the 'aud' and 'scope' claims must be passed, but none were found.")

	// Test an unrecognized profile
	_, err = CreateEncodedToken(claims, "unknown_profile", 1200)
	assert.EqualError(t, err, "The provided profile 'unknown_profile' is not recognized. "+
		"Valid options are 'scitokens2' or 'wlcg'")

	// Test providing issuer via claim
	viper.Set("IssuerUrl", "")
	claims = map[string]string{
		"aud": "foo",
		"sub": "bar",
		"iss": "https://new-issuer.com",
	}
	_, err = CreateEncodedToken(claims, "wlcg", 1200)
	assert.NoError(t, err)

	// Test without configured issuer
	claims = map[string]string{
		"aud": "foo",
		"sub": "bar",
	}
	_, err = CreateEncodedToken(claims, "wlcg", 1200)
	assert.EqualError(t, err, "No issuer was found in the configuration file, "+
		"and none was provided as a claim")
}

func TestParseInputSlice(t *testing.T) {
	// A quick test, just to make sure this gets what it needs to
	rawSlice := []string{"https://my-issuer.com"}
	parsedSlice := parseInputSlice(&rawSlice, "iss")
	assert.Equal(t, parsedSlice, []string{"iss=https://my-issuer.com"})
}
