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
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCreateSciTokens2(t *testing.T) {
	// Start by feeding it a valid claims map
	tokenConfig := TokenConfig{TokenProfile: Scitokens2, Audience: []string{"foo"}, Version: "scitokens:2.0", Scope: "read:/storage"}
	err := tokenConfig.verifyCreateSciTokens2()
	assert.NoError(t, err)

	// Fail to give it audience
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Version: "scitokens:2.0", Scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "The 'audience' claim is required for the scitokens2 profile, but it could not be found.")

	// Fail to give it scope
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Audience: []string{"foo"}, Version: "scitokens:2.0"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "The 'scope' claim is required for the scitokens2 profile, but it could not be found.")

	// Give it bad version
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Audience: []string{"foo"}, Version: "scitokens:2.xxxx", Scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "The provided version 'scitokens:2.xxxx' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x")

	// Don't give it a version and make sure it gets set correctly
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Audience: []string{"foo"}, Scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.NoError(t, err)
	assert.Equal(t, tokenConfig.Version, "scitokens:2.0")
}

func TestVerifyCreateWLCG(t *testing.T) {
	// Start by feeding it a valid claims map
	tokenConfig := TokenConfig{TokenProfile: WLCG, Audience: []string{"director"}, Version: "1.0", Subject: "foo"}
	err := tokenConfig.verifyCreateWLCG()
	assert.NoError(t, err)

	// Fail to give it a sub
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"director"}, Version: "1.0"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "The 'subject' claim is required for the scitokens2 profile, but it could not be found.")

	// Fail to give it an aud
	tokenConfig = TokenConfig{TokenProfile: WLCG, Version: "1.0", Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "The 'audience' claim is required for the scitokens2 profile, but it could not be found.")

	// Give it bad version
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"director"}, Version: "1.xxxx", Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "The provided version '1.xxxx' is not valid. It must be of the form '1.x'")

	// Don't give it a version and make sure it gets set correctly
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"director"}, Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.NoError(t, err)
	assert.Equal(t, tokenConfig.Version, "1.0")
}

func TestCreateToken(t *testing.T) {
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
	tokenConfig := TokenConfig{TokenProfile: WLCG, Audience: []string{"foo"}, Subject: "bar", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()

	assert.NoError(t, err)

	// Test that the wlcg profile fails if neither sub or aud not found
	tokenConfig = TokenConfig{TokenProfile: WLCG, Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "Invalid tokenConfig: The 'audience' claim is required for the scitokens2 profile, but it could not be found.")

	// Test that the scitokens2 profile works
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Audience: []string{"foo"}, Scope: "bar", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.NoError(t, err)

	// Test that the scitokens2 profile fails if claims not found
	tokenConfig = TokenConfig{TokenProfile: Scitokens2, Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "Invalid tokenConfig: The 'audience' claim is required for the scitokens2 profile, but it could not be found.")

	// Test an unrecognized profile
	tokenConfig = TokenConfig{TokenProfile: TokenProfile("unknown"), Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "Invalid tokenConfig: Unsupported token profile: unknown")

	// Test that additional claims can be passed into the token
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"foo"}, Subject: "bar", Lifetime: time.Minute * 10, Claims: map[string]string{"foo": "bar"}}
	token, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	jwt, err := jwt.ParseString(token, jwt.WithVerify(false))
	require.NoError(t, err)
	val, found := jwt.Get("foo")
	assert.True(t, found)
	assert.Equal(t, "bar", val)

	// Test providing issuer via claim
	viper.Set("IssuerUrl", "")
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"foo"}, Subject: "bar", Issuer: "https://localhost:9999", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.NoError(t, err)

	// Test without configured issuer
	tokenConfig = TokenConfig{TokenProfile: WLCG, Audience: []string{"foo"}, Subject: "bar", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "No issuer was found in the configuration file, "+
		"and none was provided as a claim")
}
