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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestVerifyCreateSciTokens2(t *testing.T) {
	// Start by feeding it a valid claims map
	tokenConfig := TokenConfig{tokenProfile: TokenProfileScitokens2, audience: []string{"foo"}, version: "scitokens:2.0", scope: "read:/storage"}
	err := tokenConfig.verifyCreateSciTokens2()
	assert.NoError(t, err)

	// Fail to give it audience
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, version: "scitokens:2.0", scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "the 'audience' claim is required for the scitokens2 profile, but it could not be found")

	// Fail to give it scope
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, audience: []string{"foo"}, version: "scitokens:2.0"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "the 'scope' claim is required for the scitokens2 profile, but it could not be found")

	// Give it bad version
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, audience: []string{"foo"}, version: "scitokens:2.xxxx", scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.EqualError(t, err, "the provided version 'scitokens:2.xxxx' is not valid. It must match 'scitokens:<version>', where version is of the form 2.x")

	// Don't give it a version and make sure it gets set correctly
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, audience: []string{"foo"}, scope: "read:/storage"}
	err = tokenConfig.verifyCreateSciTokens2()
	assert.NoError(t, err)
	assert.Equal(t, tokenConfig.version, "scitokens:2.0")
}

func TestVerifyCreateWLCG(t *testing.T) {
	// Start by feeding it a valid claims map
	tokenConfig := TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"director"}, version: "1.0", Subject: "foo"}
	err := tokenConfig.verifyCreateWLCG()
	assert.NoError(t, err)

	// Fail to give it a sub
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"director"}, version: "1.0"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "the 'subject' claim is required for the WLCG profile, but it could not be found")

	// Fail to give it an aud
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, version: "1.0", Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "the 'audience' claim is required for the WLCG profile, but it could not be found")

	// Give it bad version
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"director"}, version: "1.xxxx", Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.EqualError(t, err, "the provided version '1.xxxx' is not valid. It must be of the form '1.x'")

	// Don't give it a version and make sure it gets set correctly
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"director"}, Subject: "foo"}
	err = tokenConfig.verifyCreateWLCG()
	assert.NoError(t, err)
	assert.Equal(t, tokenConfig.version, "1.0")
}

// TestAddScopes tests the AddScopes method of TokenConfig
func TestAddScopes(t *testing.T) {
	tests := []struct {
		name             string
		initialScope     string
		additionalScopes []token_scopes.TokenScope
		expectedScope    string
	}{
		{
			name:             "empty-initial-scope-and-empty-additional-scopes",
			initialScope:     "",
			additionalScopes: []token_scopes.TokenScope{},
			expectedScope:    "",
		},
		{
			name:             "empty-initial-scope-and-non-empty-additional-scopes",
			initialScope:     "",
			additionalScopes: []token_scopes.TokenScope{"scope1", "scope2"},
			expectedScope:    "scope1 scope2",
		},
		{
			name:             "non-empty-initial-scope-and-empty-additional-scopes",
			initialScope:     "existing_scope",
			additionalScopes: []token_scopes.TokenScope{},
			expectedScope:    "existing_scope",
		},
		{
			name:             "non-empty-initial-scope-and-non-empty-additional-scopes",
			initialScope:     "existing_scope",
			additionalScopes: []token_scopes.TokenScope{"scope1", "scope2"},
			expectedScope:    "existing_scope scope1 scope2",
		},
		{
			name:             "multiple-initial-scope-and-multiple-additional-scopes",
			initialScope:     "existing_scope1 existing_scope2",
			additionalScopes: []token_scopes.TokenScope{"scope1", "scope2"},
			expectedScope:    "existing_scope1 existing_scope2 scope1 scope2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &TokenConfig{scope: tt.initialScope}
			config.AddScopes(tt.additionalScopes...)
			assert.Equal(t, tt.expectedScope, config.GetScope(), fmt.Sprintf("AddScopes() = %v, want %v", config.scope, tt.expectedScope))
		})
	}
}

// TestAddRawScope tests the AddRawScope method of TokenConfig
func TestAddRawScope(t *testing.T) {
	tests := []struct {
		name          string
		initialScope  string
		newScope      string
		expectedScope string
	}{
		{
			name:          "empty-initial-scope-and-empty-new-scope",
			initialScope:  "",
			newScope:      "",
			expectedScope: "",
		},
		{
			name:          "empty-initial-scope-and-non-empty-new-scope",
			initialScope:  "",
			newScope:      "storage:read",
			expectedScope: "storage:read",
		},
		{
			name:          "non-empty-initial-scope-and-empty-new-scope",
			initialScope:  "existing_scope",
			newScope:      "",
			expectedScope: "existing_scope",
		},
		{
			name:          "non-empty-initial-scope-and-non-empty-new-scope",
			initialScope:  "existing_scope",
			newScope:      "storage:read",
			expectedScope: "existing_scope storage:read",
		},
		{
			name:          "non-empty-initial-scope-and-multiple-new-scopes",
			initialScope:  "existing_scope",
			newScope:      "storage:read storage:write",
			expectedScope: "existing_scope storage:read storage:write",
		},
		{
			name:          "multiple-initial-scope-and-multiple-new-scopes",
			initialScope:  "existing_scope1 existing_scope2",
			newScope:      "storage:read storage:write",
			expectedScope: "existing_scope1 existing_scope2 storage:read storage:write",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &TokenConfig{scope: tt.initialScope}
			config.AddRawScope(tt.newScope)
			assert.Equal(t, tt.expectedScope, config.GetScope(), fmt.Sprintf("AddRawScope() = %v, want %v", config.scope, tt.expectedScope))
		})
	}
}

func TestCreateToken(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Some viper pre-requisites
	viper.Reset()
	viper.Set("IssuerUrl", "https://my-issuer.com")
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	err := config.InitServer(ctx, config.DirectorType)
	require.NoError(t, err)

	// Generate a private key to use for the test
	_, err = config.GetIssuerPublicJWKS()
	assert.NoError(t, err)

	// Test that the wlcg profile works
	tokenConfig := TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"foo"}, Subject: "bar", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()

	assert.NoError(t, err)

	// Test that the wlcg profile fails if neither sub or aud not found
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "invalid tokenConfig: the 'audience' claim is required for the WLCG profile, but it could not be found")

	// Test that the scitokens2 profile works
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, audience: []string{"foo"}, scope: "bar", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.NoError(t, err)

	// Test that the scitokens2 profile fails if claims not found
	tokenConfig = TokenConfig{tokenProfile: TokenProfileScitokens2, Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "invalid tokenConfig: the 'audience' claim is required for the scitokens2 profile, but it could not be found")

	// Test an unrecognized profile
	tokenConfig = TokenConfig{tokenProfile: TokenProfile("unknown"), Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.EqualError(t, err, "invalid tokenConfig: unsupported token profile: unknown")

	// Test that additional claims can be passed into the token
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"foo"}, Subject: "bar", Lifetime: time.Minute * 10, Claims: map[string]string{"foo": "bar"}}
	token, err := tokenConfig.CreateToken()
	require.NoError(t, err)
	jwt, err := jwt.ParseString(token, jwt.WithVerify(false))
	require.NoError(t, err)
	val, found := jwt.Get("foo")
	assert.True(t, found)
	assert.Equal(t, "bar", val)

	// Test providing issuer via claim
	viper.Set("IssuerUrl", "")
	tokenConfig = TokenConfig{tokenProfile: TokenProfileWLCG, audience: []string{"foo"}, Subject: "bar", Issuer: "https://localhost:9999", Lifetime: time.Minute * 10}
	_, err = tokenConfig.CreateToken()
	assert.NoError(t, err)

	// Note: we used to test what occurred when no issuer was set (assuming it should fail).  However, we switched to a new
	// helper function in the `config` module which falls back to an auto-constructed IssuerUrl, meaning the
	// test condition was no longer valid; the test was deleted.
}

func TestLookupIssuerJwksUrl(t *testing.T) {
	var resp *string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/issuer/.well-known/openid-configuration" {
			if resp == nil || *resp == "" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(*resp))
			require.NoError(t, err)
		}
	}))

	issuerURL, err := url.Parse(srv.URL)
	require.NoError(t, err)
	issuerURL.Path = "/issuer"

	tests := []struct {
		resp   string
		result string
		errStr string
	}{
		{
			resp:   `{"jwks_uri": "https://osdf.org"}`,
			result: "https://osdf.org",
			errStr: "",
		},
		{
			resp:   "",
			result: "",
			errStr: fmt.Sprintf("issuer %s returned error 500 Internal Server Error (HTTP 500) for its OpenID auto-discovery configuration", issuerURL),
		},
		{
			resp:   `{}`,
			result: "",
			errStr: fmt.Sprintf("issuer %s provided no JWKS URL in its OpenID auto-discovery configuration", issuerURL),
		},
		{
			resp:   `{{`,
			result: "",
			errStr: fmt.Sprintf("failed to parse the OpenID auto-discovery configuration for issuer %s: invalid character '{' looking for beginning of object key string", issuerURL),
		},
		{
			resp:   `{"jwks_uri": "http_blah://foo"}`,
			result: "",
			errStr: fmt.Sprintf("issuer %s provided an invalid JWKS URL in its OpenID auto-discovery configuration: parse \"http_blah://foo\": first path segment in URL cannot contain colon", issuerURL),
		},
	}

	ctx := context.Background()
	for _, tt := range tests {
		resp = &tt.resp
		result, err := LookupIssuerJwksUrl(ctx, issuerURL.String())
		if tt.errStr == "" {
			assert.NoError(t, err)
		} else {
			assert.Error(t, err)
			if err != nil {
				assert.Equal(t, tt.errStr, err.Error())
			}
		}
		if tt.result != "" {
			assert.NoError(t, err)
			assert.Equal(t, tt.result, result.String())
		}
	}
}
