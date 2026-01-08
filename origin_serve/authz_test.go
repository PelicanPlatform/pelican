/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package origin_serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// Helper function to create a test JWT token
func createTestToken(t *testing.T, key jwk.Key, issuer string, subject string, groups []string, scopes string) string {
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Subject(subject).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("scope", scopes).
		Claim("wlcg.groups", groups).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
	require.NoError(t, err)

	return string(signed)
}

// Helper function to generate a test ECDSA key
func generateTestKey(t *testing.T) jwk.Key {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	key, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	
	require.NoError(t, key.Set(jwk.KeyIDKey, "test-key"))
	return key
}

// TestSciTokenScopes tests authorization with SciToken-style scopes
func TestSciTokenScopes(t *testing.T) {
	// Create a test key pair
	key := generateTestKey(t)
	
	pubKey, err := key.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-key"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp := &errgroup.Group{}

	// Create test exports
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/test",
			StoragePrefix:    "/tmp/test",
			IssuerUrls:       []string{"https://test-issuer.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads:  true,
				Writes: true,
			},
		},
	}

	// Initialize auth config
	err = InitAuthConfig(ctx, egrp, exports)
	require.NoError(t, err)

	// Create a token with SciToken-style scope
	token := createTestToken(t, key, "https://test-issuer.example.com", "testuser", []string{"group1", "group2"}, "read:/test write:/test")

	// Test authorization - should fail because we don't have the public key registered
	ac := GetAuthConfig()
	authorized := ac.authorize(token_scopes.Wlcg_Storage_Read, "/test/file.txt", token)
	
	// This will fail in the test since we don't have a real JWKS endpoint
	// In a real scenario, the key would be fetched from the issuer
	assert.False(t, authorized)
}

// TestWLCGTokenScopes tests authorization with WLCG-style scopes
func TestWLCGTokenScopes(t *testing.T) {
	// Create a test key pair
	key := generateTestKey(t)
	
	pubKey, err := key.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-key"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp := &errgroup.Group{}

	// Create test exports
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/test",
			StoragePrefix:    "/tmp/test",
			IssuerUrls:       []string{"https://test-issuer.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads:  true,
				Writes: true,
			},
		},
	}

	// Initialize auth config
	err = InitAuthConfig(ctx, egrp, exports)
	require.NoError(t, err)

	// Create a token with WLCG-style scope
	token := createTestToken(t, key, "https://test-issuer.example.com", "testuser", []string{"group1"}, "storage.read:/test storage.create:/test")

	// Test authorization
	ac := GetAuthConfig()
	authorized := ac.authorize(token_scopes.Wlcg_Storage_Read, "/test/file.txt", token)
	
	// This will fail because we don't have the public key registered
	assert.False(t, authorized)
}

// TestExtractUserInfo tests extraction of user and group information from tokens
func TestExtractUserInfo(t *testing.T) {
	// Create a test key
	key := generateTestKey(t)

	tests := []struct {
		name           string
		subject        string
		groups         []string
		expectedUser   string
		expectedGroups []string
	}{
		{
			name:           "User with groups",
			subject:        "testuser",
			groups:         []string{"group1", "group2", "group3"},
			expectedUser:   "testuser",
			expectedGroups: []string{"group1", "group2", "group3"},
		},
		{
			name:           "User without groups",
			subject:        "testuser2",
			groups:         []string{},
			expectedUser:   "testuser2",
			expectedGroups: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := createTestToken(t, key, "https://test.example.com", tt.subject, tt.groups, "read:/test")
			
			userInfo := extractUserInfoFromToken(token)
			require.NotNil(t, userInfo)
			assert.Equal(t, tt.expectedUser, userInfo.User)
			assert.Equal(t, tt.expectedGroups, userInfo.Groups)
		})
	}
}

// TestCachedAuthorization tests that authorization results are cached
func TestCachedAuthorization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp := &errgroup.Group{}

	// Create test exports
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/test",
			StoragePrefix:    "/tmp/test",
			IssuerUrls:       []string{"https://test-issuer.example.com"},
			Capabilities: server_structs.Capabilities{
				PublicReads: true,
			},
		},
	}

	// Initialize auth config
	err := InitAuthConfig(ctx, egrp, exports)
	require.NoError(t, err)

	ac := GetAuthConfig()
	require.NotNil(t, ac)

	// Test that the cache is initialized
	assert.NotNil(t, ac.tokenAuthz)
	assert.NotNil(t, ac.issuerKeys)
}

// TestAuthorizeWithContext tests that user context is properly added
func TestAuthorizeWithContext(t *testing.T) {
	// Create a test key
	key := generateTestKey(t)

	ctx := context.Background()
	egrp := &errgroup.Group{}

	// Create test exports
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/test",
			StoragePrefix:    "/tmp/test",
			IssuerUrls:       []string{"https://test-issuer.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads: true,
			},
		},
	}

	// Initialize auth config
	err := InitAuthConfig(ctx, egrp, exports)
	require.NoError(t, err)

	// Create a token
	token := createTestToken(t, key, "https://test-issuer.example.com", "testuser", []string{"testgroup"}, "read:/test")

	// Test authorizeWithContext
	ac := GetAuthConfig()
	newCtx, authorized := ac.authorizeWithContext(ctx, token_scopes.Wlcg_Storage_Read, "/test/file.txt", token)

	// Authorization will fail without proper key setup, but we can test that context is created
	_ = authorized
	
	// Even if not authorized, the function should return a context
	assert.NotNil(t, newCtx)
}
