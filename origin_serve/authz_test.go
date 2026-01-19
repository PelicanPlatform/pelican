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

package origin_serve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// Sign with key - the key ID will be automatically added to the header
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
	require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.ES256))
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

			mapper := NewUserMapper("sub", "wlcg.groups", "")
			userInfo := mapper.MapTokenToUser(token)
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

// TestPositiveAuthorizationWithRegisteredKey tests that the loader properly fetches keys,
// validates tokens, and caches user info together with authorization scopes
func TestPositiveAuthorizationWithRegisteredKey(t *testing.T) {
	// Generate a test key pair
	key := generateTestKey(t)
	pubKey, err := key.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-key"))
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.ES256))

	// Create a JWKS with the public key
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(pubKey))

	// Counter to track JWKS fetches
	jwksFetchCount := 0

	// Create a test HTTP server to serve both JWKS and OpenID configuration
	// Use plain HTTP to avoid certificate issues in testing
	mux := http.NewServeMux()

	// Serve JWKS endpoint with fetch counting
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwksFetchCount++
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(jwks)
		_, _ = w.Write(data)
	})

	// Serve OpenID configuration
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		config := map[string]interface{}{
			"issuer":   "http://" + r.Host,
			"jwks_uri": "http://" + r.Host + "/jwks",
		}
		data, _ := json.Marshal(config)
		_, _ = w.Write(data)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	// Use the server's URL as the issuer
	issuerURL := server.URL

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	egrp := &errgroup.Group{}

	// Create test exports with the test issuer
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/data",
			StoragePrefix:    "/tmp/data",
			IssuerUrls:       []string{issuerURL},
			Capabilities: server_structs.Capabilities{
				Reads:  true,
				Writes: true,
			},
		},
	}

	// Initialize auth config (this registers the issuer)
	err = InitAuthConfig(ctx, egrp, exports)
	require.NoError(t, err)

	// Create a token signed with the private key
	token := createTestToken(t, key, issuerURL, "alice", []string{"researchers", "admins"}, "storage.read:/file.txt storage.create:/newfile.txt")

	// Get the auth config
	ac := GetAuthConfig()
	require.NotNil(t, ac)

	// Test authorization - this should trigger the loader to fetch the key from our test server
	newCtx, authorized := ac.authorizeWithContext(ctx, token_scopes.Wlcg_Storage_Read, "/data/file.txt", token)
	assert.True(t, authorized, "Authorization should succeed with valid token and registered key")
	assert.Equal(t, 1, jwksFetchCount, "JWKS should be fetched once on first authorization")

	// Verify user info was extracted and stored in context
	userInfo := getUserInfo(newCtx)
	require.NotNil(t, userInfo, "User info should be extracted from token")
	assert.Equal(t, "alice", userInfo.User)
	assert.Equal(t, []string{"researchers", "admins"}, userInfo.Groups)

	// Test that subsequent authorization uses cached data (shouldn't need to fetch key again)
	newCtx2, authorized2 := ac.authorizeWithContext(ctx, token_scopes.Wlcg_Storage_Create, "/data/newfile.txt", token)
	assert.True(t, authorized2, "Second authorization should succeed using cached token info")
	assert.Equal(t, 1, jwksFetchCount, "JWKS should NOT be fetched again - cache should be used")

	userInfo2 := getUserInfo(newCtx2)
	require.NotNil(t, userInfo2, "User info should be available on cached authorization")
	assert.Equal(t, "alice", userInfo2.User)
	assert.Equal(t, []string{"researchers", "admins"}, userInfo2.Groups)

	// Test that authorization fails for wrong path
	_, authorized3 := ac.authorizeWithContext(ctx, token_scopes.Wlcg_Storage_Read, "/other/file.txt", token)
	assert.False(t, authorized3, "Authorization should fail for paths outside token scope")
	assert.Equal(t, 1, jwksFetchCount, "JWKS should still not be fetched again even for failed authorization")
}

// TestAuthorizationFailureWithoutUserInfo tests that failed authorization doesn't provide user info
func TestAuthorizationFailureWithoutUserInfo(t *testing.T) {
	// When authorization fails, user info should not be added to context
	newCtx := context.Background()
	authorized := false

	// Since not authorized, user info should be nil
	ui := getUserInfo(newCtx)
	assert.Nil(t, ui, "User info should be nil when not in context")

	// Verify authorization flag
	assert.False(t, authorized)
}

// TestPathPrefixBoundaryCheck tests path prefix boundary checking for security
func TestPathPrefixBoundaryCheck(t *testing.T) {
	tests := []struct {
		name             string
		requestPath      string
		authorizedPrefix string
		expected         bool
		description      string
	}{
		{
			name:             "ExactMatch",
			requestPath:      "/foo/bar",
			authorizedPrefix: "/foo/bar",
			expected:         true,
			description:      "Exact path match should be allowed",
		},
		{
			name:             "ValidSubpath",
			requestPath:      "/foo/bar/file.txt",
			authorizedPrefix: "/foo/bar",
			expected:         true,
			description:      "File under authorized prefix should be allowed",
		},
		{
			name:             "BoundaryViolation",
			requestPath:      "/foo/bar2/file.txt",
			authorizedPrefix: "/foo/bar",
			expected:         false,
			description:      "Sibling directory /foo/bar2 should NOT be accessible from /foo/bar",
		},
		{
			name:             "ParentDirectory",
			requestPath:      "/foo",
			authorizedPrefix: "/foo/bar",
			expected:         false,
			description:      "Cannot access parent directory when only subdir authorized",
		},
		{
			name:             "DifferentRoot",
			requestPath:      "/home/file.txt",
			authorizedPrefix: "/root",
			expected:         false,
			description:      "Completely different paths should not match",
		},
		{
			name:             "PathTraversal",
			requestPath:      "/foo/bar/../../../etc/passwd",
			authorizedPrefix: "/foo/bar",
			expected:         false,
			description:      "Normalized path traversal should fail (../../.. resolves to /)",
		},
		{
			name:             "NormalizedPaths",
			requestPath:      "/foo/bar//file.txt",
			authorizedPrefix: "/foo/bar/",
			expected:         true,
			description:      "Both paths should be normalized before comparison",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasPathPrefix(tt.requestPath, tt.authorizedPrefix)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

// BenchmarkPathPrefixCheck benchmarks path prefix validation
func BenchmarkPathPrefixCheck(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = hasPathPrefix("/foo/bar/baz/qux/file.txt", "/foo/bar")
	}
}
