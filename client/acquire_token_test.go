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

package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestParseScope tests the parseScope helper function
func TestParseScope(t *testing.T) {
	tests := []struct {
		name           string
		scope          string
		expectedAuthz  string
		expectedRes    string
		expectedHasRes bool
	}{
		{
			name:           "scope with resource",
			scope:          "storage.read:/foo/bar",
			expectedAuthz:  "storage.read",
			expectedRes:    "/foo/bar",
			expectedHasRes: true,
		},
		{
			name:           "scope without resource",
			scope:          "storage.read",
			expectedAuthz:  "storage.read",
			expectedRes:    "",
			expectedHasRes: false,
		},
		{
			name:           "scope with empty resource",
			scope:          "storage.read:",
			expectedAuthz:  "storage.read",
			expectedRes:    "",
			expectedHasRes: true,
		},
		{
			name:           "scope with multiple colons",
			scope:          "storage.read:/foo:bar/baz",
			expectedAuthz:  "storage.read",
			expectedRes:    "/foo:bar/baz",
			expectedHasRes: true,
		},
		{
			name:           "empty scope",
			scope:          "",
			expectedAuthz:  "",
			expectedRes:    "",
			expectedHasRes: false,
		},
		{
			name:           "scitoken read scope with resource",
			scope:          "read:/data",
			expectedAuthz:  "read",
			expectedRes:    "/data",
			expectedHasRes: true,
		},
		{
			name:           "scitoken write scope with resource",
			scope:          "write:/data",
			expectedAuthz:  "write",
			expectedRes:    "/data",
			expectedHasRes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authz, resource, hasResource := parseScope(tt.scope)
			assert.Equal(t, tt.expectedAuthz, authz)
			assert.Equal(t, tt.expectedRes, resource)
			assert.Equal(t, tt.expectedHasRes, hasResource)
		})
	}
}

// TestMatchesResource tests the matchesResource helper function
func TestMatchesResource(t *testing.T) {
	tests := []struct {
		name           string
		targetResource string
		scopeResource  string
		operation      config.TokenOperation
		expected       bool
	}{
		// Basic prefix matching (non-shared operations)
		{
			name:           "exact match",
			targetResource: "/foo/bar",
			scopeResource:  "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "prefix match",
			targetResource: "/foo/bar/baz",
			scopeResource:  "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "prefix match at root",
			targetResource: "/foo/bar",
			scopeResource:  "/",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "no match - different paths",
			targetResource: "/other/path",
			scopeResource:  "/foo/bar",
			operation:      config.TokenRead,
			expected:       false,
		},
		{
			name:           "partial prefix does match (string prefix behavior)",
			targetResource: "/foobar",
			scopeResource:  "/foo",
			operation:      config.TokenRead,
			expected:       true, // Note: This is string prefix matching, not path-segment matching
		},
		{
			name:           "no match - completely different paths",
			targetResource: "/bar/baz",
			scopeResource:  "/foo",
			operation:      config.TokenRead,
			expected:       false,
		},
		// Trailing slash normalization
		{
			name:           "scope with trailing slash matches target without",
			targetResource: "/gluex",
			scopeResource:  "/gluex/",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "scope with trailing slash matches target subpath",
			targetResource: "/gluex/data/file.txt",
			scopeResource:  "/gluex/",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "target with trailing slash matches scope without",
			targetResource: "/gluex/",
			scopeResource:  "/gluex",
			operation:      config.TokenRead,
			expected:       true,
		},
		// Shared operations (prefer exact match)
		{
			name:           "shared write exact match",
			targetResource: "/foo/bar",
			scopeResource:  "/foo/bar",
			operation:      config.TokenSharedWrite,
			expected:       true,
		},
		{
			name:           "shared read exact match",
			targetResource: "/foo/bar",
			scopeResource:  "/foo/bar",
			operation:      config.TokenSharedRead,
			expected:       true,
		},
		{
			name:           "shared write prefix match still works",
			targetResource: "/foo/bar/baz",
			scopeResource:  "/foo/bar",
			operation:      config.TokenSharedWrite,
			expected:       true,
		},
		// Write operation
		{
			name:           "write prefix match",
			targetResource: "/data/upload/file.txt",
			scopeResource:  "/data/upload",
			operation:      config.TokenWrite,
			expected:       true,
		},
		// Delete operation
		{
			name:           "delete prefix match",
			targetResource: "/data/file.txt",
			scopeResource:  "/data",
			operation:      config.TokenDelete,
			expected:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesResource(tt.targetResource, tt.scopeResource, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsValidWLCGScope tests the isValidWLCGScope helper function
func TestIsValidWLCGScope(t *testing.T) {
	tests := []struct {
		name      string
		authz     string
		operation config.TokenOperation
		expected  bool
	}{
		// Read operations
		{
			name:      "storage.read for TokenRead",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: config.TokenRead,
			expected:  true,
		},
		{
			name:      "storage.read for TokenSharedRead",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: config.TokenSharedRead,
			expected:  true,
		},
		{
			name:      "storage.modify for TokenRead - rejected",
			authz:     token_scopes.Wlcg_Storage_Modify.String(),
			operation: config.TokenRead,
			expected:  false,
		},
		// Write operations
		{
			name:      "storage.modify for TokenWrite",
			authz:     token_scopes.Wlcg_Storage_Modify.String(),
			operation: config.TokenWrite,
			expected:  true,
		},
		{
			name:      "storage.create for TokenWrite",
			authz:     token_scopes.Wlcg_Storage_Create.String(),
			operation: config.TokenWrite,
			expected:  true,
		},
		{
			name:      "storage.modify for TokenSharedWrite",
			authz:     token_scopes.Wlcg_Storage_Modify.String(),
			operation: config.TokenSharedWrite,
			expected:  true,
		},
		{
			name:      "storage.create for TokenSharedWrite",
			authz:     token_scopes.Wlcg_Storage_Create.String(),
			operation: config.TokenSharedWrite,
			expected:  true,
		},
		{
			name:      "storage.read for TokenWrite - rejected",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: config.TokenWrite,
			expected:  false,
		},
		// Delete operations
		{
			name:      "storage.modify for TokenDelete",
			authz:     token_scopes.Wlcg_Storage_Modify.String(),
			operation: config.TokenDelete,
			expected:  true,
		},
		{
			name:      "storage.create for TokenDelete - rejected",
			authz:     token_scopes.Wlcg_Storage_Create.String(),
			operation: config.TokenDelete,
			expected:  false,
		},
		{
			name:      "storage.read for TokenDelete - rejected",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: config.TokenDelete,
			expected:  false,
		},
		// Invalid scope
		{
			name:      "invalid scope for any operation",
			authz:     "invalid.scope",
			operation: config.TokenRead,
			expected:  false,
		},
		// Zero operation (no operation set)
		{
			name:      "storage.read with no operation",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: 0,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidWLCGScope(tt.authz, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestIsValidSciScope tests the isValidSciScope helper function
func TestIsValidSciScope(t *testing.T) {
	tests := []struct {
		name      string
		authz     string
		operation config.TokenOperation
		expected  bool
	}{
		// Read operations
		{
			name:      "read for TokenRead",
			authz:     token_scopes.Scitokens_Read.String(),
			operation: config.TokenRead,
			expected:  true,
		},
		{
			name:      "read for TokenSharedRead",
			authz:     token_scopes.Scitokens_Read.String(),
			operation: config.TokenSharedRead,
			expected:  true,
		},
		{
			name:      "write for TokenRead - rejected",
			authz:     token_scopes.Scitokens_Write.String(),
			operation: config.TokenRead,
			expected:  false,
		},
		// Write operations
		{
			name:      "write for TokenWrite",
			authz:     token_scopes.Scitokens_Write.String(),
			operation: config.TokenWrite,
			expected:  true,
		},
		{
			name:      "write for TokenSharedWrite",
			authz:     token_scopes.Scitokens_Write.String(),
			operation: config.TokenSharedWrite,
			expected:  true,
		},
		{
			name:      "read for TokenWrite - rejected",
			authz:     token_scopes.Scitokens_Read.String(),
			operation: config.TokenWrite,
			expected:  false,
		},
		// Delete operations
		{
			name:      "write for TokenDelete",
			authz:     token_scopes.Scitokens_Write.String(),
			operation: config.TokenDelete,
			expected:  true,
		},
		{
			name:      "read for TokenDelete - rejected",
			authz:     token_scopes.Scitokens_Read.String(),
			operation: config.TokenDelete,
			expected:  false,
		},
		// Invalid scope
		{
			name:      "invalid scope for any operation",
			authz:     "invalid.scope",
			operation: config.TokenRead,
			expected:  false,
		},
		// WLCG scopes should be rejected for SciToken validation
		{
			name:      "storage.read for TokenRead - rejected (WLCG scope)",
			authz:     token_scopes.Wlcg_Storage_Read.String(),
			operation: config.TokenRead,
			expected:  false,
		},
		// Zero operation (no operation set)
		{
			name:      "read with no operation",
			authz:     token_scopes.Scitokens_Read.String(),
			operation: 0,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSciScope(tt.authz, tt.operation)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestHasAcceptableScope tests the hasAcceptableScope helper function
func TestHasAcceptableScope(t *testing.T) {
	tests := []struct {
		name           string
		scopes         string
		isWLCG         bool
		isSci          bool
		targetResource string
		operation      config.TokenOperation
		expected       bool
	}{
		// WLCG token scopes
		{
			name:           "WLCG read scope matches",
			scopes:         "storage.read:/foo",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "WLCG modify scope for write",
			scopes:         "storage.modify:/data",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/data/file.txt",
			operation:      config.TokenWrite,
			expected:       true,
		},
		{
			name:           "WLCG create scope for write",
			scopes:         "storage.create:/data",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/data/file.txt",
			operation:      config.TokenWrite,
			expected:       true,
		},
		{
			name:           "WLCG scope without resource",
			scopes:         "storage.read",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/any/path",
			operation:      config.TokenRead,
			expected:       true,
		},
		// SciToken scopes
		{
			name:           "SciToken read scope matches",
			scopes:         "read:/foo",
			isWLCG:         false,
			isSci:          true,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "SciToken write scope for write",
			scopes:         "write:/data",
			isWLCG:         false,
			isSci:          true,
			targetResource: "/data/file.txt",
			operation:      config.TokenWrite,
			expected:       true,
		},
		{
			name:           "SciToken scope without resource",
			scopes:         "read",
			isWLCG:         false,
			isSci:          true,
			targetResource: "/any/path",
			operation:      config.TokenRead,
			expected:       true,
		},
		// Multiple scopes
		{
			name:           "multiple WLCG scopes - second matches",
			scopes:         "storage.modify:/other storage.read:/foo",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "multiple SciToken scopes - second matches",
			scopes:         "write:/other read:/foo",
			isWLCG:         false,
			isSci:          true,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		// No matching scope
		{
			name:           "WLCG wrong resource path",
			scopes:         "storage.read:/other",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       false,
		},
		{
			name:           "SciToken wrong resource path",
			scopes:         "read:/other",
			isWLCG:         false,
			isSci:          true,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       false,
		},
		{
			name:           "WLCG wrong scope type for operation",
			scopes:         "storage.read:/foo",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/foo/bar",
			operation:      config.TokenWrite,
			expected:       false,
		},
		// Both isWLCG and isSci can be true (dual-profile token)
		{
			name:           "dual profile - WLCG scope matches",
			scopes:         "storage.read:/foo",
			isWLCG:         true,
			isSci:          true,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		{
			name:           "dual profile - SciToken scope matches",
			scopes:         "read:/foo",
			isWLCG:         true,
			isSci:          true,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       true,
		},
		// Empty/invalid scopes
		{
			name:           "empty scope string",
			scopes:         "",
			isWLCG:         true,
			isSci:          false,
			targetResource: "/foo",
			operation:      config.TokenRead,
			expected:       false,
		},
		{
			name:           "neither WLCG nor SciToken",
			scopes:         "storage.read:/foo",
			isWLCG:         false,
			isSci:          false,
			targetResource: "/foo/bar",
			operation:      config.TokenRead,
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := config.TokenGenerationOpts{Operation: tt.operation}
			result := hasAcceptableScope(tt.scopes, tt.isWLCG, tt.isSci, tt.targetResource, opts)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// FuzzParseScope fuzzes the parseScope function to ensure it handles arbitrary input without panicking
func FuzzParseScope(f *testing.F) {
	// Seed corpus with representative examples
	seeds := []string{
		"",
		"storage.read",
		"storage.read:/",
		"storage.read:/foo/bar",
		"read:/data",
		"write:/data",
		"storage.modify:/path/to/resource",
		"scope:resource:extra:colons",
		":",
		"::",
		"a]]]]]]]]]",
		"\x00\x01\x02",
		"storage.read:" + string(make([]byte, 1000)), // long resource path
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, scope string) {
		// parseScope should never panic
		authz, resource, hasResource := parseScope(scope)

		// Basic invariants
		if scope == "" {
			if authz != "" || resource != "" || hasResource {
				t.Errorf("empty scope should return empty authz and resource")
			}
		}
		if hasResource && !strings.Contains(scope, ":") {
			t.Errorf("hasResource is true but scope has no colon: %q", scope)
		}
	})
}

// FuzzMatchesResource fuzzes the matchesResource function
func FuzzMatchesResource(f *testing.F) {
	// Seed corpus
	seeds := []struct {
		target string
		scope  string
	}{
		{"/foo/bar", "/foo"},
		{"/foo/bar/baz", "/foo/bar"},
		{"/", "/"},
		{"/foo", "/foo/"},
		{"/foo/", "/foo"},
		{"", ""},
		{"/foobar", "/foo"},
		{"/data/file.txt", "/data"},
	}
	for _, seed := range seeds {
		f.Add(seed.target, seed.scope)
	}

	operations := []config.TokenOperation{
		config.TokenRead,
		config.TokenWrite,
		config.TokenSharedRead,
		config.TokenSharedWrite,
		config.TokenDelete,
	}

	f.Fuzz(func(t *testing.T, targetResource, scopeResource string) {
		// matchesResource should never panic for any input
		for _, op := range operations {
			_ = matchesResource(targetResource, scopeResource, op)
		}
	})
}

// FuzzIsValidWLCGScope fuzzes the isValidWLCGScope function
func FuzzIsValidWLCGScope(f *testing.F) {
	// Seed corpus with valid and invalid scopes
	seeds := []string{
		"storage.read",
		"storage.create",
		"storage.modify",
		"storage.stage",
		"read",
		"write",
		"",
		"invalid.scope",
		"STORAGE.READ",
		"storage.read.extra",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	operations := []config.TokenOperation{
		0, // no operation
		config.TokenRead,
		config.TokenWrite,
		config.TokenSharedRead,
		config.TokenSharedWrite,
		config.TokenDelete,
	}

	f.Fuzz(func(t *testing.T, authz string) {
		// isValidWLCGScope should never panic
		for _, op := range operations {
			_ = isValidWLCGScope(authz, op)
		}
	})
}

// FuzzIsValidSciScope fuzzes the isValidSciScope function
func FuzzIsValidSciScope(f *testing.F) {
	// Seed corpus with valid and invalid scopes
	seeds := []string{
		"read",
		"write",
		"storage.read",
		"storage.modify",
		"",
		"invalid",
		"READ",
		"read.extra",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	operations := []config.TokenOperation{
		0,
		config.TokenRead,
		config.TokenWrite,
		config.TokenSharedRead,
		config.TokenSharedWrite,
		config.TokenDelete,
	}

	f.Fuzz(func(t *testing.T, authz string) {
		// isValidSciScope should never panic
		for _, op := range operations {
			_ = isValidSciScope(authz, op)
		}
	})
}

// FuzzHasAcceptableScope fuzzes the hasAcceptableScope function
func FuzzHasAcceptableScope(f *testing.F) {
	// Seed corpus
	seeds := []struct {
		scopes         string
		targetResource string
	}{
		{"storage.read:/foo", "/foo/bar"},
		{"read:/data write:/other", "/data/file"},
		{"storage.modify:/", "/any/path"},
		{"", "/foo"},
		{"invalid", "/foo"},
		{"storage.read", "/any"},
		{"read write", "/path"},
		{"storage.read:/foo storage.modify:/bar", "/foo/baz"},
	}
	for _, seed := range seeds {
		f.Add(seed.scopes, seed.targetResource)
	}

	operations := []config.TokenOperation{
		config.TokenRead,
		config.TokenWrite,
		config.TokenSharedRead,
		config.TokenSharedWrite,
		config.TokenDelete,
	}

	f.Fuzz(func(t *testing.T, scopes, targetResource string) {
		opts := config.TokenGenerationOpts{}

		// hasAcceptableScope should never panic for any combination
		for _, op := range operations {
			opts.Operation = op
			// Test all combinations of isWLCG and isSci
			_ = hasAcceptableScope(scopes, true, false, targetResource, opts)
			_ = hasAcceptableScope(scopes, false, true, targetResource, opts)
			_ = hasAcceptableScope(scopes, true, true, targetResource, opts)
			_ = hasAcceptableScope(scopes, false, false, targetResource, opts)
		}
	})
}

// Helper function to create a test JWT key
func createTestJWK(t *testing.T) jwk.Key {
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-ec-key"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))

	return jwkKey
}

// TestTokenIsAcceptableForSciTokens verifies if a scitoken-profile JWT is acceptable for a given namespace
func TestTokenIsAcceptableForSciTokens(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example")
	require.NoError(t, err)

	// Build a minimal DirectorResponse whose namespace is "/foo"
	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/foo",
		},
		XPelTokGenHdr: server_structs.XPelTokGen{
			Issuers:   []*url.URL{issuerURL},
			BasePaths: []string{"/foo"},
		},
	}

	jwkKey := createTestJWK(t)

	t.Run("SciToken read accepted for matching resource", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}

		tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Read, "/bar"))

		sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		sciTok := string(sciTokBytes)

		// Resource "/foo/bar/baz" is inside namespace and matches scope
		accepted := tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected SciToken to be acceptable for /foo/bar/baz")
	})

	t.Run("SciToken rejected for resource outside namespace", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}

		tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Read, "/bar"))

		sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		sciTok := string(sciTokBytes)

		// Resource "/other/bar" lies outside the declared namespace
		accepted := tokenIsAcceptable(sciTok, "/other/bar", dirResp, opts)
		assert.False(t, accepted, "expected SciToken for /other/bar to be rejected")
	})

	t.Run("SciToken write accepted for delete operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenDelete}

		tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Write, "/bar"))

		sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		sciTok := string(sciTokBytes)

		accepted := tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected SciToken with write scope to be acceptable for TokenDelete operation")
	})

	t.Run("SciToken write accepted for write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenWrite}

		tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Write, "/bar"))

		sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		sciTok := string(sciTokBytes)

		accepted := tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected SciToken with write scope to be acceptable for TokenWrite operation")
	})

	t.Run("SciToken read rejected for write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenWrite}

		tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Read, "/bar"))

		sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		sciTok := string(sciTokBytes)

		accepted := tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
		assert.False(t, accepted, "expected SciToken with read scope to be rejected for TokenWrite operation")
	})
}

// TestTokenIsAcceptableForWLCGTokens verifies if a WLCG-profile JWT is acceptable for a given namespace
func TestTokenIsAcceptableForWLCGTokens(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example")
	require.NoError(t, err)

	// Build a minimal DirectorResponse whose namespace is "/foo"
	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/foo",
		},
		XPelTokGenHdr: server_structs.XPelTokGen{
			Issuers:   []*url.URL{issuerURL},
			BasePaths: []string{"/foo"},
		},
	}

	jwkKey := createTestJWK(t)

	t.Run("WLCG storage.read accepted for read operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		// Resource "/foo/bar/baz" is inside namespace and matches scope
		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token to be acceptable for /foo/bar/baz")
	})

	t.Run("WLCG storage.read accepted for shared read operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenSharedRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token to be acceptable for shared read")
	})

	t.Run("WLCG rejected for resource outside namespace", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		// Resource "/other/bar" lies outside the declared namespace
		accepted := tokenIsAcceptable(wlcgTok, "/other/bar", dirResp, opts)
		assert.False(t, accepted, "expected WLCG token for /other/bar to be rejected")
	})

	t.Run("WLCG storage.modify accepted for write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenWrite}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token with storage.modify to be acceptable for write")
	})

	t.Run("WLCG storage.create accepted for write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenWrite}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token with storage.create to be acceptable for write")
	})

	t.Run("WLCG storage.create accepted for shared write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenSharedWrite}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token with storage.create to be acceptable for shared write")
	})

	t.Run("WLCG storage.modify accepted for delete operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenDelete}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Modify, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.True(t, accepted, "expected WLCG token with storage.modify to be acceptable for delete")
	})

	t.Run("WLCG storage.create rejected for delete operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenDelete}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.False(t, accepted, "expected WLCG token with storage.create to be rejected for delete")
	})

	t.Run("WLCG storage.read rejected for write operation", func(t *testing.T) {
		opts := config.TokenGenerationOpts{Operation: config.TokenWrite}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		wlcgTokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		wlcgTok := string(wlcgTokBytes)

		accepted := tokenIsAcceptable(wlcgTok, "/foo/bar/baz", dirResp, opts)
		assert.False(t, accepted, "expected WLCG token with storage.read to be rejected for write")
	})
}

// TestTokenIsAcceptableIssuerValidation verifies issuer matching behavior
func TestTokenIsAcceptableIssuerValidation(t *testing.T) {
	jwkKey := createTestJWK(t)

	t.Run("token rejected when issuer does not match", func(t *testing.T) {
		issuerURL, err := url.Parse("https://trusted-issuer.example")
		require.NoError(t, err)

		dirResp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				Namespace: "/foo",
			},
			XPelTokGenHdr: server_structs.XPelTokGen{
				Issuers:   []*url.URL{issuerURL},
				BasePaths: []string{"/foo"},
			},
		}

		opts := config.TokenGenerationOpts{Operation: config.TokenRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://untrusted-issuer.example" // Different from dirResp
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		tokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		tok := string(tokBytes)

		accepted := tokenIsAcceptable(tok, "/foo/bar", dirResp, opts)
		assert.False(t, accepted, "expected token with wrong issuer to be rejected")
	})

	t.Run("token accepted when issuer is in list", func(t *testing.T) {
		issuerURL1, _ := url.Parse("https://issuer1.example")
		issuerURL2, _ := url.Parse("https://issuer2.example")

		dirResp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				Namespace: "/foo",
			},
			XPelTokGenHdr: server_structs.XPelTokGen{
				Issuers:   []*url.URL{issuerURL1, issuerURL2},
				BasePaths: []string{"/foo"},
			},
		}

		opts := config.TokenGenerationOpts{Operation: config.TokenRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://issuer2.example" // Second issuer in list
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		tokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		tok := string(tokBytes)

		accepted := tokenIsAcceptable(tok, "/foo/bar", dirResp, opts)
		assert.True(t, accepted, "expected token with matching issuer to be accepted")
	})

	t.Run("token accepted when no issuers specified in dirResp", func(t *testing.T) {
		dirResp := server_structs.DirectorResponse{
			XPelNsHdr: server_structs.XPelNs{
				Namespace: "/foo",
			},
			XPelTokGenHdr: server_structs.XPelTokGen{
				Issuers:   []*url.URL{}, // Empty issuers list
				BasePaths: []string{"/foo"},
			},
		}

		opts := config.TokenGenerationOpts{Operation: config.TokenRead}

		tc, err := token.NewTokenConfig(token.WlcgProfile{})
		require.NoError(t, err)
		tc.Lifetime = time.Hour
		tc.Issuer = "https://any-issuer.example"
		tc.Subject = "test-subject"
		tc.AddAudienceAny()
		tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/bar"))

		tokBytes, err := tc.CreateTokenWithKey(jwkKey)
		require.NoError(t, err)
		tok := string(tokBytes)

		accepted := tokenIsAcceptable(tok, "/foo/bar", dirResp, opts)
		assert.True(t, accepted, "expected token to be accepted when no issuers specified")
	})
}
