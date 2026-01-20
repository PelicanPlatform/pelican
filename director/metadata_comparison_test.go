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

package director

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestNormalizeUrl(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty-string",
			input:    "",
			expected: "",
		},
		{
			name:     "simple-https-url",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "https-with-port",
			input:    "https://example.com:8444",
			expected: "https://example.com:8444",
		},
		{
			name:     "root-trailing-slash-preserved",
			input:    "https://example.com/",
			expected: "https://example.com/", // Root path "/" is preserved
		},
		{
			name:     "trailing-slash-with-path",
			input:    "https://example.com/api/v1/",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "path-without-trailing-slash",
			input:    "https://example.com/api/v1",
			expected: "https://example.com/api/v1",
		},
		{
			name:     "http-url-unchanged",
			input:    "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "invalid-url-returned-as-is",
			input:    "not a valid url ://",
			expected: "not a valid url ://",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeUrl(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// generateTestJWKS creates a JWKS with a single ECDSA public key for testing
func generateTestJWKS(t *testing.T) (jwk.Set, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pKey, err := jwk.FromRaw(privateKey)
	require.NoError(t, err)

	err = jwk.AssignKeyID(pKey)
	require.NoError(t, err)

	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	require.NoError(t, err)

	publicKey, err := pKey.PublicKey()
	require.NoError(t, err)

	jwks := jwk.NewSet()
	err = jwks.AddKey(publicKey)
	require.NoError(t, err)

	jsonData, err := json.Marshal(jwks)
	require.NoError(t, err)

	return jwks, string(jsonData)
}

func TestCompareJwksKeys(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("same-uri-returns-overlap", func(t *testing.T) {
		ctx := context.Background()
		hasOverlap, err := compareJwksKeys(ctx, "https://example.com/jwks", "https://example.com/jwks")
		require.NoError(t, err)
		assert.True(t, hasOverlap, "Same URI should return overlap")
	})

	t.Run("matching-keys-return-overlap", func(t *testing.T) {
		ctx := context.Background()

		// Generate a single JWKS that will be served by both endpoints
		_, jwksJson := generateTestJWKS(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(jwksJson))
		}))
		defer server.Close()

		hasOverlap, err := compareJwksKeys(ctx, server.URL+"/jwks1", server.URL+"/jwks2")
		require.NoError(t, err)
		assert.True(t, hasOverlap, "Matching keys should return overlap")
	})

	t.Run("different-keys-return-no-overlap", func(t *testing.T) {
		ctx := context.Background()

		// Generate two different JWKS
		_, jwksJson1 := generateTestJWKS(t)
		_, jwksJson2 := generateTestJWKS(t)

		callCount := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if callCount == 0 {
				_, _ = w.Write([]byte(jwksJson1))
			} else {
				_, _ = w.Write([]byte(jwksJson2))
			}
			callCount++
		}))
		defer server.Close()

		hasOverlap, err := compareJwksKeys(ctx, server.URL+"/jwks1", server.URL+"/jwks2")
		require.NoError(t, err)
		assert.False(t, hasOverlap, "Different keys should return no overlap")
	})

	t.Run("fetch-error-returns-error", func(t *testing.T) {
		ctx := context.Background()

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := compareJwksKeys(ctx, server.URL+"/jwks1", server.URL+"/jwks2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch Director JWKS")
	})
}

func TestGetSetMetadataDiscrepancy(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("initial-state-is-disabled", func(t *testing.T) {
		ResetMetadataDiscrepancyForTest()
		result := GetMetadataDiscrepancy()
		assert.False(t, result.Enabled)
		assert.False(t, result.HasDiscrepancy)
	})

	t.Run("set-and-get-discrepancy", func(t *testing.T) {
		ResetMetadataDiscrepancyForTest()

		testDiscrepancy := &MetadataDiscrepancy{
			HasDiscrepancy: true,
			Enabled:        true,
			DiscoveryUrl:   "https://discovery.example.com",
			DirectorUrlMismatch: &UrlMismatch{
				DirectorValue:  "https://director1.example.com",
				DiscoveryValue: "https://director2.example.com",
			},
			LastChecked: time.Now(),
		}

		setMetadataDiscrepancy(testDiscrepancy)
		result := GetMetadataDiscrepancy()

		assert.True(t, result.Enabled)
		assert.True(t, result.HasDiscrepancy)
		assert.Equal(t, "https://discovery.example.com", result.DiscoveryUrl)
		assert.NotNil(t, result.DirectorUrlMismatch)
		assert.Equal(t, "https://director1.example.com", result.DirectorUrlMismatch.DirectorValue)
		assert.Equal(t, "https://director2.example.com", result.DirectorUrlMismatch.DiscoveryValue)
	})

	t.Run("reset-clears-state", func(t *testing.T) {
		testDiscrepancy := &MetadataDiscrepancy{
			HasDiscrepancy: true,
			Enabled:        true,
		}
		setMetadataDiscrepancy(testDiscrepancy)

		ResetMetadataDiscrepancyForTest()
		result := GetMetadataDiscrepancy()

		assert.False(t, result.Enabled)
		assert.False(t, result.HasDiscrepancy)
	})
}

func TestCompareMetadata(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("disabled-when-director-is-discovery-url", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Set up mock where director URL equals discovery URL
		fedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}
		test_utils.MockFederationRoot(t, &fedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): "https://director.example.com",
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		ctx := context.Background()
		result, err := CompareMetadata(ctx)
		require.NoError(t, err)

		assert.False(t, result.Enabled, "Comparison should be disabled when Director is the discovery URL")
		assert.False(t, result.HasDiscrepancy)
	})

	t.Run("disabled-when-no-discovery-url", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Set up mock with empty discovery URL
		fedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}
		test_utils.MockFederationRoot(t, &fedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			"Federation.DirectorUrl":      "https://director.example.com",
			"Federation.RegistryUrl":      "https://registry.example.com",
			"Server.ExternalWebUrl":       "https://director.example.com",
			param.TLSSkipVerify.GetName(): true,
		})

		ctx := context.Background()
		result, err := CompareMetadata(ctx)
		require.NoError(t, err)

		assert.False(t, result.Enabled, "Comparison should be disabled when no discovery URL is configured")
	})

	t.Run("detects-director-url-mismatch", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Discovery metadata (what the discovery URL returns)
		discoveryMetadata := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://different-director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}

		// Create mock discovery server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/pelican-configuration" {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(discoveryMetadata)
				require.NoError(t, err)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer discoveryServer.Close()

		// Local federation info (what the Director serves)
		localFedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint:  "https://director.example.com",
			RegistryEndpoint:  "https://registry.example.com",
			DiscoveryEndpoint: discoveryServer.URL,
		}
		test_utils.MockFederationRoot(t, &localFedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): discoveryServer.URL,
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://my-director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		ctx := context.Background()
		result, err := CompareMetadata(ctx)
		require.NoError(t, err)

		assert.True(t, result.Enabled)
		assert.True(t, result.HasDiscrepancy)
		assert.NotNil(t, result.DirectorUrlMismatch)
		assert.Equal(t, "https://director.example.com", result.DirectorUrlMismatch.DirectorValue)
		assert.Equal(t, "https://different-director.example.com", result.DirectorUrlMismatch.DiscoveryValue)
	})

	t.Run("detects-registry-url-mismatch", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Discovery metadata (what the discovery URL returns)
		discoveryMetadata := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://different-registry.example.com",
		}

		// Create mock discovery server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/pelican-configuration" {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(discoveryMetadata)
				require.NoError(t, err)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer discoveryServer.Close()

		// Local federation info (what the Director serves)
		localFedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint:  "https://director.example.com",
			RegistryEndpoint:  "https://registry.example.com",
			DiscoveryEndpoint: discoveryServer.URL,
		}
		test_utils.MockFederationRoot(t, &localFedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): discoveryServer.URL,
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://my-director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		ctx := context.Background()
		result, err := CompareMetadata(ctx)
		require.NoError(t, err)

		assert.True(t, result.Enabled)
		assert.True(t, result.HasDiscrepancy)
		assert.NotNil(t, result.RegistryUrlMismatch)
		assert.Equal(t, "https://registry.example.com", result.RegistryUrlMismatch.DirectorValue)
		assert.Equal(t, "https://different-registry.example.com", result.RegistryUrlMismatch.DiscoveryValue)
	})

	t.Run("no-discrepancy-when-matching", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Discovery metadata matches local config
		discoveryMetadata := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}

		// Create mock discovery server
		discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/pelican-configuration" {
				w.Header().Set("Content-Type", "application/json")
				err := json.NewEncoder(w).Encode(discoveryMetadata)
				require.NoError(t, err)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer discoveryServer.Close()

		localFedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint:  "https://director.example.com",
			RegistryEndpoint:  "https://registry.example.com",
			DiscoveryEndpoint: discoveryServer.URL,
		}
		test_utils.MockFederationRoot(t, &localFedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): discoveryServer.URL,
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://my-director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		ctx := context.Background()
		result, err := CompareMetadata(ctx)
		require.NoError(t, err)

		assert.True(t, result.Enabled)
		assert.False(t, result.HasDiscrepancy)
		assert.Nil(t, result.DirectorUrlMismatch)
		assert.Nil(t, result.RegistryUrlMismatch)
	})
}

func TestCompareAndStoreMetadataDiscrepancy(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("stores-result-on-success", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Set up so Director is the discovery URL (simplest case)
		fedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}
		test_utils.MockFederationRoot(t, &fedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): "https://director.example.com",
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		ctx := context.Background()
		compareAndStoreMetadataDiscrepancy(ctx)

		result := GetMetadataDiscrepancy()
		// When Director is discovery URL, Enabled should be false
		assert.False(t, result.Enabled)
		assert.False(t, result.HasDiscrepancy)
	})
}

func TestLaunchMetadataComparisonLoop(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	t.Run("runs-initial-comparison-and-periodic", func(t *testing.T) {
		server_utils.ResetTestState()
		config.ResetConfig()
		defer config.ResetConfig()
		ResetMetadataDiscrepancyForTest()

		// Set up so Director is the discovery URL
		fedInfo := pelican_url.FederationDiscovery{
			DirectorEndpoint: "https://director.example.com",
			RegistryEndpoint: "https://registry.example.com",
		}
		test_utils.MockFederationRoot(t, &fedInfo, nil)
		test_utils.InitClient(t, map[string]any{
			param.Federation_DiscoveryUrl.GetName(): "https://director.example.com",
			"Federation.DirectorUrl":                "https://director.example.com",
			"Federation.RegistryUrl":                "https://registry.example.com",
			"Server.ExternalWebUrl":                 "https://director.example.com",
			param.TLSSkipVerify.GetName():           true,
		})

		// Set a short interval for testing
		require.NoError(t, param.Set("Director.MetadataComparisonInterval", "100ms"))

		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		LaunchMetadataComparisonLoop(ctx, egrp)

		// Wait for initial comparison to complete
		require.Eventually(t, func() bool {
			result := GetMetadataDiscrepancy()
			// LastChecked should be set (non-zero)
			return !result.LastChecked.IsZero()
		}, 2*time.Second, 50*time.Millisecond, "Initial comparison should have run")

		// Record the time of the first comparison
		firstResult := GetMetadataDiscrepancy()
		firstCheckTime := firstResult.LastChecked

		// Wait for at least one periodic comparison
		require.Eventually(t, func() bool {
			result := GetMetadataDiscrepancy()
			return result.LastChecked.After(firstCheckTime)
		}, 2*time.Second, 50*time.Millisecond, "Periodic comparison should have run")
	})
}
