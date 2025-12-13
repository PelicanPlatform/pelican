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

package director

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestVerifyAdvertiseToken(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "t-issuer-keys")

	//Setup a private key and a token
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))

	// Mock registry server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/api/v1.0/registry/checkNamespaceStatus" {
			res := server_structs.CheckNamespaceStatusRes{Approved: true}
			resByte, err := json.Marshal(res)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, err = w.Write(resByte)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	// Spin up mock federation discovery endpoint with embedded mock registry URL.
	fedInfo := pelican_url.FederationDiscovery{RegistryEndpoint: ts.URL}
	test_utils.MockFederationRoot(t, &fedInfo, nil)

	// Mock cached jwks
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))
	err := config.InitServer(ctx, server_structs.DirectorType)
	require.NoError(t, err)

	kSet, err := config.GetIssuerPublicJWKS()
	require.NoError(t, err)
	namespaceKeys.Set(ts.URL+"/api/v1.0/registry/test-namespace/.well-known/issuer.jwks", kSet, ttlcache.DefaultTTL)

	issuerUrl, err := server_utils.GetNSIssuerURL("/test-namespace")
	assert.NoError(t, err)

	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = issuerUrl
	advTokenCfg.Subject = "origin"
	advTokenCfg.AddAudiences("https://director-url.org")
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	// CreateToken also handles validation for us
	tok, err := advTokenCfg.CreateToken()
	assert.NoError(t, err, "failed to create director prometheus token")

	ok, err := verifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.NoError(t, err)
	assert.Equal(t, true, ok, "Expected scope to be 'pelican.advertise'")

	//Create token without a scope - should return an error upon validation
	scopelessTokCfg := token.NewWLCGToken()
	scopelessTokCfg.Lifetime = time.Minute
	scopelessTokCfg.Issuer = "https://get-your-tokens.org"
	scopelessTokCfg.Subject = "origin"
	scopelessTokCfg.AddAudiences("director.test")

	tok, err = scopelessTokCfg.CreateToken()
	assert.NoError(t, err, "error creating scopeless token. Should have succeeded")

	ok, err = verifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.Equal(t, false, ok)
	assert.Equal(t, "no scope is present; required to advertise to director", err.Error())

	// Create a token with a bad scope - should return an error upon validation
	wrongScopeTokenCfg := token.NewWLCGToken()
	wrongScopeTokenCfg.Lifetime = time.Minute
	wrongScopeTokenCfg.Issuer = "https://get-your-tokens.org"
	wrongScopeTokenCfg.AddAudiences("director.test")
	wrongScopeTokenCfg.Subject = "origin"
	wrongScopeTokenCfg.Claims = map[string]string{"scope": "wrong.scope"}

	tok, err = wrongScopeTokenCfg.CreateToken()
	assert.NoError(t, err, "error creating wrong-scope token. Should have succeeded")

	ok, err = verifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.Equal(t, false, ok, "Should fail due to incorrect scope name")
	assert.NoError(t, err, "Incorrect scope name should not throw and error")
}

func TestNamespaceKeysCacheEviction(t *testing.T) {
	t.Run("evict-after-expire-time", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		LaunchTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		mockNamespaceKey := "foo"

		deletedChan := make(chan int)
		cancelChan := make(chan int)

		go func() {
			namespaceKeys.DeleteAll()

			namespaceKeys.Set(mockNamespaceKey, jwk.NewSet(), time.Second*2)
			require.True(t, namespaceKeys.Has(mockNamespaceKey), "Failed to register namespace key")
		}()

		// Keep checking if the cache item is absent or cancelled
		go func() {
			for {
				select {
				case <-cancelChan:
					return
				default:
					if !namespaceKeys.Has(mockNamespaceKey) {
						deletedChan <- 1
						return
					}
				}
			}
		}()

		// Wait for 3s to check if the expired cache item is evicted
		select {
		case <-deletedChan:
			require.True(t, true)
		case <-time.After(3 * time.Second):
			cancelChan <- 1
			require.False(t, true, "Cache didn't evict expired item")
		}
	})
}

// TestNamespaceKeysCacheTTLExpiration tests that the namespaceKeys cache
// properly expires keys after the TTL period and that WithDisableTouchOnHit
// prevents TTL refresh on cache access. This validates the fix for the bug
// where stale keys would remain cached indefinitely if accessed frequently.
func TestNamespaceKeysCacheTTLExpiration(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	t.Cleanup(server_utils.ResetTestState)

	// Create test keys using config.GeneratePEM helper
	keyDir := t.TempDir()
	oldKey, err := config.GeneratePEM(keyDir)
	require.NoError(t, err, "Failed to generate old private key")
	oldPublicKey, err := oldKey.PublicKey()
	require.NoError(t, err, "Failed to create old public key")

	newKey, err := config.GeneratePEM(keyDir)
	require.NoError(t, err, "Failed to generate new private key")
	newPublicKey, err := newKey.PublicKey()
	require.NoError(t, err, "Failed to create new public key")

	// Track how many times the JWKS endpoint is called
	jwksCallCount := 0
	var currentKey jwk.Key = oldPublicKey
	var registryServerURL string

	// Mock registry server that serves JWKS
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/api/v1.0/registry/checkNamespaceStatus" {
			res := server_structs.CheckNamespaceStatusRes{Approved: true}
			resByte, err := json.Marshal(res)
			require.NoError(t, err)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(resByte)
		} else if req.URL.Path == "/api/v1.0/registry/test-namespace/.well-known/openid-configuration" {
			// Return openid-configuration pointing to JWKS
			jwksUrl := fmt.Sprintf("%s/api/v1.0/registry/test-namespace/.well-known/issuer.jwks", registryServerURL)
			config := map[string]string{
				"jwks_uri": jwksUrl,
			}
			configByte, err := json.Marshal(config)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(configByte)
		} else if req.URL.Path == "/api/v1.0/registry/test-namespace/.well-known/issuer.jwks" {
			jwksCallCount++
			// Return the current key (starts with old key, can be updated to new key)
			jwks := jwk.NewSet()
			err := jwks.AddKey(currentKey)
			require.NoError(t, err)
			jwksByte, err := json.Marshal(jwks)
			require.NoError(t, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jwksByte)
		} else {
			t.Fatalf("Unmocked endpoint hit: %s %s", req.Method, req.URL.Path)
		}
	}))
	defer ts.Close()
	registryServerURL = ts.URL

	// Spin up mock federation discovery endpoint with embedded mock registry URL.
	fedInfo := pelican_url.FederationDiscovery{RegistryEndpoint: registryServerURL}
	test_utils.MockFederationRoot(t, &fedInfo, nil)

	// Initialize director
	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "t-issuer-keys")
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
	require.NoError(t, param.Set("ConfigDir", tDir))

	// Use a shorter TTL for testing (2 seconds instead of 15 minutes)
	// This affects both the server ad cache and the namespaceKeys cache expiration
	originalTTL := param.Director_AdvertisementTTL.GetDuration()
	require.NoError(t, param.Set(param.Director_AdvertisementTTL.GetName(), 2*time.Second))
	t.Cleanup(func() {
		require.NoError(t, param.Set(param.Director_AdvertisementTTL.GetName(), originalTTL))
	})

	err = config.InitServer(ctx, server_structs.DirectorType)
	require.NoError(t, err)

	// Start the TTL cache
	LaunchTTLCache(ctx, egrp)

	// Get the namespace issuer URL and JWKS URL
	issuerUrl, err := server_utils.GetNSIssuerURL("/test-namespace")
	require.NoError(t, err)
	keyLoc, err := server_utils.GetJWKSURLFromIssuerURL(issuerUrl)
	require.NoError(t, err)

	// Get the director URL from federation info for token audience
	fedInfo, err = config.GetFederation(ctx)
	require.NoError(t, err)
	directorURL := fedInfo.DirectorEndpoint
	require.NotEmpty(t, directorURL, "Director endpoint should be set from mock federation root")

	// Create a token signed with the old key
	advTokenCfg := token.NewWLCGToken()
	advTokenCfg.Lifetime = time.Minute
	advTokenCfg.Issuer = issuerUrl
	advTokenCfg.Subject = "test-cache"
	advTokenCfg.AddAudiences(directorURL)
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	// Sign token with old key
	tok, err := advTokenCfg.CreateTokenWithKey(oldKey)
	require.NoError(t, err, "Failed to create token with old key")

	// First verification - this act caches the key and should fetch keys from registry (jwksCallCount = 1)
	ok, err := verifyAdvertiseToken(ctx, tok, "/test-namespace")
	require.NoError(t, err)
	assert.True(t, ok, "Token verification should succeed with old key")
	assert.Equal(t, 1, jwksCallCount, "JWKS should be fetched once on first verification")

	// Verify the key is cached
	item := namespaceKeys.Get(keyLoc)
	require.NotNil(t, item, "Key should be cached")
	assert.False(t, item.IsExpired(), "Cached key should not be expired yet")

	// Access the cache multiple times - WithDisableTouchOnHit should prevent TTL refresh
	var expiration time.Time
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		item = namespaceKeys.Get(keyLoc)
		require.NotNil(t, item, "Key should still be cached")
		if i == 0 {
			expiration = item.ExpiresAt()
		}
	}
	assert.Equal(t, expiration, namespaceKeys.Get(keyLoc).ExpiresAt(), "TTL should not be refreshed on cache access (WithDisableTouchOnHit)")

	// Verify JWKS was not fetched again (still count = 1)
	assert.Equal(t, 1, jwksCallCount, "JWKS should not be fetched again while cached")

	// Update the key in the registry (simulate key rotation)
	currentKey = newPublicKey

	// Create a new token signed with the new key
	newTok, err := advTokenCfg.CreateTokenWithKey(newKey)
	require.NoError(t, err, "Failed to create token with new key")

	// Try to verify with new token while old key is still cached
	// This should fail because the cache still has the old key
	ok, err = verifyAdvertiseToken(ctx, newTok, "/test-namespace")
	assert.Error(t, err, "Token verification should fail with new key while old key is cached")
	assert.False(t, ok, "Token verification should return false")

	// JWKS should not be fetched yet (cache still valid)
	assert.Equal(t, 1, jwksCallCount, "JWKS should not be fetched while cache is still valid")

	// Wait for TTL to expire (2 seconds + small buffer)
	// The namespaceKeys cache expiration is set using Director.AdvertisementTTL,
	// which we configured to 2 seconds above
	time.Sleep(2500 * time.Millisecond)

	// Verify the cache entry has expired
	item = namespaceKeys.Get(keyLoc)
	if item != nil {
		assert.True(t, item.IsExpired(), "Cached key should be expired after TTL")
	}

	// Now verify with new token - should fetch fresh keys from registry
	ok, err = verifyAdvertiseToken(ctx, newTok, "/test-namespace")
	require.NoError(t, err)
	assert.True(t, ok, "Token verification should succeed with new key after cache expiry")
	assert.Equal(t, 2, jwksCallCount, "JWKS should be fetched again after cache expiry")

	// Verify the new key is now cached
	item = namespaceKeys.Get(keyLoc)
	require.NotNil(t, item, "New key should be cached")
	assert.False(t, item.IsExpired(), "New cached key should not be expired")
}
