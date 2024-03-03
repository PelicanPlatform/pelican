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
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

// For these tests, we only need to lookup key locations. Create a dummy registry that only returns
// the jwks_uri location for the given key. Once a server is instantiated, it will only return
// locations for the provided prefix. To change prefixes, create a new registry mockup.
func registryMockup(t *testing.T, prefix string) *httptest.Server {
	registryUrl, _ := url.Parse("https://registry.com:8446")
	path, err := url.JoinPath("/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to parse key path for prefix %s", prefix)
	}
	registryUrl.Path = path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + registryUrl.String() + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	}))
	return server
}

func TestVerifyAdvertiseToken(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "t-key")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	viper.Set("Federation.DirectorURL", "https://director-url.org")

	config.InitConfig()
	err := config.InitServer(ctx, config.DirectorType)
	require.NoError(t, err)
	// Mock registry server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/api/v1.0/registry/checkNamespaceStatus" {
			res := checkStatusRes{Approved: true}
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

	viper.Set("Federation.RegistryUrl", ts.URL)

	kSet, err := config.GetIssuerPublicJWKS()
	ar := MockCache{
		GetFn: func(key string, keyset *jwk.Set) (jwk.Set, error) {
			if key != ts.URL+"/api/v1.0/registry/test-namespace/.well-known/issuer.jwks" {
				t.Errorf("expecting: %s/api/v1.0/registry/test-namespace/.well-known/issuer.jwks, got %q", ts.URL, key)
			}
			return *keyset, nil
		},
		RegisterFn: func(m *MockCache) error {
			m.keyset = kSet
			return nil
		},
	}

	// Perform injections (ar.Register will create a jwk.keyset with the publickey in it)
	func() {
		if err = ar.Register("", jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
			t.Errorf("this should never happen, should actually be impossible, including check for the linter")
		}
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		namespaceKeys.Set("/test-namespace", &ar, ttlcache.DefaultTTL)
	}()

	issuerUrl, err := GetNSIssuerURL("/test-namespace")
	assert.NoError(t, err)

	advTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Version:      "1.0",
		Lifetime:     time.Minute,
		Issuer:       issuerUrl,
		Audience:     []string{"https://director-url.org"},
		Subject:      "origin",
	}
	advTokenCfg.AddScopes(token_scopes.Pelican_Advertise)

	// CreateToken also handles validation for us
	tok, err := advTokenCfg.CreateToken()
	assert.NoError(t, err, "failed to create director prometheus token")

	ok, err := VerifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.NoError(t, err)
	assert.Equal(t, true, ok, "Expected scope to be 'pelican.advertise'")

	//Create token without a scope - should return an error upon validation
	scopelessTokCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       "https://get-your-tokens.org",
		Audience:     []string{"director.test"},
		Version:      "1.0",
		Subject:      "origin",
	}

	tok, err = scopelessTokCfg.CreateToken()
	assert.NoError(t, err, "error creating scopeless token. Should have succeeded")

	ok, err = VerifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.Equal(t, false, ok)
	assert.Equal(t, "No scope is present; required to advertise to director", err.Error())

	// Create a token with a bad scope - should return an error upon validation
	wrongScopeTokenCfg := utils.TokenConfig{
		TokenProfile: utils.WLCG,
		Lifetime:     time.Minute,
		Issuer:       "https://get-your-tokens.org",
		Audience:     []string{"director.test"},
		Version:      "1.0",
		Subject:      "origin",
		Claims:       map[string]string{"scope": "wrong.scope"},
	}

	tok, err = wrongScopeTokenCfg.CreateToken()
	assert.NoError(t, err, "error creating wrong-scope token. Should have succeeded")

	ok, err = VerifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.Equal(t, false, ok, "Should fail due to incorrect scope name")
	assert.NoError(t, err, "Incorrect scope name should not throw and error")
}

func TestGetNSIssuerURL(t *testing.T) {
	viper.Reset()
	viper.Set("Federation.RegistryUrl", "https://registry.com:8446")
	url, err := GetNSIssuerURL("/test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, "https://registry.com:8446/api/v1.0/registry/test-prefix", url)
	viper.Reset()
}

func TestGetJWKSURLFromIssuerURL(t *testing.T) {
	viper.Reset()
	registry := registryMockup(t, "/test-prefix")
	defer registry.Close()
	viper.Set("Federation.RegistryUrl", registry.URL)
	expectedIssuerUrl := registry.URL + "/api/v1.0/registry/test-prefix"
	url, err := GetNSIssuerURL("/test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, expectedIssuerUrl, url)

	keyLoc, err := GetJWKSURLFromIssuerURL(url)
	assert.Equal(t, nil, err)
	assert.Equal(t, "https://registry.com:8446/api/v1.0/registry/test-prefix/.well-known/issuer.jwks", keyLoc)
}

func TestNamespaceKeysCacheEviction(t *testing.T) {
	t.Run("evict-after-expire-time", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		ConfigTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		mockNamespaceKey := "foo"
		mockCtx := context.Background()
		mockAr := jwk.NewCache(mockCtx)

		deletedChan := make(chan int)
		cancelChan := make(chan int)

		go func() {
			namespaceKeysMutex.Lock()
			defer namespaceKeysMutex.Unlock()
			namespaceKeys.DeleteAll()

			namespaceKeys.Set(mockNamespaceKey, mockAr, time.Second*2)
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
