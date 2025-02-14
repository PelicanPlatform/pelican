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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
)

func NamespaceAdContainsPath(ns []server_structs.NamespaceAdV2, path string) bool {
	for _, v := range ns {
		if v.Path == path {
			return true
		}
	}
	return false
}

func TestGetLinkDepth(t *testing.T) {
	tests := []struct {
		name     string
		filepath string
		prefix   string
		err      error
		depth    int
	}{
		{
			name: "empty-file-prefix",
			err:  errors.New("either filepath or prefix is an empty path"),
		}, {
			name: "empty-file",
			err:  errors.New("either filepath or prefix is an empty path"),
		}, {
			name: "empty-prefix",
			err:  errors.New("either filepath or prefix is an empty path"),
		}, {
			name:     "no-match",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/bar",
			err:      errors.New("filepath does not contain the prefix"),
		}, {
			name:     "depth-1-case",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/foo/bar",
			depth:    1,
		}, {
			name:     "depth-1-w-trailing-slash",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/foo/bar/",
			depth:    1,
		}, {
			name:     "depth-2-case",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/foo",
			depth:    2,
		},
		{
			name:     "depth-2-w-trailing-slash",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/foo/",
			depth:    2,
		},
		{
			name:     "depth-3-case",
			filepath: "/foo/bar/barz.txt",
			prefix:   "/",
			depth:    3,
		},
		{
			name:     "short-path",
			filepath: "/foo/barz.txt",
			prefix:   "/foo",
			depth:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			depth, err := getLinkDepth(tt.filepath, tt.prefix)
			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err.Error(), err.Error())
			}
			assert.Equal(t, tt.depth, depth)
		})
	}
}

// Tests the RegisterOrigin endpoint. Specifically it creates a keypair and
// corresponding token and invokes the registration endpoint, it then does
// so again with an invalid token and confirms that the correct error is returned
func TestDirectorRegistration(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	// Mock registry server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "POST" && req.URL.Path == "/api/v1.0/registry/checkNamespaceStatus" {
			reqBody, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			reqJson := server_structs.CheckNamespaceStatusReq{}
			err = json.Unmarshal(reqBody, &reqJson)
			require.NoError(t, err)
			// we expect the registration to use "test" for namespace, /caches/test for cache, and /origins/test for origin
			if reqJson.Prefix != "test" && reqJson.Prefix != "/caches/test" && reqJson.Prefix != "/origins/test" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
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

	viper.Set("Federation.RegistryUrl", ts.URL)
	viper.Set("Director.CacheSortMethod", "distance")
	viper.Set("Director.StatTimeout", 300*time.Millisecond)
	viper.Set("Director.StatConcurrencyLimit", 1)

	setupContext := func() (*gin.Context, *gin.Engine, *httptest.ResponseRecorder) {
		// Setup httptest recorder and context for the the unit test
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		return c, r, w
	}

	generateToken := func() (jwk.Key, string, url.URL) {
		// Create a private key to use for the test
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		assert.NoError(t, err, "Error generating private key")

		// Convert from raw ecdsa to jwk.Key
		pKey, err := jwk.FromRaw(privateKey)
		assert.NoError(t, err, "Unable to convert ecdsa.PrivateKey to jwk.Key")

		//Assign Key id to the private key
		err = jwk.AssignKeyID(pKey)
		assert.NoError(t, err, "Error assigning kid to private key")

		//Set an algorithm for the key
		err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
		assert.NoError(t, err, "Unable to set algorithm for pKey")

		issuerURL := url.URL{
			Scheme: "https",
			Path:   ts.URL,
		}

		// Create a token to be inserted
		tok, err := jwt.NewBuilder().
			Issuer(issuerURL.String()).
			Claim("scope", token_scopes.Pelican_Advertise.String()).
			Audience([]string{"director.test"}).
			Subject("origin").
			Build()
		assert.NoError(t, err, "Error creating token")

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, pKey))
		assert.NoError(t, err, "Error signing token")

		return pKey, string(signed), issuerURL
	}

	generateReadToken := func(key jwk.Key, object, issuer string) string {
		tc := token.NewWLCGToken()
		tc.Lifetime = time.Minute
		tc.Issuer = issuer
		tc.AddAudiences("director")
		tc.Subject = "test"
		tc.Claims = map[string]string{"scope": "storage.read:" + object}
		tok, err := tc.CreateTokenWithKey(key)
		require.NoError(t, err)
		return tok
	}

	setupRequest := func(c *gin.Context, r *gin.Engine, bodyByte []byte, token string, stype server_structs.ServerType) {
		r.POST("/", func(gctx *gin.Context) { registerServeAd(ctx, gctx, stype) })
		c.Request, _ = http.NewRequest(http.MethodPost, "/", bytes.NewBuffer(bodyByte))
		c.Request.Header.Set("Authorization", "Bearer "+token)
		c.Request.Header.Set("Content-Type", "application/json")
		// Hard code the current min version. When this test starts failing because of new stuff in the Director,
		// we'll know that means it's time to update the min version in redirect.go
		c.Request.Header.Set("User-Agent", "pelican-origin/7.0.0")
	}

	// Configure the request context and Gin router to generate a redirect
	setupRedirect := func(c *gin.Context, r *gin.Engine, object, token string) {
		r.GET("/api/v1.0/director/origin/*any", redirectToOrigin)
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/director/origin"+object, nil)
		c.Request.Header.Set("X-Real-Ip", "1.1.1.1")
		c.Request.Header.Set("Authorization", "Bearer "+token)
		c.Request.Header.Set("User-Agent", "pelican-origin/7.0.0")
	}

	setupJwksCache := func(t *testing.T, ns string, key jwk.Key) {
		jwks := jwk.NewSet()
		err := jwks.AddKey(key)
		require.NoError(t, err)
		namespaceKeys.Set(ts.URL+"/api/v1.0/registry"+ns+"/.well-known/issuer.jwks", jwks, ttlcache.DefaultTTL)
	}

	teardown := func() {
		serverAds.DeleteAll()
		namespaceKeys.DeleteAll()
	}

	t.Run("valid-token-V1", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")

		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{
			Name: "test",
			URL:  "https://or-url.org",
			Namespaces: []server_structs.NamespaceAdV1{{
				Path:   "/foo/bar",
				Issuer: isurl,
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		// Check to see that the code exits with status code 200 after given it a good token
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, getAd.Name, ad.Name)
		require.Len(t, getAd.NamespaceAds, 1)
		assert.Equal(t, getAd.NamespaceAds[0].Path, "/foo/bar")
		teardown()
	})

	t.Run("valid-token-V2", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")

		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			BrokerURL: "https://broker-url.org",
			DataURL:   "https://or-url.org",
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		// Check to see that the code exits with status code 200 after given it a good token
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, getAd.Name, ad.Name)
		require.Len(t, getAd.NamespaceAds, 1)
		assert.Equal(t, getAd.NamespaceAds[0].Path, "/foo/bar")
		teardown()
	})

	// Now repeat the above test, but with an invalid token
	t.Run("invalid-token-V1", func(t *testing.T) {
		c, r, w := setupContext()
		wrongPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		assert.NoError(t, err, "Error creating another private key")
		_, token, _ := generateToken()

		wrongPublicKey, err := jwk.PublicKeyOf(wrongPrivateKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", wrongPublicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{
			Name: "test",
			URL:  "https://or-url.org",
			Namespaces: []server_structs.NamespaceAdV1{
				{
					Path:   "/foo/bar",
					Issuer: isurl,
				},
			}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Expected failing status code of 403")
		body, _ := io.ReadAll(w.Result().Body)
		assert.Contains(t, string(body), "Authorization token verification failed", "Failure wasn't because token verification failed")

		namaspaceADs := listNamespacesFromOrigins()
		assert.False(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Found namespace in the director cache even if the token validation failed.")
		teardown()
	})

	t.Run("invalid-token-V2", func(t *testing.T) {
		c, r, w := setupContext()
		wrongPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		assert.NoError(t, err, "Error creating another private key")
		_, token, _ := generateToken()

		wrongPublicKey, err := jwk.PublicKeyOf(wrongPrivateKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", wrongPublicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{Name: "test", DataURL: "https://or-url.org", Namespaces: []server_structs.NamespaceAdV2{{
			Path:   "/foo/bar",
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
		}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Expected failing status code of 403")
		body, _ := io.ReadAll(w.Result().Body)
		assert.Contains(t, string(body), "Authorization token verification failed", "Failure wasn't because token verification failed")

		namaspaceADs := listNamespacesFromOrigins()
		assert.False(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Found namespace in the director cache even if the token validation failed.")
		teardown()
	})

	t.Run("valid-token-with-web-url-V1", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{
			URL:    "https://or-url.org",
			WebURL: "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV1{
				{
					Path:   "/foo/bar",
					Issuer: isurl,
				},
			}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://or-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://or-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in origin registration request")
		teardown()
	})

	t.Run("valid-token-with-web-url-V2", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{DataURL: "https://data-url.org", WebURL: "https://localhost:8844", Namespaces: []server_structs.NamespaceAdV2{{
			Path:   "/foo/bar",
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
		}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://data-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://data-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in origin registration request")
		teardown()
	})

	// We want to ensure backwards compatibility for WebURL
	t.Run("valid-token-without-web-url-V1", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{URL: "https://or-url.org", Namespaces: []server_structs.NamespaceAdV1{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, 1, serverAds.Get("https://or-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "", serverAds.Get("https://or-url.org").Value().WebURL.String(), "WebURL in serverAds isn't empty with no WebURL provided in registration")
		teardown()
	})

	t.Run("valid-token-without-web-url-V2", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{DataURL: "https://or-url.org", Namespaces: []server_structs.NamespaceAdV2{{Path: "/foo/bar",
			Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}}}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://or-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "", serverAds.Get("https://or-url.org").Value().WebURL.String(), "WebURL in serverAds isn't empty with no WebURL provided in registration")
		teardown()
	})

	// Determines if the broker URL set in the advertisement is the same one received on redirect
	t.Run("broker-url-redirect", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")

		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		brokerUrl := "https://broker-url.org/some/path?origin=foo"

		ad := server_structs.OriginAdvertiseV2{
			DataURL:   "https://or-url.org",
			BrokerURL: brokerUrl,
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		// Check to see that the code exits with status code 200 after given it a good token
		require.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		c, r, w = setupContext()
		token = generateReadToken(pKey, "/foo/bar", isurl.String())
		// Since we didn't set up any real server for the test
		// skip the stat for get a 307
		setupRedirect(c, r, "/foo/bar/baz?skipstat", token)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
		if w.Result().StatusCode != http.StatusTemporaryRedirect {
			body, err := io.ReadAll(w.Result().Body)
			assert.NoError(t, err)
			assert.Fail(t, "Error when generating redirect: "+string(body))
		}
		assert.Equal(t, brokerUrl, w.Result().Header.Get("X-Pelican-Broker"))
	})

	t.Run("cache-with-registryname", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/caches/test", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/caches/test",        // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		// Reset the timestamp so the cache server ad is not rejected.
		allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())

		setupRequest(c, r, jsonad, token, server_structs.CacheType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://data-url.org"), "Cache fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://data-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in cache registration request")
		teardown()
	})

	// Verify if the prefixes in the cache server ad are correctly filtered
	// based on the allowed prefix for caches data.
	t.Run("cache-with-not-allowed-prefix-in-ad", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/caches/test", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		// Define allowed prefixes
		allowedPrefixes := map[string]map[string]struct{}{
			"data-url.org": {
				"/foo/baz": {},
			},
		}
		allowedPrefixesForCaches.Store(&allowedPrefixes)
		allowedPrefixesForCachesLastSetTimestamp.Store(time.Now().Unix())

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name",
			RegistryPrefix: "/caches/test",
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{
				{
					Path:   "/foo/bar",
					Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
				},
				{
					Path:   "/foo/baz",
					Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
				},
			},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.CacheType)
		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode)

		adEntry := serverAds.Get("https://data-url.org")
		assert.NotNil(t, adEntry, "Cache failed to register at serverAds")

		namespaceAds := adEntry.Value().NamespaceAds
		assert.NotNil(t, namespaceAds, "NamespaceAds should not be nil")

		foundFooBar := false
		foundFooBaz := false

		for _, ns := range namespaceAds {
			if ns.Path == "/foo/bar" {
				foundFooBar = true
			}
			if ns.Path == "/foo/baz" {
				foundFooBaz = true
			}
		}

		assert.False(t, foundFooBar, "Prefix /foo/bar should not have been registered")
		assert.True(t, foundFooBaz, "Prefix /foo/baz should have been registered")

		teardown()
	})

	t.Run("origin-with-registryname", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/origins/test", publicKey) // for origin
		setupJwksCache(t, "/foo/bar", publicKey)      // for namespace

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/origins/test",       // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://data-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://data-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in origin registration request")
		teardown()
	})

	t.Run("cache-without-registry-name", func(t *testing.T) { // For Pelican <7.8.1
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/caches/test", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "test", // XrootD.Sitename
			RegistryPrefix: "",     // For Pelican <7.8.1, there's no such field
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.CacheType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://data-url.org"), "Origin fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://data-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in origin registration request")
		teardown()
	})

	t.Run("origin-s3-type-and-disable-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/origins/test", publicKey) // for origin
		setupJwksCache(t, "/foo/bar", publicKey)      // for namespace

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/origins/test",       // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			StorageType:         "s3",
			DisableDirectorTest: true,
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		get := serverAds.Get("https://data-url.org")
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, get, "Origin fail to register at serverAds")

		getAd := get.Value()
		assert.Equal(t, server_structs.OriginStorageS3, getAd.StorageType)
		assert.True(t, getAd.DisableDirectorTest)
		teardown()
	})

	t.Run("origin-s3-type-and-enable-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/origins/test", publicKey) // for origin
		setupJwksCache(t, "/foo/bar", publicKey)      // for namespace

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/origins/test",       // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			StorageType: "s3",
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		get := serverAds.Get("https://data-url.org")
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, get, "Origin fail to register at serverAds")

		getAd := get.Value()
		assert.Equal(t, server_structs.OriginStorageS3, getAd.StorageType)
		assert.True(t, getAd.DisableDirectorTest)
		teardown()
	})

	t.Run("origin-POSIX-type-and-enable-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/origins/test", publicKey) // for origin
		setupJwksCache(t, "/foo/bar", publicKey)      // for namespace

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/origins/test",       // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			StorageType: "posix",
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		get := serverAds.Get("https://data-url.org")
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, get, "Origin fail to register at serverAds")

		getAd := get.Value()
		assert.Equal(t, server_structs.OriginStoragePosix, getAd.StorageType)
		assert.False(t, getAd.DisableDirectorTest)
		teardown()
	})

	t.Run("origin-POSIX-type-and-disable-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/origins/test", publicKey) // for origin
		setupJwksCache(t, "/foo/bar", publicKey)      // for namespace

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			Name:           "Human-readable name", // This is for web UI to display
			RegistryPrefix: "/origins/test",       // This one should be used to look up status at the registry
			DataURL:        "https://data-url.org",
			WebURL:         "https://localhost:8844",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			StorageType:         "posix",
			DisableDirectorTest: true,
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		get := serverAds.Get("https://data-url.org")
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, get, "Origin fail to register at serverAds")

		getAd := get.Value()
		assert.Equal(t, server_structs.OriginStoragePosix, getAd.StorageType)
		assert.True(t, getAd.DisableDirectorTest)
		teardown()
	})

	t.Run("origin-storage-type-and-test-V1", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{URL: "https://v1-url.org", Namespaces: []server_structs.NamespaceAdV1{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		get := serverAds.Get("https://v1-url.org")
		assert.NotNil(t, get, "Origin fail to register at serverAds")

		getAd := get.Value()
		assert.Equal(t, server_structs.OriginStoragePosix, getAd.StorageType)
		assert.False(t, getAd.DisableDirectorTest)
		teardown()
	})

	t.Run("origin-advertise-with-version-and-ua-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			BrokerURL: "https://broker-url.org",
			DataURL:   "https://or-url.org",
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			Version: "7.0.0",
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, ad.Version, getAd.Version)
		teardown()

	})
	t.Run("origin-advertise-with-ua-version-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			BrokerURL: "https://broker-url.org",
			DataURL:   "https://or-url.org",
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, "7.0.0", getAd.Version)
		teardown()
	})

	t.Run("origin-advertise-with-no-version-info-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			BrokerURL: "https://broker-url.org",
			DataURL:   "https://or-url.org",
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)
		// set header so that it doesn't have any version info
		c.Request.Header.Set("User-Agent", "fake-curl")

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, "unknown", getAd.Version)
		teardown()
	})

	t.Run("origin-advertise-with-old-ad-test", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV1{
			Name: "test",
			URL:  "https://or-url.org",
			Namespaces: []server_structs.NamespaceAdV1{{
				Path:   "/foo/bar",
				Issuer: isurl,
			}},
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, "7.0.0", getAd.Version)
		teardown()

	})

	t.Run("origin-advertise-with-mismatch-versions", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, _ := generateToken()
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		setupJwksCache(t, "/foo/bar", publicKey)

		isurl := url.URL{}
		isurl.Path = ts.URL

		ad := server_structs.OriginAdvertiseV2{
			BrokerURL: "https://broker-url.org",
			DataURL:   "https://or-url.org",
			Name:      "test",
			Namespaces: []server_structs.NamespaceAdV2{{
				Path:   "/foo/bar",
				Issuer: []server_structs.TokenIssuer{{IssuerUrl: isurl}},
			}},
			Version: "7.0.0",
		}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token, server_structs.OriginType)

		// 7.0.1 != 7.0.0
		c.Request.Header.Set("User-Agent", "pelican-origin/7.0.1")

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		get := serverAds.Get("https://or-url.org")
		getAd := get.Value()
		require.NotNil(t, get, "Coudln't find server in the director cache.")
		assert.Equal(t, "7.0.0", getAd.Version)
		teardown()
	})
}

func TestGetAuthzEscaped(t *testing.T) {
	// Test passing a token via header with no bearer prefix
	req, err := http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "tokenstring")
	escapedToken := getRequestParameters(req)
	expected := url.Values{"authz": []string{"tokenstring"}}
	assert.EqualValues(t, expected, escapedToken)

	// Test passing a token via query with no bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getRequestParameters(req)
	assert.EqualValues(t, expected, escapedToken)

	// Test passing the token via header with Bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tokenstring")
	escapedToken = getRequestParameters(req)
	assert.EqualValues(t, expected, escapedToken)

	// Test passing the token via URL with Bearer prefix and + encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer+tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getRequestParameters(req)
	assert.EqualValues(t, expected, escapedToken)

	// Finally, the same test as before, but test with %20 encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer%20tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getRequestParameters(req)
	assert.EqualValues(t, expected, escapedToken)
}

func TestGetRequestParameters(t *testing.T) {
	// Test passing a token & timeout via header
	req, err := http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "tokenstring")
	req.Header.Set("X-Pelican-Timeout", "3s")
	escapedParam := getRequestParameters(req)
	expected := url.Values{"authz": []string{"tokenstring"}, "pelican.timeout": []string{"3s"}}
	assert.EqualValues(t, expected, escapedParam)

	// Test passing a timeout via query
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?pelican.timeout=3s", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"pelican.timeout": []string{"3s"}}
	assert.EqualValues(t, expected, escapedParam)

	// Test passing skipstat via query
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?skipstat", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"skipstat": []string{""}}
	assert.EqualValues(t, expected, escapedParam)
	assert.True(t, escapedParam.Has("skipstat"))

	// Test passing skipstat with value via query
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?skipstat=true", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"skipstat": []string{""}}
	assert.EqualValues(t, expected, escapedParam)
	assert.True(t, escapedParam.Has("skipstat"))

	// Test passing prefercached via query
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?prefercached", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"prefercached": []string{""}}
	assert.EqualValues(t, expected, escapedParam)
	assert.True(t, escapedParam.Has("prefercached"))

	// Test passing prefercached with value via query
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?prefercached=true", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"prefercached": []string{""}}
	assert.EqualValues(t, expected, escapedParam)
	assert.True(t, escapedParam.Has("prefercached"))

	// Test passing nothing
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{}
	assert.EqualValues(t, expected, escapedParam)

	// Test passing the token & timeout via URL query string
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?pelican.timeout=3s&authz=tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedParam = getRequestParameters(req)
	expected = url.Values{"authz": []string{"tokenstring"}, "pelican.timeout": []string{"3s"}}
	assert.EqualValues(t, expected, escapedParam)
}

func TestCheckRedirectQuery(t *testing.T) {
	t.Run("valid-directread-only", func(t *testing.T) {
		mockQueryStr := "directread"
		mockQuery, err := url.ParseQuery(mockQueryStr)
		require.NoError(t, err)

		assert.NoError(t, checkRedirectQuery(mockQuery))
	})

	t.Run("valid-prefercached-only", func(t *testing.T) {
		mockQueryStr := "prefercached"
		mockQuery, err := url.ParseQuery(mockQueryStr)
		require.NoError(t, err)

		assert.NoError(t, checkRedirectQuery(mockQuery))
	})

	t.Run("invalid-both-directread-and-prefercached", func(t *testing.T) {
		mockQueryStr := "directread&prefercached"
		mockQuery, err := url.ParseQuery(mockQueryStr)
		require.NoError(t, err)

		checkErr := checkRedirectQuery(mockQuery)
		require.Error(t, checkErr)
		assert.Equal(t, "cannot have both directread and prefercached query parameters", checkErr.Error())
	})

	t.Run("valid-nothing", func(t *testing.T) {
		mockQueryStr := ""
		mockQuery, err := url.ParseQuery(mockQueryStr)
		require.NoError(t, err)

		assert.NoError(t, checkRedirectQuery(mockQuery))
	})

	t.Run("valid-random-param", func(t *testing.T) {
		mockQueryStr := "foo=bar&pelican.timeout=12"
		mockQuery, err := url.ParseQuery(mockQueryStr)
		require.NoError(t, err)

		assert.NoError(t, checkRedirectQuery(mockQuery))
	})
}

func TestDiscoverOriginCache(t *testing.T) {
	mockPelicanOriginServerAd := server_structs.ServerAd{
		Name: "1-test-origin-server",
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8444",
		},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}

	mockTopoOriginServerAd := server_structs.ServerAd{
		Name: "test-topology-origin-server",
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-topology-origin.org:8443",
		},
		Type:      server_structs.OriginType.String(),
		Latitude:  123.05,
		Longitude: 456.78,
	}

	mockCacheServerAd := server_structs.ServerAd{
		Name: "2-test-cache-server",
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-cache.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-cache.org:8444",
		},
		Type:      server_structs.CacheType.String(),
		Latitude:  45.67,
		Longitude: 123.05,
	}

	mockNamespaceAd := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{
			PublicReads: false,
		},
		Path: "/foo/bar/",
		Issuer: []server_structs.TokenIssuer{{
			BasePaths: []string{""},
			IssuerUrl: url.URL{},
		}},
	}

	mockDirectorUrl := "https://fake-director.org:8888"

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	// Direcor SD will only be used for director's Prometheus scraper to get available origins,
	// so the token issuer is issentially the director server itself
	// There's no need to rely on Federation.DirectorUrl as token issuer in this case
	viper.Set("Server.ExternalWebUrl", mockDirectorUrl)

	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	viper.Set(param.IssuerKeysDirectory.GetName(), kDir)

	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	err := config.InitServer(ctx, server_structs.DirectorType)
	require.NoError(t, err)

	// Generate a private key to use for the test
	_, err = config.GetIssuerPublicJWKS()
	assert.NoError(t, err, "Error generating private key")
	// Get private key
	privateKey, err := config.GetIssuerPrivateJWK()
	assert.NoError(t, err, "Error loading private key")

	// Batch set up different tokens
	setupToken := func(wrongIssuer string) []byte {
		issuerURL, err := url.Parse(mockDirectorUrl)
		assert.NoError(t, err, "Error parsing director's URL")
		tokenIssuerString := ""
		if wrongIssuer != "" {
			tokenIssuerString = wrongIssuer
		} else {
			tokenIssuerString = issuerURL.String()
		}

		tok, err := jwt.NewBuilder().
			Issuer(tokenIssuerString).
			Claim("scope", token_scopes.Pelican_DirectorServiceDiscovery).
			Audience([]string{"director.test"}).
			Subject("director").
			Expiration(time.Now().Add(time.Hour)).
			Build()
		assert.NoError(t, err, "Error creating token")

		err = jwk.AssignKeyID(privateKey)
		assert.NoError(t, err, "Error assigning key id")

		// Sign token with previously created private key
		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privateKey))
		assert.NoError(t, err, "Error signing token")
		return signed
	}

	areSlicesEqualIgnoreOrder := func(slice1, slice2 []PromDiscoveryItem) bool {
		if len(slice1) != len(slice2) {
			return false
		}

		counts := make(map[string]int)

		for _, item := range slice1 {
			bytes, err := json.Marshal(item)
			require.NoError(t, err)
			counts[string(bytes)]++
		}

		for _, item := range slice2 {
			bytes, err := json.Marshal(item)
			require.NoError(t, err)
			counts[string(bytes)]--
			if counts[string(bytes)] < 0 {
				return false
			}
		}

		return true
	}

	r := gin.Default()
	r.GET("/test", discoverOriginCache)

	t.Run("no-token-should-give-401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
		assert.Equal(t, `{"status":"error","msg":"Authentication is required but no token is present."}`, w.Body.String())
	})
	t.Run("token-present-with-wrong-issuer-should-give-403", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+string(setupToken("https://wrong-issuer.org")))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 403, w.Code)
		assert.Equal(t, `{"status":"error","msg":"Cannot verify token: Cannot verify token with server issuer:  Token issuer https://wrong-issuer.org does not match the local issuer on the current server. Expecting https://fake-director.org:8888\n"}`, w.Body.String())
	})
	t.Run("token-present-valid-should-give-200-and-empty-array", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+string(setupToken("")))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, `[]`, w.Body.String())
	})
	t.Run("response-should-match-serverAds", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		serverAds.DeleteAll()
		serverAds.Set(mockPelicanOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockPelicanOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)
		// Server fetched from topology should not be present in SD response
		serverAds.Set(mockTopoOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockTopoOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)
		serverAds.Set(mockCacheServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)

		expectedRes := []PromDiscoveryItem{{
			Targets: []string{mockCacheServerAd.WebURL.Hostname() + ":" + mockCacheServerAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(mockCacheServerAd.Type),
				"server_name":     mockCacheServerAd.Name,
				"server_auth_url": mockCacheServerAd.URL.String(),
				"server_url":      mockCacheServerAd.URL.String(),
				"server_web_url":  mockCacheServerAd.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", mockCacheServerAd.Latitude),
				"server_long":     fmt.Sprintf("%.4f", mockCacheServerAd.Longitude),
			},
		}, {
			Targets: []string{mockPelicanOriginServerAd.WebURL.Hostname() + ":" + mockPelicanOriginServerAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(mockPelicanOriginServerAd.Type),
				"server_name":     mockPelicanOriginServerAd.Name,
				"server_auth_url": mockPelicanOriginServerAd.URL.String(),
				"server_url":      mockPelicanOriginServerAd.URL.String(),
				"server_web_url":  mockPelicanOriginServerAd.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", mockPelicanOriginServerAd.Latitude),
				"server_long":     fmt.Sprintf("%.4f", mockPelicanOriginServerAd.Longitude),
			},
		}}

		req.Header.Set("Authorization", "Bearer "+string(setupToken("")))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		require.Equal(t, 200, w.Code)

		var resMarshalled []PromDiscoveryItem
		err = json.Unmarshal(w.Body.Bytes(), &resMarshalled)
		require.NoError(t, err, "Error unmarshall response to json")

		assert.True(t, areSlicesEqualIgnoreOrder(expectedRes, resMarshalled))
	})

	t.Run("no-duplicated-origins", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		serverAds.DeleteAll()
		// Add multiple same serverAds
		serverAds.Set(mockPelicanOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockPelicanOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)
		serverAds.Set(mockPelicanOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockPelicanOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)
		serverAds.Set(mockPelicanOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockPelicanOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)
		// Server fetched from topology should not be present in SD response
		serverAds.Set(mockTopoOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockTopoOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{mockNamespaceAd},
		}, ttlcache.DefaultTTL)

		expectedRes := []PromDiscoveryItem{{
			Targets: []string{mockPelicanOriginServerAd.WebURL.Hostname() + ":" + mockPelicanOriginServerAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(mockPelicanOriginServerAd.Type),
				"server_name":     mockPelicanOriginServerAd.Name,
				"server_auth_url": mockPelicanOriginServerAd.URL.String(),
				"server_url":      mockPelicanOriginServerAd.URL.String(),
				"server_web_url":  mockPelicanOriginServerAd.WebURL.String(),
				"server_lat":      fmt.Sprintf("%.4f", mockPelicanOriginServerAd.Latitude),
				"server_long":     fmt.Sprintf("%.4f", mockPelicanOriginServerAd.Longitude),
			},
		}}

		resStr, err := json.Marshal(expectedRes)
		assert.NoError(t, err, "Could not marshal json response")

		req.Header.Set("Authorization", "Bearer "+string(setupToken("")))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 200, w.Code)
		assert.Equal(t, string(resStr), w.Body.String(), "Response doesn't match expected")
	})
}

func TestRedirectCheckHostnames(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Use ads generated via mock topology for generating list of caches
	topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)
	// viper.Set("Director.CacheSortMethod", "random")
	// Populate ads for redirectToCache to use
	err := AdvertiseOSDF(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		serverAds.DeleteAll()
	})

	router := gin.Default()
	router.GET("/api/v1.0/director/origin/*any", redirectToOrigin)

	// Check that the checkHostnameRedirects uses the pre-configured hostnames to redirect
	// requests that come in at the default paths, but not if the request is made
	// specifically for an object or a cache via the API.
	viper.Set("Director.OriginResponseHostnames", []string{"origin-hostname.com"})
	viper.Set("Director.CacheResponseHostnames", []string{"cache-hostname.com"})

	type redirectHostNames struct {
		desc         string
		requestPath  string
		host         string
		expectedPath string
	}

	hostnamesTestCases := []redirectHostNames{
		{
			desc:         "redirect to origin",
			requestPath:  "/foo/bar",
			host:         "origin-hostname.com",
			expectedPath: "/api/v1.0/director/origin/foo/bar",
		},
		{
			desc:         "redirect to cache",
			requestPath:  "/foo/bar",
			host:         "cache-hostname.com",
			expectedPath: "/api/v1.0/director/object/foo/bar",
		},
		{
			desc:         "always redirect to origin",
			requestPath:  "/api/v1.0/director/origin/foo/bar",
			host:         "cache-hostname.com",
			expectedPath: "/api/v1.0/director/origin/foo/bar",
		},
		{
			desc:         "always redirect to cache",
			requestPath:  "/api/v1.0/director/object/foo/bar",
			host:         "origin-hostname.com",
			expectedPath: "/api/v1.0/director/object/foo/bar",
		},
	}

	for _, tc := range hostnamesTestCases {
		t.Run(tc.desc, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			req := httptest.NewRequest("GET", tc.requestPath, nil)
			c.Request = req
			checkHostnameRedirects(c, tc.host)

			assert.Equal(t, tc.expectedPath, c.Request.URL.Path)
		})
	}
	server_utils.ResetTestState()
}

func TestRedirectMiddleware(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Use ads generated via mock topology for generating list of caches
	topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)
	err := AdvertiseOSDF(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		serverAds.DeleteAll()
	})

	router := gin.Default()
	router.GET("/api/v1.0/director/origin/*any", redirectToOrigin)

	type testCase struct {
		description  string            // Description of the test case
		method       string            // HTTP Method (e.g., GET, PUT)
		path         string            // Request path
		mode         string            // Mode for middleware (either "origin" or "cache")
		expectedPath string            // Expected path after middleware is applied
		headers      map[string]string // Optional headers (like Host or X-Forwarded-Host)
	}

	// Helper function to run the middleware and assert the URL path
	testRequest := func(tc testCase) {
		t.Run(tc.description, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = req

			// Set headers if any
			for key, value := range tc.headers {
				c.Request.Header.Set(key, value)
			}

			ShortcutMiddleware(tc.mode)(c)
			assert.Equal(t, tc.expectedPath, c.Request.URL.Path)
		})
	}

	testCases := []testCase{
		// Test cache mode for different paths
		{"Cache mode - origin path", "GET", "/api/v1.0/director/origin/foo/bar", "cache", "/api/v1.0/director/origin/foo/bar", nil},
		{"Cache mode - object path", "GET", "/api/v1.0/director/object/foo/bar", "cache", "/api/v1.0/director/object/foo/bar", nil},

		// Test origin mode for different paths
		{"Origin mode - origin path", "GET", "/api/v1.0/director/origin/foo/bar", "origin", "/api/v1.0/director/origin/foo/bar", nil},
		{"Origin mode - object path", "GET", "/api/v1.0/director/object/foo/bar", "origin", "/api/v1.0/director/object/foo/bar", nil},

		// Test base paths when in origin mode
		{"Base path - origin mode", "GET", "/foo/bar", "origin", "/api/v1.0/director/origin/foo/bar", nil},

		// Test base paths when in cache mode
		{"Base path - cache mode", "GET", "/api/v1.0/director/object/foo/bar", "cache", "/api/v1.0/director/object/foo/bar", nil},

		// Test PUT method always goes to origin
		{"PUT request goes to origin", "PUT", "/foo/bar", "cache", "/api/v1.0/director/origin/foo/bar", nil},

		// Test PROPFIND for both base path and API path
		{"PROPFIND - base path", "PROPFIND", "/foo/bar", "origin", "/api/v1.0/director/origin/foo/bar", nil},
		{"PROPFIND - api path", "PROPFIND", "/api/v1.0/director/origin/foo/bar", "origin", "/api/v1.0/director/origin/foo/bar", nil},

		// Host-aware tests for different headers
		{"Host header - cache mode", "GET", "/foo/bar", "cache", "/api/v1.0/director/origin/foo/bar", map[string]string{"Host": "origin-hostname.com"}},
		{"X-Forwarded-Host header - cache mode", "GET", "/foo/bar", "cache", "/api/v1.0/director/origin/foo/bar", map[string]string{"X-Forwarded-Host": "origin-hostname.com"}},
	}

	// Set the necessary viper configuration for host-aware tests
	viper.Set("Director.OriginResponseHostnames", []string{"origin-hostname.com"})
	viper.Set("Director.HostAwareRedirects", true)

	// Run all test cases
	for _, tc := range testCases {
		testRequest(tc)
	}

	server_utils.ResetTestState()

}
func TestRedirects(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	// Use ads generated via mock topology for generating list of caches
	topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
	defer topoServer.Close()
	viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)
	err := AdvertiseOSDF(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		serverAds.DeleteAll()
	})

	router := gin.Default()
	router.GET("/api/v1.0/director/origin/*any", redirectToOrigin)

	t.Run("cache-test-file-redirect", func(t *testing.T) {
		viper.Set("Server.ExternalWebUrl", "https://example.com")
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/origin/pelican/monitoring/test.txt", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusTemporaryRedirect, w.Code)
		assert.NotEmpty(t, w.Header().Get("Location"))
		assert.Equal(t, "https://example.com/api/v1.0/director/healthTest/pelican/monitoring/test.txt", w.Header().Get("Location"))
	})

	t.Run("redirect-link-header-length", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(func() {
			server_utils.ResetTestState()
		})

		viper.Set("Director.CacheSortMethod", "random")

		req, _ := http.NewRequest("GET", "/my/server", nil)
		// Provide a few things so that redirectToCache doesn't choke
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req

		redirectToCache(c)
		// We should have a random collection of 6 caches in the header
		assert.Contains(t, c.Writer.Header().Get("Link"), "pri=6")
		// We should not have a 7th cache in the header
		assert.NotContains(t, c.Writer.Header().Get("Link"), "pri=7")

		// Make sure we can still get a cache list with a smaller number of caches
		req, _ = http.NewRequest("GET", "/my/server/2", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		c.Request = req

		redirectToCache(c)
		assert.Contains(t, c.Writer.Header().Get("Link"), "pri=1")
		assert.NotContains(t, c.Writer.Header().Get("Link"), "pri=2")
	})

	t.Run("no-redirect-to-topology-cache-public-reads", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(func() {
			server_utils.ResetTestState()
		})

		viper.Set("Director.CacheSortMethod", "random")

		// Make sure the http cache from topology isn't included in the cache list
		req, _ := http.NewRequest("GET", "/my/server/3", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")

		pelCacheAd := server_structs.ServerAd{
			Name: "pel-cache",
			URL: url.URL{
				Scheme: "https",
				Host:   "pelcache.test.edu",
			},
			Type: server_structs.CacheType.String(),
		}

		nsAd := server_structs.NamespaceAdV2{
			Caps: server_structs.Capabilities{PublicReads: true},
			Path: "/my/server/3",
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: url.URL{
					Scheme: "https",
					Host:   "wisc.edu",
				},
			},
			},
		}

		cSlice := []server_structs.NamespaceAdV2{nsAd}
		recordAd(context.Background(), pelCacheAd, &cSlice)

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req

		redirectToCache(c)

		assert.Contains(t, c.Writer.Header().Get("Link"), "pelcache.test.edu")
		assert.NotContains(t, c.Writer.Header().Get("Link"), "http:")
	})

	t.Run("redirect-to-topology-caches-auth-reads", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(func() {
			server_utils.ResetTestState()
		})

		viper.Set("Director.CacheSortMethod", "random")

		// Make sure the http cache from topology isn't included in the cache list
		req, _ := http.NewRequest("GET", "/my/server", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")

		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req

		redirectToCache(c)

		assert.Contains(t, c.Writer.Header().Get("Link"), "pri=6")
		assert.NotContains(t, c.Writer.Header().Get("Link"), "http:")
	})

	// Make sure collections-url is correctly populated when the ns/origin comes from topology
	t.Run("collections-url-from-topology", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(func() {
			server_utils.ResetTestState()
		})

		viper.Set("Director.CacheSortMethod", "random")

		// This one should have a collections url because it has a dirlisthost
		req, _ := http.NewRequest("GET", "/my/server", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req
		redirectToCache(c)
		assert.Contains(t, c.Writer.Header().Get("X-Pelican-Namespace"), "collections-url=https://origin1-auth-endpoint.com")

		// This one has no dirlisthost
		req, _ = http.NewRequest("GET", "/my/server/2", nil)
		req.Header.Add("User-Agent", "pelican-client/7.6.1")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		c.Request = req
		redirectToCache(c)
		assert.NotContains(t, c.Writer.Header().Get("X-Pelican-Namespace"), "collections-url")
	})

	t.Run("origin-endpoint-returns-all-headers", func(t *testing.T) {
		server_utils.ResetTestState()
		t.Cleanup(func() {
			server_utils.ResetTestState()
		})

		viper.Set("Director.CacheSortMethod", "random")

		req, _ := http.NewRequest("GET", "/my/server", nil)
		req.Header.Add("User-Agent", "pelican-v7.999.999")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req
		redirectToOrigin(c)

		assert.NotEmpty(t, c.Writer.Header().Get("Location"))
		assert.NotEmpty(t, c.Writer.Header().Get("Link"))
		assert.NotEmpty(t, c.Writer.Header().Get("X-Pelican-Authorization"))
		assert.NotEmpty(t, c.Writer.Header().Get("X-Pelican-Token-Generation"))
		assert.NotEmpty(t, c.Writer.Header().Get("X-Pelican-Namespace"))
	})
}

func TestHeaderGenFuncs(t *testing.T) {
	issUrl := url.URL{
		Scheme: "https",
		Host:   "my-issuer.com",
	}
	tGen := server_structs.TokenGen{
		Strategy:         server_structs.OAuthStrategy,
		MaxScopeDepth:    3,
		CredentialIssuer: issUrl,
	}

	tIss := server_structs.TokenIssuer{
		BasePaths: []string{"/my/server"},
		IssuerUrl: issUrl,
	}
	authedNamespaceAd := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{
			PublicReads: false,
			Reads:       true,
		},
		Generation: []server_structs.TokenGen{tGen},
		Issuer:     []server_structs.TokenIssuer{tIss},
		Path:       "/my/server",
	}

	publicNamespaceAd := server_structs.NamespaceAdV2{
		Caps: server_structs.Capabilities{
			PublicReads: true,
		},
		Path: "/different/server",
	}

	authReq, _ := http.NewRequest("GET", "/my/server", nil)
	authReq.Header.Add("User-Agent", "pelican-v7.999.999")
	authReq.Header.Add("X-Real-Ip", "128.104.153.60")

	pubReq, _ := http.NewRequest("GET", "/different/server", nil)
	pubReq.Header.Add("User-Agent", "pelican-v7.999.999")
	pubReq.Header.Add("X-Real-Ip", "128.104.153.60")

	// recorder := httptest.NewRecorder()
	t.Run("test-x-pel-auth", func(t *testing.T) {
		authedRecorder := httptest.NewRecorder()
		cAuth, _ := gin.CreateTestContext(authedRecorder)
		cAuth.Request = authReq
		generateXAuthHeader(cAuth, authedNamespaceAd)
		assert.NotEmpty(t, cAuth.Writer.Header().Get("X-Pelican-Authorization"))
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Authorization"), "issuer=https://my-issuer.com")

		pubRecorder := httptest.NewRecorder()
		cPub, _ := gin.CreateTestContext(pubRecorder)
		cPub.Request = pubReq
		generateXAuthHeader(cPub, publicNamespaceAd)
		assert.Empty(t, cPub.Writer.Header().Get("X-Pelican-Authorization"))
	})

	t.Run("test-x-pel-tok-gen", func(t *testing.T) {
		authedRecorder := httptest.NewRecorder()
		cAuth, _ := gin.CreateTestContext(authedRecorder)
		cAuth.Request = authReq

		generateXTokenGenHeader(cAuth, authedNamespaceAd)
		assert.NotEmpty(t, cAuth.Writer.Header().Get("X-Pelican-Token-Generation"))
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Token-Generation"), "issuer=https://my-issuer.com")
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Token-Generation"), "strategy=OAuth2")
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Token-Generation"), "max-scope-depth=3")

		pubRecorder := httptest.NewRecorder()
		cPub, _ := gin.CreateTestContext(pubRecorder)
		cPub.Request = pubReq
		generateXTokenGenHeader(cPub, publicNamespaceAd)
		assert.Empty(t, cPub.Writer.Header().Get("X-Pelican-Token-Generation"))
	})

	t.Run("test-x-pel-namespace", func(t *testing.T) {
		authedRecorder := httptest.NewRecorder()
		cAuth, _ := gin.CreateTestContext(authedRecorder)
		cAuth.Request = authReq

		collUrl := "https://my-origin.com"
		generateXNamespaceHeader(cAuth, authedNamespaceAd, collUrl)
		assert.NotEmpty(t, cAuth.Writer.Header().Get("X-Pelican-Namespace"))
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Namespace"), "namespace=/my/server")
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Namespace"), "require-token=true")
		assert.Contains(t, cAuth.Writer.Header().Get("X-Pelican-Namespace"), "collections-url=https://my-origin.com")

		pubRecorder := httptest.NewRecorder()
		cPub, _ := gin.CreateTestContext(pubRecorder)
		cPub.Request = pubReq
		generateXNamespaceHeader(cPub, publicNamespaceAd, "")
		assert.NotEmpty(t, cPub.Writer.Header().Get("X-Pelican-Namespace"))
		assert.Contains(t, cPub.Writer.Header().Get("X-Pelican-Namespace"), "namespace=/different/server")
		assert.Contains(t, cPub.Writer.Header().Get("X-Pelican-Namespace"), "require-token=false")
		assert.NotContains(t, cPub.Writer.Header().Get("X-Pelican-Namespace"), "collections-url")
	})
}

func TestGetHealthTestFile(t *testing.T) {
	gEngine := gin.Default()
	router := gEngine.Group("/")
	ctx := context.Background()
	ctx, cancel, _ := test_utils.TestContext(ctx, t)
	defer cancel()
	RegisterDirectorAPI(ctx, router)

	tests := []struct {
		name       string
		method     string
		url        string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "400-on-empty-path",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "400-on-random-path",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/foo/bar",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "400-on-dir",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "400-on-missing-file-ext-self-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/selfTest/testfile",
			wantStatus: http.StatusBadRequest,
			wantBody:   "{\"status\":\"error\",\"msg\":\"Test file name is missing file extension: /pelican/monitoring/selfTest/testfile\"}",
		},
		{
			name:       "400-on-missing-file-ext-director-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/directorTest/testfile",
			wantStatus: http.StatusBadRequest,
			wantBody:   "{\"status\":\"error\",\"msg\":\"Test file name is missing file extension: /pelican/monitoring/directorTest/testfile\"}",
		},
		{
			name:       "400-on-bad-timestamp-self-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/selfTest/self-test-123123123123123.txt",
			wantStatus: http.StatusBadRequest,
			wantBody:   "{\"status\":\"error\",\"msg\":\"Invalid timestamp in file name: '123123123123123'. Should conform to 2006-01-02T15:04:05Z07:00 format (RFC 3339)\"}",
		},
		{
			name:       "400-on-bad-timestamp-director-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/directorTest/director-test-123123123123123.txt",
			wantStatus: http.StatusBadRequest,
			wantBody:   "{\"status\":\"error\",\"msg\":\"Invalid timestamp in file name: '123123123123123'. Should conform to 2006-01-02T15:04:05Z07:00 format (RFC 3339)\"}",
		},
		{
			name:       "200-on-correct-request-file-self-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/selfTest/self-test-2006-01-02T15:04:10Z.txt",
			wantStatus: http.StatusOK,
			wantBody:   server_utils.DirectorTestBody + "\n",
		},
		{
			name:       "200-on-correct-request-file-director-test",
			method:     "GET",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/directorTest/director-test-2006-01-02T15:04:10Z.txt",
			wantStatus: http.StatusOK,
			wantBody:   server_utils.DirectorTestBody + "\n",
		},
		{
			name:       "207-and-XML-on-PROPFIND-self-test",
			method:     "PROPFIND",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/selfTest/self-test-2006-01-02T15:04:10Z.txt",
			wantStatus: http.StatusMultiStatus,
			wantBody: `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns1="http://apache.org/dav/props/" xmlns:ns0="DAV:">
	<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:lp3="LCGDM:">
		<D:href>/pelican/monitoring/selfTest/self-test-2006-01-02T15:04:10Z.txt</D:href>
		<D:propstat>
			<D:prop>
				<lp1:getcontentlength>67</lp1:getcontentlength>
				<lp1:getlastmodified>Mon, 02 Jan 2006 15:04:10 GMT</lp1:getlastmodified>
				<lp1:iscollection>0</lp1:iscollection>
				<lp1:executable>F</lp1:executable>
			</D:prop>
			<D:status>HTTP/1.1 200 OK</D:status>
		</D:propstat>
	</D:response>
</D:multistatus>`,
		},
		{
			name:       "207-and-XML-on-PROPFIND-director-test",
			method:     "PROPFIND",
			url:        "/api/v1.0/director/healthTest/pelican/monitoring/directorTest/director-test-2006-01-02T15:04:10Z.txt",
			wantStatus: http.StatusMultiStatus,
			wantBody: `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns1="http://apache.org/dav/props/" xmlns:ns0="DAV:">
	<D:response xmlns:lp1="DAV:" xmlns:lp2="http://apache.org/dav/props/" xmlns:lp3="LCGDM:">
		<D:href>/pelican/monitoring/directorTest/director-test-2006-01-02T15:04:10Z.txt</D:href>
		<D:propstat>
			<D:prop>
				<lp1:getcontentlength>67</lp1:getcontentlength>
				<lp1:getlastmodified>Mon, 02 Jan 2006 15:04:10 GMT</lp1:getlastmodified>
				<lp1:iscollection>0</lp1:iscollection>
				<lp1:executable>F</lp1:executable>
			</D:prop>
			<D:status>HTTP/1.1 200 OK</D:status>
		</D:propstat>
	</D:response>
</D:multistatus>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.url, nil)
			gEngine.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantBody != "" {
				bytes, err := io.ReadAll(w.Result().Body)
				require.NoError(t, err)
				// Normalize whitespace in the response body and expected body so
				// we can compare them directly
				actual := strings.Join(strings.Fields(string(bytes)), " ")
				expected := strings.Join(strings.Fields(tt.wantBody), " ")
				assert.Equal(t, expected, actual)
			}
		})
	}
}

func TestHandleFilterServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
		TeardownMockDirectorDB(t)
	})
	SetupMockDirectorDB(t)
	router := gin.Default()
	router.GET("/servers/filter/*name", handleFilterServer)

	t.Run("filter-server-success", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-dne", nil)
		filteredServersMutex.Lock()
		delete(filteredServers, "mock-dne")
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-dne"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-dne")
		assert.Equal(t, tempFiltered, filterType)
		require.NoError(t, err)
	})
	t.Run("filter-server-w-permFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-pf", nil)

		// Tweak the downtime status (filter type) to permFiltered
		filteredServersMutex.Lock()
		filteredServers["mock-pf"] = permFiltered
		filteredServersMutex.Unlock()
		err := setServerDowntime("mock-pf", permFiltered)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-pf"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-pf")
		assert.Equal(t, permFiltered, filterType)
		require.NoError(t, err)

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been filtered")
	})
	t.Run("filter-server-w-tempFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-tf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-tf"] = tempFiltered
		filteredServersMutex.Unlock()
		err := setServerDowntime("mock-tf", tempFiltered)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-tf"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-tf")
		assert.Equal(t, tempFiltered, filterType)
		require.NoError(t, err)

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been filtered")
	})
	t.Run("filter-server-w-tempAllowed", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-ta", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-ta"] = tempAllowed
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-ta"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-ta")
		assert.Equal(t, permFiltered, filterType)
		require.NoError(t, err)
	})
	t.Run("filter-with-invalid-name", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "'name' is a required path parameter")
	})
}

func TestHandleFilterServerDataIntegrity(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
		TeardownMockDirectorDB(t)
	})
	SetupMockDirectorDB(t)

	router := gin.Default()
	router.GET("/servers/filter/*name", handleFilterServer)

	t.Run("db-error-when-setting-downtime", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-error", nil)

		// Set up original filter type
		filteredServersMutex.Lock()
		filteredServers["mock-error"] = tempAllowed
		filteredServersMutex.Unlock()

		// Mock setServerDowntime to return error
		origSetServerDowntime := setServerDowntime
		defer func() { setServerDowntimeFn = origSetServerDowntime }()
		setServerDowntimeFn = func(serverName string, ft filterType) error {
			return fmt.Errorf("mock db error")
		}

		router.ServeHTTP(w, req)

		// Check response code
		require.Equal(t, http.StatusInternalServerError, w.Code)

		// Verify the server was reverted to original filter type
		filteredServersMutex.RLock()
		actualType, exists := filteredServers["mock-error"]
		filteredServersMutex.RUnlock()
		assert.True(t, exists, "Server should exist in filteredServers")
		assert.Equal(t, tempAllowed, actualType, "Filter type should be reverted to original value")

		// Check error message
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Failed to persist server downtime due to database error")
	})
}

func TestHandleAllowServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
		TeardownMockDirectorDB(t)
	})
	SetupMockDirectorDB(t)
	router := gin.Default()
	router.GET("/servers/allow/*name", handleAllowServer)

	t.Run("allow-server-that-dne", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-dne", nil)

		// Server is not in the in-memory downtime map
		filteredServersMutex.Lock()
		delete(filteredServers, "mock-dne")
		filteredServersMutex.Unlock()
		// Server is also not in the Director db downtime table
		err := deleteServerDowntime("mock-dne")
		require.NoError(t, err)
		// Note: Both map deletion and db deletion do not trigger an error if there’s nothing to delete
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow server mock-dne that is not being filtered")
	})
	t.Run("allow-server-w-permFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-pf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-pf"] = permFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-pf"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-pf")
		assert.Equal(t, tempAllowed, filterType)
		require.NoError(t, err)
	})
	t.Run("allow-server-w-tempFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-tf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-tf"] = tempFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 200, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Empty(t, filteredServers["mock-tf"])

		// Check the Director database
		filterType, err := getServerDowntime("mock-tf")
		assert.Equal(t, "", string(filterType))
		assert.Contains(t, err.Error(), "is not found in the Director db")
	})
	t.Run("allow-server-w-tempAllowed", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-ta", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-ta"] = tempAllowed
		filteredServersMutex.Unlock()
		err := setServerDowntime("mock-ta", tempAllowed)
		require.NoError(t, err)

		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		// Check the in-memory cache storage
		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-ta"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow server mock-ta that is not being filtered")

		// Check the Director database
		filterType, err := getServerDowntime("mock-ta")
		assert.Equal(t, tempAllowed, filterType)
		require.NoError(t, err)
	})
	t.Run("allow-with-invalid-name", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/", nil)
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "'name' is a required path parameter")
	})
}

func TestHandleAllowServerDataIntegrity(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
		TeardownMockDirectorDB(t)
	})
	SetupMockDirectorDB(t)

	router := gin.Default()
	router.GET("/servers/allow/*name", handleAllowServer)

	// Sub-test 1: When server is permanently filtered
	t.Run("permFiltered-db-error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-error", nil)

		// Set up initial state as permFiltered
		filteredServersMutex.Lock()
		filteredServers["mock-error"] = permFiltered
		filteredServersMutex.Unlock()

		// Mock setServerDowntimeFn to return error
		origSetServerDowntime := setServerDowntimeFn
		defer func() { setServerDowntimeFn = origSetServerDowntime }()
		setServerDowntimeFn = func(serverName string, ft filterType) error {
			return fmt.Errorf("mock db error")
		}

		router.ServeHTTP(w, req)

		// Check response code
		require.Equal(t, http.StatusInternalServerError, w.Code)

		// Verify the server maintained original filter type
		filteredServersMutex.RLock()
		actualType, exists := filteredServers["mock-error"]
		filteredServersMutex.RUnlock()
		assert.True(t, exists, "Server should still exist in filteredServers")
		assert.Equal(t, permFiltered, actualType, "Filter type should remain as permFiltered")

		// Check error message
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Failed to remove the downtime of server mock-error in director db")
	})

	// Sub-test 2: When server is temporarily filtered and deletion fails
	t.Run("tempFiltered-deletion-error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-error", nil)

		// Set up initial state as tempFiltered
		filteredServersMutex.Lock()
		filteredServers["mock-error"] = tempFiltered
		filteredServersMutex.Unlock()

		// Mock deleteServerDowntime to return error
		origDeleteServerDowntime := deleteServerDowntimeFn
		defer func() { deleteServerDowntimeFn = origDeleteServerDowntime }()
		deleteServerDowntimeFn = func(serverName string) error {
			return fmt.Errorf("mock deletion error")
		}

		router.ServeHTTP(w, req)

		// Check response code
		require.Equal(t, http.StatusInternalServerError, w.Code)

		// Verify the server maintained original filter type
		filteredServersMutex.RLock()
		actualType, exists := filteredServers["mock-error"]
		filteredServersMutex.RUnlock()
		assert.True(t, exists, "Server should still exist in filteredServers")
		assert.Equal(t, tempFiltered, actualType, "Filter type should remain as tempFiltered")

		// Check error message
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Failed to remove the downtime of server mock-error in director db")
	})

	// Sub-test 3: When server is already tempAllowed and db error occurs
	t.Run("tempAllowed-db-error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-error", nil)

		// Set up initial state as tempAllowed
		filteredServersMutex.Lock()
		filteredServers["mock-error"] = tempAllowed
		filteredServersMutex.Unlock()
		err := setServerDowntime("mock-error", tempAllowed)
		require.NoError(t, err)

		// Mock setServerDowntimeFn to return error
		origSetServerDowntime := setServerDowntimeFn
		defer func() { setServerDowntimeFn = origSetServerDowntime }()
		setServerDowntimeFn = func(serverName string, ft filterType) error {
			return fmt.Errorf("mock db error")
		}

		router.ServeHTTP(w, req)

		// Should return 400 as the server is already tempAllowed
		require.Equal(t, http.StatusBadRequest, w.Code)

		// Verify the server maintained original filter type
		filteredServersMutex.RLock()
		actualType, exists := filteredServers["mock-error"]
		filteredServersMutex.RUnlock()
		assert.True(t, exists, "Server should still exist in filteredServers")
		assert.Equal(t, tempAllowed, actualType, "Filter type should remain as tempAllowed")

		// Check error message
		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow server")
	})
}

func TestGetRedirectUrl(t *testing.T) {
	adFromTopo := server_structs.ServerAd{
		URL: url.URL{
			Host: "fake-topology-ad.org:8443",
		},
		AuthURL: url.URL{
			Host: "fake-topology-ad.org:8444",
		},
		FromTopology: true,
	}
	adFromPelican := server_structs.ServerAd{
		URL: url.URL{
			Host: "fake-pelican-ad.org:8443",
		},
		AuthURL: url.URL{
			Host: "fake-pelican-ad.org:8444",
		},
		FromTopology: false,
	}
	adWithTopoNotSet := server_structs.ServerAd{
		URL: url.URL{
			Host: "fake-ad.org:8443",
		},
		AuthURL: url.URL{
			Host: "fake-ad.org:8444",
		},
		FromTopology: false,
	}

	t.Run("get-redirect-url-topology", func(t *testing.T) {
		// Public object from topology
		url := getRedirectURL("/some/path", adFromTopo, false)
		assert.Equal(t, "http://fake-topology-ad.org:8443/some/path", url.String())

		// Protected object from topology
		url = getRedirectURL("/some/path", adFromTopo, true)
		assert.Equal(t, "https://fake-topology-ad.org:8444/some/path", url.String())
	})
	t.Run("get-redirect-url-pelican", func(t *testing.T) {
		// Public object from pelican
		url := getRedirectURL("/some/path", adFromPelican, false)
		assert.Equal(t, "https://fake-pelican-ad.org:8443/some/path", url.String())

		// Protected object from pelican
		url = getRedirectURL("/some/path", adFromPelican, true)
		assert.Equal(t, "https://fake-pelican-ad.org:8444/some/path", url.String())
	})
	t.Run("get-redirect-url-topo-not-set", func(t *testing.T) {
		// When the FromTopology field is not set, we assume the ad is from Pelican
		url := getRedirectURL("/some/path", adWithTopoNotSet, false)
		assert.Equal(t, "https://fake-ad.org:8443/some/path", url.String())

		url = getRedirectURL("/some/path", adWithTopoNotSet, true)
		assert.Equal(t, "https://fake-ad.org:8444/some/path", url.String())
	})
}

func TestGetFinalRedirectURL(t *testing.T) {
	t.Run("url-without-params", func(t *testing.T) {
		base := url.URL{Scheme: "https", Host: "example.org:8444"}
		query := url.Values{"key1": []string{"val1"}}
		get := getFinalRedirectURL(base, query)
		assert.Equal(t, "https://example.org:8444?key1=val1", get)
	})

	t.Run("url-without-params-and-no-passed-params", func(t *testing.T) {
		base := url.URL{Scheme: "https", Host: "example.org:8444"}
		query := url.Values{}
		get := getFinalRedirectURL(base, query)
		assert.Equal(t, "https://example.org:8444", get)
	})

	t.Run("url-with-params-and-no-passed-params", func(t *testing.T) {
		base := url.URL{Scheme: "https", Host: "example.org:8444", RawQuery: "key1=val1&key2=val2"}
		query := url.Values{}
		get := getFinalRedirectURL(base, query)
		assert.Equal(t, "https://example.org:8444?key1=val1&key2=val2", get)
	})

	t.Run("url-with-params-and-with-params", func(t *testing.T) {
		base := url.URL{Scheme: "https", Host: "example.org:8444", RawQuery: "key1=val1&key2=val2"}
		query := url.Values{"pkey1": []string{"pval1"}, "pkey2": []string{"pval2"}}
		get := getFinalRedirectURL(base, query)
		assert.Equal(t, "https://example.org:8444?key1=val1&key2=val2&pkey1=pval1&pkey2=pval2", get)
	})

	t.Run("escape-passed-param", func(t *testing.T) {
		rawVal := "https://origin.org:8444/api/v1.0?query=value"
		encodedVal := url.QueryEscape(rawVal)
		base := url.URL{Scheme: "https", Host: "example.org:8444", RawQuery: "key1=val1&key2=val2"}
		query := url.Values{"raw": []string{rawVal}}
		get := getFinalRedirectURL(base, query)
		assert.Equal(t, "https://example.org:8444?key1=val1&key2=val2&raw="+encodedVal, get)
	})
}

func TestExtractProjectFromUserAgent(t *testing.T) {
	t.Run("Single User-Agent with project prefix", func(t *testing.T) {
		userAgents := []string{"pelican-client/1.0.0 project/test"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "test", result)
	})
	t.Run("Singlue User-Agent with swapped order", func(t *testing.T) {
		userAgents := []string{"project/test pelican-client/1.0.0"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "test", result)
	})

	t.Run("Single User-Agent with additional segments", func(t *testing.T) {
		userAgents := []string{"pelican-client/blah project/myproject foo/bar"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "myproject", result)
	})

	t.Run("Multiple User-Agents with project prefix", func(t *testing.T) {
		userAgents := []string{"pelican-client/1.0.0 project/test", "pelican-client/1.0.0 project/test2"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "test", result)
	})

	t.Run("Multiple User-Agents with swapped order", func(t *testing.T) {
		userAgents := []string{"project/test pelican-client/1.0.0", "project/test2 pelican-client/1.0.0"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "test", result)
	})

	t.Run("No Project Prefix", func(t *testing.T) {
		userAgents := []string{"pelican-client/1.0.0"}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "", result)
	})

	t.Run("No User-Agent", func(t *testing.T) {
		userAgents := []string{}
		result := utils.ExtractProjectFromUserAgent(userAgents)
		assert.Equal(t, "", result)
	})
}
