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
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
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

	viper.Reset()

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

	setupRequest := func(c *gin.Context, r *gin.Engine, bodyByt []byte, token string, stype server_structs.ServerType) {
		r.POST("/", func(gctx *gin.Context) { registerServeAd(ctx, gctx, stype) })
		c.Request, _ = http.NewRequest(http.MethodPost, "/", bytes.NewBuffer(bodyByt))
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

		namaspaceADs := listNamespacesFromOrigins()
		// If the origin was successfully registered at director, we should be able to find it in director's originAds
		assert.True(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Coudln't find namespace in the director cache.")
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

		namaspaceADs := listNamespacesFromOrigins()
		// If the origin was successfully registered at director, we should be able to find it in director's originAds
		assert.True(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Coudln't find namespace in the director cache.")
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

		setupRequest(c, r, jsonad, token, server_structs.CacheType)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.NotNil(t, serverAds.Get("https://data-url.org"), "Cache fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Get("https://data-url.org").Value().WebURL.String(), "WebURL in serverAds does not match data in cache registration request")
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
		Type:      server_structs.OriginType,
		Latitude:  123.05,
		Longitude: 456.78,
	}

	mockTopoOriginServerAd := server_structs.ServerAd{
		Name: "test-topology-origin-server",
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-topology-origin.org:8443",
		},
		Type:      server_structs.OriginType,
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
		Type:      server_structs.CacheType,
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

	viper.Reset()
	// Direcor SD will only be used for director's Prometheus scraper to get available origins,
	// so the token issuer is issentially the director server itself
	// There's no need to rely on Federation.DirectorUrl as token issuer in this case
	viper.Set("Server.ExternalWebUrl", mockDirectorUrl)

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()
	err := config.InitServer(ctx, config.DirectorType)
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

func TestRedirects(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	router := gin.Default()
	router.GET("/api/v1.0/director/origin/*any", redirectToOrigin)

	// Check that the checkkHostnameRedirects uses the pre-configured hostnames to redirect
	// requests that come in at the default paths, but not if the request is made
	// specifically for an object or a cache via the API.
	t.Run("redirect-check-hostnames", func(t *testing.T) {
		// Note that we don't test here for the case when hostname redirects is turned off
		// because the checkHostnameRedirects function should be unreachable via ShortcutMiddleware
		// in that case, ie if we call this function and the incoming hostname matches, we should do
		// the redirect specified
		viper.Set("Director.OriginResponseHostnames", []string{"origin-hostname.com"})
		viper.Set("Director.CacheResponseHostnames", []string{"cache-hostname.com"})

		// base path with origin-redirect hostname, should redirect to origin
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/foo/bar", nil)
		c.Request = req
		checkHostnameRedirects(c, "origin-hostname.com")
		expectedPath := "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// base path with cache-redirect hostname, should redirect to cache
		req = httptest.NewRequest("GET", "/foo/bar", nil)
		c.Request = req
		checkHostnameRedirects(c, "cache-hostname.com")
		expectedPath = "/api/v1.0/director/object/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// API path that should ALWAYS redirect to an origin
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar", nil)
		c.Request = req
		// Tell it cache, but it shouldn't switch what it redirects to
		checkHostnameRedirects(c, "cache-hostname.com")
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// API path that should ALWAYS redirect to a cache
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar", nil)
		c.Request = req
		// Tell it origin, but it shouldn't switch what it redirects to
		checkHostnameRedirects(c, "origin-hostname.com")
		expectedPath = "/api/v1.0/director/object/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		viper.Reset()
	})

	t.Run("redirect-middleware", func(t *testing.T) {
		// First test that two API endpoints are functioning properly
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar", nil)
		c.Request = req

		// test both APIs when in cache mode
		ShortcutMiddleware("cache")(c)
		expectedPath := "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("cache")(c)
		expectedPath = "/api/v1.0/director/object/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// test both APIs when in origin mode
		req = httptest.NewRequest("GET", "/api/v1.0/director/origin/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("origin")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("origin")(c)
		expectedPath = "/api/v1.0/director/object/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// Test the base paths
		// test that we get an origin at the base path when in origin mode
		req = httptest.NewRequest("GET", "/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("origin")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// test that we get a cache at the base path when in cache mode
		req = httptest.NewRequest("GET", "/api/v1.0/director/object/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("cache")(c)
		expectedPath = "/api/v1.0/director/object/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// test a PUT request always goes to the origin endpoint
		req = httptest.NewRequest("PUT", "/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("cache")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// Test PROPFIND works for both base path and API path
		req = httptest.NewRequest("PROPFIND", "/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("origin")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		req = httptest.NewRequest("PROPFIND", "/api/v1.0/director/origin/foo/bar", nil)
		c.Request = req
		ShortcutMiddleware("origin")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// Host-aware tests
		// Test that we can turn on host-aware redirects and get one appropriate redirect from each
		// type of header (as we've already tested that hostname redirects function)

		// Host header
		viper.Set("Director.OriginResponseHostnames", []string{"origin-hostname.com"})
		viper.Set("Director.HostAwareRedirects", true)
		req = httptest.NewRequest("GET", "/foo/bar", nil)
		c.Request = req
		c.Request.Header.Set("Host", "origin-hostname.com")
		ShortcutMiddleware("cache")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		// X-Forwarded-Host header
		req = httptest.NewRequest("GET", "/foo/bar", nil)
		c.Request = req
		c.Request.Header.Set("X-Forwarded-Host", "origin-hostname.com")
		ShortcutMiddleware("cache")(c)
		expectedPath = "/api/v1.0/director/origin/foo/bar"
		assert.Equal(t, expectedPath, c.Request.URL.Path)

		viper.Reset()
	})

	t.Run("cache-test-file-redirect", func(t *testing.T) {
		viper.Set("Server.ExternalWebUrl", "https://example.com")
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/origin/pelican/monitoring/test.txt", nil)
		req.Header.Add("User-Agent", "pelican-v7.6.1")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusTemporaryRedirect, w.Code)
		assert.NotEmpty(t, w.Header().Get("Location"))
		assert.Equal(t, "https://example.com/api/v1.0/director/healthTest/pelican/monitoring/test.txt", w.Header().Get("Location"))
	})

	t.Run("redirect-link-header-length", func(t *testing.T) {
		ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
		defer func() { require.NoError(t, egrp.Wait()) }()
		defer cancel()

		viper.Reset()
		serverAds.DeleteAll()
		t.Cleanup(func() {
			viper.Reset()
			serverAds.DeleteAll()
		})

		// Use ads generated via mock topology for generating list of caches
		topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
		defer topoServer.Close()
		viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)
		viper.Set("Director.CacheSortMethod", "random")
		// Populate ads for redirectToCache to use
		err := AdvertiseOSDF(ctx)
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "/my/server", nil)
		// Provide a few things so that redirectToCache doesn't choke
		req.Header.Add("User-Agent", "pelican-v7.999.999")
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
		req.Header.Add("User-Agent", "pelican-v7.999.999")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		c.Request = req

		redirectToCache(c)
		assert.Contains(t, c.Writer.Header().Get("Link"), "pri=1")
		assert.NotContains(t, c.Writer.Header().Get("Link"), "pri=2")
	})

	// Make sure collections-url is correctly populated when the ns/origin comes from topology
	t.Run("collections-url-from-topology", func(t *testing.T) {
		viper.Reset()
		serverAds.DeleteAll()
		t.Cleanup(func() {
			viper.Reset()
			serverAds.DeleteAll()
		})

		topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
		defer topoServer.Close()
		viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)
		viper.Set("Director.CacheSortMethod", "random")
		err := AdvertiseOSDF(ctx)
		require.NoError(t, err)

		// This one should have a collections url because it has a dirlisthost
		req, _ := http.NewRequest("GET", "/my/server", nil)
		req.Header.Add("User-Agent", "pelican-v7.999.999")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = req
		redirectToCache(c)
		assert.Contains(t, c.Writer.Header().Get("X-Pelican-Namespace"), "collections-url=https://origin1-auth-endpoint.com")

		// This one has no dirlisthost
		req, _ = http.NewRequest("GET", "/my/server/2", nil)
		req.Header.Add("User-Agent", "pelican-v7.999.999")
		req.Header.Add("X-Real-Ip", "128.104.153.60")
		c.Request = req
		redirectToCache(c)
		assert.NotContains(t, c.Writer.Header().Get("X-Pelican-Namespace"), "collections-url")
	})
}

func TestGetHealthTestFile(t *testing.T) {
	router := gin.Default()
	router.GET("/api/v1.0/director/healthTest/*path", getHealthTestFile)

	t.Run("400-on-empty-path", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/healthTest/", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("400-on-random-path", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/healthTest/foo/bar", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("400-on-dir", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/healthTest/pelican/monitoring", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("400-on-missing-file-ext", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/healthTest/pelican/monitoring/testfile", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("200-on-correct-request-file", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/director/healthTest/pelican/monitoring/testfile.txt", nil)
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		bytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err)
		assert.Equal(t, server_utils.DirectorTestBody+"\n", string(bytes))
	})
}

func TestHandleFilterServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
	})
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

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-dne"])
	})
	t.Run("filter-server-w-permFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-pf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-pf"] = permFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-pf"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been fitlered")
	})
	t.Run("filter-server-w-tempFiltered", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/filter/mock-tf", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-tf"] = tempFiltered
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempFiltered, filteredServers["mock-tf"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't filter a server that already has been fitlered")
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

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, permFiltered, filteredServers["mock-ta"])
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

func TestHandleAllowServer(t *testing.T) {
	t.Cleanup(func() {
		filteredServersMutex.Lock()
		defer filteredServersMutex.Unlock()
		filteredServers = map[string]filterType{}
	})
	router := gin.Default()
	router.GET("/servers/allow/*name", handleAllowServer)

	t.Run("allow-server-that-dne", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-dne", nil)
		filteredServersMutex.Lock()
		delete(filteredServers, "mock-dne")
		filteredServersMutex.Unlock()
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

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-pf"])
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

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Empty(t, filteredServers["mock-tf"])
	})
	t.Run("allow-server-w-tempAllowed", func(t *testing.T) {
		// Create a request to the endpoint
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/servers/allow/mock-ta", nil)
		filteredServersMutex.Lock()
		filteredServers["mock-ta"] = tempAllowed
		filteredServersMutex.Unlock()
		router.ServeHTTP(w, req)

		// Check the response
		require.Equal(t, 400, w.Code)

		filteredServersMutex.RLock()
		defer filteredServersMutex.RUnlock()
		assert.Equal(t, tempAllowed, filteredServers["mock-ta"])

		resB, err := io.ReadAll(w.Body)
		require.NoError(t, err)
		assert.Contains(t, string(resB), "Can't allow server mock-ta that is not being filtered")
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
