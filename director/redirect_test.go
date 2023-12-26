package director

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
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
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type MockCache struct {
	GetFn      func(u string, kset *jwk.Set) (jwk.Set, error)
	RegisterFn func(*MockCache) error

	keyset jwk.Set
}

func (m *MockCache) Get(ctx context.Context, u string) (jwk.Set, error) {
	return m.GetFn(u, &m.keyset)
}

func (m *MockCache) Register(u string, options ...jwk.RegisterOption) error {
	m.keyset = jwk.NewSet()
	return m.RegisterFn(m)
}

func NamespaceAdContainsPath(ns []NamespaceAd, path string) bool {
	for _, v := range ns {
		if v.Path == path {
			return true
		}
	}
	return false
}

func TestDirectorRegistration(t *testing.T) {
	/*
	* Tests the RegisterOrigin endpoint. Specifically it creates a keypair and
	* corresponding token and invokes the registration endpoint, it then does
	* so again with an invalid token and confirms that the correct error is returned
	 */

	viper.Reset()

	viper.Set("Federation.NamespaceURL", "https://get-your-tokens.org")

	setupContext := func() (*gin.Context, *gin.Engine, *httptest.ResponseRecorder) {
		// Setup httptest recorder and context for the the unit test
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			assert.Equal(t, "POST", req.Method, "Not POST Method")
			_, err := w.Write([]byte(":)"))
			assert.NoError(t, err)
		}))
		defer ts.Close()

		c.Request = &http.Request{
			URL: &url.URL{},
		}
		return c, r, w
	}

	generateToken := func(c *gin.Context) (jwk.Key, string, url.URL) {
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
			Path:   "get-your-tokens.org/namespaces/foo/bar",
			Host:   c.Request.URL.Host,
		}

		// Create a token to be inserted
		tok, err := jwt.NewBuilder().
			Issuer(issuerURL.String()).
			Claim("scope", "pelican.advertise").
			Audience([]string{"director.test"}).
			Subject("origin").
			Build()
		assert.NoError(t, err, "Error creating token")

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, pKey))
		assert.NoError(t, err, "Error signing token")

		return pKey, string(signed), issuerURL
	}

	setupRequest := func(c *gin.Context, r *gin.Engine, bodyByt []byte, token string) {
		r.POST("/", RegisterOrigin)
		c.Request, _ = http.NewRequest(http.MethodPost, "/", bytes.NewBuffer(bodyByt))
		c.Request.Header.Set("Authorization", "Bearer "+token)
		c.Request.Header.Set("Content-Type", "application/json")
		// Hard code the current min version. When this test starts failing because of new stuff in the Director,
		// we'll know that means it's time to update the min version in redirect.go
		c.Request.Header.Set("User-Agent", "pelican-origin/7.0.0")
	}

	// Inject into the cache, using a mock cache to avoid dealing with
	// real namespaces
	setupMockCache := func(t *testing.T, publicKey jwk.Key) MockCache {
		return MockCache{
			GetFn: func(key string, keyset *jwk.Set) (jwk.Set, error) {
				if key != "https://get-your-tokens.org/api/v2.0/registry/metadata/foo/bar/.well-known/issuer.jwks" {
					t.Errorf("expecting: https://get-your-tokens.org/api/v2.0/registry/metadata/foo/bar/.well-known/issuer.jwks, got %q", key)
				}
				return *keyset, nil
			},
			RegisterFn: func(m *MockCache) error {
				err := jwk.Set.AddKey(m.keyset, publicKey)
				if err != nil {
					t.Error(err)
				}
				return nil
			},
		}
	}

	// Perform injections (ar.Register will create a jwk.keyset with the publickey in it)
	useMockCache := func(ar MockCache, issuerURL url.URL) {
		if err := ar.Register(issuerURL.String(), jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
			t.Errorf("this should never happen, should actually be impossible, including check for the linter")
		}
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		namespaceKeys.Set("/foo/bar", &ar, ttlcache.DefaultTTL)
	}

	teardown := func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
		serverAds.DeleteAll()
	}

	t.Run("valid-token", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, issuerURL := generateToken(c)
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")

		ar := setupMockCache(t, publicKey)
		useMockCache(ar, issuerURL)

		isurl := url.URL{}
		isurl.Path = "https://get-your-tokens.org"

		ad := OriginAdvertise{Name: "test", URL: "https://or-url.org", Namespaces: []NamespaceAd{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token)

		r.ServeHTTP(w, c.Request)

		// Check to see that the code exits with status code 200 after given it a good token
		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

		namaspaceADs := ListNamespacesFromOrigins()
		// If the origin was successfully registed at director, we should be able to find it in director's originAds
		assert.True(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Coudln't find namespace in the director cache.")
		teardown()
	})

	// Now repeat the above test, but with an invalid token
	t.Run("invalid-token", func(t *testing.T) {
		c, r, w := setupContext()
		wrongPrivateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		assert.NoError(t, err, "Error creating another private key")
		_, token, issuerURL := generateToken(c)

		wrongPublicKey, err := jwk.PublicKeyOf(wrongPrivateKey)
		assert.NoError(t, err, "Error creating public key from private key")
		ar := setupMockCache(t, wrongPublicKey)
		useMockCache(ar, issuerURL)

		isurl := url.URL{}
		isurl.Path = "https://get-your-tokens.org"

		ad := OriginAdvertise{Name: "test", URL: "https://or-url.org", Namespaces: []NamespaceAd{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, http.StatusForbidden, w.Result().StatusCode, "Expected failing status code of 403")
		body, _ := io.ReadAll(w.Result().Body)
		assert.Equal(t, `{"error":"Authorization token verification failed"}`, string(body), "Failure wasn't because token verification failed")

		namaspaceADs := ListNamespacesFromOrigins()
		assert.False(t, NamespaceAdContainsPath(namaspaceADs, "/foo/bar"), "Found namespace in the director cache even if the token validation failed.")
		teardown()
	})

	t.Run("valid-token-with-web-url", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, issuerURL := generateToken(c)
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		ar := setupMockCache(t, publicKey)
		useMockCache(ar, issuerURL)

		isurl := url.URL{}
		isurl.Path = "https://get-your-tokens.org"

		ad := OriginAdvertise{WebURL: "https://localhost:8844", Namespaces: []NamespaceAd{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.Equal(t, 1, len(serverAds.Keys()), "Origin fail to register at serverAds")
		assert.Equal(t, "https://localhost:8844", serverAds.Keys()[0].WebURL.String(), "WebURL in serverAds does not match data in origin registration request")
		teardown()
	})

	// We want to ensure backwards compatibility for WebURL
	t.Run("valid-token-without-web-url", func(t *testing.T) {
		c, r, w := setupContext()
		pKey, token, issuerURL := generateToken(c)
		publicKey, err := jwk.PublicKeyOf(pKey)
		assert.NoError(t, err, "Error creating public key from private key")
		ar := setupMockCache(t, publicKey)
		useMockCache(ar, issuerURL)

		isurl := url.URL{}
		isurl.Path = "https://get-your-tokens.org"

		ad := OriginAdvertise{Namespaces: []NamespaceAd{{Path: "/foo/bar", Issuer: isurl}}}

		jsonad, err := json.Marshal(ad)
		assert.NoError(t, err, "Error marshalling OriginAdvertise")

		setupRequest(c, r, jsonad, token)

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")
		assert.Equal(t, 1, len(serverAds.Keys()), "Origin fail to register at serverAds")
		assert.Equal(t, "", serverAds.Keys()[0].WebURL.String(), "WebURL in serverAds isn't empty with no WebURL provided in registration")
		teardown()
	})
}

func TestGetAuthzEscaped(t *testing.T) {
	// Test passing a token via header with no bearer prefix
	req, err := http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "tokenstring")
	escapedToken := getAuthzEscaped(req)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing a token via query with no bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getAuthzEscaped(req)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing the token via header with Bearer prefix
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	req.Header.Set("Authorization", "Bearer tokenstring")
	escapedToken = getAuthzEscaped(req)
	assert.Equal(t, escapedToken, "tokenstring")

	// Test passing the token via URL with Bearer prefix and + encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer+tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getAuthzEscaped(req)
	assert.Equal(t, escapedToken, "tokenstring")

	// Finally, the same test as before, but test with %20 encoded space
	req, err = http.NewRequest(http.MethodPost, "http://fake-server.com/foo?authz=Bearer%20tokenstring", bytes.NewBuffer([]byte("a body")))
	assert.NoError(t, err)
	escapedToken = getAuthzEscaped(req)
	assert.Equal(t, escapedToken, "tokenstring")
}

func TestDiscoverOriginCache(t *testing.T) {
	mockPelicanOriginServerAd := ServerAd{
		Name:    "1-test-origin-server",
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8444",
		},
		Type:      OriginType,
		Latitude:  123.05,
		Longitude: 456.78,
	}

	mockTopoOriginServerAd := ServerAd{
		Name:    "test-topology-origin-server",
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-topology-origin.org:8443",
		},
		Type:      OriginType,
		Latitude:  123.05,
		Longitude: 456.78,
	}

	mockCacheServerAd := ServerAd{
		Name:    "2-test-cache-server",
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-cache.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-cache.org:8444",
		},
		Type:      CacheType,
		Latitude:  45.67,
		Longitude: 123.05,
	}

	mockNamespaceAd := NamespaceAd{
		RequireToken:  true,
		Path:          "/foo/bar/",
		Issuer:        url.URL{},
		MaxScopeDepth: 1,
		Strategy:      "",
		BasePath:      "",
		VaultServer:   "",
	}

	mockDirectorUrl := "https://fake-director.org:8888"
	viper.Reset()
	// Direcor SD will only be used for director's Prometheus scraper to get available origins,
	// so the token issuer is issentially the director server itself
	// There's no need to rely on Federation.DirectorUrl as token issuer in this case
	viper.Set("Server.ExternalWebUrl", mockDirectorUrl)

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	viper.Set("IssuerKey", kfile)

	// Generate a private key to use for the test
	_, err := config.GetIssuerPublicJWKS()
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
			Claim("scope", "pelican.directorSD").
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
	r.GET("/test", DiscoverOriginCache)

	t.Run("no-token-should-give-401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
		assert.Equal(t, `{"error":"Bearer token not present in the 'Authorization' header"}`, w.Body.String())
	})
	t.Run("token-present-with-wrong-issuer-should-give-401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			t.Fatalf("Could not make a GET request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+string(setupToken("https://wrong-issuer.org")))

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)
		assert.Equal(t, `{"error":"Authorization token verification failed: Token issuer is not a director\n"}`, w.Body.String())
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

		func() {
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()
			serverAds.Set(mockPelicanOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			// Server fetched from topology should not be present in SD response
			serverAds.Set(mockTopoOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			serverAds.Set(mockCacheServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
		}()

		expectedRes := []PromDiscoveryItem{{
			Targets: []string{mockCacheServerAd.WebURL.Hostname() + ":" + mockCacheServerAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(mockCacheServerAd.Type),
				"server_name":     mockCacheServerAd.Name,
				"server_auth_url": mockCacheServerAd.AuthURL.String(),
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
				"server_auth_url": mockPelicanOriginServerAd.AuthURL.String(),
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

		func() {
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()
			// Add multiple same serverAds
			serverAds.Set(mockPelicanOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			serverAds.Set(mockPelicanOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			serverAds.Set(mockPelicanOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			// Server fetched from topology should not be present in SD response
			serverAds.Set(mockTopoOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
		}()

		expectedRes := []PromDiscoveryItem{{
			Targets: []string{mockPelicanOriginServerAd.WebURL.Hostname() + ":" + mockPelicanOriginServerAd.WebURL.Port()},
			Labels: map[string]string{
				"server_type":     string(mockPelicanOriginServerAd.Type),
				"server_name":     mockPelicanOriginServerAd.Name,
				"server_auth_url": mockPelicanOriginServerAd.AuthURL.String(),
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
		assert.Equal(t, string(resStr), w.Body.String(), "Reponse doesn't match expected")
	})
}

func TestRedirects(t *testing.T) {
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
}
