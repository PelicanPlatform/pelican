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
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
)

// For these tests, we only need to lookup key locations. Create a dummy registry that only
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

	// A verified token with a the correct scope - should return no error
	tok, err := CreateAdvertiseToken("/test-namespace")
	assert.NoError(t, err)
	ok, err := VerifyAdvertiseToken(ctx, tok, "/test-namespace")
	assert.NoError(t, err)
	assert.Equal(t, true, ok, "Expected scope to be 'pelican.advertise'")

	//Create token without a scope - should return an error
	key, err := config.GetIssuerPrivateJWK()
	err = jwk.AssignKeyID(key)
	assert.NoError(t, err)

	scopelessTok, err := jwt.NewBuilder().
		Issuer("").
		Audience([]string{"director.test"}).
		Subject("origin").
		Build()

	signed, err := jwt.Sign(scopelessTok, jwt.WithKey(jwa.ES256, key))

	ok, err = VerifyAdvertiseToken(ctx, string(signed), "/test-namespace")
	assert.Equal(t, false, ok)
	assert.Equal(t, "No scope is present; required to advertise to director", err.Error())

	//Create a token without a string valued scope
	nonStrScopeTok, err := jwt.NewBuilder().
		Issuer("").
		Claim("scope", 22).
		Audience([]string{"director.test"}).
		Subject("origin").
		Build()

	signed, err = jwt.Sign(nonStrScopeTok, jwt.WithKey(jwa.ES256, key))

	ok, err = VerifyAdvertiseToken(ctx, string(signed), "/test-namespace")
	assert.Equal(t, false, ok)
	assert.Equal(t, "scope claim in token is not string-valued", err.Error())

	//Create a token without a pelican.namespace scope
	wrongScopeTok, err := jwt.NewBuilder().
		Issuer("").
		Claim("scope", "wrong.scope").
		Audience([]string{"director.test"}).
		Subject("origin").
		Build()

	signed, err = jwt.Sign(wrongScopeTok, jwt.WithKey(jwa.ES256, key))

	ok, err = VerifyAdvertiseToken(ctx, string(signed), "/test-namespace")
	assert.Equal(t, false, ok, "Should fail due to incorrect scope name")
	assert.NoError(t, err, "Incorrect scope name should not throw and error")
}

func TestCreateAdvertiseToken(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	// Create a temp directory to store the private key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "t-key")

	// Generate a private key
	viper.Set("IssuerKey", kfile)
	config.InitConfig()
	err := config.InitServer(ctx, config.DirectorType)
	require.NoError(t, err)

	// Launcher will set default values to some of the server urls. Reset here.
	viper.Set("Federation.RegistryUrl", "")
	viper.Set("Federation.DirectorURL", "")

	registry := registryMockup(t, "/test-namespace")
	defer registry.Close()

	// Test without a registry URL set and check to see if it returns the expected error
	tok, err := CreateAdvertiseToken("/test-namespace")
	assert.Equal(t, "", tok)
	assert.Equal(t, "federation registry URL is not set and was not discovered", err.Error())
	viper.Set("Federation.RegistryUrl", registry.URL)

	// Test without a DirectorURL set and check to see if it returns the expected error
	tok, err = CreateAdvertiseToken("/test-namespace")
	assert.Equal(t, "", tok)
	assert.Equal(t, "Director URL is not known; cannot create advertise token", err.Error())
	viper.Set("Federation.DirectorURL", "https://director-url.org")

	// Test the CreateAdvertiseToken with good values and test that it returns a non-nil token value and no error
	tok, err = CreateAdvertiseToken("/test-namespace")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "", tok)
}

func TestGetNSIssuerURL(t *testing.T) {
	viper.Reset()

	emptyRegistry := registryMockup(t, "")
	defer emptyRegistry.Close()

	viper.Set("Federation.RegistryUrl", emptyRegistry.URL)
	// No namespace url has been set, so an error is expected
	url, err := GetNSIssuerURL("")
	assert.Equal(t, "the prefix \"\" is invalid", err.Error())
	assert.Equal(t, "", url)

	// Test to make sure the path is as expected
	registry := registryMockup(t, "/test-prefix")
	defer registry.Close()
	viper.Set("Federation.RegistryUrl", registry.URL)
	url, err = GetNSIssuerURL("/test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, "https://registry.com:8446/api/v1.0/registry/test-prefix/.well-known/issuer.jwks", url)
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
