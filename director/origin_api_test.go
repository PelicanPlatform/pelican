package director

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyAdvertiseToken(t *testing.T) {
	/*
	* Runs unit tests on the VerifyAdvertiseToken function
	 */

	viper.Reset()

	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "t-key")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	viper.Set("Federation.RegistryUrl", "https://get-your-tokens.org")
	viper.Set("Federation.DirectorURL", "https://director-url.org")

	config.InitConfig()
	err := config.InitServer([]config.ServerType{config.DirectorType}, config.DirectorType)
	require.NoError(t, err)

	kSet, err := config.GetIssuerPublicJWKS()
	ar := MockCache{
		GetFn: func(key string, keyset *jwk.Set) (jwk.Set, error) {
			if key != "https://get-your-tokens.org/api/v2.0/registry/metadata/test-namespace/.well-known/issuer.jwks" {
				t.Errorf("expecting: https://get-your-tokens.org/api/v2.0/registry/metadata/test-namespace/.well-known/issuer.jwks, got %q", key)
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
		namespaceKeys.Set("test-namespace", &ar, ttlcache.DefaultTTL)
	}()

	// A verified token with a the correct scope - should return no error
	tok, err := CreateAdvertiseToken("test-namespace")
	assert.NoError(t, err)
	ok, err := VerifyAdvertiseToken(tok, "test-namespace")
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

	ok, err = VerifyAdvertiseToken(string(signed), "test-namespace")
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

	ok, err = VerifyAdvertiseToken(string(signed), "test-namespace")
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

	ok, err = VerifyAdvertiseToken(string(signed), "test-namespace")
	assert.Equal(t, false, ok, "Should fail due to incorrect scope name")
	assert.NoError(t, err, "Incorrect scope name should not throw and error")
}

func TestCreateAdvertiseToken(t *testing.T) {
	/*
	* Runs unit tests on the CreateAdvertiseToken function
	 */

	viper.Reset()

	// Create a temp directory to store the private key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "t-key")

	// Generate a private key
	viper.Set("IssuerKey", kfile)
	config.InitConfig()
	err := config.InitServer([]config.ServerType{config.DirectorType}, config.DirectorType)
	require.NoError(t, err)

	// Test without a namsepace set and check to see if it returns the expected error
	tok, err := CreateAdvertiseToken("test-namespace")
	assert.Equal(t, "", tok)
	assert.Equal(t, "Namespace URL is not set", err.Error())
	viper.Set("Federation.RegistryUrl", "https://get-your-tokens.org")

	// Test without a DirectorURL set and check to see if it returns the expected error
	tok, err = CreateAdvertiseToken("test-namespace")
	assert.Equal(t, "", tok)
	assert.Equal(t, "Director URL is not known; cannot create advertise token", err.Error())
	viper.Set("Federation.DirectorURL", "https://director-url.org")

	// Test the CreateAdvertiseToken with good values and test that it returns a non-nil token value and no error
	tok, err = CreateAdvertiseToken("test-namespace")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "", tok)
}

func TestGetRegistryIssuerURL(t *testing.T) {
	/*
	* Runs unit tests on the GetRegistryIssuerURL function
	 */
	viper.Reset()

	// No namespace url has been set, so an error is expected
	url, err := GetRegistryIssuerURL("")
	assert.Equal(t, "", url)
	assert.Equal(t, "Namespace URL is not set", err.Error())

	// Test to make sure the path is as expected
	viper.Set("Federation.RegistryUrl", "test-path")
	url, err = GetRegistryIssuerURL("test-prefix")
	assert.Equal(t, nil, err)
	assert.Equal(t, "test-path/api/v2.0/registry/metadata/test-prefix/.well-known/issuer.jwks", url)

}

func TestNamespaceKeysCacheEviction(t *testing.T) {
	t.Run("evict-after-expire-time", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		var wg sync.WaitGroup
		ConfigTTLCache(shutdownCtx, &wg)
		wg.Add(1)
		defer func() {
			shutdownCancel()
			wg.Wait()
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
