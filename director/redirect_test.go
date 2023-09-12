package director

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jellydator/ttlcache/v3"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

type MockCache struct {
	GetFn      func(u string, kset *jwk.Set) (jwk.Set, error)
	RegisterFn func(kset *jwk.Set) error

	keyset jwk.Set
}

func (m *MockCache) Get(ctx context.Context, u string) (jwk.Set, error) {
	return m.GetFn(u, &m.keyset)
}

func (m *MockCache) Register(u string, options ...jwk.RegisterOption) error {
	m.keyset = jwk.NewSet()
	return m.RegisterFn(&m.keyset)
}

func TestDirectorRegistration(t *testing.T) {
	/*
	* Tests the RegisterOrigin endpoint. Specifically it creates a keypair and
	* corresponding token and invokes the registration endpoint, it then does
	* so again with an invalid token and confirms that the correct error is returned
	 */

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
	err = pKey.Set(jwk.AlgorithmKey, jwa.ES512)
	assert.NoError(t, err, "Unable to set algorithm for pKey")

	// Create a public key from the private key
	publicKey, err := jwk.PublicKeyOf(pKey)
	assert.NoError(t, err, "Error creating public key from private key")

	// Create a token to be inserted
	issuerURL := url.URL{}
	issuerURL.Scheme = "https"
	issuerURL.Path = "get-your-tokens.org/namespaces/foo/bar"
	issuerURL.Host = c.Request.URL.Host

	tok, err := jwt.NewBuilder().
		Issuer(issuerURL.String()).
		Claim("scope", "pelican.advertise").
		Audience([]string{"director.test"}).
		Subject("origin").
		Build()

	assert.NoError(t, err, "Error creating token")

	// Sign token with previously created private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, pKey))
	assert.NoError(t, err, "Error signing token")

	// Inject into the cache, using a mock cache to avoid dealing with
	// real namespaces
	ar := MockCache{
		GetFn: func(key string, keyset *jwk.Set) (jwk.Set, error) {
			if key != "https://get-your-tokens.org/api/v1.0/registry/foo/bar/.well-known/issuer.jwks" {
				t.Errorf("expecting: https://get-your-tokens.org/api/v1.0/registry/foo/bar/.well-known/issuer.jwks, got %q", key)
			}
			return *keyset, nil
		},
		RegisterFn: func(keyset *jwk.Set) error {
			err := jwk.Set.AddKey(*keyset, publicKey)
			if err != nil {
				t.Error(err)
			}
			return nil
		},
	}

	// Perform injections (ar.Register will create a jwk.keyset with the publickey in it)
	func() {
		ar.Register(issuerURL.String(), jwk.WithMinRefreshInterval(15*time.Minute))
		namespaceKeysMutex.Lock()
		defer namespaceKeysMutex.Unlock()
		namespaceKeys.Set("/foo/bar", &ar, ttlcache.DefaultTTL)
	}()

	// Set the namespaceurl
	viper.Set("NamespaceURL", "https://get-your-tokens.org")

	// Create the  request and set the headers
	r.POST("/", RegisterOrigin)
	c.Request, _ = http.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{"Namespaces": [{"Path": "/foo/bar", "URL": "https://get-your-tokens.org"}]}`)))

	c.Request.Header.Set("Authorization", string(signed))
	c.Request.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, c.Request)

	// Check to see that the code exits with status code 200 after given it a good token
	assert.Equal(t, 200, w.Result().StatusCode, "Expected status code of 200")

	// Now repeat the above test, but with an invalid token
	// Setup httptest recorder and context for the the unit test
	wInv := httptest.NewRecorder()
	cInv, rInv := gin.CreateTestContext(wInv)
	tsInv := httptest.NewServer(http.HandlerFunc(func(wInv http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "POST", req.Method, "Not POST Method")
		_, err := wInv.Write([]byte(":)"))
		assert.NoError(t, err)
	}))
	defer tsInv.Close()
	cInv.Request = &http.Request{
		URL: &url.URL{},
	}

	// Create a private key to use for the test
	privateKeyInv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(t, err, "Error generating private key")

	// Convert from raw ecdsa to jwk.Key
	pKeyInv, err := jwk.FromRaw(privateKeyInv)
	assert.NoError(t, err, "Unable to convert ecdsa.PrivateKey to jwk.Key")

	//Assign Key id to the private key
	err = jwk.AssignKeyID(pKeyInv)
	assert.NoError(t, err, "Error assigning kid to private key")

	//Set an algorithm for the key
	err = pKeyInv.Set(jwk.AlgorithmKey, jwa.ES512)
	assert.NoError(t, err, "Unable to set algorithm for pKey")

	// Create a token to be inserted
	issuerURL.Host = cInv.Request.URL.Host

	// Sign token with previously created private key (mismatch to what's in the keyset)
	signedInv, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, pKeyInv))
	assert.NoError(t, err, "Error signing token")

	// Create the  request and set the headers
	rInv.POST("/", RegisterOrigin)
	cInv.Request, _ = http.NewRequest(http.MethodPost, "/", bytes.NewBuffer([]byte(`{"Namespaces": [{"Path": "/foo/bar", "URL": "https://get-your-tokens.org"}]}`)))

	cInv.Request.Header.Set("Authorization", string(signedInv))
	cInv.Request.Header.Set("Content-Type", "application/json")

	rInv.ServeHTTP(wInv, cInv.Request)
	assert.Equal(t, 400, wInv.Result().StatusCode, "Expected failing status code of 400")
	body, _ := io.ReadAll(wInv.Result().Body)
	assert.Equal(t, `{"error":"Authorization token verification failed"}`, string(body), "Failure wasn't because token verification failed")
}
