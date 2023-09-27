package web_ui

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/prometheus/common/route"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestPrometheusProtection(t *testing.T) {

	/*
	* Tests that prometheus metrics are behind the origin's token. Specifically it signs a token
	* with the origin's keyand invokes a prometheus GET endpoint with both URL and Header authorization,
	* it then does so again with an invalid token and confirms that the correct error is returned
	 */

	// Setup httptest recorder and context for the the unit test
	viper.Reset()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method, "Not GET Method")
		_, err := w.Write([]byte(":)"))
		assert.NoError(t, err)
	}))
	defer ts.Close()
	c.Request = &http.Request{
		URL: &url.URL{},
	}

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	viper.Set("NamespaceURL", "https://get-your-tokens.org")
	viper.Set("DirectorURL", "https://director-url.org")

	// Generate the origin private and public keys
	_, err := config.LoadPublicKey("", kfile)

	if err != nil {
		t.Fatal(err)
	}

	privKey, err := config.LoadPrivateKey(kfile)
	if err != nil {
		t.Fatal(err)
	}

	// Create a token
	issuerURL := url.URL{}
	issuerURL.Scheme = "https"
	issuerURL.Host = "test-host"
	now := time.Now()
	tok, err := jwt.NewBuilder().
		Issuer(issuerURL.String()).
		IssuedAt(now).
		Expiration(now.Add(30 * time.Minute)).
		NotBefore(now).
		Build()

	if err != nil {
		t.Fatal(err)
	}

	// Sign the token with the origin private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES512, privKey))

	if err != nil {
		t.Fatal(err)
	}

	// Set the request to run through the checkPromToken function
	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Puts the token within the URL
	new_query := c.Request.URL.Query()
	new_query.Add("authz", string(signed))
	c.Request.URL.RawQuery = new_query.Encode()

	r.ServeHTTP(w, c.Request)

	// Check to see that the code exits with status code 404 after giving it a good token
	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")

	// Create a new Recorder and Context for the next HTTPtest call
	wH := httptest.NewRecorder()
	cH, rH := gin.CreateTestContext(wH)
	tsH := httptest.NewServer(http.HandlerFunc(func(wH http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method, "Not GET Method")
		_, err := wH.Write([]byte(":)"))
		assert.NoError(t, err)
	}))
	defer tsH.Close()

	// Set the request to go through the checkPromToken function
	rH.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	cH.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Put the signed token within the header
	cH.Request.Header.Set("Authorization", "Bearer "+string(signed))
	cH.Request.Header.Set("Content-Type", "application/json")

	rH.ServeHTTP(wH, cH.Request)
	// Check to see that the code exits with status code 404 after given it a good token
	assert.Equal(t, 404, wH.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")

	// Create a new Recorder and Context for testing an invalid token
	wI := httptest.NewRecorder()
	cI, rI := gin.CreateTestContext(wI)
	tsI := httptest.NewServer(http.HandlerFunc(func(wI http.ResponseWriter, req *http.Request) {
		assert.Equal(t, "GET", req.Method, "Not GET Method")
		_, err := wI.Write([]byte(":)"))
		assert.NoError(t, err)
	}))
	defer tsI.Close()
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

	// Create a new token to be used
	tok, err = jwt.NewBuilder().
		Issuer(issuerURL.String()).
		IssuedAt(now).
		Expiration(now.Add(30 * time.Minute)).
		NotBefore(now).
		Build()

	assert.NoError(t, err, "Error creating token")

	// Sign token with private key (not the origin)
	signed, err = jwt.Sign(tok, jwt.WithKey(jwa.ES512, pKey))
	assert.NoError(t, err, "Error signing token")

	rI.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	cI.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	cI.Request.Header.Set("Authorization", "Bearer "+string(signed))
	cI.Request.Header.Set("Content-Type", "application/json")

	rI.ServeHTTP(wI, cI.Request)
	// Assert that it gets the correct Permission Denied 403 code
	assert.Equal(t, 403, wI.Result().StatusCode, "Expected failing status code of 403: Permission Denied")
}
