/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
package web_ui

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/prometheus/common/route"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestPrometheusProtectionFederationURL(t *testing.T) {

	/*
	* Tests that prometheus metrics are behind federation's token. Specifically it signs a token
	* with the a generated key o prometheus GET endpoint with both URL. It mimics matching the Federation URL
	* to ensure that check is done, but intercepts with returning a generated jwk for testing purposes
	 */

	// Setup httptest recorder and context for the the unit test
	viper.Reset()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)
	// Note, this handler function intercepts the "http.Get call to the federation uri
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		issuerKeyFile := param.IssuerKey.GetString()
		contents, err := os.ReadFile(issuerKeyFile)
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Write(contents)
		if err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()
	c.Request = &http.Request{
		URL: &url.URL{},
	}

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

	buf, err := json.MarshalIndent(pKey, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(kfile, buf, 0644)

	if err != nil {
		t.Fatal(err)
	}

	// Create a token
	issuerURL := url.URL{}
	issuerURL.Scheme = "https"
	issuerURL.Host = "test-http"

	jti_bytes := make([]byte, 16)
	_, err = rand.Read(jti_bytes)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	originUrl := param.Origin_Url.GetString()
	tok, err := jwt.NewBuilder().
		Claim("scope", "prometheus.read").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerURL.String()).
		Audience([]string{originUrl}).
		Subject("sub").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Fatal(err)
	}

	// Sign the token with the origin private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, pKey))

	if err != nil {
		t.Fatal(err)
	}

	//Set the Federation information so as not to run through all of DiscoverFederation (that should be a tested elsewhere)
	viper.Set("Federation.DiscoveryUrl", "https://test-http")
	viper.Set("Federation.DirectorUrl", "https://test-director")
	viper.Set("Federation.NamespaceUrl", "https://test-namesapce")
	viper.Set("Federation.JwkUrl", ts.URL)

	// Set the request to run through the checkPromToken function
	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Puts the token within the URL
	new_query := c.Request.URL.Query()
	new_query.Add("authz", string(signed))
	c.Request.URL.RawQuery = new_query.Encode()

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")
}

func TestPrometheusProtectionOriginHeaderScope(t *testing.T) {
	/*
	* Tests that the prometheus protections are behind the origin's token and tests that the token is accessable from
	* the header function. It signs a token with the origin's jwks key and adds it to the header before attempting
	* to access the prometheus metrics. It then attempts to access the metrics with a token with an invalid scope.
	* It attempts to do so again with a token signed by a bad key. Both these are expected to fail.
	 */

	viper.Reset()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	// Generate the origin private and public keys
	_, err := config.LoadPublicKey("", kfile)

	if err != nil {
		t.Fatal(err)
	}

	// Load the private key
	privKey, err := config.LoadPrivateKey(kfile)
	if err != nil {
		t.Fatal(err)
	}

	// Create a token
	issuerURL := url.URL{}
	issuerURL.Scheme = "https"
	issuerURL.Host = "test-http"

	jti_bytes := make([]byte, 16)
	_, err = rand.Read(jti_bytes)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	originUrl := param.Origin_Url.GetString()
	tok, err := jwt.NewBuilder().
		Claim("scope", "prometheus.read").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerURL.String()).
		Audience([]string{originUrl}).
		Subject("sub").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Fatal(err)
	}

	// Sign the token with the origin private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	if err != nil {
		t.Fatal(err)
	}

	// Set the request to go through the checkPromToken function
	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Put the signed token within the header
	c.Request.Header.Set("Authorization", "Bearer "+string(signed))
	c.Request.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")

	// Create a new Recorder and Context for the next HTTPtest call
	w = httptest.NewRecorder()
	c, r = gin.CreateTestContext(w)

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
	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	assert.NoError(t, err, "Unable to set algorithm for pKey")

	jti_bytes = make([]byte, 16)
	_, err = rand.Read(jti_bytes)
	if err != nil {
		t.Fatal(err)
	}
	jti = base64.RawURLEncoding.EncodeToString(jti_bytes)

	// Create a new token to be used
	tok, err = jwt.NewBuilder().
		Claim("scope", "prometheus.read").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerURL.String()).
		Audience([]string{originUrl}).
		Subject("sub").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()

	assert.NoError(t, err, "Error creating token")

	// Sign token with private key (not the origin)
	signed, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256, pKey))
	assert.NoError(t, err, "Error signing token")

	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	c.Request.Header.Set("Authorization", "Bearer "+string(signed))
	c.Request.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, c.Request)
	// Assert that it gets the correct Permission Denied 403 code
	assert.Equal(t, 403, w.Result().StatusCode, "Expected failing status code of 403: Permission Denied")

	// Create a new Recorder and Context for the next HTTPtest call
	w = httptest.NewRecorder()
	c, r = gin.CreateTestContext(w)

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	// Create a new token to be used
	tok, err = jwt.NewBuilder().
		Claim("scope", "not.prometheus").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerURL.String()).
		Audience([]string{originUrl}).
		Subject("sub").
		Expiration(time.Now().Add(time.Minute)).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Fatal(err)
	}

	// Sign the token with the origin private key
	signed, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256, privKey))
	if err != nil {
		t.Fatal(err)
	}

	// Set the request to go through the checkPromToken function
	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Put the signed token within the header
	c.Request.Header.Set("Authorization", "Bearer "+string(signed))
	c.Request.Header.Set("Content-Type", "application/json")

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 403, w.Result().StatusCode, "Expected status code of 403 due to bad token scope")

	key, err := config.GetOriginJWK()
	if err != nil {
		t.Fatal(err)
	}

	// Create a new Recorder and Context for the next HTTPtest call
	w = httptest.NewRecorder()
	c, r = gin.CreateTestContext(w)

	now := time.Now()
	tok, err = jwt.NewBuilder().
		Issuer(issuerURL.String()).
		Claim("scope", "prometheus.read").
		Claim("wlcg.ver", "1.0").
		IssuedAt(now).
		Expiration(now.Add(30 * time.Minute)).
		NotBefore(now).
		Subject("user").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	var raw ecdsa.PrivateKey
	if err = (*key).Raw(&raw); err != nil {
		t.Fatal(err)
	}
	signed, err = jwt.Sign(tok, jwt.WithKey(jwa.ES256, raw))
	if err != nil {
		t.Fatal(err)
	}

	// Set the request to go through the checkPromToken function
	r.GET("/api/v1.0/prometheus/*any", checkPromToken(av1))

	http.SetCookie(w, &http.Cookie{Name: "login", Value: string(signed)})
	if err != nil {
		t.Fatal(err)
	}

	//&http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}}

	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))
	c.Request.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")
}
