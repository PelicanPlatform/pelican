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
	"github.com/pelicanplatform/pelican/param"
	"github.com/prometheus/common/route"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test the Prometheus query engine endpoint auth check with an server issuer token
// set in cookie
func TestPrometheusProtectionCookieAuth(t *testing.T) {
	// Setup httptest recorder and context for the the unit test
	viper.Reset()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")
	//Setup a private key
	viper.Set("IssuerKey", kfile)
	config.InitConfig()
	err := config.InitServer(config.OriginType)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	// Set ExternalWebUrl so that IssuerCheck can pass
	viper.Set("Server.ExternalWebUrl", "https://test-origin.org:8444")

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	jti_bytes := make([]byte, 16)
	_, err = rand.Read(jti_bytes)
	if err != nil {
		t.Fatal(err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

	issuerUrl := param.Server_ExternalWebUrl.GetString()
	tok, err := jwt.NewBuilder().
		Claim("scope", "monitoring.query").
		Claim("wlcg.ver", "1.0").
		JwtID(jti).
		Issuer(issuerUrl).
		Audience([]string{issuerUrl}).
		Subject("sub").
		Expiration(time.Now().Add(10 * time.Minute)).
		IssuedAt(time.Now()).
		Build()

	if err != nil {
		t.Fatal(err)
	}

	pkey, err := config.GetIssuerPrivateJWK()
	if err != nil {
		t.Fatal(err)
	}

	// Sign the token with the origin private key
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, pkey))

	if err != nil {
		t.Fatal(err)
	}

	// Set the request to run through the promQueryEngineAuthHandler function
	r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Puts the token in cookie
	c.Request.AddCookie(&http.Cookie{Name: "login", Value: string(signed)})

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")
}

// Tests that the prometheus protections are behind the server issuer token and tests that the token is accessable from
// the header function. It signs a token with the issuer's jwks key and adds it to the header before attempting
// to access the prometheus metrics. It then attempts to access the metrics with a token with an invalid scope.
// It attempts to do so again with a token signed by a bad key. Both these are expected to fail.
func TestPrometheusProtectionOriginHeaderScope(t *testing.T) {
	viper.Reset()
	viper.Set("Server.ExternalWebUrl", "https://test-origin.org:8444")

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kfile := filepath.Join(tDir, "testKey")

	//Setup a private key and a token
	viper.Set("IssuerKey", kfile)

	config.InitConfig()
	err := config.InitServer(config.OriginType)
	require.NoError(t, err)

	issuerUrl := param.Server_ExternalWebUrl.GetString()

	// Shared function to create a token
	createToken := func(scope, aud string, key jwk.Key) string {
		jti_bytes := make([]byte, 16)
		if _, err := rand.Read(jti_bytes); err != nil {
			t.Fatal(err)
		}
		jti := base64.RawURLEncoding.EncodeToString(jti_bytes)

		tok, err := jwt.NewBuilder().
			Claim("scope", scope).
			Claim("wlcg.ver", "1.0").
			JwtID(jti).
			Issuer(issuerUrl).
			Audience([]string{aud}).
			Subject("sub").
			Expiration(time.Now().Add(10 * time.Minute)).
			IssuedAt(time.Now()).
			Build()
		if err != nil {
			t.Fatal(err)
		}

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, key))
		if err != nil {
			t.Fatal(err)
		}
		return string(signed)
	}

	t.Run("valid-token-in-header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		c.Request = &http.Request{
			URL: &url.URL{},
		}

		// Load the private key
		privKey, err := config.GetIssuerPrivateJWK()
		if err != nil {
			t.Fatal(err)
		}

		token := createToken("monitoring.query", issuerUrl, privKey)

		// Set the request to go through the promQueryEngineAuthHandler function
		r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

		// Put the signed token within the header
		c.Request.Header.Set("Authorization", "Bearer "+string(token))
		c.Request.Header.Set("Content-Type", "application/json")

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")

	})

	t.Run("invalid-token-sig-key", func(t *testing.T) {
		// Create a new Recorder and Context for the next HTTPtest call
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		c.Request = &http.Request{
			URL: &url.URL{},
		}

		// Create a private key to use for the test
		privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		assert.NoError(t, err, "Error generating private key")

		// Convert from raw ecdsa to jwk.Key
		pKey, err := jwk.FromRaw(privateKey)
		assert.NoError(t, err, "Unable to convert ecdsa.PrivateKey to jwk.Key")

		// Assign Key id to the private key
		err = jwk.AssignKeyID(pKey)
		assert.NoError(t, err, "Error assigning kid to private key")

		// Set an algorithm for the key
		err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
		assert.NoError(t, err, "Unable to set algorithm for pKey")

		token := createToken("monitoring.query", issuerUrl, pKey)

		r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

		c.Request.Header.Set("Authorization", "Bearer "+string(token))
		c.Request.Header.Set("Content-Type", "application/json")

		r.ServeHTTP(w, c.Request)
		// Assert that it gets the correct Permission Denied 403 code
		assert.Equal(t, 403, w.Result().StatusCode, "Expected failing status code of 403: Permission Denied")
	})

	t.Run("token-with-wrong-scope", func(t *testing.T) {
		// Create a new Recorder and Context for the next HTTPtest call
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		c.Request = &http.Request{
			URL: &url.URL{},
		}
		key, err := config.GetIssuerPrivateJWK()
		if err != nil {
			t.Fatal(err)
		}

		token := createToken("no.prometheus", issuerUrl, key)

		// Set the request to go through the promQueryEngineAuthHandler function
		r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

		// Put the signed token within the header
		c.Request.Header.Set("Authorization", "Bearer "+string(token))
		c.Request.Header.Set("Content-Type", "application/json")

		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 403, w.Result().StatusCode, "Expected status code of 403 due to bad token scope")
	})
}
