/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/common/route"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestPrometheusUnprotected(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")
	av1.Get("/query", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Prometheus response"))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	//Setup a private key
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	test_utils.MockFederationRoot(t, nil, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	require.NoError(t, param.Set(param.Monitoring_PromQLAuthorization.GetName(), false))

	// Set ExternalWebUrl so that IssuerCheck can pass
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://test-origin.org:8444"))

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	// Set the request to run through the promQueryEngineAuthHandler function
	r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/query", bytes.NewBuffer([]byte(`{}`)))
	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 200, w.Result().StatusCode)
	resultBytes, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err, "Error reading the response body")

	assert.NotEmpty(t, string(resultBytes), "Response is 200 but with an empty body. Potentially Prometheus handler is not called in promQueryEngineAuthHandler")
	assert.Contains(t, string(resultBytes), `Prometheus response`)
}

// Test the Prometheus query engine endpoint auth check with an server issuer token
// set in cookie
func TestPrometheusProtectionCookieAuth(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	// Setup a private key directory
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	test_utils.MockFederationRoot(t, nil, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	require.NoError(t, param.Set(param.Monitoring_PromQLAuthorization.GetName(), true))

	// Set ExternalWebUrl so that IssuerCheck can pass
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://test-origin.org:8444"))

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	issuerUrl := param.Server_ExternalWebUrl.GetString()
	promTokenCfg := token.NewWLCGToken()

	promTokenCfg.Lifetime = 10 * time.Minute
	promTokenCfg.Issuer = issuerUrl
	promTokenCfg.AddAudiences(issuerUrl)
	promTokenCfg.Subject = "sub"
	promTokenCfg.Claims = map[string]string{"scope": token_scopes.Monitoring_Query.String()}

	tok, err := promTokenCfg.CreateToken()
	assert.NoError(t, err, "failed to create prometheus token")

	// Set the request to run through the promQueryEngineAuthHandler function
	r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

	// Puts the token in cookie
	c.Request.AddCookie(&http.Cookie{Name: "login", Value: tok})

	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 404, w.Result().StatusCode, "Expected status code of 404 representing failure due to minimal server setup, not token check")
}

// Tests that the prometheus protections are behind the server issuer token and tests that the token is accessible from
// the header function. It signs a token with the issuer's jwks key and adds it to the header before attempting
// to access the prometheus metrics. It then attempts to access the metrics with a token with an invalid scope.
// It attempts to do so again with a token signed by a bad key. Both these are expected to fail.
func TestPrometheusProtectionOriginHeaderScope(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://test-origin.org:8444"))
	require.NoError(t, param.Set(param.Monitoring_PromQLAuthorization.GetName(), true))

	av1 := route.New().WithPrefix("/api/v1.0/prometheus")

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	keysDir := filepath.Join(tDir, "testKeys")

	//Setup a private key and a token
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), keysDir))

	// Setting the ConfigDir to t.TempDir() causes issues with this test on Windows because
	// the process tries to clean up the directory before the test is done with it.
	configDir, err := os.MkdirTemp("", "tmpDir")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.RemoveAll(configDir)
	})
	require.NoError(t, param.Set("ConfigDir", configDir))

	test_utils.MockFederationRoot(t, nil, nil)
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	issuerUrl := param.Server_ExternalWebUrl.GetString()

	// Shared function to create a token
	createToken := func(scope, aud string) string {
		tokenCfg := token.NewWLCGToken()
		tokenCfg.Lifetime = param.Monitoring_TokenExpiresIn.GetDuration()
		tokenCfg.Issuer = issuerUrl
		tokenCfg.AddAudiences(aud)
		tokenCfg.Subject = "sub"
		tokenCfg.Claims = map[string]string{"scope": scope}

		tok, err := tokenCfg.CreateToken()
		assert.NoError(t, err, "failed to create prometheus test token")

		return tok
	}

	t.Run("valid-token-in-header", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)
		c.Request = &http.Request{
			URL: &url.URL{},
		}

		token := createToken("monitoring.query", issuerUrl)

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

		// Create a new private key by re-initializing config to point at a new temp dir
		k2dir := filepath.Join(tDir, "whatever", "testDir2")
		require.NoError(t, param.Set("IssuerKeysDirectory", k2dir))
		err = config.InitServer(ctx, server_structs.OriginType)
		require.NoError(t, err)

		token := createToken("monitoring.query", issuerUrl)

		// Re-init the config again, this time pointing at the original key
		config.ResetIssuerPrivateKeys()
		require.NoError(t, param.Set("IssuerKeysDirectory", keysDir))
		err = config.InitServer(ctx, server_structs.OriginType)
		require.NoError(t, err)

		r.GET("/api/v1.0/prometheus/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/test", bytes.NewBuffer([]byte(`{}`)))

		c.Request.Header.Set("Authorization", "Bearer "+token)
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

		token := createToken("no.prometheus", issuerUrl)

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

// TestPrometheusRulesEndpoint tests that the Prometheus /rules endpoint returns empty results
// without panicking when using the stub implementation.
func TestPrometheusRulesEndpoint(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	// Create a mock Prometheus API v1 router with stub implementations
	av1 := route.New().WithPrefix("/api/v1.0/prometheus/api/v1")

	// Register handlers that use the stub implementations
	stubRules := stubRulesRetriever{}
	av1.Get("/rules", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulate what Prometheus API would do with the stub
		ruleGroups := stubRules.RuleGroups()
		response := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"groups": ruleGroups,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	})

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	test_utils.MockFederationRoot(t, nil, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	require.NoError(t, param.Set(param.Monitoring_PromQLAuthorization.GetName(), false))
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://test-origin.org:8444"))

	c.Request = &http.Request{
		URL: &url.URL{},
	}

	// Set the request to run through the promQueryEngineAuthHandler function
	r.GET("/api/v1.0/prometheus/api/v1/*any", promQueryEngineAuthHandler(av1))
	c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/api/v1/rules", nil)
	r.ServeHTTP(w, c.Request)

	assert.Equal(t, 200, w.Result().StatusCode, "Expected status code 200 for /rules endpoint")
	resultBytes, err := io.ReadAll(w.Result().Body)
	require.NoError(t, err, "Error reading the response body")

	assert.NotEmpty(t, string(resultBytes), "Response should not be empty")
	assert.Contains(t, string(resultBytes), "success", "Response should contain success status")
	assert.Contains(t, string(resultBytes), "groups", "Response should contain groups field")
	assert.Contains(t, string(resultBytes), "[]", "Response should contain empty array")
}

// TestPrometheusAlertsEndpoint tests that the Prometheus /alerts endpoint returns empty results
// without panicking when using the stub implementation.
func TestPrometheusAlertsEndpoint(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	server_utils.ResetTestState()

	// Create a mock Prometheus API v1 router with stub implementations
	av1 := route.New().WithPrefix("/api/v1.0/prometheus/api/v1")

	// Register handler that uses the stub implementation
	stubAlertmgr := stubAlertmanagerRetriever{}
	av1.Get("/alertmanagers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulate what Prometheus API would do with the stub
		activeAlertmanagers := stubAlertmgr.Alertmanagers()
		droppedAlertmanagers := stubAlertmgr.DroppedAlertmanagers()
		response := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"activeAlertmanagers":  activeAlertmanagers,
				"droppedAlertmanagers": droppedAlertmanagers,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	})

	// Test the alerts endpoint as well
	stubRules := stubRulesRetriever{}
	av1.Get("/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Simulate what Prometheus API would do with the stub
		alertingRules := stubRules.AlertingRules()
		response := map[string]interface{}{
			"status": "success",
			"data": map[string]interface{}{
				"alerts": alertingRules,
			},
		}
		err := json.NewEncoder(w).Encode(response)
		require.NoError(t, err)
	})

	// Create temp dir for the origin key file
	tDir := t.TempDir()
	kDir := filepath.Join(tDir, "testKeyDir")
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), kDir))
	require.NoError(t, param.Set("ConfigDir", t.TempDir()))

	test_utils.MockFederationRoot(t, nil, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	require.NoError(t, param.Set(param.Monitoring_PromQLAuthorization.GetName(), false))
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://test-origin.org:8444"))

	t.Run("alertmanagers-endpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		c.Request = &http.Request{
			URL: &url.URL{},
		}

		r.GET("/api/v1.0/prometheus/api/v1/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/api/v1/alertmanagers", nil)
		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code 200 for /alertmanagers endpoint")
		resultBytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err, "Error reading the response body")

		assert.NotEmpty(t, string(resultBytes), "Response should not be empty")
		assert.Contains(t, string(resultBytes), "success", "Response should contain success status")
		assert.Contains(t, string(resultBytes), "activeAlertmanagers", "Response should contain activeAlertmanagers field")
		assert.Contains(t, string(resultBytes), "droppedAlertmanagers", "Response should contain droppedAlertmanagers field")
		assert.Contains(t, string(resultBytes), "[]", "Response should contain empty arrays")
	})

	t.Run("alerts-endpoint", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, r := gin.CreateTestContext(w)

		c.Request = &http.Request{
			URL: &url.URL{},
		}

		r.GET("/api/v1.0/prometheus/api/v1/*any", promQueryEngineAuthHandler(av1))
		c.Request, _ = http.NewRequest(http.MethodGet, "/api/v1.0/prometheus/api/v1/alerts", nil)
		r.ServeHTTP(w, c.Request)

		assert.Equal(t, 200, w.Result().StatusCode, "Expected status code 200 for /alerts endpoint")
		resultBytes, err := io.ReadAll(w.Result().Body)
		require.NoError(t, err, "Error reading the response body")

		assert.NotEmpty(t, string(resultBytes), "Response should not be empty")
		assert.Contains(t, string(resultBytes), "success", "Response should contain success status")
		assert.Contains(t, string(resultBytes), "alerts", "Response should contain alerts field")
		assert.Contains(t, string(resultBytes), "[]", "Response should contain empty array")
	})
}
