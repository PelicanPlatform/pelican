/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package issuer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

// TestRegistrationRateLimiter tests the token-bucket rate limiter directly.
func TestRegistrationRateLimiter(t *testing.T) {
	t.Run("BurstAllowed", func(t *testing.T) {
		rl := newRegistrationRateLimiter(1.0, 3) // 1/s, burst 3

		// First 3 requests should be allowed
		assert.True(t, rl.Allow("1.2.3.4"), "1st request should be allowed")
		assert.True(t, rl.Allow("1.2.3.4"), "2nd request should be allowed")
		assert.True(t, rl.Allow("1.2.3.4"), "3rd request should be allowed")
		// 4th should be denied
		assert.False(t, rl.Allow("1.2.3.4"), "4th request should be denied (burst exhausted)")
	})

	t.Run("DifferentIPsIndependent", func(t *testing.T) {
		rl := newRegistrationRateLimiter(1.0, 1) // 1/s, burst 1

		assert.True(t, rl.Allow("1.2.3.4"), "first IP should be allowed")
		assert.False(t, rl.Allow("1.2.3.4"), "first IP exhausted")
		assert.True(t, rl.Allow("5.6.7.8"), "second IP should be independent")
	})

	t.Run("RefillOverTime", func(t *testing.T) {
		// Rate = 1000/s so tokens refill almost instantly in test
		rl := newRegistrationRateLimiter(1000.0, 1)

		assert.True(t, rl.Allow("1.2.3.4"), "initial request allowed")
		assert.False(t, rl.Allow("1.2.3.4"), "burst exhausted")

		// After a tiny sleep, tokens should have refilled
		time.Sleep(5 * time.Millisecond)
		assert.True(t, rl.Allow("1.2.3.4"), "should be allowed after refill")
	})

	t.Run("Cleanup", func(t *testing.T) {
		rl := newRegistrationRateLimiter(1.0, 3)
		rl.Allow("old-ip")
		rl.Allow("new-ip")

		// Manually age the old entry
		rl.mu.Lock()
		rl.buckets["old-ip"].lastSeen = time.Now().Add(-2 * time.Hour)
		rl.mu.Unlock()

		rl.Cleanup(1 * time.Hour)

		rl.mu.Lock()
		_, hasOld := rl.buckets["old-ip"]
		_, hasNew := rl.buckets["new-ip"]
		rl.mu.Unlock()

		assert.False(t, hasOld, "old-ip should have been cleaned up")
		assert.True(t, hasNew, "new-ip should still exist")
	})
}

// TestDCRRateLimitIntegration tests that the HTTP endpoint returns 429 when the
// rate limit is exceeded.
func TestDCRRateLimitIntegration(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Override the limiter with a tight burst of 2
	provider.RegistrationLimiter = newRegistrationRateLimiter(0, 2)

	regBody := `{"redirect_uris": [], "client_name": "rate-test"}`

	// First 2 should succeed
	for i := 0; i < 2; i++ {
		resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
			"application/json", strings.NewReader(regBody))
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "registration %d should succeed", i+1)
		resp.Body.Close()
	}

	// 3rd should be rate-limited
	resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"3rd registration should be rate-limited")

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	assert.Contains(t, string(body), "rate_limit_exceeded")
}

// TestDCRGrantTypeRestriction tests that dynamically registered clients only
// receive device_code + refresh_token grant types.
func TestDCRGrantTypeRestriction(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Register a client — intentionally request authorization_code
	regBody := `{
		"redirect_uris": [],
		"grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
		"client_name": "grant-test"
	}`

	resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))

	grantTypes, ok := result["grant_types"].([]interface{})
	require.True(t, ok, "grant_types should be an array")

	// Should only contain device_code and refresh_token, NOT authorization_code
	var gtStrings []string
	for _, gt := range grantTypes {
		gtStrings = append(gtStrings, gt.(string))
	}
	assert.Contains(t, gtStrings, "urn:ietf:params:oauth:grant-type:device_code",
		"should include device_code grant")
	assert.Contains(t, gtStrings, "refresh_token",
		"should include refresh_token grant")
	assert.NotContains(t, gtStrings, "authorization_code",
		"should NOT include authorization_code for dynamically registered clients")
}

// TestDCRDynamicallyRegisteredFlag tests that CreateDynamicClient sets the flag.
func TestDCRDynamicallyRegisteredFlag(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()
	ctx := context.Background()

	// The static test client should NOT be dynamically registered
	isDynStatic, err := provider.Storage().IsDynamicallyRegistered(ctx, testClientID)
	require.NoError(t, err)
	assert.False(t, isDynStatic, "static client should not be dynamically registered")

	// Register a dynamic client via the API
	regBody := `{"redirect_uris": [], "client_name": "dynamic-flag-test"}`
	resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))
	dynamicClientID := result["client_id"].(string)

	// The dynamically registered client should be marked as such
	isDynDynamic, err := provider.Storage().IsDynamicallyRegistered(ctx, dynamicClientID)
	require.NoError(t, err)
	assert.True(t, isDynDynamic, "DCR client should be marked as dynamically registered")
}

// TestSingleUserClientBinding tests that a dynamically registered client can
// only be used by one user.
func TestSingleUserClientBinding(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Register a dynamic client
	regBody := `{"redirect_uris": [], "client_name": "binding-test"}`
	resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var regResult map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &regResult))
	dynamicClientID := regResult["client_id"].(string)
	dynamicSecret := regResult["client_secret"].(string)

	// Step 1: Initiate device code flow
	deviceResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization",
		map[string][]string{
			"client_id":     {dynamicClientID},
			"client_secret": {dynamicSecret},
			"scope":         {"openid offline_access storage.read:/data/analysis"},
		})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deviceResp.StatusCode)

	deviceBody, _ := io.ReadAll(deviceResp.Body)
	deviceResp.Body.Close()
	var deviceResult map[string]interface{}
	require.NoError(t, json.Unmarshal(deviceBody, &deviceResult))
	userCode := deviceResult["user_code"].(string)

	// Step 2: testuser approves the device code (this should bind the client)
	approveResp := approveDeviceCode(t, httpClient, ts.URL, userCode)
	assert.Equal(t, http.StatusOK, approveResp.StatusCode)
	approveResp.Body.Close()

	// Step 3: Verify the client is bound to testuser
	ctx := context.Background()
	boundUser, err := provider.Storage().GetBoundUser(ctx, dynamicClientID)
	require.NoError(t, err)
	assert.Equal(t, testUser, boundUser, "client should be bound to the approving user")

	// Step 4: A different user should not be able to approve a device code for
	// this client.  Set up a second device code.
	deviceResp2, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization",
		map[string][]string{
			"client_id":     {dynamicClientID},
			"client_secret": {dynamicSecret},
			"scope":         {"openid"},
		})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, deviceResp2.StatusCode)
	deviceBody2, _ := io.ReadAll(deviceResp2.Body)
	deviceResp2.Body.Close()
	var deviceResult2 map[string]interface{}
	require.NoError(t, json.Unmarshal(deviceBody2, &deviceResult2))
	userCode2 := deviceResult2["user_code"].(string)

	// Build a separate test server that injects a *different* user
	ts2 := setupTestServerWithUser("otheruser", "otheruser", []string{"/collab/analysis"}, provider)
	defer ts2.Close()
	httpClient2 := newTestClientWithJar(t, ts2)

	approveResp2 := approveDeviceCode(t, httpClient2, ts2.URL, userCode2)
	// Should still return 200 (HTML page) but the page should indicate an error
	approveBody2, _ := io.ReadAll(approveResp2.Body)
	approveResp2.Body.Close()
	assert.Contains(t, string(approveBody2), "different user",
		"should show error when different user tries to approve bound client's device code")
}

// TestUnusedDynamicClientCleanup tests that unused dynamically registered
// clients are cleaned up.
func TestUnusedDynamicClientCleanup(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()
	ctx := context.Background()

	// Register two dynamic clients
	var clientIDs []string
	for i := 0; i < 2; i++ {
		resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
			"application/json",
			bytes.NewReader([]byte(`{"redirect_uris": [], "client_name": "cleanup-test"}`)))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		clientIDs = append(clientIDs, result["client_id"].(string))
	}

	// "Use" the first client (touch last_used_at)
	require.NoError(t, provider.Storage().TouchClientLastUsed(ctx, clientIDs[0]))

	// Both should exist now
	_, err := provider.Storage().GetClient(ctx, clientIDs[0])
	require.NoError(t, err, "used client should exist")
	_, err = provider.Storage().GetClient(ctx, clientIDs[1])
	require.NoError(t, err, "unused client should exist")

	// Back-date the unused client's created_at so cleanup will catch it
	require.NoError(t, provider.storage.db.Exec(
		`UPDATE oidc_clients SET created_at = ? WHERE id = ?`,
		time.Now().Add(-2*time.Hour), clientIDs[1],
	).Error)

	// Run cleanup with 1-hour max age
	deleted, err := provider.Storage().DeleteUnusedDynamicClients(ctx, 1*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "should delete exactly 1 unused client")

	// Used client should still exist
	_, err = provider.Storage().GetClient(ctx, clientIDs[0])
	require.NoError(t, err, "used client should survive cleanup")

	// Unused client should be gone
	_, err = provider.Storage().GetClient(ctx, clientIDs[1])
	assert.Error(t, err, "unused client should have been deleted")

	// The static test client should survive too (not dynamically registered)
	_, err = provider.Storage().GetClient(ctx, testClientID)
	require.NoError(t, err, "static client should survive cleanup")
}

// TestStaleDynamicClientCleanup tests that dynamically registered clients that
// were previously used but have been idle for too long are cleaned up, while
// recently-used clients and static clients are left alone.
func TestStaleDynamicClientCleanup(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()
	ctx := context.Background()

	// Register three dynamic clients
	var clientIDs []string
	for i := 0; i < 3; i++ {
		resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/oidc-cm",
			"application/json",
			bytes.NewReader([]byte(`{"redirect_uris": [], "client_name": "stale-test"}`)))
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		clientIDs = append(clientIDs, result["client_id"].(string))
	}

	// Client 0: used recently (should survive)
	require.NoError(t, provider.Storage().TouchClientLastUsed(ctx, clientIDs[0]))

	// Client 1: used but stale -- back-date last_used_at
	require.NoError(t, provider.Storage().TouchClientLastUsed(ctx, clientIDs[1]))
	require.NoError(t, provider.storage.db.Exec(
		`UPDATE oidc_clients SET last_used_at = ? WHERE id = ?`,
		time.Now().Add(-15*24*time.Hour), clientIDs[1], // 15 days ago
	).Error)

	// Client 2: never used (should NOT be affected by stale cleanup)
	// (it would be caught by the unused cleanup instead)

	// Run stale cleanup with 2-week max age
	deleted, err := provider.Storage().DeleteStaleDynamicClients(ctx, 14*24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "should delete exactly 1 stale client")

	// Recently-used client should survive
	_, err = provider.Storage().GetClient(ctx, clientIDs[0])
	require.NoError(t, err, "recently-used client should survive stale cleanup")

	// Stale client should be gone
	_, err = provider.Storage().GetClient(ctx, clientIDs[1])
	assert.Error(t, err, "stale client should have been deleted")

	// Never-used client should survive (stale cleanup only targets used clients)
	_, err = provider.Storage().GetClient(ctx, clientIDs[2])
	require.NoError(t, err, "never-used client should survive stale cleanup")

	// Static test client survives
	_, err = provider.Storage().GetClient(ctx, testClientID)
	require.NoError(t, err, "static client should survive stale cleanup")
}

// setupTestServerWithUser creates an httptest.TLS Server with a Gin engine that
// injects the given user identity and registers all OIDC routes.
func setupTestServerWithUser(user, userID string, groups []string, provider *OIDCProvider) *httptest.Server {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("User", user)
		c.Set("UserId", userID)
		c.Set("Groups", groups)
		c.Next()
	})
	RegisterRoutesWithMiddleware(engine, provider)
	return httptest.NewTLSServer(engine)
}

// T3: Verify CSRF protection on device verification form
func TestDeviceVerifyCSRF(t *testing.T) {
	provider, ts := setupIntegration(t)

	// Register a device code to have a valid user_code
	httpClient := ts.Client()
	form := map[string][]string{
		"client_id":     {testClientID},
		"client_secret": {testSecret},
		"scope":         {"openid"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var deviceResp map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &deviceResp))
	userCode := deviceResp["user_code"].(string)

	_ = provider // provider used for setup

	t.Run("MissingCSRFToken", func(t *testing.T) {
		// POST directly without ever doing a GET (no CSRF cookie)
		client := ts.Client()
		approveForm := strings.NewReader("user_code=" + userCode + "&action=approve")
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/device", approveForm)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"POST without CSRF cookie should be rejected")
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Contains(t, string(respBody), "CSRF")
	})

	t.Run("WrongCSRFToken", func(t *testing.T) {
		// GET the page to get a valid CSRF cookie, then POST with wrong form value
		client := newTestClientWithJar(t, ts)
		getResp, err := client.Get(ts.URL + "/api/v1.0/issuer/device?user_code=" + userCode)
		require.NoError(t, err)
		getResp.Body.Close()

		// POST with deliberately wrong csrf_token form field
		wrongForm := strings.NewReader("user_code=" + userCode + "&action=approve&csrf_token=wrong-token")
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/device", wrongForm)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"POST with wrong CSRF token should be rejected")
		resp.Body.Close()
	})

	t.Run("CorrectCSRFToken", func(t *testing.T) {
		// Normal flow via approveDeviceCode helper should succeed.
		// Need a fresh device code since we may have consumed the first one.
		resp2, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization", form)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp2.StatusCode)
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		var deviceResp2 map[string]interface{}
		require.NoError(t, json.Unmarshal(body2, &deviceResp2))
		userCode2 := deviceResp2["user_code"].(string)

		client := newTestClientWithJar(t, ts)
		approveResp := approveDeviceCode(t, client, ts.URL, userCode2)
		assert.Equal(t, http.StatusOK, approveResp.StatusCode,
			"POST with correct CSRF token should succeed")
		approveResp.Body.Close()
	})
}

// T17: Verify DCR rejects redirect_uris not in the allowed list
func TestDCRRedirectURIValidation(t *testing.T) {
	provider, ts := setupIntegration(t)
	_ = provider
	httpClient := ts.Client()

	// Configure an explicit allowed redirect_uris list
	require.NoError(t, param.Set("Issuer.RedirectUris", []string{
		"https://allowed.example.com/callback",
		"https://also-allowed.example.com/callback",
	}))

	t.Run("DisallowedURI", func(t *testing.T) {
		regBody := `{
			"redirect_uris": ["https://evil.example.com/steal-tokens"],
			"client_name": "evil-client"
		}`
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/oidc-cm",
			bytes.NewReader([]byte(regBody)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"disallowed redirect_uri should be rejected, body: %s", string(body))

		var errResult map[string]interface{}
		if json.Unmarshal(body, &errResult) == nil {
			assert.Equal(t, "invalid_redirect_uri", errResult["error"])
		}
	})

	t.Run("AllowedURI", func(t *testing.T) {
		regBody := `{
			"redirect_uris": ["https://allowed.example.com/callback"],
			"client_name": "good-client"
		}`
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/oidc-cm",
			bytes.NewReader([]byte(regBody)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode,
			"allowed redirect_uri should be accepted, body: %s", string(body))
	})

	t.Run("MixedAllowedDisallowed", func(t *testing.T) {
		regBody := `{
			"redirect_uris": [
				"https://allowed.example.com/callback",
				"https://evil.example.com/steal-tokens"
			],
			"client_name": "mixed-client"
		}`
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/oidc-cm",
			bytes.NewReader([]byte(regBody)))
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode,
			"request with any disallowed URI should be rejected, body: %s", string(body))
	})
}
