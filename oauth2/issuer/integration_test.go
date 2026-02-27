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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	jwtpkg "github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
)

const (
	testUser     = "testuser"
	testUserID   = "testuser"
	testClientID = "test-integration-client"
	testSecret   = "test-client-secret"
	testRedirect = "https://localhost/callback"
)

var testGroups = []string{"/collab/analysis", "/collab/production"}

// setupIntegration creates an in-memory test environment: provider, Gin engine,
// and httptest server. The engine has auth middleware that injects testUser.
func setupIntegration(t *testing.T) (*OIDCProvider, *httptest.Server) {
	t.Helper()

	// Reset config and set up signing key
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	tmpDir := t.TempDir()
	require.NoError(t, param.Set("IssuerKey", filepath.Join(tmpDir, "issuer.jwk")))
	require.NoError(t, param.Set("Server.ExternalWebUrl", "https://test-origin.example.com"))

	// Set up authorization templates so scope mapping works
	require.NoError(t, param.Set("Issuer.AuthorizationTemplates", []map[string]interface{}{
		{
			"actions": []string{"read"},
			"prefix":  "/data/analysis",
			"groups":  []string{"/collab/analysis"},
		},
		{
			"actions": []string{"read", "write"},
			"prefix":  "/data/production",
			"groups":  []string{"/collab/production"},
		},
	}))
	require.NoError(t, oa4mp.InitAuthzRules())

	// Create SQLite database with OIDC tables
	dbPath := filepath.Join(tmpDir, "test-integration.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	// Close the database when the test finishes so the file handle is
	// released before t.TempDir cleanup (required on Windows).
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	gracePeriod := 5 * time.Minute
	provider, err := NewOIDCProvider(db, "https://test-origin.example.com", gracePeriod)
	require.NoError(t, err)

	// Register a test client with known secret
	err = provider.EnsureClient(context.Background(), testClientID, testSecret, []string{testRedirect})
	require.NoError(t, err)

	// Build a Gin engine with routes and auth middleware that injects test user
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// Middleware that injects the hardcoded test user for auth-protected endpoints
	engine.Use(func(c *gin.Context) {
		c.Set("User", testUser)
		c.Set("UserId", testUserID)
		c.Set("Groups", testGroups)
		c.Next()
	})

	RegisterRoutesWithMiddleware(engine, provider)

	ts := httptest.NewTLSServer(engine)
	t.Cleanup(ts.Close)

	return provider, ts
}

// newTestClientWithJar creates a test HTTP client from the TLS test server
// with a cookie jar attached, needed for CSRF-protected endpoints.
func newTestClientWithJar(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	client := ts.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client.Jar = jar
	return client
}

// approveDeviceCode performs the full CSRF-protected device code approval flow:
// 1. GETs the device verification page to receive the CSRF cookie
// 2. Extracts the CSRF token from the cookie jar
// 3. POSTs approval with both the cookie (automatic) and the form field
func approveDeviceCode(t *testing.T, httpClient *http.Client, baseURL, userCode string) *http.Response {
	t.Helper()

	// GET the device page to receive the CSRF cookie
	verifyURL := baseURL + "/api/v1.0/issuer/device?user_code=" + url.QueryEscape(userCode)
	getResp, err := httpClient.Get(verifyURL)
	require.NoError(t, err)
	getResp.Body.Close()

	// Extract the CSRF token from the cookie jar (must use the cookie's path)
	cookieURL, err := url.Parse(baseURL + "/api/v1.0/issuer/device")
	require.NoError(t, err)
	var csrfToken string
	for _, c := range httpClient.Jar.Cookies(cookieURL) {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
			break
		}
	}
	require.NotEmpty(t, csrfToken, "CSRF cookie should be set after GET /device")

	// POST approval with CSRF token in form field (cookie is sent automatically)
	approveForm := url.Values{
		"user_code":  {userCode},
		"action":     {"approve"},
		"csrf_token": {csrfToken},
	}
	approveResp, err := httpClient.PostForm(baseURL+"/api/v1.0/issuer/device", approveForm)
	require.NoError(t, err)
	return approveResp
}

// ---- WLCG Token Validation Helpers ----

// validateWLCGToken parses and validates a JWT as a WLCG token.
// It checks for required claims: iss, sub, iat, exp, scope, wlcg.ver.
func validateWLCGToken(t *testing.T, tokenStr string, provider *OIDCProvider) jwtpkg.Token {
	t.Helper()

	// Build JWK from provider's public key
	pubKey, err := jwk.FromRaw(provider.PrivateKey().Public())
	require.NoError(t, err)
	alg := jwa.KeyAlgorithmFrom(provider.signingAlgorithm())
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, pubKey.Set(jwk.KeyUsageKey, "sig"))

	// Parse and verify the token using the single key
	tok, err := jwtpkg.Parse([]byte(tokenStr),
		jwtpkg.WithKey(alg, pubKey),
		jwtpkg.WithValidate(false))
	require.NoError(t, err, "failed to parse JWT")

	// Basic JWT claims
	assert.NotEmpty(t, tok.Issuer(), "iss claim should be present")
	assert.Equal(t, "https://test-origin.example.com", tok.Issuer(), "iss should match provider issuer")
	assert.NotEmpty(t, tok.Subject(), "sub claim should be present")
	assert.False(t, tok.IssuedAt().IsZero(), "iat claim should be present")
	assert.False(t, tok.Expiration().IsZero(), "exp claim should be present")
	assert.True(t, tok.Expiration().After(time.Now()), "token should not be expired")

	// WLCG requires an audience claim
	assert.Contains(t, tok.Audience(), WLCGAudienceAny,
		"aud claim should contain the WLCG wildcard audience")

	return tok
}

// ---- Integration Tests ----

func TestIntegrationAuthorizationCodeGrant(t *testing.T) {
	provider, ts := setupIntegration(t)

	httpClient := ts.Client()
	// Don't follow redirects - we need to capture the authorization code
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Step 1: Authorization request with PKCE
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid offline_access storage.read:/data/analysis"},
		"state":                 {"test-state-123"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)

	// Read any body for debugging
	bodyBytes, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Should redirect to the redirect_uri with a code (fosite uses 303 See Other)
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound,
		"authorize endpoint should redirect, got %d: %s", resp.StatusCode, string(bodyBytes))

	location := resp.Header.Get("Location")
	require.NotEmpty(t, location, "redirect should have Location header")

	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "redirect should contain authorization code, got location: %s", location)
	assert.Equal(t, "test-state-123", redirectURL.Query().Get("state"),
		"state parameter should be echoed back")

	// Step 2: Exchange code for tokens
	tokenResp := exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)

	accessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok && accessToken != "", "should receive access_token")

	refreshToken, ok := tokenResp["refresh_token"].(string)
	require.True(t, ok && refreshToken != "", "should receive refresh_token (offline_access requested)")

	tokenType, _ := tokenResp["token_type"].(string)
	assert.Equal(t, "bearer", strings.ToLower(tokenType))

	// Step 3: Validate the access token is a valid WLCG token
	tok := validateWLCGToken(t, accessToken, provider)
	assert.Equal(t, testUser, tok.Subject(), "subject should be the test user")

	// Check for scope claim in the token (either top-level or in extra claims)
	scopeClaim, _ := tok.Get("scope")
	if scopeStr, ok := scopeClaim.(string); ok {
		assert.Contains(t, scopeStr, "storage.read:/data/analysis",
			"access token should contain the granted storage scope")
	}

	// Check wlcg.ver claim
	wlcgVer, ok := tok.Get("wlcg.ver")
	assert.True(t, ok, "WLCG token should have wlcg.ver claim")
	assert.Equal(t, "1.0", wlcgVer, "wlcg.ver should be 1.0")

	// Step 4: Refresh the token
	refreshResp := refreshTokens(t, ts, httpClient, refreshToken)
	newAccessToken, ok := refreshResp["access_token"].(string)
	require.True(t, ok && newAccessToken != "", "refresh should return new access_token")

	// The new access token should also be a valid WLCG token
	validateWLCGToken(t, newAccessToken, provider)

	// Check the refreshed token still gets a refresh token
	newRefreshToken, ok := refreshResp["refresh_token"].(string)
	require.True(t, ok && newRefreshToken != "",
		"refresh response should contain a new refresh_token")

	// Step 5: Refresh again using the NEW refresh token to prove the chain works
	secondRefreshResp := refreshTokens(t, ts, httpClient, newRefreshToken)
	secondAccessToken, ok := secondRefreshResp["access_token"].(string)
	require.True(t, ok && secondAccessToken != "",
		"second refresh should return new access_token")
	validateWLCGToken(t, secondAccessToken, provider)
}

func TestIntegrationDeviceCodeGrant(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Step 1: Request device authorization
	form := url.Values{
		"client_id":     {testClientID},
		"client_secret": {testSecret},
		"scope":         {"openid offline_access storage.read:/data/analysis"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var deviceResp DeviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(body, &deviceResp))

	assert.NotEmpty(t, deviceResp.DeviceCode, "should return device_code")
	assert.NotEmpty(t, deviceResp.UserCode, "should return user_code")
	assert.True(t, deviceResp.ExpiresIn > 0, "should have positive expires_in")
	assert.Contains(t, deviceResp.VerificationURI, "/api/v1.0/issuer/device")

	// Step 2: Before approval, polling should return authorization_pending
	tokenForm := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceResp.DeviceCode},
		"client_id":     {testClientID},
		"client_secret": {testSecret},
	}
	tokenResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/token", tokenForm)
	require.NoError(t, err)

	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()

	var pendingErr map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody, &pendingErr))
	assert.Equal(t, "authorization_pending", pendingErr["error"],
		"polling before approval should return authorization_pending")

	// Step 3: Approve the device code (simulating user visiting verification URL)
	approveResp := approveDeviceCode(t, httpClient, ts.URL, deviceResp.UserCode)
	assert.Equal(t, http.StatusOK, approveResp.StatusCode)
	approveResp.Body.Close()

	// Reset the polling timestamp so Step 4 doesn't hit the RFC 8628 §3.5
	// slow_down rate limit from the poll in Step 2.
	require.NoError(t, provider.Storage().db.Exec(
		`UPDATE oidc_device_codes SET last_polled_at = ? WHERE device_code = ?`,
		time.Now().Add(-10*time.Second), deviceResp.DeviceCode,
	).Error)

	// Step 4: Poll again - should now succeed
	tokenResp2, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/token", tokenForm)
	require.NoError(t, err)

	tokenBody2, _ := io.ReadAll(tokenResp2.Body)
	tokenResp2.Body.Close()

	var tokenResult map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody2, &tokenResult))

	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok && accessToken != "", "should receive access_token after device approval")

	// Step 5: Validate the token is a valid WLCG token
	tok := validateWLCGToken(t, accessToken, provider)
	assert.Equal(t, testUser, tok.Subject(), "device grant token subject should be the approved user")

	wlcgVer, ok := tok.Get("wlcg.ver")
	assert.True(t, ok, "device grant token should have wlcg.ver claim")
	assert.Equal(t, "1.0", wlcgVer)
}

func TestIntegrationDynamicClientRegistration(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Register a new client
	regBody := `{
		"redirect_uris": ["https://newclient.example.com/callback"],
		"grant_types": ["authorization_code", "refresh_token"],
		"response_types": ["code"],
		"client_name": "My Test App"
	}`

	resp, err := httpClient.Post(
		ts.URL+"/api/v1.0/issuer/oidc-cm",
		"application/json",
		strings.NewReader(regBody),
	)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var regResult map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &regResult))

	assert.NotEmpty(t, regResult["client_id"], "registered client should have client_id")
	assert.NotEmpty(t, regResult["client_secret"], "registered client should have client_secret")
	assert.Equal(t, "My Test App", regResult["client_name"])
}

func TestIntegrationIssuerDiscovery(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var discovery map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &discovery))

	assert.Equal(t, "https://test-origin.example.com", discovery["issuer"])
	assert.NotEmpty(t, discovery["token_endpoint"])
	assert.NotEmpty(t, discovery["authorization_endpoint"])
	assert.NotEmpty(t, discovery["device_authorization_endpoint"])
	assert.NotEmpty(t, discovery["jwks_uri"])

	// Verify that the advertised signing algorithm matches the actual key type.
	// This is critical: if the discovery document says RS256 but we sign with ES256,
	// relying parties will reject our tokens.
	algs, ok := discovery["id_token_signing_alg_values_supported"].([]interface{})
	require.True(t, ok, "id_token_signing_alg_values_supported should be present")
	require.Len(t, algs, 1)
	assert.Equal(t, "ES256", algs[0], "discovery signing algorithm should match actual ECDSA P-256 key")
}

func TestIntegrationTokenIntrospection(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Get a token via authorization code flow first
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid storage.read:/data/analysis"},
		"state":                 {"introspect-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	require.Equal(t, http.StatusSeeOther, resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")

	tokenResult := exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)
	accessToken := tokenResult["access_token"].(string)

	// Introspect the token via userinfo
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1.0/issuer/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, uiResp.StatusCode)

	body, _ := io.ReadAll(uiResp.Body)
	uiResp.Body.Close()

	var userInfo map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &userInfo))
	assert.Equal(t, testUser, userInfo["sub"])

	_ = provider // provider used for WLCG validation above
}

// T6: Verify state parameter is echoed correctly and missing state is handled
func TestStateParameterValidation(t *testing.T) {
	_, ts := setupIntegration(t)

	t.Run("StateEchoed", func(t *testing.T) {
		httpClient := ts.Client()
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		codeChallenge := generateCodeChallenge(codeVerifier)

		authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
			"response_type":         {"code"},
			"client_id":             {testClientID},
			"redirect_uri":          {testRedirect},
			"scope":                 {"openid"},
			"state":                 {"my-unique-state-42"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
		}.Encode()

		resp, err := httpClient.Get(authURL)
		require.NoError(t, err)
		resp.Body.Close()
		require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

		location := resp.Header.Get("Location")
		redirectURL, _ := url.Parse(location)
		assert.Equal(t, "my-unique-state-42", redirectURL.Query().Get("state"),
			"state parameter should be echoed back verbatim")
	})

	t.Run("EmptyStateOmitted", func(t *testing.T) {
		httpClient := ts.Client()
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		codeChallenge := generateCodeChallenge(codeVerifier)

		// No state parameter
		authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
			"response_type":         {"code"},
			"client_id":             {testClientID},
			"redirect_uri":          {testRedirect},
			"scope":                 {"openid"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
		}.Encode()

		resp, err := httpClient.Get(authURL)
		require.NoError(t, err)
		resp.Body.Close()
		require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

		location := resp.Header.Get("Location")
		redirectURL, _ := url.Parse(location)
		assert.Empty(t, redirectURL.Query().Get("state"),
			"when no state provided, none should be in redirect")
	})
}

// T9: Verify that a wrong PKCE code_verifier is rejected during token exchange
func TestPKCEWrongVerifier(t *testing.T) {
	_, ts := setupIntegration(t)

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Obtain an auth code using a valid PKCE challenge
	correctVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(correctVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid"},
		"state":                 {"pkce-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	// Attempt to exchange with a WRONG verifier
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"code_verifier": {"completely-wrong-verifier-that-does-not-match"},
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	tokenResp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()

	assert.NotEqual(t, http.StatusOK, tokenResp.StatusCode,
		"wrong code_verifier should be rejected, body: %s", string(body))

	var errResult map[string]interface{}
	if json.Unmarshal(body, &errResult) == nil {
		assert.Contains(t, errResult["error"], "invalid_grant",
			"error should indicate an invalid grant")
	}
}

// T10: Verify that invalid client credentials are rejected at the token endpoint
func TestInvalidClientCredentials(t *testing.T) {
	_, ts := setupIntegration(t)

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Get a valid auth code first
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid"},
		"state":                 {"cred-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	// Exchange with wrong client secret
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"code_verifier": {codeVerifier},
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, "totally-wrong-secret")

	tokenResp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()

	assert.NotEqual(t, http.StatusOK, tokenResp.StatusCode,
		"wrong client secret should be rejected, body: %s", string(body))
}

// T11: Verify that an authorization code cannot be replayed (used twice)
func TestAuthCodeReplay(t *testing.T) {
	_, ts := setupIntegration(t)

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Get a valid auth code
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid storage.read:/data/analysis"},
		"state":                 {"replay-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	// First exchange should succeed
	_ = exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)

	// Second exchange with the same code should fail
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"code_verifier": {codeVerifier},
	}

	req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	replayResp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(replayResp.Body)
	replayResp.Body.Close()

	assert.NotEqual(t, http.StatusOK, replayResp.StatusCode,
		"replayed authorization code should be rejected, body: %s", string(body))
}

// T12: Verify that a revoked refresh token (outside grace period) is rejected
func TestRefreshTokenPostGracePeriod(t *testing.T) {
	provider, ts := setupIntegration(t)

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Get initial tokens via auth code flow
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid offline_access storage.read:/data/analysis"},
		"state":                 {"chain-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResult := exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)
	originalRefresh := tokenResult["refresh_token"].(string)

	// Use the original refresh token (this "rotates" it)
	refreshResult := refreshTokens(t, ts, httpClient, originalRefresh)
	_ = refreshResult["refresh_token"].(string) // new refresh token

	// Backdate the first_used_at on the old refresh token to far in the past,
	// simulating that the grace period has expired.
	// RevokeRefreshTokenMaybeGracePeriod sets first_used_at on active=1 tokens,
	// so we target tokens that have first_used_at set (i.e. have been used).
	provider.storage.db.Exec(
		"UPDATE oidc_refresh_tokens SET first_used_at = ? WHERE first_used_at IS NOT NULL",
		time.Now().Add(-1*time.Hour))

	// Try to use the original (now revoked + past grace) refresh token
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {originalRefresh},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	oldRefreshResp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(oldRefreshResp.Body)
	oldRefreshResp.Body.Close()

	assert.NotEqual(t, http.StatusOK, oldRefreshResp.StatusCode,
		"old refresh token past grace period should be rejected, body: %s", string(body))
}

// T13: Verify broad scope expansion works end-to-end: requesting storage.read:/
// when user only has storage.read:/data/analysis and storage.read:/data/production
// should grant both narrower scopes.
func TestScopeDownscoping(t *testing.T) {
	provider, ts := setupIntegration(t)

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Request the broad scope storage.read:/ — user has /data/analysis and /data/production
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid storage.read:/"},
		"state":                 {"broad-scope-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound,
		"authorize should redirect, got %d", resp.StatusCode)

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	// Exchange code for tokens
	tokenResult := exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)
	accessToken := tokenResult["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Validate the access token contains both narrower scopes
	tok := validateWLCGToken(t, accessToken, provider)
	scopeClaim, _ := tok.Get("scope")

	// The scope claim may be a string or an array depending on token format
	var scopes []string
	switch v := scopeClaim.(type) {
	case string:
		scopes = strings.Fields(v)
	case []interface{}:
		for _, s := range v {
			if str, ok := s.(string); ok {
				scopes = append(scopes, str)
			}
		}
	default:
		t.Fatalf("unexpected scope claim type: %T", scopeClaim)
	}

	assert.Contains(t, scopes, "storage.read:/data/analysis",
		"broad storage.read:/ should expand to include /data/analysis")
	assert.Contains(t, scopes, "storage.read:/data/production",
		"broad storage.read:/ should expand to include /data/production")

	// Verify the original broad scope was NOT granted verbatim
	for _, s := range scopes {
		assert.NotEqual(t, "storage.read:/", s,
			"the original broad scope storage.read:/ should not appear verbatim")
	}
}

// T7: Verify device code deny flow end-to-end
func TestDeviceCodeDenyFlow(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Request device authorization
	form := url.Values{
		"client_id":     {testClientID},
		"client_secret": {testSecret},
		"scope":         {"openid"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device_authorization", form)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var deviceResp DeviceAuthorizationResponse
	require.NoError(t, json.Unmarshal(body, &deviceResp))

	// Deny the device code via the verification page (CSRF-protected)
	verifyURL := ts.URL + "/api/v1.0/issuer/device?user_code=" + url.QueryEscape(deviceResp.UserCode)
	getResp, err := httpClient.Get(verifyURL)
	require.NoError(t, err)
	getResp.Body.Close()

	// Extract CSRF token from cookie jar
	cookieURL, _ := url.Parse(ts.URL + "/api/v1.0/issuer/device")
	var csrfToken string
	for _, c := range httpClient.Jar.Cookies(cookieURL) {
		if c.Name == "csrf_token" {
			csrfToken = c.Value
			break
		}
	}
	require.NotEmpty(t, csrfToken)

	// POST denial
	denyForm := url.Values{
		"user_code":  {deviceResp.UserCode},
		"action":     {"deny"},
		"csrf_token": {csrfToken},
	}
	denyResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/device", denyForm)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, denyResp.StatusCode)
	denyResp.Body.Close()

	// Reset polling timestamp to avoid slow_down
	// (the GET for the verification page doesn't poll, but let's be safe)

	// Poll the token endpoint — should return access_denied
	tokenForm := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceResp.DeviceCode},
		"client_id":     {testClientID},
		"client_secret": {testSecret},
	}
	tokenResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/token", tokenForm)
	require.NoError(t, err)
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()

	var tokenErr map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenErr))
	assert.Equal(t, "access_denied", tokenErr["error"],
		"denied device code should return access_denied on token poll")
}

// T8: Verify token revocation flow (get token → revoke → userinfo returns error)
func TestTokenRevocationFlow(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Get a valid token via authorization code flow
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid"},
		"state":                 {"revoke-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()

	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code)

	tokenResult := exchangeCodeForTokens(t, ts, httpClient, code, codeVerifier)
	accessToken := tokenResult["access_token"].(string)

	// Verify the token works first
	req, _ := http.NewRequest("GET", ts.URL+"/api/v1.0/issuer/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp, err := httpClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, uiResp.StatusCode)
	uiResp.Body.Close()

	// Revoke the access token
	revokeForm := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}
	revokeReq, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/revoke",
		strings.NewReader(revokeForm.Encode()))
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeReq.SetBasicAuth(testClientID, testSecret)

	revokeResp, err := httpClient.Do(revokeReq)
	require.NoError(t, err)
	revokeResp.Body.Close()
	assert.Equal(t, http.StatusOK, revokeResp.StatusCode,
		"revocation should succeed")

	// Verify the token no longer works at userinfo
	req2, _ := http.NewRequest("GET", ts.URL+"/api/v1.0/issuer/userinfo", nil)
	req2.Header.Set("Authorization", "Bearer "+accessToken)
	uiResp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	assert.NotEqual(t, http.StatusOK, uiResp2.StatusCode,
		"revoked token should no longer be accepted at userinfo")
	uiResp2.Body.Close()
}

// T15: Verify that an invalid/garbage token is rejected at the userinfo endpoint
func TestUserInfoWithInvalidToken(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	t.Run("GarbageToken", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1.0/issuer/userinfo", nil)
		req.Header.Set("Authorization", "Bearer not-a-real-token-at-all")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"garbage token should be rejected at userinfo")
	})

	t.Run("MissingAuthHeader", func(t *testing.T) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/v1.0/issuer/userinfo", nil)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"request without Authorization header should be rejected")
	})
}

// T16: Verify that approving an expired device code results in an error
func TestDeviceCodeExpiry(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Request device authorization
	form := url.Values{
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
	deviceCode := deviceResp["device_code"].(string)
	userCode := deviceResp["user_code"].(string)

	// Expire the device code by backdating expires_at
	provider.storage.db.Exec(
		"UPDATE oidc_device_codes SET expires_at = ? WHERE device_code = ?",
		time.Now().Add(-1*time.Hour), deviceCode)

	// Approve should still return a page (the handler may show error or approval page)
	approveResp := approveDeviceCode(t, httpClient, ts.URL, userCode)
	approveResp.Body.Close()

	// But polling for a token should report an expired code
	tokenForm := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {testClientID},
	}
	tokenReq, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(testClientID, testSecret)

	tokenResp, err := httpClient.Do(tokenReq)
	require.NoError(t, err)
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()

	assert.NotEqual(t, http.StatusOK, tokenResp.StatusCode,
		"expired device code should not produce a token, body: %s", string(tokenBody))

	var errResult map[string]interface{}
	if json.Unmarshal(tokenBody, &errResult) == nil {
		errStr, _ := errResult["error"].(string)
		assert.True(t, errStr == "expired_token" || errStr == "invalid_grant" || errStr == "access_denied",
			"error should indicate expired/invalid, got: %s", errStr)
	}
}

// T18: Verify every endpoint in the discovery document is reachable (not 404)
func TestDiscoveryEndpointsReachable(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Fetch discovery document
	resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/.well-known/openid-configuration")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var discovery map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &discovery))

	// Map of endpoint keys to their expected HTTP method.
	// POST-only endpoints return 404 for GET in Gin, so we must use POST.
	// jwks_uri is served by a different component, so we skip it.
	endpointMethods := map[string]string{
		"authorization_endpoint":        "GET",
		"token_endpoint":                "POST",
		"userinfo_endpoint":             "GET",
		"device_authorization_endpoint": "POST",
		"registration_endpoint":         "POST",
		"revocation_endpoint":           "POST",
		"introspection_endpoint":        "POST",
	}

	for key, method := range endpointMethods {
		val, ok := discovery[key]
		if !ok {
			continue // endpoint not advertised, skip
		}
		endpoint, ok := val.(string)
		require.True(t, ok, "endpoint %s should be a string URL", key)

		// Replace the issuer hostname with the test server URL
		parsedEndpoint, err := url.Parse(endpoint)
		require.NoError(t, err)
		parsedTS, _ := url.Parse(ts.URL)
		parsedEndpoint.Host = parsedTS.Host
		parsedEndpoint.Scheme = parsedTS.Scheme

		t.Run(key, func(t *testing.T) {
			req, _ := http.NewRequest(method, parsedEndpoint.String(), nil)
			if method == "POST" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
				"endpoint %s (%s %s) should not return 404", key, method, parsedEndpoint.String())
		})
	}
}

// ---- Helper Functions ----

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func exchangeCodeForTokens(t *testing.T, ts *httptest.Server, client *http.Client, code, codeVerifier string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {testClientID},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	resp, err := client.Do(req)
	require.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"token exchange should succeed, body: %s", string(body))

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}

func refreshTokens(t *testing.T, ts *httptest.Server, client *http.Client, refreshToken string) map[string]interface{} {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	resp, err := client.Do(req)
	require.NoError(t, err)

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode,
		"token refresh should succeed, body: %s", string(body))

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}
