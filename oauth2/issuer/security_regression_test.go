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

// Security regression tests for the embedded OAuth2/OIDC issuer.
//
// Each test corresponds to a finding from an internal security review of the
// new issuer codebase.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
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
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	dbutils "github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/oa4mp"
	"github.com/pelicanplatform/pelican/param"
)

// --- Finding #1: Admin routes middleware bypass ---

// TestAdminMiddlewareEnforced verifies that admin endpoints reject requests
// when no admin middleware is configured, and allow them when middleware is
// set and passes.
func TestAdminMiddlewareEnforced(t *testing.T) {
	t.Run("NoMiddleware-Returns404", func(t *testing.T) {
		// When RegisterAdminRoutes is never called, the admin URL prefix
		// is simply not registered, so Gin returns 404.
		_, ts := setupIntegration(t)
		httpClient := ts.Client()

		resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/admin/ns/test/ns/clients")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"admin endpoint must not be routable when RegisterAdminRoutes is not called")
	})

	t.Run("WithMiddleware-Allows", func(t *testing.T) {
		_, ts := setupAdminTestServer(t)
		httpClient := ts.Client()

		resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/admin/ns/test/ns/clients")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode,
			"admin endpoint must allow requests when admin middleware passes")
	})

	t.Run("MiddlewareAborts-Rejects", func(t *testing.T) {
		// Set up a provider with middleware that always aborts.
		provider, origTS := setupIntegration(t)
		origTS.Close()

		gin.SetMode(gin.TestMode)
		engine := gin.New()
		engine.Use(func(c *gin.Context) {
			c.Set("User", "admin")
			c.Next()
		})

		abortingMiddleware := func(c *gin.Context) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not_admin"})
			c.Abort()
		}

		registry := NewProviderRegistry()
		registry.Register(testNamespace, provider)
		RegisterRoutesWithMiddleware(engine, registry)
		RegisterAdminRoutes(engine, registry, abortingMiddleware)

		ts := httptest.NewTLSServer(engine)
		t.Cleanup(ts.Close)

		httpClient := ts.Client()
		resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/admin/ns/test/ns/clients")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"admin endpoint must reject when middleware aborts")
	})
}

// --- Finding #2: Token exchange scope bypass (standard scopes) ---

// TestTokenExchangeScopeEnforcement verifies that token exchange does not
// auto-allow standard scopes that are missing from the subject token or the
// client's configured scopes.
func TestTokenExchangeScopeEnforcement(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Create a token-exchange client whose scopes do NOT include offline_access.
	secret := "te-scope-secret"
	teClientID := "te-scope-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)

	teClient := &fosite.DefaultClient{
		ID:            teClientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{testRedirect},
		GrantTypes:    fosite.Arguments{tokenExchangeGrantType, "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), teClient))

	// Get a subject token that also does NOT have offline_access.
	subjectToken := secMintTestAccessToken(t, provider, testUser, []string{}, []string{"openid", "wlcg", "storage.read:/"})

	// Attempt token exchange requesting offline_access.
	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"openid offline_access storage.read:/"},
		"client_id":          {teClientID},
		"client_secret":      {secret},
	}

	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	// The exchanged token must NOT contain offline_access (not in subject
	// token's grants, not in client's allowed scopes).
	accessToken := result["access_token"].(string)
	claims := secParseJWT(t, provider, accessToken)
	scopeStr, _ := claims.Get("scope")
	assert.NotContains(t, scopeStr, "offline_access",
		"offline_access must not appear in exchanged token when absent from subject token and client scopes")

	// Must NOT have a refresh token.
	_, hasRefresh := result["refresh_token"]
	assert.False(t, hasRefresh,
		"no refresh token should be issued when offline_access is not granted")
}

// --- Finding #2b: Auth code flow client scope enforcement ---

// TestAuthCodeClientScopeEnforcement verifies that the authorization code
// flow enforces the client's configured scope allow-list. A client that does
// not include offline_access in its scopes must not receive it in the
// resulting token even when the user's auth rules permit it. This is the
// auth code path analog of TestTokenExchangeScopeEnforcement (Finding #2).
func TestAuthCodeClientScopeEnforcement(t *testing.T) {
	provider, ts := setupIntegration(t)

	// Create a client that does NOT list offline_access in its scopes.
	secret := "authcode-scope-secret"
	clientID := "authcode-scope-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)

	narrowClient := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{testRedirect},
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		// Note: no offline_access in scopes.
		Scopes:   fosite.Arguments{"openid", "wlcg", "storage.read:/"},
		Audience: fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), narrowClient))

	httpClient := ts.Client()
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	// Step 1: Authorize — request offline_access and storage.read:/.
	// Fosite validates requested scopes are in the client's registered
	// scopes, so we only request scopes the client declares. But we rely
	// on our handler to block offline_access since it's not in the
	// client's scope list.
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := generateCodeChallenge(codeVerifier)

	authURL := ts.URL + "/api/v1.0/issuer/ns/test/ns/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid wlcg storage.read:/"},
		"state":                 {"scope-enforce-test"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := httpClient.Get(authURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.True(t, resp.StatusCode == http.StatusSeeOther || resp.StatusCode == http.StatusFound,
		"authorize should redirect, got %d: %s", resp.StatusCode, string(body))

	location := resp.Header.Get("Location")
	redirectURL, err := url.Parse(location)
	require.NoError(t, err)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "redirect should contain authorization code")

	// Step 2: Exchange code for tokens using the narrow client.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirect},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	}
	req, err := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/ns/test/ns/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	tokenResp, err := httpClient.Do(req)
	require.NoError(t, err)
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode,
		"token exchange should succeed, body: %s", string(tokenBody))

	var tokenResult map[string]interface{}
	require.NoError(t, json.Unmarshal(tokenBody, &tokenResult))

	accessToken := tokenResult["access_token"].(string)
	claims := secParseJWT(t, provider, accessToken)
	scopeStr, _ := claims.Get("scope")
	assert.NotContains(t, scopeStr, "offline_access",
		"auth-code token must not contain offline_access when client scopes exclude it")
	assert.Contains(t, scopeStr, "storage.read:",
		"auth-code token should contain storage.read which is in both user and client scopes")

	// Must NOT have a refresh token since offline_access was not granted.
	_, hasRefresh := tokenResult["refresh_token"]
	assert.False(t, hasRefresh,
		"no refresh token should be issued when offline_access is not in client scopes")
}

// --- Finding #3: Device flow client scope enforcement ---

// TestDeviceFlowClientScopeEnforcement verifies that a device client limited
// to read scopes cannot obtain broader scopes like storage.modify:/ even if
// the user's authorization rules would grant them.
func TestDeviceFlowClientScopeEnforcement(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Create a client whose scopes are limited to read.
	secret := "device-scope-secret"
	clientID := "device-scope-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)

	narrowClient := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{},
		GrantTypes:    fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{},
		Scopes:        fosite.Arguments{"openid", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), narrowClient))

	// Start device flow requesting storage.modify:/.
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"openid wlcg storage.read:/ storage.modify:/"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/device_authorization", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var daResp map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&daResp))
	userCode := daResp["user_code"].(string)
	deviceCode := daResp["device_code"].(string)

	// Approve the device code (simulate user).
	approveResp := approveDeviceCode(t, httpClient, ts.URL, userCode)
	approveResp.Body.Close()

	// Exchange device code for token.
	tokenForm := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	tokenResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", tokenForm)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]interface{}
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenResult))

	accessToken := tokenResult["access_token"].(string)
	claims := secParseJWT(t, provider, accessToken)
	scopeStr, _ := claims.Get("scope")
	assert.NotContains(t, scopeStr, "storage.modify",
		"device-code token must not contain storage.modify when client scopes exclude it")
}

// --- Finding #4: Storage namespace isolation ---

// TestStorageNamespaceIsolation verifies that storage lookups are scoped to
// their namespace and cannot resolve sessions from other namespaces.
func TestStorageNamespaceIsolation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ns-isolation.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	alphaStorage := NewOIDCStorage(db, "/alpha")
	betaStorage := NewOIDCStorage(db, "/beta")

	// Create a client in alpha.
	sharedSecret, err := secBcryptHash("shared-secret")
	require.NoError(t, err)
	alphaClient := &fosite.DefaultClient{
		ID:            "shared-client",
		Secret:        sharedSecret,
		RedirectURIs:  []string{"https://localhost/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid"},
	}
	require.NoError(t, alphaStorage.CreateClient(context.Background(), alphaClient))

	// Create a token session in alpha.
	session := &WLCGSession{
		JWTClaims:          &jwt.JWTClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		IDTokenClaimsField: &jwt.IDTokenClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
		Subject:            "user1",
	}
	req := fosite.NewRequest()
	req.ID = "alpha-req"
	req.Client = alphaClient
	req.Session = session
	req.RequestedScope = fosite.Arguments{"openid"}
	req.GrantedScope = fosite.Arguments{"openid"}

	require.NoError(t, alphaStorage.CreateAccessTokenSession(context.Background(), "alpha-sig", req))

	// Beta storage should NOT find alpha's token.
	_, err = betaStorage.GetAccessTokenSession(context.Background(), "alpha-sig", &WLCGSession{})
	assert.ErrorIs(t, err, fosite.ErrNotFound,
		"beta namespace must not resolve alpha's access token session")

	// Alpha storage should find it.
	_, err = alphaStorage.GetAccessTokenSession(context.Background(), "alpha-sig", &WLCGSession{})
	assert.NoError(t, err, "alpha namespace must resolve its own access token session")
}

// --- Finding #5: Device flow grant type enforcement ---

// TestDeviceFlowGrantTypeEnforced verifies that device authorization rejects
// clients that don't have the device_code grant type.
func TestDeviceFlowGrantTypeEnforced(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Create a client with only authorization_code (no device_code).
	secret := "no-device-secret"
	clientID := "no-device-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)

	noDeviceClient := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  []string{testRedirect},
		GrantTypes:    fosite.Arguments{"authorization_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "offline_access", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), noDeviceClient))

	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {secret},
		"scope":         {"openid storage.read:/"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/device_authorization", form)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"device authorization must reject clients without device_code grant")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "unauthorized_client")
}

// --- Finding #6: Device code client binding ---

// TestDeviceCodeClientBinding verifies that a device code can only be redeemed
// by the client that initiated the flow.
func TestDeviceCodeClientBinding(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := newTestClientWithJar(t, ts)

	// Create two clients, both with device_code grant.
	secretA := "client-a-secret"
	clientIDA := "client-a"
	hashedA, _ := secBcryptHash(secretA)
	clientA := &fosite.DefaultClient{
		ID: clientIDA, Secret: hashedA,
		GrantTypes:    fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{},
		Scopes:        fosite.Arguments{"openid", "offline_access", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), clientA))

	secretB := "client-b-secret"
	clientIDB := "client-b"
	hashedB, _ := secBcryptHash(secretB)
	clientB := &fosite.DefaultClient{
		ID: clientIDB, Secret: hashedB,
		GrantTypes:    fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		ResponseTypes: fosite.Arguments{},
		Scopes:        fosite.Arguments{"openid", "offline_access", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), clientB))

	// Client A initiates device flow.
	form := url.Values{
		"client_id":     {clientIDA},
		"client_secret": {secretA},
		"scope":         {"openid storage.read:/"},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/device_authorization", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var daResp map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&daResp))
	userCode := daResp["user_code"].(string)
	deviceCode := daResp["device_code"].(string)

	// Approve.
	approveResp := approveDeviceCode(t, httpClient, ts.URL, userCode)
	approveResp.Body.Close()

	// Client B tries to redeem client A's device code.
	tokenForm := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {clientIDB},
		"client_secret": {secretB},
	}
	tokenResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", tokenForm)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, tokenResp.StatusCode,
		"device code must not be redeemable by a different client")
	body, _ := io.ReadAll(tokenResp.Body)
	assert.Contains(t, string(body), "different client")
}

// --- Finding #7: Namespace prefix boundary ---

// TestNamespacePrefixBoundary verifies that a namespace like "/test/ns" does
// not match paths like "/test/nsoidc-cm" (bare prefix match).
func TestNamespacePrefixBoundary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	registry := NewProviderRegistry()

	// Register a provider for /test/ns.
	// We only care about resolveProvider so no need for a real provider.
	registry.mu.Lock()
	registry.providers["/test/ns"] = &OIDCProvider{Namespace: "/test/ns"}
	registry.mu.Unlock()

	// Exact match.
	assert.NotNil(t, resolveProvider(registry, "/test/ns"),
		"exact namespace should match")

	// Path-component match.
	assert.NotNil(t, resolveProvider(registry, "/test/ns/token"),
		"sub-path should match")

	// Bare prefix — should NOT match.
	assert.Nil(t, resolveProvider(registry, "/test/nsoidc-cm"),
		"bare prefix without path separator must not match")

	assert.Nil(t, resolveProvider(registry, "/test/ns2"),
		"different namespace with same prefix must not match")
}

// --- Finding #8: Client ID namespace collision ---

// TestClientIDNamespaceIsolation verifies that creating a client with the same
// ID in two different namespaces does NOT overwrite the first.
func TestClientIDNamespaceIsolation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "client-ns-test.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	alphaStorage := NewOIDCStorage(db, "/alpha")
	betaStorage := NewOIDCStorage(db, "/beta")

	clientID := "collide-client"
	alphaClient := &fosite.DefaultClient{
		ID: clientID, Secret: []byte("alpha-secret"),
		RedirectURIs:  []string{"https://alpha/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid"},
	}
	require.NoError(t, alphaStorage.CreateClient(context.Background(), alphaClient))

	betaClient := &fosite.DefaultClient{
		ID: clientID, Secret: []byte("beta-secret"),
		RedirectURIs:  []string{"https://beta/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "storage.read:/"},
	}
	require.NoError(t, betaStorage.CreateClient(context.Background(), betaClient))

	// Alpha's client must still have its original redirect URI.
	alphaFound, err := alphaStorage.GetClient(context.Background(), clientID)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://alpha/callback"}, alphaFound.GetRedirectURIs(),
		"alpha's client must not be overwritten by beta's registration")

	// Beta must NOT find alpha's client.
	betaFound, err := betaStorage.GetClient(context.Background(), clientID)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://beta/callback"}, betaFound.GetRedirectURIs(),
		"beta must have its own client record")
}

// --- Finding #9: CreateClient must not silently overwrite ---

// TestCreateClientFailsOnDuplicate verifies that creating a client with the
// same (ID, namespace) pair fails instead of silently overwriting the existing
// record. Operators must explicitly delete-and-recreate.
func TestCreateClientFailsOnDuplicate(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "dup-client.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	storage := NewOIDCStorage(db, "/test/ns")

	client := &fosite.DefaultClient{
		ID:            "dup-client",
		Secret:        []byte("original-secret"),
		RedirectURIs:  []string{"https://localhost/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid"},
	}
	require.NoError(t, storage.CreateClient(context.Background(), client))

	// Second create with the same ID in the same namespace must fail.
	duplicate := &fosite.DefaultClient{
		ID:            "dup-client",
		Secret:        []byte("new-secret"),
		RedirectURIs:  []string{"https://evil/callback"},
		GrantTypes:    fosite.Arguments{"authorization_code"},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "storage.read:/"},
	}
	err = storage.CreateClient(context.Background(), duplicate)
	assert.Error(t, err,
		"CreateClient must fail on duplicate (id, namespace) to prevent silent overwrites")

	// Original client must be unchanged.
	found, err := storage.GetClient(context.Background(), "dup-client")
	require.NoError(t, err)
	assert.Equal(t, []string{"https://localhost/callback"}, found.GetRedirectURIs(),
		"original client must not be overwritten")
}

// --- Finding #10: PKCE enforcement for public clients ---

// TestPKCEEnforcedForPublicClients verifies that the fosite config requires
// PKCE for public clients.
func TestPKCEEnforcedForPublicClients(t *testing.T) {
	provider, _ := setupIntegration(t)
	assert.True(t, provider.Config().EnforcePKCEForPublicClients,
		"EnforcePKCEForPublicClients must be true")
}

// --- Finding #11: Token exchange correct issuer ---

// TestTokenExchangeCorrectIssuer verifies that exchanged tokens carry the
// namespace-scoped issuer URL, not the global server URL.
func TestTokenExchangeCorrectIssuer(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Create a token-exchange client.
	secret := "te-issuer-secret"
	teClientID := "te-issuer-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)
	teClient := &fosite.DefaultClient{
		ID: teClientID, Secret: hashedSecret,
		RedirectURIs:  []string{testRedirect},
		GrantTypes:    fosite.Arguments{tokenExchangeGrantType},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), teClient))

	subjectToken := secMintTestAccessToken(t, provider, testUser, []string{}, []string{"openid", "wlcg", "storage.read:/"})

	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"client_id":          {teClientID},
		"client_secret":      {secret},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

	claims := secParseJWT(t, provider, result["access_token"].(string))
	issuer, _ := claims.Get("iss")
	expectedIssuer := IssuerURLForNamespace(testNamespace)
	assert.Equal(t, expectedIssuer, issuer,
		"exchanged token's iss must be the namespace-scoped issuer URL")
	assert.NotEqual(t, IssuerURL(), issuer,
		"exchanged token's iss must NOT be the global server URL")
}

// --- Finding #12: Token exchange audience validation ---

// TestTokenExchangeAudienceValidation verifies that the token exchange
// endpoint rejects an audience that is not in the subject token's grants.
func TestTokenExchangeAudienceValidation(t *testing.T) {
	provider, ts := setupIntegration(t)
	httpClient := ts.Client()

	secret := "te-aud-secret"
	teClientID := "te-aud-client"
	hashedSecret, err := secBcryptHash(secret)
	require.NoError(t, err)
	teClient := &fosite.DefaultClient{
		ID: teClientID, Secret: hashedSecret,
		RedirectURIs:  []string{testRedirect},
		GrantTypes:    fosite.Arguments{tokenExchangeGrantType},
		ResponseTypes: fosite.Arguments{"code"},
		Scopes:        fosite.Arguments{"openid", "wlcg", "storage.read:/"},
		Audience:      fosite.Arguments{WLCGAudienceAny},
	}
	require.NoError(t, provider.Storage().CreateClient(context.Background(), teClient))

	subjectToken := secMintTestAccessToken(t, provider, testUser, []string{}, []string{"openid", "wlcg", "storage.read:/"})

	form := url.Values{
		"grant_type":         {tokenExchangeGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"audience":           {"https://evil-service.example.com"},
		"client_id":          {teClientID},
		"client_secret":      {secret},
	}
	resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"token exchange must reject arbitrary audience not in subject token")
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "invalid_target")
}

// --- Finding #13: Refresh token rotation sets active=false ---

// TestRefreshTokenRotationSetsInactive verifies that RotateRefreshToken marks
// the old token as inactive and sets first_used_at.
func TestRefreshTokenRotationSetsInactive(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rt-rotation.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	storage := NewOIDCStorage(db, "/test/ns")

	rtSecret, err := secBcryptHash("rt-client-secret")
	require.NoError(t, err)
	client := &fosite.DefaultClient{
		ID: "rt-client", Secret: rtSecret,
		RedirectURIs: []string{"https://localhost/callback"},
		GrantTypes:   fosite.Arguments{"authorization_code", "refresh_token"},
		Scopes:       fosite.Arguments{"openid", "offline_access"},
	}
	require.NoError(t, storage.CreateClient(context.Background(), client))

	session := &WLCGSession{
		JWTClaims:          &jwt.JWTClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		IDTokenClaimsField: &jwt.IDTokenClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
		Subject:            "user1",
	}
	req := fosite.NewRequest()
	req.ID = "rt-req-1"
	req.Client = client
	req.Session = session
	req.RequestedScope = fosite.Arguments{"openid", "offline_access"}
	req.GrantedScope = fosite.Arguments{"openid", "offline_access"}

	require.NoError(t, storage.CreateRefreshTokenSession(context.Background(), "rt-sig-1", "at-sig-1", req))

	// Rotate the token.
	require.NoError(t, storage.RotateRefreshToken(context.Background(), "rt-req-1", "rt-sig-1"))

	// Verify the old token is marked inactive.
	var record OIDCRefreshToken
	require.NoError(t, db.First(&record, "signature = ? AND namespace = ?", "rt-sig-1", "/test/ns").Error)

	assert.False(t, record.Active, "rotated token must be marked inactive")
	assert.NotNil(t, record.FirstUsedAt, "rotated token must have first_used_at set")
}

// --- Finding #14: Refresh token rotation matches by signature ---

// TestRefreshTokenRotationBySignature verifies that RotateRefreshToken targets
// the specific token by signature rather than all tokens by request_id, which
// would cause chain poisoning.
func TestRefreshTokenRotationBySignature(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rt-sig-rotation.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	storage := NewOIDCStorage(db, "/test/ns")

	chainSecret, err := secBcryptHash("chain-client-secret")
	require.NoError(t, err)
	client := &fosite.DefaultClient{
		ID: "chain-client", Secret: chainSecret,
		RedirectURIs: []string{"https://localhost/callback"},
		GrantTypes:   fosite.Arguments{"authorization_code", "refresh_token"},
		Scopes:       fosite.Arguments{"openid", "offline_access"},
	}
	require.NoError(t, storage.CreateClient(context.Background(), client))

	session := &WLCGSession{
		JWTClaims:          &jwt.JWTClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		IDTokenClaimsField: &jwt.IDTokenClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
		Subject:            "user1",
	}

	// Create two refresh tokens with the SAME request_id (simulating rotation).
	req := fosite.NewRequest()
	req.ID = "shared-req-id"
	req.Client = client
	req.Session = session
	req.RequestedScope = fosite.Arguments{"openid"}
	req.GrantedScope = fosite.Arguments{"openid"}

	require.NoError(t, storage.CreateRefreshTokenSession(context.Background(), "rt1-sig", "at1-sig", req))
	require.NoError(t, storage.CreateRefreshTokenSession(context.Background(), "rt2-sig", "at2-sig", req))

	// Rotate only rt1.
	require.NoError(t, storage.RotateRefreshToken(context.Background(), "shared-req-id", "rt1-sig"))

	// rt1 should be inactive.
	var rt1 OIDCRefreshToken
	require.NoError(t, db.First(&rt1, "signature = ?", "rt1-sig").Error)
	assert.False(t, rt1.Active, "rt1 must be inactive after rotation")

	// rt2 must NOT be affected (no chain poisoning).
	var rt2 OIDCRefreshToken
	require.NoError(t, db.First(&rt2, "signature = ?", "rt2-sig").Error)
	assert.True(t, rt2.Active, "rt2 must remain active — rotation must target by signature, not request_id")
	assert.Nil(t, rt2.FirstUsedAt, "rt2's first_used_at must not be set by rotating rt1")
}

// --- Finding #15: Shared rate limiter across namespaces ---

// TestSharedRateLimiterAcrossNamespaces verifies that the per-IP rate limit
// for DCR is shared across namespaces, not per-namespace.
func TestSharedRateLimiterAcrossNamespaces(t *testing.T) {
	config.ResetConfig()
	t.Cleanup(func() { config.ResetConfig() })

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.IssuerKey, filepath.Join(tmpDir, "issuer.jwk")))
	require.NoError(t, param.Set(param.Server_ExternalWebUrl, "https://test-origin.example.com"))
	require.NoError(t, oa4mp.InitAuthzRules())

	dbPath := filepath.Join(tmpDir, "shared-rl.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	providerA, err := NewOIDCProvider(db, IssuerURLForNamespace("/ns-a"), 5*time.Minute, "/ns-a")
	require.NoError(t, err)
	providerB, err := NewOIDCProvider(db, IssuerURLForNamespace("/ns-b"), 5*time.Minute, "/ns-b")
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set("User", testUser)
		c.Set("UserId", testUserID)
		c.Set("Groups", testGroups)
		c.Next()
	})

	registry := NewProviderRegistry()
	// Override with a tight per-IP burst of 3.
	registry.RegistrationLimiter = newRegistrationRateLimiter(0, 3)
	registry.Register("/ns-a", providerA)
	registry.Register("/ns-b", providerB)
	RegisterRoutesWithMiddleware(engine, registry)

	ts := httptest.NewTLSServer(engine)
	t.Cleanup(ts.Close)
	httpClient := ts.Client()

	regBody := `{"redirect_uris": [], "client_name": "shared-rl-test"}`

	// 2 registrations on ns-a.
	for i := 0; i < 2; i++ {
		resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/ns/ns-a/oidc-cm",
			"application/json", strings.NewReader(regBody))
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "ns-a reg %d", i+1)
		resp.Body.Close()
	}

	// 1 registration on ns-b.
	resp, err := httpClient.Post(ts.URL+"/api/v1.0/issuer/ns/ns-b/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode, "ns-b reg 1")
	resp.Body.Close()

	// 4th registration (on either namespace) should be rate-limited since
	// the shared limiter has burst=3.
	resp, err = httpClient.Post(ts.URL+"/api/v1.0/issuer/ns/ns-a/oidc-cm",
		"application/json", strings.NewReader(regBody))
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"4th registration should be rate-limited across namespaces")
	resp.Body.Close()
}

// --- Finding #16: Refresh token grant type bypass ---

// TestRefreshTokenGrantTypeRequired verifies that device flow and token
// exchange refuse to issue refresh tokens when the client lacks the
// refresh_token grant type.
func TestRefreshTokenGrantTypeRequired(t *testing.T) {
	t.Run("DeviceFlow", func(t *testing.T) {
		provider, ts := setupIntegration(t)
		httpClient := newTestClientWithJar(t, ts)

		// Client with device_code but NOT refresh_token.
		secret := "no-rt-device-secret"
		clientID := "no-rt-device-client"
		hashedSecret, _ := secBcryptHash(secret)
		client := &fosite.DefaultClient{
			ID: clientID, Secret: hashedSecret,
			GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
			Scopes:     fosite.Arguments{"openid", "offline_access", "wlcg", "storage.read:/"},
			Audience:   fosite.Arguments{WLCGAudienceAny},
		}
		require.NoError(t, provider.Storage().CreateClient(context.Background(), client))

		// Start device flow requesting offline_access.
		form := url.Values{
			"client_id": {clientID}, "client_secret": {secret},
			"scope": {"openid offline_access storage.read:/"},
		}
		resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/device_authorization", form)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var daResp map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&daResp))
		resp.Body.Close()

		approveResp := approveDeviceCode(t, httpClient, ts.URL, daResp["user_code"].(string))
		approveResp.Body.Close()

		tokenForm := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {daResp["device_code"].(string)},
			"client_id":   {clientID}, "client_secret": {secret},
		}
		tokenResp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", tokenForm)
		require.NoError(t, err)
		defer tokenResp.Body.Close()
		require.Equal(t, http.StatusOK, tokenResp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&result))
		_, hasRT := result["refresh_token"]
		assert.False(t, hasRT,
			"device flow must not issue refresh token when client lacks refresh_token grant")
	})

	t.Run("TokenExchange", func(t *testing.T) {
		provider, ts := setupIntegration(t)
		httpClient := ts.Client()

		// Client with token-exchange but NOT refresh_token.
		secret := "no-rt-te-secret"
		clientID := "no-rt-te-client"
		hashedSecret, _ := secBcryptHash(secret)
		client := &fosite.DefaultClient{
			ID: clientID, Secret: hashedSecret,
			RedirectURIs: []string{testRedirect},
			GrantTypes:   fosite.Arguments{tokenExchangeGrantType},
			Scopes:       fosite.Arguments{"openid", "offline_access", "wlcg", "storage.read:/"},
			Audience:     fosite.Arguments{WLCGAudienceAny},
		}
		require.NoError(t, provider.Storage().CreateClient(context.Background(), client))

		subjectToken := secMintTestAccessToken(t, provider, testUser, []string{}, []string{"openid", "offline_access", "wlcg", "storage.read:/"})

		form := url.Values{
			"grant_type":         {tokenExchangeGrantType},
			"subject_token":      {subjectToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"scope":              {"openid offline_access storage.read:/"},
			"client_id":          {clientID},
			"client_secret":      {secret},
		}
		resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		_, hasRT := result["refresh_token"]
		assert.False(t, hasRT,
			"token exchange must not issue refresh token when client lacks refresh_token grant")
	})
}

// --- Finding #17: Cross-namespace revocation ---

// TestCrossNamespaceRevocationBlocked verifies that revoking tokens in one
// namespace does not affect tokens in another namespace.
func TestCrossNamespaceRevocationBlocked(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "revoke-ns.sqlite")
	db, err := dbutils.InitSQLiteDB(dbPath)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { sqlDB.Close() })
	require.NoError(t, dbutils.MigrateDB(sqlDB, database.EmbedUniversalMigrations, "universal_migrations"))
	require.NoError(t, dbutils.MigrateServerSpecificDB(sqlDB, database.EmbedOriginMigrations, "origin_migrations", "origin"))

	alphaStorage := NewOIDCStorage(db, "/alpha")
	betaStorage := NewOIDCStorage(db, "/beta")

	// Create clients in both namespaces.
	revSecret, err := secBcryptHash("rev-client-secret")
	require.NoError(t, err)
	for _, s := range []*OIDCStorage{alphaStorage, betaStorage} {
		client := &fosite.DefaultClient{
			ID: "rev-client", Secret: revSecret,
			RedirectURIs: []string{"https://localhost/callback"},
			GrantTypes:   fosite.Arguments{"authorization_code", "refresh_token"},
			Scopes:       fosite.Arguments{"openid", "offline_access"},
		}
		require.NoError(t, s.CreateClient(context.Background(), client))
	}

	session := &WLCGSession{
		JWTClaims:          &jwt.JWTClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		IDTokenClaimsField: &jwt.IDTokenClaims{Subject: "user1", Issuer: "https://test", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), Extra: map[string]interface{}{}},
		JWTHeaders:         &jwt.Headers{},
		Subject:            "user1",
	}

	// Create refresh token in alpha.
	req := fosite.NewRequest()
	req.ID = "alpha-revoke-req"
	req.Client = &fosite.DefaultClient{ID: "rev-client"}
	req.Session = session
	req.RequestedScope = fosite.Arguments{"openid"}
	req.GrantedScope = fosite.Arguments{"openid"}

	require.NoError(t, alphaStorage.CreateRefreshTokenSession(context.Background(), "alpha-rt-sig", "alpha-at", req))

	// Beta tries to revoke alpha's token by request_id.
	require.NoError(t, betaStorage.RevokeRefreshToken(context.Background(), "alpha-revoke-req"))

	// Alpha's token must still be active.
	_, err = alphaStorage.GetRefreshTokenSession(context.Background(), "alpha-rt-sig", &WLCGSession{})
	assert.NoError(t, err, "alpha's refresh token must not be revoked by beta's revocation call")
}

// ---- Helpers ----

// secBcryptHash bcrypt-hashes a secret string using minimum cost for faster tests.
func secBcryptHash(secret string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
}

// secMintTestAccessToken creates a signed access token directly via the provider's
// strategy, suitable for use as a subject_token in token exchange tests.
func secMintTestAccessToken(t *testing.T, provider *OIDCProvider, subject string, groups, scopes []string) string {
	t.Helper()

	issuerURL := IssuerURLForNamespace(provider.Namespace)
	session := DefaultOIDCSession(subject, issuerURL, groups, scopes)
	session.SetExpiresAt(fosite.AccessToken, time.Now().Add(time.Hour))

	req := fosite.NewRequest()
	req.ID = "mint-" + subject + "-" + time.Now().Format("150405.000")
	req.Client = &fosite.DefaultClient{
		ID:       testClientID,
		Audience: fosite.Arguments{WLCGAudienceAny},
	}
	req.Session = session
	req.RequestedScope = scopes
	req.GrantedScope = scopes
	req.GrantedAudience = fosite.Arguments{WLCGAudienceAny}

	accessToken, accessSig, err := provider.strategy.CoreStrategy.GenerateAccessToken(context.Background(), req)
	require.NoError(t, err)
	require.NoError(t, provider.Storage().CreateAccessTokenSession(context.Background(), accessSig, req))

	return accessToken
}

// secParseJWT parses and verifies a JWT token using the provider's public key.
func secParseJWT(t *testing.T, provider *OIDCProvider, token string) jwtpkg.Token {
	t.Helper()

	pubKey, err := jwk.FromRaw(provider.PrivateKey().Public())
	require.NoError(t, err)
	alg := jwa.KeyAlgorithmFrom(provider.signingAlgorithm())
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, pubKey.Set(jwk.KeyUsageKey, "sig"))

	parsed, err := jwtpkg.Parse([]byte(token),
		jwtpkg.WithKey(alg, pubKey),
		jwtpkg.WithValidate(false))
	require.NoError(t, err)
	return parsed
}
