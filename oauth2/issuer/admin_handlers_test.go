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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// ---- Storage: Admin Client CRUD ----

func TestAdminClientCRUD(t *testing.T) {
	storage := createTestDB(t)
	ctx := context.Background()

	t.Run("ListClients-empty", func(t *testing.T) {
		clients, err := storage.ListClients(ctx)
		require.NoError(t, err)
		assert.Empty(t, clients)
	})

	t.Run("CreateAndList", func(t *testing.T) {
		newTestClient(t, storage, "admin-test-client-1")
		clients, err := storage.ListClients(ctx)
		require.NoError(t, err)
		assert.Len(t, clients, 1)
		assert.Equal(t, "admin-test-client-1", clients[0].ClientID)
		assert.False(t, clients[0].DynamicallyRegistered)
	})

	t.Run("GetClientDetail", func(t *testing.T) {
		detail, err := storage.GetClientDetail(ctx, "admin-test-client-1")
		require.NoError(t, err)
		assert.Equal(t, "admin-test-client-1", detail.ClientID)
		assert.False(t, detail.Public)
	})

	t.Run("GetClientDetail-NotFound", func(t *testing.T) {
		_, err := storage.GetClientDetail(ctx, "nonexistent")
		require.Error(t, err)
	})

	t.Run("DeleteClient", func(t *testing.T) {
		deleted, err := storage.DeleteClient(ctx, "admin-test-client-1")
		require.NoError(t, err)
		assert.True(t, deleted)

		// Second delete returns false.
		deleted, err = storage.DeleteClient(ctx, "admin-test-client-1")
		require.NoError(t, err)
		assert.False(t, deleted)
	})
}

// ---- Admin API Handler Tests ----

// setupAdminTestServer creates a gin engine with admin handlers and an
// authenticated middleware stub.
func setupAdminTestServer(t *testing.T) (*OIDCProvider, *httptest.Server) {
	t.Helper()

	provider, ts := setupIntegration(t)

	// The integration setup already registers issuer routes but not admin routes.
	// We need a second server with admin routes registered.
	// Instead, we'll close the old ts and create a new engine.
	ts.Close()

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// Fake admin auth middleware
	engine.Use(func(c *gin.Context) {
		c.Set("User", "admin")
		c.Next()
	})

	RegisterRoutesWithMiddleware(engine, provider)
	RegisterAdminRoutes(engine, provider)

	newTS := httptest.NewTLSServer(engine)
	t.Cleanup(newTS.Close)

	return provider, newTS
}

func TestAdminListClientsAPI(t *testing.T) {
	_, ts := setupAdminTestServer(t)
	client := ts.Client()

	resp, err := client.Get(ts.URL + "/api/v1.0/issuer/admin/clients")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var clients []map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&clients))
	// Should have at least the test client from setupIntegration
	assert.GreaterOrEqual(t, len(clients), 1)
}

func TestAdminCreateClientAPI(t *testing.T) {
	_, ts := setupAdminTestServer(t)
	httpClient := ts.Client()

	t.Run("create-token-exchange-client", func(t *testing.T) {
		body := `{
			"grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"],
			"scopes": ["openid", "storage.read:/", "storage.modify:/"]
		}`
		resp, err := httpClient.Post(
			ts.URL+"/api/v1.0/issuer/admin/clients",
			"application/json",
			strings.NewReader(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

		assert.NotEmpty(t, result["client_id"])
		assert.NotEmpty(t, result["client_secret"])

		grantTypes, ok := result["grant_types"].([]interface{})
		require.True(t, ok)
		assert.Len(t, grantTypes, 2)
	})

	t.Run("create-with-invalid-grant-type", func(t *testing.T) {
		body := `{"grant_types": ["bogus_grant"]}`
		resp, err := httpClient.Post(
			ts.URL+"/api/v1.0/issuer/admin/clients",
			"application/json",
			strings.NewReader(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("create-empty-grant-types", func(t *testing.T) {
		body := `{"grant_types": []}`
		resp, err := httpClient.Post(
			ts.URL+"/api/v1.0/issuer/admin/clients",
			"application/json",
			strings.NewReader(body),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestAdminDeleteClientAPI(t *testing.T) {
	_, ts := setupAdminTestServer(t)
	httpClient := ts.Client()

	// Create a client first
	body := `{"grant_types": ["refresh_token"]}`
	createResp, err := httpClient.Post(
		ts.URL+"/api/v1.0/issuer/admin/clients",
		"application/json",
		strings.NewReader(body),
	)
	require.NoError(t, err)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created map[string]interface{}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	clientID := created["client_id"].(string)

	t.Run("delete-existing", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("delete-nonexistent", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestAdminUpdateClientAPI(t *testing.T) {
	_, ts := setupAdminTestServer(t)
	httpClient := ts.Client()

	// Create a client to update.
	body := `{
		"grant_types": ["refresh_token"],
		"scopes": ["openid", "storage.read:/"]
	}`
	createResp, err := httpClient.Post(
		ts.URL+"/api/v1.0/issuer/admin/clients",
		"application/json",
		strings.NewReader(body),
	)
	require.NoError(t, err)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created map[string]interface{}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	clientID := created["client_id"].(string)

	t.Run("update-grant-types", func(t *testing.T) {
		updateBody := `{"grant_types": ["refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"]}`
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		grantTypes, ok := result["grant_types"].([]interface{})
		require.True(t, ok)
		assert.Len(t, grantTypes, 2)
		assert.Equal(t, "refresh_token", grantTypes[0])
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", grantTypes[1])

		// Scopes should be unchanged.
		scopes, ok := result["scopes"].([]interface{})
		require.True(t, ok)
		assert.Len(t, scopes, 2)
	})

	t.Run("update-scopes-only", func(t *testing.T) {
		updateBody := `{"scopes": ["openid", "storage.read:/", "storage.modify:/"]}`
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		scopes, ok := result["scopes"].([]interface{})
		require.True(t, ok)
		assert.Len(t, scopes, 3)

		// Grant types should still reflect the previous update.
		grantTypes, ok := result["grant_types"].([]interface{})
		require.True(t, ok)
		assert.Len(t, grantTypes, 2)
	})

	t.Run("update-invalid-grant-type", func(t *testing.T) {
		updateBody := `{"grant_types": ["bogus_grant"]}`
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("update-empty-grant-types", func(t *testing.T) {
		updateBody := `{"grant_types": []}`
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1.0/issuer/admin/clients/"+clientID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("update-nonexistent", func(t *testing.T) {
		updateBody := `{"scopes": ["openid"]}`
		req, _ := http.NewRequest("PUT", ts.URL+"/api/v1.0/issuer/admin/clients/nonexistent-id", strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

// ---- Token Exchange Tests ----

func TestTokenExchange(t *testing.T) {
	provider, ts := setupAdminTestServer(t)
	httpClient := ts.Client()

	// Create a token-exchange client via the admin API.
	body := `{
		"grant_types": ["urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"],
		"scopes": ["openid", "offline_access", "storage.read:/", "storage.modify:/"]
	}`
	createResp, err := httpClient.Post(
		ts.URL+"/api/v1.0/issuer/admin/clients",
		"application/json",
		strings.NewReader(body),
	)
	require.NoError(t, err)
	defer createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	var created map[string]interface{}
	require.NoError(t, json.NewDecoder(createResp.Body).Decode(&created))
	teClientID := created["client_id"].(string)
	teClientSecret := created["client_secret"].(string)

	// Mint a valid access token that we'll use as the subject_token.
	subjectToken := mintTestAccessToken(t, provider, ts.URL)

	t.Run("successful-exchange", func(t *testing.T) {
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {subjectToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"scope":              {"storage.read:/"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(teClientID, teClientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.NotEmpty(t, result["access_token"])
		assert.Equal(t, "Bearer", result["token_type"])
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", result["issued_token_type"])
	})

	t.Run("exchange-inherits-scopes", func(t *testing.T) {
		// No explicit scope → inherits from subject token
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {subjectToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(teClientID, teClientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("missing-subject-token", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(teClientID, teClientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid-subject-token", func(t *testing.T) {
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {"not.a.valid.jwt"},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(teClientID, teClientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("client-not-authorized-for-exchange", func(t *testing.T) {
		// Use the standard integration test client (which only has device_code grant)
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {subjectToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var result map[string]interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
		assert.Equal(t, "unauthorized_client", result["error"])
	})

	t.Run("unsupported-subject-token-type", func(t *testing.T) {
		form := url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {subjectToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"},
		}
		req, _ := http.NewRequest("POST", ts.URL+"/api/v1.0/issuer/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(teClientID, teClientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// mintTestAccessToken creates a valid JWT access token signed by the provider's
// key, stores the session, and returns the serialized token for use in tests.
func mintTestAccessToken(t *testing.T, provider *OIDCProvider, baseURL string) string {
	t.Helper()

	ctx := context.Background()
	issuerURL := "https://test-origin.example.com"

	session := DefaultOIDCSession(testUser, issuerURL, testGroups,
		[]string{"openid", "storage.read:/", "storage.modify:/"})
	session.SetExpiresAt("access_token", session.JWTClaims.ExpiresAt)

	client, err := provider.Storage().GetClient(ctx, testClientID)
	require.NoError(t, err)

	ar := &testAccessRequest{
		client:          client,
		grantedScopes:   []string{"openid", "storage.read:/", "storage.modify:/"},
		requestedScopes: []string{"openid", "storage.read:/", "storage.modify:/"},
		session:         session,
		grantedAudience: []string{WLCGAudienceAny},
	}

	accessToken, accessSig, err := provider.strategy.CoreStrategy.GenerateAccessToken(ctx, ar)
	require.NoError(t, err)

	err = provider.storage.CreateAccessTokenSession(ctx, accessSig, ar)
	require.NoError(t, err)

	// Quick sanity: the token should introspect successfully.
	introSession := DefaultOIDCSession("", issuerURL, nil, nil)
	_, _, err = provider.Provider().IntrospectToken(ctx, accessToken, "access_token", introSession)
	require.NoError(t, err, "minted test token should introspect cleanly")

	return accessToken
}

// testAccessRequest is a minimal fosite.Requester used in token minting.
type testAccessRequest struct {
	client          fosite.Client
	grantedScopes   fosite.Arguments
	requestedScopes fosite.Arguments
	session         fosite.Session
	grantedAudience fosite.Arguments
}

func (r *testAccessRequest) SetID(id string)                        {}
func (r *testAccessRequest) GetID() string                          { return "test-req-id" }
func (r *testAccessRequest) GetRequestedAt() time.Time              { return time.Now() }
func (r *testAccessRequest) GetClient() fosite.Client               { return r.client }
func (r *testAccessRequest) GetRequestedScopes() fosite.Arguments   { return r.requestedScopes }
func (r *testAccessRequest) GetGrantedScopes() fosite.Arguments     { return r.grantedScopes }
func (r *testAccessRequest) GetRequestedAudience() fosite.Arguments { return nil }
func (r *testAccessRequest) GetGrantedAudience() fosite.Arguments   { return r.grantedAudience }
func (r *testAccessRequest) GetSession() fosite.Session             { return r.session }
func (r *testAccessRequest) SetSession(s fosite.Session)            { r.session = s }
func (r *testAccessRequest) GetRequestForm() url.Values             { return url.Values{} }
func (r *testAccessRequest) GetGrantTypes() fosite.Arguments        { return fosite.Arguments{"urn:ietf:params:oauth:grant-type:token-exchange"} }
func (r *testAccessRequest) GrantScope(scope string) {
	r.grantedScopes = append(r.grantedScopes, scope)
}
func (r *testAccessRequest) GrantAudience(aud string) {
	r.grantedAudience = append(r.grantedAudience, aud)
}
func (r *testAccessRequest) AppendRequestedScope(scope string) {
	r.requestedScopes = append(r.requestedScopes, scope)
}
func (r *testAccessRequest) SetRequestedScopes(scopes fosite.Arguments) {
	r.requestedScopes = scopes
}
func (r *testAccessRequest) SetRequestedAudience(aud fosite.Arguments) {}
func (r *testAccessRequest) Merge(requester fosite.Requester)          {}
func (r *testAccessRequest) Sanitize(allowedParams []string) fosite.Requester {
	return r
}

// TestDiscoveryIncludesTokenExchange checks that the OIDC discovery document
// advertises the token-exchange grant type.
func TestDiscoveryIncludesTokenExchange(t *testing.T) {
	_, ts := setupAdminTestServer(t)
	httpClient := ts.Client()

	resp, err := httpClient.Get(ts.URL + "/api/v1.0/issuer/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	var disco map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&disco))

	grants, ok := disco["grant_types_supported"].([]interface{})
	require.True(t, ok)

	found := false
	for _, g := range grants {
		if g == "urn:ietf:params:oauth:grant-type:token-exchange" {
			found = true
			break
		}
	}
	assert.True(t, found, "discovery should list token-exchange grant type")
}

// Ensure the import of time comes from the test access request methods
var _ = func() time.Time { return time.Now() }

// Ensure config, param and crypto imports are used
var (
	_ = config.ResetConfig
	_ = param.Set
	_ = bcrypt.DefaultCost
	_ = jwa.ES256
	_ = jwk.FromRaw
)
