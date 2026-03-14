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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registerDynamicClient registers a dynamic client via the /oidc-cm endpoint
// and returns the parsed JSON response.
func registerDynamicClient(t *testing.T, httpClient *http.Client, baseURL, clientName string) map[string]interface{} {
	t.Helper()

	body := `{"redirect_uris": [], "client_name": "` + clientName + `"}`
	resp, err := httpClient.Post(baseURL+"/api/v1.0/issuer/ns/test/ns/oidc-cm",
		"application/json", strings.NewReader(body))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(respBody, &result))
	return result
}

// ---- RFC 7592: Registration Access Token in Response ----

func TestDCRReturnsRegistrationAccessToken(t *testing.T) {
	_, ts := setupIntegration(t)
	result := registerDynamicClient(t, ts.Client(), ts.URL, "rat-test")

	assert.NotEmpty(t, result["registration_access_token"], "response should include registration_access_token")
	assert.NotEmpty(t, result["registration_client_uri"], "response should include registration_client_uri")

	uri := result["registration_client_uri"].(string)
	clientID := result["client_id"].(string)
	assert.Contains(t, uri, "/api/v1.0/issuer/ns/test/ns/oidc-cm/"+clientID,
		"registration_client_uri should point to the client config endpoint")
}

// ---- RFC 7592 §2.1: GET (read) client configuration ----

func TestClientConfigurationRead(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	reg := registerDynamicClient(t, httpClient, ts.URL, "read-test")
	clientID := reg["client_id"].(string)
	rat := reg["registration_access_token"].(string)
	configURI := ts.URL + "/api/v1.0/issuer/ns/test/ns/oidc-cm/" + clientID

	t.Run("Success", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, configURI, nil)
		req.Header.Set("Authorization", "Bearer "+rat)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var meta map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &meta))

		assert.Equal(t, clientID, meta["client_id"])
		assert.Equal(t, "read-test", meta["client_name"])
		assert.NotNil(t, meta["grant_types"])
		assert.NotNil(t, meta["scope"])
		assert.NotNil(t, meta["registration_client_uri"])
	})

	t.Run("MissingToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, configURI, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("WrongToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, configURI, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("NonexistentClient", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1.0/issuer/ns/test/ns/oidc-cm/nonexistent", nil)
		req.Header.Set("Authorization", "Bearer "+rat)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

// ---- RFC 7592 §2.2: PUT (update) client configuration ----

func TestClientConfigurationUpdate(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	reg := registerDynamicClient(t, httpClient, ts.URL, "update-test")
	clientID := reg["client_id"].(string)
	rat := reg["registration_access_token"].(string)
	configURI := ts.URL + "/api/v1.0/issuer/ns/test/ns/oidc-cm/" + clientID

	t.Run("UpdateClientName", func(t *testing.T) {
		updateBody := `{"client_name": "updated-name"}`
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(updateBody))
		req.Header.Set("Authorization", "Bearer "+rat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var meta map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &meta))
		assert.Equal(t, "updated-name", meta["client_name"])
		assert.Equal(t, clientID, meta["client_id"])
	})

	t.Run("UpdateRedirectURIs", func(t *testing.T) {
		// Loopback URIs should be accepted by default
		updateBody := `{"redirect_uris": ["http://127.0.0.1:8080/callback"]}`
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(updateBody))
		req.Header.Set("Authorization", "Bearer "+rat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var meta map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &meta))
		uris := meta["redirect_uris"].([]interface{})
		assert.Len(t, uris, 1)
		assert.Equal(t, "http://127.0.0.1:8080/callback", uris[0])
	})

	t.Run("RejectNonLoopbackRedirectURI", func(t *testing.T) {
		updateBody := `{"redirect_uris": ["https://evil.example.com/callback"]}`
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(updateBody))
		req.Header.Set("Authorization", "Bearer "+rat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("MissingToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(`{"client_name":"x"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("WrongToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(`{"client_name":"x"}`))
		req.Header.Set("Authorization", "Bearer bad-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

// ---- RFC 7592 §2.3: DELETE client configuration ----

func TestClientConfigurationDelete(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	reg := registerDynamicClient(t, httpClient, ts.URL, "delete-test")
	clientID := reg["client_id"].(string)
	rat := reg["registration_access_token"].(string)
	configURI := ts.URL + "/api/v1.0/issuer/ns/test/ns/oidc-cm/" + clientID

	t.Run("MissingToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, configURI, nil)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("WrongToken", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, configURI, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("Success", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, configURI, nil)
		req.Header.Set("Authorization", "Bearer "+rat)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
		resp.Body.Close()

		// Verify client is gone — GET should fail
		getReq, _ := http.NewRequest(http.MethodGet, configURI, nil)
		getReq.Header.Set("Authorization", "Bearer "+rat)
		getResp, err := httpClient.Do(getReq)
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, getResp.StatusCode)
		getResp.Body.Close()
	})
}

// ---- Client Validity Ping (client_credentials grant) ----

func TestClientValidityPing(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	// Register a dynamic client to test with
	reg := registerDynamicClient(t, httpClient, ts.URL, "ping-test")
	clientID := reg["client_id"].(string)
	clientSecret := reg["client_secret"].(string)

	t.Run("ValidClient-BasicAuth", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1.0/issuer/ns/test/ns/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Valid client → 400 unauthorized_client (grant not supported)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "unauthorized_client", result["error"])
	})

	t.Run("ValidClient-PostAuth", func(t *testing.T) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {clientID},
			"client_secret": {clientSecret},
		}
		resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "unauthorized_client", result["error"])
	})

	t.Run("UnknownClient", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1.0/issuer/ns/test/ns/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("nonexistent-client", "some-secret")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Unknown client → 401 invalid_client
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "invalid_client", result["error"])
	})

	t.Run("WrongSecret", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1.0/issuer/ns/test/ns/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, "wrong-secret")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Wrong secret → 401 invalid_client
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "invalid_client", result["error"])
	})

	t.Run("NoCredentials", func(t *testing.T) {
		form := url.Values{"grant_type": {"client_credentials"}}
		resp, err := httpClient.PostForm(ts.URL+"/api/v1.0/issuer/ns/test/ns/token", form)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "invalid_client", result["error"])
	})

	t.Run("StaticClient-BasicAuth", func(t *testing.T) {
		// The integration setup creates a static client with known credentials
		form := url.Values{"grant_type": {"client_credentials"}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1.0/issuer/ns/test/ns/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(testClientID, testSecret)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Static client with correct credentials → 400 unauthorized_client
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "unauthorized_client", result["error"])
	})

	t.Run("DeletedClientBecomesInvalid", func(t *testing.T) {
		// Register a new client, delete it, then try to ping
		reg2 := registerDynamicClient(t, httpClient, ts.URL, "delete-ping-test")
		id2 := reg2["client_id"].(string)
		secret2 := reg2["client_secret"].(string)
		rat2 := reg2["registration_access_token"].(string)

		// Delete via RFC 7592
		delReq, _ := http.NewRequest(http.MethodDelete,
			ts.URL+"/api/v1.0/issuer/ns/test/ns/oidc-cm/"+id2, nil)
		delReq.Header.Set("Authorization", "Bearer "+rat2)
		delResp, err := httpClient.Do(delReq)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, delResp.StatusCode)
		delResp.Body.Close()

		// Ping the deleted client
		form := url.Values{"grant_type": {"client_credentials"}}
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1.0/issuer/ns/test/ns/token",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(id2, secret2)

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Deleted client → 401 invalid_client
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(body, &result))
		assert.Equal(t, "invalid_client", result["error"])
	})
}

// ---- Length / count limits ----

func TestDCRRejectsOversizedMetadata(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()
	baseURL := ts.URL + "/api/v1.0/issuer/ns/test/ns/oidc-cm"

	t.Run("ClientNameTooLong", func(t *testing.T) {
		longName := strings.Repeat("a", maxClientNameLen+1) // 129 bytes
		body := `{"redirect_uris": [], "client_name": "` + longName + `"}`
		resp, err := httpClient.Post(baseURL, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &result))
		assert.Equal(t, "invalid_client_metadata", result["error"])
		assert.Contains(t, result["error_description"], "client_name too long")
	})

	t.Run("ClientNameAtLimit", func(t *testing.T) {
		exactName := strings.Repeat("b", maxClientNameLen) // 128 bytes — should succeed
		body := `{"redirect_uris": [], "client_name": "` + exactName + `"}`
		resp, err := httpClient.Post(baseURL, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("TooManyRedirectURIs", func(t *testing.T) {
		// Build 11 loopback URIs
		uris := make([]string, maxRedirectURIs+1)
		for i := range uris {
			uris[i] = `"http://127.0.0.1:` + strings.Repeat("0", 4) + `"`
		}
		body := `{"redirect_uris": [` + strings.Join(uris, ",") + `], "client_name": "many-uris"}`
		resp, err := httpClient.Post(baseURL, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &result))
		assert.Contains(t, result["error_description"], "Too many redirect_uris")
	})

	t.Run("RedirectURITooLong", func(t *testing.T) {
		longURI := "http://127.0.0.1:8080/" + strings.Repeat("x", maxRedirectURILen)
		body := `{"redirect_uris": ["` + longURI + `"], "client_name": "long-uri"}`
		resp, err := httpClient.Post(baseURL, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &result))
		assert.Contains(t, result["error_description"], "redirect_uri too long")
	})
}

func TestClientConfigurationUpdateRejectsOversizedMetadata(t *testing.T) {
	_, ts := setupIntegration(t)
	httpClient := ts.Client()

	reg := registerDynamicClient(t, httpClient, ts.URL, "limit-update-test")
	clientID := reg["client_id"].(string)
	rat := reg["registration_access_token"].(string)
	configURI := ts.URL + "/api/v1.0/issuer/ns/test/ns/oidc-cm/" + clientID

	t.Run("UpdateClientNameTooLong", func(t *testing.T) {
		longName := strings.Repeat("c", maxClientNameLen+1)
		body := `{"client_name": "` + longName + `"}`
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &result))
		assert.Contains(t, result["error_description"], "client_name too long")
	})

	t.Run("UpdateTooManyRedirectURIs", func(t *testing.T) {
		uris := make([]string, maxRedirectURIs+1)
		for i := range uris {
			uris[i] = `"http://127.0.0.1:8080/cb"`
		}
		body := `{"redirect_uris": [` + strings.Join(uris, ",") + `]}`
		req, _ := http.NewRequest(http.MethodPut, configURI, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+rat)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var result map[string]interface{}
		require.NoError(t, json.Unmarshal(respBody, &result))
		assert.Contains(t, result["error_description"], "Too many redirect_uris")
	})
}
