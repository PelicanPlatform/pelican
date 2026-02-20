//go:build !windows

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

package fed_tests

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// deviceCodeOriginConfig enables the embedded OIDC issuer on a POSIXv2 origin
// with authorization rules that grant authenticated users (the "admin" user
// specifically) read, write, and create access under /test.
const deviceCodeOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
Issuer:
  AuthorizationTemplates:
    - prefix: /test
      actions: ["read", "write", "create"]
      users: ["admin"]
`

// TestDeviceCodeE2E exercises the entire OIDC device-code flow through a live
// Pelican federation:
//
//  1. Start federation with embedded issuer enabled.
//  2. Perform Dynamic Client Registration (DCR).
//  3. Initiate device authorization — obtain user_code / device_code.
//  4. Log in via POST /api/v1.0/auth/login (emulating the user).
//  5. Approve the device code via the device-verify page.
//  6. Poll the token endpoint until an access token is issued.
//  7. Validate that the access token conforms to the WLCG token profile.
//  8. Upload and download a file using the token to prove transfer auth.
func TestDeviceCodeE2E(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// ----- Step 0: Create htpasswd file BEFORE federation starts -----
	// The auth subsystem reads Server.UIPasswordFile at startup.
	// It requires an 'admin' user for configureAuthDB() to succeed.
	htpasswdDir := t.TempDir()
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	password := randomString(16)

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(fmt.Sprintf("admin:%s\n", string(hash))), 0600))
	require.NoError(t, param.Set(param.Server_UIPasswordFile.GetName(), htpasswdFile))

	// ----- Step 1: Start the federation -----
	tmpDir := t.TempDir()
	originConfig := fmt.Sprintf(deviceCodeOriginConfig, tmpDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.Greater(t, len(ft.Exports), 0, "Federation should have at least one export")

	serverURL := param.Server_ExternalWebUrl.GetString()
	issuerURL := serverURL // embedded issuer URL == server URL
	t.Logf("Federation started. Server URL: %s", serverURL)

	// Build an HTTP client that trusts the federation CA and stores cookies.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		Jar:       jar,
		// Do NOT follow redirects automatically — we need to inspect them.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// ----- Step 2: Dynamic Client Registration -----
	dcrURL := issuerURL + "/api/v1.0/issuer/oidc-cm"
	dcrPayload := `{
		"grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
		"token_endpoint_auth_method": "client_secret_post",
		"scope": "offline_access wlcg storage.read:/ storage.modify:/ storage.create:/"
	}`
	resp, err := httpClient.Post(dcrURL, "application/json", strings.NewReader(dcrPayload))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "DCR should return 201 Created")

	var dcrResp struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&dcrResp))
	require.NotEmpty(t, dcrResp.ClientID)
	require.NotEmpty(t, dcrResp.ClientSecret)
	t.Logf("DCR succeeded. client_id=%s", dcrResp.ClientID)

	// ----- Step 3: Device Authorization Request -----
	deviceAuthURL := issuerURL + "/api/v1.0/issuer/device_authorization"
	formData := url.Values{
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
		"scope":         {"offline_access wlcg storage.read:/ storage.modify:/ storage.create:/"},
	}
	resp, err = httpClient.PostForm(deviceAuthURL, formData)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Device authorization should return 200")

	var deviceResp struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&deviceResp))
	require.NotEmpty(t, deviceResp.DeviceCode)
	require.NotEmpty(t, deviceResp.UserCode)
	require.NotEmpty(t, deviceResp.VerificationURI)
	t.Logf("Device auth started. user_code=%s device_code=%s", deviceResp.UserCode, deviceResp.DeviceCode)

	// Confirm polling initially returns "authorization_pending".
	tokenURL := issuerURL + "/api/v1.0/issuer/token"
	pollForm := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceResp.DeviceCode},
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
	}
	resp, err = httpClient.PostForm(tokenURL, pollForm)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"Polling before approval should return 400: %s", string(body))
	assert.Contains(t, string(body), "authorization_pending")

	// ----- Step 4: Log in as admin -----
	loginURL := serverURL + "/api/v1.0/auth/login"
	loginForm := url.Values{
		"user":     {"admin"},
		"password": {password},
	}
	resp, err = httpClient.PostForm(loginURL, loginForm)
	require.NoError(t, err)
	loginBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed: %s", string(loginBody))

	// Verify the login cookie was set.
	serverParsed, _ := url.Parse(serverURL)
	var loginCookie *http.Cookie
	for _, c := range jar.Cookies(serverParsed) {
		if c.Name == "login" {
			loginCookie = c
			break
		}
	}
	require.NotNil(t, loginCookie, "Login cookie should be set after successful authentication")
	t.Log("Login succeeded; login cookie obtained")

	// ----- Step 5: Approve the device code -----
	// GET the device verification page to obtain the CSRF cookie.
	verifyPageURL := fmt.Sprintf("%s/api/v1.0/issuer/device?user_code=%s", issuerURL, deviceResp.UserCode)
	resp, err = httpClient.Get(verifyPageURL)
	require.NoError(t, err)
	pageBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// If we got a redirect to the login page, something is wrong with the auth middleware.
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Device-verify page should return 200 when logged in (got redirect or error); body: %s", string(pageBody))

	// Extract the CSRF cookie from the jar.
	// The CSRF cookie is scoped to /api/v1.0/issuer/device, so use a path-specific URL.
	csrfURL, _ := url.Parse(issuerURL + "/api/v1.0/issuer/device")
	var csrfCookie *http.Cookie
	for _, c := range jar.Cookies(csrfURL) {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	require.NotNil(t, csrfCookie, "CSRF cookie should be set on device-verify page")

	// Extract CSRF token from the HTML form (hidden field).
	csrfFromPage := extractCSRFFromHTML(t, string(pageBody))
	require.NotEmpty(t, csrfFromPage, "Should find CSRF token in HTML form")

	// POST approval.
	approveForm := url.Values{
		"user_code":  {deviceResp.UserCode},
		"action":     {"approve"},
		"csrf_token": {csrfFromPage},
	}
	resp, err = httpClient.PostForm(issuerURL+"/api/v1.0/issuer/device", approveForm)
	require.NoError(t, err)
	approveBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Device approval should return 200: %s", string(approveBody))
	assert.Contains(t, string(approveBody), "User Code Accepted",
		"Approval page should confirm approval: %s", string(approveBody))
	t.Log("Device code approved by user")

	// ----- Step 6: Poll for the access token -----
	var tokenRespData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}

	require.Eventually(t, func() bool {
		resp, err = httpClient.PostForm(tokenURL, pollForm)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			// Drain body to allow connection reuse
			_, _ = io.ReadAll(resp.Body)
			return false
		}
		return json.NewDecoder(resp.Body).Decode(&tokenRespData) == nil
	}, 60*time.Second, 6*time.Second, "Token endpoint should return an access token after approval")

	require.NotEmpty(t, tokenRespData.AccessToken, "Access token must not be empty")
	require.NotEmpty(t, tokenRespData.RefreshToken, "Refresh token must be present (offline_access requested)")
	t.Logf("Access token obtained. type=%s expires_in=%d scope=%s",
		tokenRespData.TokenType, tokenRespData.ExpiresIn, tokenRespData.Scope)

	// ----- Step 7: Validate WLCG token profile -----
	validateWLCGToken(t, tokenRespData.AccessToken, issuerURL)

	// ----- Step 8: Upload and download using the token -----
	testContent := "Hello from the device code E2E test!"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "device_code_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/device_code_test.txt",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	// Upload with the device-code-issued token.
	uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Upload with device-code token should succeed")
	require.NotEmpty(t, uploadResults)
	assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))
	t.Log("Upload succeeded using device-code-issued token")

	// Download the file back.
	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Download with device-code token should succeed")
	require.NotEmpty(t, downloadResults)
	assert.Equal(t, uploadResults[0].TransferredBytes, downloadResults[0].TransferredBytes)

	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent), "Downloaded content should match uploaded")
	t.Log("Download succeeded; content verified. E2E device code flow is fully working.")
}

// ----- Helper functions -----

// randomString generates a cryptographically random alphanumeric string.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// extractCSRFFromHTML pulls the CSRF token out of a hidden form field in the
// device-consent HTML page.  Looks for: <input ... name="csrf_token" value="...">
func extractCSRFFromHTML(t *testing.T, html string) string {
	t.Helper()
	re := regexp.MustCompile(`name="csrf_token"\s+value="([^"]+)"`)
	matches := re.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}
	// Also try the alternate attribute order
	re2 := regexp.MustCompile(`value="([^"]+)"\s+name="csrf_token"`)
	matches = re2.FindStringSubmatch(html)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

// validateWLCGToken decodes the JWT (without signature verification, since
// we're testing the structure) and asserts the required WLCG profile fields.
func validateWLCGToken(t *testing.T, tokenStr string, expectedIssuer string) {
	t.Helper()

	// Split JWT into parts
	parts := strings.Split(tokenStr, ".")
	require.Equal(t, 3, len(parts), "JWT must have 3 parts (header.payload.signature)")

	// Decode the payload (part[1])
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "JWT payload should be valid base64url")

	var claims map[string]interface{}
	require.NoError(t, json.Unmarshal(payload, &claims), "JWT payload should be valid JSON")

	// WLCG profile requirements:
	// - iss: must match the issuer URL
	// - sub: must be present
	// - iat, exp, nbf: must be present
	// - wlcg.ver: should be "1.0"
	// - scope: should contain storage scopes

	assert.Equal(t, expectedIssuer, claims["iss"], "Token issuer must match server URL")
	assert.NotEmpty(t, claims["sub"], "Token must have a subject")
	assert.NotNil(t, claims["iat"], "Token must have iat (issued-at)")
	assert.NotNil(t, claims["exp"], "Token must have exp (expiration)")

	// Check wlcg.ver claim
	wlcgVer, ok := claims["wlcg.ver"]
	assert.True(t, ok, "Token should have wlcg.ver claim")
	if ok {
		assert.Equal(t, "1.0", wlcgVer, "wlcg.ver should be '1.0'")
	}

	// Check scope claim contains storage scopes
	// The scope may be a string (space-separated) or an array of strings
	var scopeStr string
	switch s := claims["scope"].(type) {
	case string:
		scopeStr = s
	case []interface{}:
		parts := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				parts = append(parts, str)
			}
		}
		scopeStr = strings.Join(parts, " ")
	}
	assert.NotEmpty(t, scopeStr, "Token should have a scope claim")
	if scopeStr != "" {
		t.Logf("Token scopes: %s", scopeStr)
		// With our authz template giving admin read/write/create on /test,
		// and the broad scope expansion, we should see at least storage.read:/test
		assert.True(t,
			strings.Contains(scopeStr, "storage.read:") ||
				strings.Contains(scopeStr, "storage.modify:") ||
				strings.Contains(scopeStr, "storage.create:"),
			"Token scope should contain storage scopes, got: %s", scopeStr)
	}

	t.Logf("WLCG token validation passed: iss=%v sub=%v wlcg.ver=%v scope=%v",
		claims["iss"], claims["sub"], claims["wlcg.ver"], claims["scope"])
}
