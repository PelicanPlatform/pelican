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
// with three exports:
//
//   - /users: Accessible to any authenticated user under /users/$USER via the
//     $USER authorization template variable.  This demonstrates per-user path
//     scoping — each user receives scopes only for their own subdirectory.
//   - /projects: Accessible to members of the matching group via $GROUP.
//     This demonstrates group-based authorization.
//   - /restricted: Accessible only to "privilegeduser", used for the negative
//     authorization test (verifying that testuser receives a 403).
const deviceCodeOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /users
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
    - FederationPrefix: /projects
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
    - FederationPrefix: /restricted
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
Issuer:
  AuthorizationTemplates:
    - prefix: /users/$USER
      actions: ["read", "write", "create"]
    - prefix: /projects/$GROUP
      actions: ["read", "write", "create"]
    - prefix: /restricted
      actions: ["read", "write", "create"]
      users: ["privilegeduser"]
`

// TestDeviceCodeE2E exercises the entire OIDC device-code flow through a live
// Pelican federation using a non-admin user ("testuser") to verify that no
// admin-specific behavior leaks into the auth flow. It demonstrates:
//
//  1. Per-user path scoping via the $USER authorization template variable.
//  2. Group-based path scoping via the $GROUP template variable.
//  3. Positive authorization — upload/download within the user's own namespace
//     and within a group-scoped namespace.
//  4. Negative authorization — error when accessing a prefix the user lacks.
//  5. Token refresh — using refresh_token to obtain a new access token and
//     proving the refreshed token is valid for real transfers.
func TestDeviceCodeE2E(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// ----- Step 0: Create htpasswd file BEFORE federation starts -----
	// The auth subsystem requires an "admin" user in the htpasswd file for
	// configureAuthDB() to succeed.  We also add "testuser", the non-admin
	// account used for the entire device-code flow.
	htpasswdDir := t.TempDir()
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	adminPassword := randomString(16)
	testUserPassword := randomString(16)

	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	testUserHash, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	htpasswdContent := fmt.Sprintf("admin:%s\ntestuser:%s\n", string(adminHash), string(testUserHash))
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(htpasswdContent), 0600))
	require.NoError(t, param.Set(param.Server_UIPasswordFile.GetName(), htpasswdFile))

	// Create a JSON group file mapping testuser to groups.
	// This exercises the file-based group source (Issuer.GroupSource = "file").
	groupFileDir := t.TempDir()
	groupFilePath := filepath.Join(groupFileDir, "groups.json")
	groupData := `{"testuser": ["physics", "computing"], "admin": []}`
	require.NoError(t, os.WriteFile(groupFilePath, []byte(groupData), 0600))
	require.NoError(t, param.Set("Issuer.GroupSource", "file"))
	require.NoError(t, param.Set("Issuer.GroupFile", groupFilePath))

	// ----- Step 1: Start the federation -----
	tmpDir := t.TempDir()
	usersDir := filepath.Join(tmpDir, "users-store")
	projectsDir := filepath.Join(tmpDir, "projects-store")
	restrictedDir := filepath.Join(tmpDir, "restricted-store")
	require.NoError(t, os.MkdirAll(usersDir, 0755))
	require.NoError(t, os.MkdirAll(projectsDir, 0755))
	require.NoError(t, os.MkdirAll(restrictedDir, 0755))

	// Pre-create the testuser subdirectory so the origin can write files there.
	testUserDir := filepath.Join(usersDir, "testuser")
	require.NoError(t, os.MkdirAll(testUserDir, 0755))

	// Pre-create group subdirectories for $GROUP-scoped writes.
	physicsDir := filepath.Join(projectsDir, "physics")
	require.NoError(t, os.MkdirAll(physicsDir, 0755))

	originConfig := fmt.Sprintf(deviceCodeOriginConfig, usersDir, projectsDir, restrictedDir)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.GreaterOrEqual(t, len(ft.Exports), 3, "Federation should have at least three exports")

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

	// ----- Step 4: Log in as testuser (non-admin) -----
	loginURL := serverURL + "/api/v1.0/auth/login"
	loginForm := url.Values{
		"user":     {"testuser"},
		"password": {testUserPassword},
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
	t.Log("Login succeeded as testuser; login cookie obtained")

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
	t.Log("Device code approved by testuser")

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

	// ----- Step 7: Validate WLCG token profile and $USER-scoped claims -----
	claims := validateWLCGToken(t, tokenRespData.AccessToken, issuerURL)

	// Verify the subject is "testuser", not "admin".
	assert.Equal(t, "testuser", claims["sub"],
		"Token subject should be testuser, not admin")

	// Verify scopes contain the $USER-expanded path /users/testuser.
	scopeStr := extractScopeString(claims)
	assert.Contains(t, scopeStr, "storage.read:/users/testuser",
		"$USER template should expand to testuser in storage.read scope")
	assert.Contains(t, scopeStr, "storage.modify:/users/testuser",
		"$USER template should expand to testuser in storage.modify scope")
	assert.Contains(t, scopeStr, "storage.create:/users/testuser",
		"$USER template should expand to testuser in storage.create scope")

	// Ensure no scopes leak for /restricted.
	assert.NotContains(t, scopeStr, "/restricted",
		"Token should NOT contain scopes for /restricted (testuser is not authorized)")

	// Verify group-scoped paths from the $GROUP template.
	// testuser belongs to groups ["physics", "computing"], so the token should
	// contain scopes for /projects/physics and /projects/computing.
	assert.Contains(t, scopeStr, "storage.read:/projects/physics",
		"$GROUP template should produce storage.read:/projects/physics")
	assert.Contains(t, scopeStr, "storage.modify:/projects/physics",
		"$GROUP template should produce storage.modify:/projects/physics")
	assert.Contains(t, scopeStr, "storage.read:/projects/computing",
		"$GROUP template should produce storage.read:/projects/computing")

	// Verify wlcg.groups claim contains the user's groups.
	var groupsClaim []string
	if rawGroups, ok := claims["wlcg.groups"]; ok {
		switch g := rawGroups.(type) {
		case []interface{}:
			for _, v := range g {
				if s, ok := v.(string); ok {
					groupsClaim = append(groupsClaim, s)
				}
			}
		case string:
			groupsClaim = strings.Split(g, " ")
		}
	}
	assert.Contains(t, groupsClaim, "physics", "wlcg.groups should contain physics")
	assert.Contains(t, groupsClaim, "computing", "wlcg.groups should contain computing")

	t.Logf("WLCG token profile valid; $USER and $GROUP templates expanded correctly for testuser")

	// ----- Step 8: Upload and download using the token (positive auth) -----
	testContent := "Hello from the device code E2E test!"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "device_code_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	uploadURL := fmt.Sprintf("pelican://%s:%d/users/testuser/device_code_test.txt",
		hostname, port)

	// Upload with the device-code-issued token.
	uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Upload to /users/testuser should succeed with $USER-scoped token")
	require.NotEmpty(t, uploadResults)
	assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))
	t.Log("Upload succeeded to /users/testuser/ using $USER-scoped token")

	// Download the file back.
	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Download from /users/testuser should succeed with $USER-scoped token")
	require.NotEmpty(t, downloadResults)
	assert.Equal(t, uploadResults[0].TransferredBytes, downloadResults[0].TransferredBytes)

	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent), "Downloaded content should match uploaded")
	t.Log("Download succeeded; content verified")

	// ----- Step 8b: Group-based upload/download (/projects/physics) -----
	groupContent := "Data for the physics project group"
	groupFile := filepath.Join(localTmpDir, "group_test.txt")
	require.NoError(t, os.WriteFile(groupFile, []byte(groupContent), 0644))

	groupUploadURL := fmt.Sprintf("pelican://%s:%d/projects/physics/group_test.txt",
		hostname, port)
	groupUploadResults, err := client.DoPut(ft.Ctx, groupFile, groupUploadURL, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Upload to /projects/physics should succeed with group-scoped token")
	require.NotEmpty(t, groupUploadResults)
	assert.Greater(t, groupUploadResults[0].TransferredBytes, int64(0))

	groupDownloadFile := filepath.Join(localTmpDir, "group_downloaded.txt")
	groupDownloadResults, err := client.DoGet(ft.Ctx, groupUploadURL, groupDownloadFile, false,
		client.WithToken(tokenRespData.AccessToken))
	require.NoError(t, err, "Download from /projects/physics should succeed")
	require.NotEmpty(t, groupDownloadResults)
	groupDownloaded, err := os.ReadFile(groupDownloadFile)
	require.NoError(t, err)
	assert.Equal(t, groupContent, string(groupDownloaded),
		"Downloaded group content should match uploaded")
	t.Log("Group-based upload/download succeeded for /projects/physics")

	// ----- Step 9: Negative authorization — access /restricted -----
	// The testuser's token is scoped to /users/testuser and has NO scopes for
	// /restricted (which requires the "privilegeduser" account). The origin
	// must reject the request.
	//
	// We use a raw HTTP GET against the origin's data endpoint rather than the
	// Pelican client, because the client falls back to the origin's local
	// signing key when the supplied token is insufficient.
	//
	// First, pre-create a file in the restricted storage directory so that a
	// successful GET would return data (ruling out 404).
	require.NoError(t, os.WriteFile(filepath.Join(restrictedDir, "secret.txt"),
		[]byte("top secret"), 0644))

	restrictedDataURL := fmt.Sprintf("%s/api/v1.0/origin/data/restricted/secret.txt", serverURL)
	req, err := http.NewRequest("GET", restrictedDataURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tokenRespData.AccessToken)
	negResp, err := httpClient.Do(req)
	require.NoError(t, err)
	_, _ = io.ReadAll(negResp.Body)
	negResp.Body.Close()
	assert.True(t, negResp.StatusCode == http.StatusForbidden || negResp.StatusCode == http.StatusUnauthorized,
		"GET /restricted with testuser token should return 401 or 403, got %d", negResp.StatusCode)
	t.Logf("Negative test passed: origin returned %d for /restricted with testuser's token", negResp.StatusCode)

	// ----- Step 10: Token refresh -----
	// Use the refresh_token grant to obtain a new access token, then prove
	// the refreshed token is valid for real data transfers.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokenRespData.RefreshToken},
		"client_id":     {dcrResp.ClientID},
		"client_secret": {dcrResp.ClientSecret},
	}
	resp, err = httpClient.PostForm(tokenURL, refreshForm)
	require.NoError(t, err)
	refreshBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Token refresh should return 200: %s", string(refreshBody))

	var refreshRespData struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(refreshBody, &refreshRespData))
	require.NotEmpty(t, refreshRespData.AccessToken, "Refreshed access token must not be empty")
	assert.NotEqual(t, tokenRespData.AccessToken, refreshRespData.AccessToken,
		"Refreshed access token should differ from the original")
	t.Logf("Token refresh succeeded. New token type=%s expires_in=%d",
		refreshRespData.TokenType, refreshRespData.ExpiresIn)

	// Validate the refreshed token also conforms to WLCG profile.
	refreshClaims := validateWLCGToken(t, refreshRespData.AccessToken, issuerURL)
	assert.Equal(t, "testuser", refreshClaims["sub"],
		"Refreshed token subject should still be testuser")

	// Prove the refreshed token works for a real transfer.
	refreshContent := "Content uploaded with refreshed token"
	refreshFile := filepath.Join(localTmpDir, "refreshed_upload.txt")
	require.NoError(t, os.WriteFile(refreshFile, []byte(refreshContent), 0644))

	refreshUploadURL := fmt.Sprintf("pelican://%s:%d/users/testuser/refreshed_upload.txt",
		hostname, port)
	refreshUploadResults, err := client.DoPut(ft.Ctx, refreshFile, refreshUploadURL, false,
		client.WithToken(refreshRespData.AccessToken))
	require.NoError(t, err, "Upload with refreshed token should succeed")
	require.NotEmpty(t, refreshUploadResults)
	assert.Greater(t, refreshUploadResults[0].TransferredBytes, int64(0))

	refreshDownloadFile := filepath.Join(localTmpDir, "refreshed_downloaded.txt")
	refreshDownloadResults, err := client.DoGet(ft.Ctx, refreshUploadURL, refreshDownloadFile, false,
		client.WithToken(refreshRespData.AccessToken))
	require.NoError(t, err, "Download with refreshed token should succeed")
	require.NotEmpty(t, refreshDownloadResults)

	refreshDownloaded, err := os.ReadFile(refreshDownloadFile)
	require.NoError(t, err)
	assert.Equal(t, refreshContent, string(refreshDownloaded),
		"Content downloaded with refreshed token should match uploaded")
	t.Log("Token refresh flow verified: refreshed access token is valid for real transfers")

	t.Log("E2E device code flow complete: non-admin user, $USER templates, $GROUP templates, negative authz, token refresh — all verified")
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

// extractScopeString extracts the scope claim from JWT claims as a single
// space-separated string, handling both string and array representations.
func extractScopeString(claims map[string]interface{}) string {
	switch s := claims["scope"].(type) {
	case string:
		return s
	case []interface{}:
		parts := make([]string, 0, len(s))
		for _, v := range s {
			if str, ok := v.(string); ok {
				parts = append(parts, str)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// validateWLCGToken decodes the JWT (without signature verification, since
// we're testing the structure) and asserts the required WLCG profile fields.
// It returns the claims map so callers can make additional assertions.
func validateWLCGToken(t *testing.T, tokenStr string, expectedIssuer string) map[string]interface{} {
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
	// - iat, exp: must be present
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
	scopeStr := extractScopeString(claims)
	assert.NotEmpty(t, scopeStr, "Token should have a scope claim")
	if scopeStr != "" {
		t.Logf("Token scopes: %s", scopeStr)
		assert.True(t,
			strings.Contains(scopeStr, "storage.read:") ||
				strings.Contains(scopeStr, "storage.modify:") ||
				strings.Contains(scopeStr, "storage.create:"),
			"Token scope should contain storage scopes, got: %s", scopeStr)
	}

	t.Logf("WLCG token validation passed: iss=%v sub=%v wlcg.ver=%v",
		claims["iss"], claims["sub"], claims["wlcg.ver"])

	return claims
}
