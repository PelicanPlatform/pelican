//go:build !windows

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

package fed_tests

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
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
	oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// clientDeviceCodeOriginConfig enables the embedded OIDC issuer on a POSIXv2
// origin with a single /data export.
//
// NOTE: AuthorizationTemplate prefix is /$USER (namespace-relative), NOT /data/$USER.
// The client requests scopes relative to the namespace (e.g. storage.create:/testuser)
// and XRootD validates with base_path=/data, so scope paths must also be namespace-relative.
const clientDeviceCodeOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  Exports:
    - FederationPrefix: /data
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings"]
Issuer:
  AuthorizationTemplates:
    - prefix: /$USER
      actions: ["read", "write", "create"]
`

// TestClientDeviceCodeE2E exercises the OIDC device-code flow through the
// Pelican client library functions — the same code paths used by the real
// CLI — against a live federation with the embedded issuer.
//
// Unlike TestDeviceCodeE2E (which uses raw HTTP calls), this test calls:
//   - config.GetIssuerMetadata          (OIDC discovery)
//   - oauth2.DCRPConfig.Register       (Dynamic Client Registration)
//   - oauth2.Config.AuthDevice         (device authorization request)
//   - oauth2.RetrieveToken             (token endpoint polling)
//
// These are the exact functions invoked internally by the client's
// AcquireToken / registerClient pipeline.  This test verifies that
// the embedded issuer's endpoints are wire-compatible with the client.
func TestClientDeviceCodeE2E(t *testing.T) {
	ft, testUserPassword, _ := setupFedAndUsers(t)

	serverURL := param.Server_ExternalWebUrl.GetString()
	t.Logf("Federation started.  Server URL: %s", serverURL)

	// ---- Step 2: OIDC Discovery (config.GetIssuerMetadata) ----
	// This is what the client's registerClient/AcquireToken calls internally
	// when it receives the issuer URL from the director's response headers.
	issuerMeta, err := config.GetIssuerMetadata(serverURL)
	require.NoError(t, err, "GetIssuerMetadata should succeed against the origin's root /.well-known/openid-configuration")
	require.NotEmpty(t, issuerMeta.RegistrationURL, "Discovery must expose registration_endpoint")
	require.NotEmpty(t, issuerMeta.DeviceAuthURL, "Discovery must expose device_authorization_endpoint")
	require.NotEmpty(t, issuerMeta.TokenURL, "Discovery must expose token_endpoint")
	require.True(t, deviceCodeGrantSupported(issuerMeta.GrantTypes),
		"Discovery must list urn:ietf:params:oauth:grant-type:device_code in grant_types_supported")
	t.Logf("Discovery OK: registration=%s  device_auth=%s  token=%s",
		issuerMeta.RegistrationURL, issuerMeta.DeviceAuthURL, issuerMeta.TokenURL)

	// ---- Step 3: Dynamic Client Registration (oauth2.DCRPConfig.Register) ----
	// This mirrors the client's registerClient() function exactly.
	drcp := oauth2.DCRPConfig{
		ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
		Transport:                     config.GetTransport(),
		Metadata: oauth2.Metadata{
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			ResponseTypes:           []string{"code"},
			ClientName:              "OSDF Command Line Client",
			Scopes:                  []string{"offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"},
		},
	}

	dcrResp, err := drcp.Register()
	require.NoError(t, err, "DCR via oauth2.DCRPConfig.Register should succeed")
	require.NotEmpty(t, dcrResp.ClientID, "DCR must return a client_id")
	require.NotEmpty(t, dcrResp.ClientSecret, "DCR must return a client_secret")
	t.Logf("DCR OK: client_id=%s", dcrResp.ClientID)

	// ---- Step 4: Device Authorization (oauth2.Config.AuthDevice) ----
	// Build the same oauth2.Config that AcquireToken would build.
	oauth2Config := oauth2.Config{
		ClientID:     dcrResp.ClientID,
		ClientSecret: dcrResp.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       issuerMeta.AuthURL,
			TokenURL:      issuerMeta.TokenURL,
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
		},
		Scopes: []string{"wlcg", "offline_access", "storage.read:/", "storage.modify:/", "storage.create:/"},
	}

	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(ft.Ctx, oauth2.HTTPClient, httpClient)

	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	require.NoError(t, err, "AuthDevice should succeed against the embedded issuer")
	require.NotEmpty(t, deviceAuth.DeviceCode, "AuthDevice must return a device_code")
	require.NotEmpty(t, deviceAuth.UserCode, "AuthDevice must return a user_code")
	require.Greater(t, deviceAuth.ExpiresIn, 0, "AuthDevice must return a positive expires_in")
	t.Logf("AuthDevice OK: user_code=%s  device_code=%s  expires_in=%d",
		deviceAuth.UserCode, deviceAuth.DeviceCode, deviceAuth.ExpiresIn)

	// ---- Step 5: Simulate user login + approval ----
	simulateUserApproval(t, serverURL, deviceAuth.UserCode, testUserPassword)

	// ---- Step 6: Token exchange via oauth2.RetrieveToken ----
	// This is the exact same call the client's Poll() loop makes.
	pollValues := url.Values{
		"client_id":   {dcrResp.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceAuth.DeviceCode},
	}

	var accessToken, refreshToken string
	require.Eventually(t, func() bool {
		tok, err := oauth2.RetrieveToken(ctx, dcrResp.ClientID, dcrResp.ClientSecret,
			issuerMeta.TokenURL, pollValues)
		if err != nil {
			return false
		}
		accessToken = tok.AccessToken
		refreshToken = tok.RefreshToken
		return true
	}, 30*time.Second, 2*time.Second, "RetrieveToken should return an access token after approval")

	require.NotEmpty(t, accessToken, "Access token must not be empty")
	require.NotEmpty(t, refreshToken, "Refresh token must be present (offline_access requested)")
	t.Logf("Token OK: access_token length=%d", len(accessToken))

	// Validate the token has WLCG claims and correct subject
	claims := validateWLCGToken(t, accessToken, serverURL)
	assert.Equal(t, "testuser", claims["sub"], "Token subject should be testuser")
	scopeStr := extractScopeString(claims)
	assert.Contains(t, scopeStr, "storage.read:/testuser",
		"$USER template should expand in storage.read scope")

	// ---- Step 7: Upload + download with the client library ----
	// Use client.DoPut / client.DoGet — the real transfer functions.
	testContent := "Hello from the client device code E2E test!"
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "client_e2e_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte(testContent), 0644))

	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	uploadURL := fmt.Sprintf("pelican://%s:%d/data/testuser/client_e2e_test.txt", hostname, port)

	uploadResults, err := client.DoPut(ft.Ctx, localFile, uploadURL, false,
		client.WithToken(accessToken))
	require.NoError(t, err, "DoPut should succeed with the device-code-issued token")
	require.NotEmpty(t, uploadResults)
	assert.Greater(t, uploadResults[0].TransferredBytes, int64(0))
	t.Log("Upload OK via client.DoPut")

	downloadFile := filepath.Join(localTmpDir, "downloaded.txt")
	downloadResults, err := client.DoGet(ft.Ctx, uploadURL, downloadFile, false,
		client.WithToken(accessToken))
	require.NoError(t, err, "DoGet should succeed with the device-code-issued token")
	require.NotEmpty(t, downloadResults)

	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent), "Downloaded content should match")
	t.Log("Download OK via client.DoGet; content verified")

	// ---- Step 8: Token refresh via oauth2.RetrieveToken (refresh_token grant) ----
	refreshValues := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	refreshedTok, err := oauth2.RetrieveToken(ctx, dcrResp.ClientID, dcrResp.ClientSecret,
		issuerMeta.TokenURL, refreshValues)
	require.NoError(t, err, "Token refresh should succeed")
	require.NotEmpty(t, refreshedTok.AccessToken, "Refreshed access token must not be empty")
	assert.NotEqual(t, accessToken, refreshedTok.AccessToken,
		"Refreshed token should differ from original")
	t.Logf("Refresh OK: new access_token length=%d", len(refreshedTok.AccessToken))

	// Prove the refreshed token works for a transfer
	refreshContent := "Content uploaded with refreshed token"
	refreshFile := filepath.Join(localTmpDir, "refreshed.txt")
	require.NoError(t, os.WriteFile(refreshFile, []byte(refreshContent), 0644))

	refreshUploadURL := fmt.Sprintf("pelican://%s:%d/data/testuser/refreshed.txt", hostname, port)
	_, err = client.DoPut(ft.Ctx, refreshFile, refreshUploadURL, false,
		client.WithToken(refreshedTok.AccessToken))
	require.NoError(t, err, "DoPut with refreshed token should succeed")

	refreshDown := filepath.Join(localTmpDir, "refreshed_down.txt")
	_, err = client.DoGet(ft.Ctx, refreshUploadURL, refreshDown, false,
		client.WithToken(refreshedTok.AccessToken))
	require.NoError(t, err, "DoGet with refreshed token should succeed")
	refreshedContent, err := os.ReadFile(refreshDown)
	require.NoError(t, err)
	assert.Equal(t, refreshContent, string(refreshedContent))
	t.Log("Refreshed token transfer verified")

	t.Log("Client device code E2E complete: discovery, DCR, device auth, token exchange, transfers, refresh — all verified via client library functions")
}

// deviceCodeGrantSupported checks if the device code grant type is in the list.
func deviceCodeGrantSupported(grants []string) bool {
	for _, g := range grants {
		if g == "urn:ietf:params:oauth:grant-type:device_code" {
			return true
		}
	}
	return false
}

// setupFedAndUsers creates a federation with an embedded issuer, htpasswd, and
// groups. Returns the FedTest, the test user password, and the data directory.
func setupFedAndUsers(t *testing.T) (ft *fed_test_utils.FedTest, testUserPassword string, dataDir string) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

	htpasswdDir := t.TempDir()
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	adminPassword := randomString(16)
	testUserPassword = randomString(16)

	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	testUserHash, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	htpasswdContent := fmt.Sprintf("admin:%s\ntestuser:%s\n", string(adminHash), string(testUserHash))
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(htpasswdContent), 0600))
	require.NoError(t, param.Set(param.Server_UIPasswordFile.GetName(), htpasswdFile))

	groupFileDir := t.TempDir()
	groupFilePath := filepath.Join(groupFileDir, "groups.json")
	require.NoError(t, os.WriteFile(groupFilePath, []byte(`{"testuser": [], "admin": []}`), 0600))
	require.NoError(t, param.Set("Issuer.GroupSource", "file"))
	require.NoError(t, param.Set("Issuer.GroupFile", groupFilePath))

	tmpDir := t.TempDir()
	dataDir = filepath.Join(tmpDir, "data-store")
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "testuser"), 0755))

	originConfig := fmt.Sprintf(clientDeviceCodeOriginConfig, dataDir)
	ft = fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	return
}

// simulateUserApproval logs in as testuser and approves the given device user_code.
//
// This simulates the real browser flow:
//  1. GET the device verification page (unauthenticated) — expect redirect to login with nextUrl
//  2. POST login with nextUrl — verify the response echoes nextUrl back
//  3. Follow nextUrl to reach the verification page
//  4. Extract CSRF token and POST approval
func simulateUserApproval(t *testing.T, serverURL, userCode, password string) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	browserClient := &http.Client{
		Transport: config.GetTransport(),
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: GET the device verification page while unauthenticated.
	// The server should redirect us to the login page with nextUrl pointing
	// back at the device verification page.
	verifyPageURL := fmt.Sprintf("%s/api/v1.0/issuer/device?user_code=%s", serverURL, userCode)
	resp, err := browserClient.Get(verifyPageURL)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode,
		"Unauthenticated GET to device page should redirect to login")

	redirectLoc := resp.Header.Get("Location")
	require.NotEmpty(t, redirectLoc, "Redirect should include a Location header")
	redirectURL, err := url.Parse(redirectLoc)
	require.NoError(t, err)
	nextUrl := redirectURL.Query().Get("nextUrl")
	require.NotEmpty(t, nextUrl, "Login redirect should include nextUrl query parameter")
	assert.Contains(t, nextUrl, "user_code="+userCode,
		"nextUrl should point back to the device verification page with the user_code")
	t.Logf("Unauthenticated redirect OK: nextUrl=%s", nextUrl)

	// Step 2: POST login with nextUrl — verify the response echoes it back.
	loginURL := fmt.Sprintf("%s/api/v1.0/auth/login?nextUrl=%s", serverURL, url.QueryEscape(nextUrl))
	loginForm := url.Values{"user": {"testuser"}, "password": {password}}
	resp, err = browserClient.PostForm(loginURL, loginForm)
	require.NoError(t, err)
	loginBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")

	// Verify that the login response includes the nextUrl so the frontend
	// can redirect the user back to the device verification page.
	var loginResp map[string]interface{}
	require.NoError(t, json.Unmarshal(loginBody, &loginResp), "Login response should be valid JSON")
	respNextUrl, ok := loginResp["nextUrl"].(string)
	require.True(t, ok, "Login response must include nextUrl field")
	assert.Contains(t, respNextUrl, "user_code="+userCode,
		"nextUrl in login response should contain the user_code")
	t.Logf("Login OK with nextUrl echoed back: %s", respNextUrl)

	// Step 3: Follow nextUrl to reach the verification page (now authenticated).
	followURL := serverURL + respNextUrl
	resp, err = browserClient.Get(followURL)
	require.NoError(t, err)
	pageBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Verification page should return 200 after login")

	// Step 4: Extract CSRF and submit approval.
	csrfURL, _ := url.Parse(serverURL + "/api/v1.0/issuer/device")
	var csrfCookie *http.Cookie
	for _, c := range jar.Cookies(csrfURL) {
		if c.Name == "csrf_token" {
			csrfCookie = c
			break
		}
	}
	require.NotNil(t, csrfCookie, "CSRF cookie should be set")
	csrfFromPage := extractCSRFFromHTML(t, string(pageBody))
	require.NotEmpty(t, csrfFromPage, "CSRF token should be in HTML form")

	approveForm := url.Values{
		"user_code":  {userCode},
		"action":     {"approve"},
		"csrf_token": {csrfFromPage},
	}
	resp, err = browserClient.PostForm(serverURL+"/api/v1.0/issuer/device", approveForm)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Approval should return 200: %s", string(body))
	assert.Contains(t, string(body), "User Code Accepted")
}

// TestClientAcquireTokenE2E exercises the full CLI `pelican object put` path
// against the embedded issuer using a forked subprocess.
//
// Running the client as a subprocess is essential: the in-process client
// shares the server's issuer private key, so the generateToken shortcut
// always succeeds, bypassing OAuth2.  A separate process has no access to
// the server's key, forcing the real flow:
//
//	registerClient → oauth2.AcquireToken → AuthDevice → Poll → token → DoPut
//
// The test monitors the subprocess's stderr for the verification URL,
// extracts the user_code, and simulates user approval via HTTP.
func TestClientAcquireTokenE2E(t *testing.T) {
	_, testUserPassword, _ := setupFedAndUsers(t)

	serverURL := param.Server_ExternalWebUrl.GetString()
	discoveryURL := param.Federation_DiscoveryUrl.GetString()

	// Get the once-built pelican CLI binary
	cliPath := getPelicanBinary(t)

	// Prepare a local file to upload
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "acquire_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte("AcquireToken E2E content"), 0644))

	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	uploadURL := fmt.Sprintf("pelican://%s:%d/data/testuser/acquire_test.txt", hostname, port)

	// Launch: pelican object put <localfile> <pelican-url>
	// No --token flag ⇒ the client must acquire one via OAuth2.
	cmd := exec.Command(cliPath, "object", "put", localFile, uploadURL)
	cmd.Env = append(os.Environ(),
		"PELICAN_FEDERATION_DISCOVERYURL="+discoveryURL,
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_SKIP_TERMINAL_CHECK=1",
		"PELICAN_LOGGING_DISABLEPROGRESSBARS=true",
		// Point the client credential file at a fresh temp location so the
		// subprocess doesn't pick up (and try to decrypt) a pre-existing
		// encrypted credential file from the user's home directory.
		"PELICAN_CLIENT_CREDENTIALFILE="+filepath.Join(localTmpDir, "client-credentials.pem"),
	)

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)

	require.NoError(t, cmd.Start(), "failed to start pelican subprocess")

	// Drain stdout in the background so the pipe doesn't block.
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			t.Logf("CLI stdout: %s", scanner.Text())
		}
	}()

	// Monitor stderr for verification URLs containing user codes.
	// The CLI may trigger multiple device code flows (e.g. one for
	// storage.create, another for storage.read used by the pre-upload
	// PROPFIND check), so we must approve every code that appears.
	userCodeCh := make(chan string, 4)
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		userCodeRe := regexp.MustCompile(`user_code=([A-Z0-9-]+)`)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("CLI stderr: %s", line)
			if matches := userCodeRe.FindStringSubmatch(line); len(matches) > 1 {
				userCodeCh <- matches[1]
			}
		}
		close(userCodeCh)
	}()

	// Keep approving user codes until the subprocess exits or we time out.
	cmdDone := make(chan error, 1)
	go func() { cmdDone <- cmd.Wait() }()

	approvalTimeout := time.After(120 * time.Second)
	approvedCount := 0
	for {
		select {
		case userCode, ok := <-userCodeCh:
			if !ok {
				goto done // stderr closed (subprocess exited)
			}
			approvedCount++
			t.Logf("Intercepted user_code #%d from CLI stderr: %s", approvedCount, userCode)
			simulateUserApproval(t, serverURL, userCode, testUserPassword)
		case err = <-cmdDone:
			goto done
		case <-approvalTimeout:
			_ = cmd.Process.Kill()
			t.Fatal("Timed out waiting for CLI to complete")
		}
	}
done:
	require.True(t, approvedCount > 0, "expected at least one user_code to approve")
	require.NoError(t, err, "pelican object put should succeed via the OAuth2 device code flow")
	t.Logf("CLI subprocess completed successfully — approved %d device code(s)", approvedCount)

	// Verify the file is actually present by downloading it with a server-generated token.
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)
	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/testuser"))
	readToken, err := tokConf.CreateToken()
	require.NoError(t, err)

	downloadFile := filepath.Join(localTmpDir, "acquire_down.txt")
	downloadURL := fmt.Sprintf("pelican://%s:%d/data/testuser/acquire_test.txt", hostname, port)
	_, err = client.DoGet(context.Background(), downloadURL, downloadFile, false,
		client.WithToken(readToken))
	require.NoError(t, err, "DoGet should succeed for the uploaded file")

	content, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, "AcquireToken E2E content", string(content),
		"Downloaded content must match the uploaded content")
	t.Log("Upload content verified via download — full CLI device code E2E passed")
}

// TestClientAcquireTokenScopeE2E verifies that the scope computation in
// oauth2.AcquireToken produces scopes that the embedded issuer accepts.
// This specifically tests the path where storageScopes are joined with
// spaces into a single string (e.g. "storage.create:/testuser storage.read:/testuser")
// and passed as one entry in the Scopes slice.
func TestClientAcquireTokenScopeE2E(t *testing.T) {
	ft, testUserPassword, _ := setupFedAndUsers(t)
	serverURL := param.Server_ExternalWebUrl.GetString()

	issuerMeta, err := config.GetIssuerMetadata(serverURL)
	require.NoError(t, err)

	// Register a client (same as registerClient)
	drcp := oauth2.DCRPConfig{
		ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
		Transport:                     config.GetTransport(),
		Metadata: oauth2.Metadata{
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			ResponseTypes:           []string{"code"},
			ClientName:              "OSDF Command Line Client",
			Scopes:                  []string{"offline_access", "wlcg", "storage.read:/", "storage.modify:/", "storage.create:/"},
		},
	}
	dcrResp, err := drcp.Register()
	require.NoError(t, err)

	// Use the exact scope format that oauth2.AcquireToken builds:
	// storage scopes joined into a single string
	joinedStorageScope := strings.Join([]string{
		"storage.create:/testuser",
		"storage.read:/testuser",
	}, " ")
	oauth2Config := oauth2.Config{
		ClientID:     dcrResp.ClientID,
		ClientSecret: dcrResp.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       issuerMeta.AuthURL,
			TokenURL:      issuerMeta.TokenURL,
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
		},
		// This matches how oauth2.AcquireToken builds the scope list:
		// ["wlcg", "offline_access", "storage.create:/path storage.read:/path"]
		Scopes: []string{"wlcg", "offline_access", joinedStorageScope},
	}

	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(ft.Ctx, oauth2.HTTPClient, httpClient)

	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	require.NoError(t, err, "AuthDevice with joined storage scopes should succeed")
	require.NotEmpty(t, deviceAuth.DeviceCode)
	t.Logf("AuthDevice with joined scopes OK: user_code=%s", deviceAuth.UserCode)

	// Approve
	simulateUserApproval(t, serverURL, deviceAuth.UserCode, testUserPassword)

	// Poll for token
	pollValues := url.Values{
		"client_id":   {dcrResp.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceAuth.DeviceCode},
	}

	var accessToken string
	require.Eventually(t, func() bool {
		tok, err := oauth2.RetrieveToken(ctx, dcrResp.ClientID, dcrResp.ClientSecret,
			issuerMeta.TokenURL, pollValues)
		if err != nil {
			return false
		}
		accessToken = tok.AccessToken
		return true
	}, 30*time.Second, 2*time.Second)

	require.NotEmpty(t, accessToken)

	// Validate scopes
	claims := validateWLCGToken(t, accessToken, serverURL)
	assert.Equal(t, "testuser", claims["sub"])
	scopeStr := extractScopeString(claims)
	assert.Contains(t, scopeStr, "storage.create:/testuser",
		"Token should have storage.create:/testuser scope from joined scope format")
	assert.Contains(t, scopeStr, "storage.read:/testuser",
		"Token should have storage.read:/testuser scope from joined scope format")
	t.Log("Joined scope format test passed")

	// Use token for transfer
	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, "scope_test.txt")
	require.NoError(t, os.WriteFile(localFile, []byte("scope test content"), 0644))
	uploadURL := fmt.Sprintf("pelican://%s:%d/data/testuser/scope_test.txt", hostname, port)

	_, err = client.DoPut(ft.Ctx, localFile, uploadURL, false,
		client.WithToken(accessToken))
	require.NoError(t, err, "DoPut with joined-scope token should succeed")
	t.Log("Joined-scope token accepted for transfer")
}
