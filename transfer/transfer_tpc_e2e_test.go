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

package transfer_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
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
	"runtime"
	"strings"
	"sync"
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
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	// testPelicanBinary holds the path to the built pelican binary for tests
	testPelicanBinary string
	// testTempDir holds the temp directory for the test binary
	testTempDir string
	// buildOnce ensures we only build the binary once across all tests
	buildOnce sync.Once
	// buildErr stores any error from building the binary
	buildErr error
)

// deviceApproval carries an intercepted device user_code together with the
// issuer namespace it belongs to, so the test approves it against the correct
// embedded-issuer provider (e.g. /.transfer for transfer-auth, /data for the
// storage token-exchange flow).
type deviceApproval struct {
	userCode  string
	namespace string
}

// getPelicanBinary builds the pelican binary once and returns its path.
func getPelicanBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binaryName := "pelican"
		if runtime.GOOS == "windows" {
			binaryName = "pelican.exe"
		}
		var err error
		testTempDir, err = os.MkdirTemp("", "pelican-tpc-test-*")
		if err != nil {
			buildErr = fmt.Errorf("failed to create temp directory: %w", err)
			return
		}
		testPelicanBinary = filepath.Join(testTempDir, binaryName)

		// The cmd package is gated behind the client/server build tags; build the
		// client-flavored binary (matching the real `pelican` binary) so the
		// object/transfer subcommands are present.
		buildCmd := exec.Command("go", "build", "-tags", "client", "-buildvcs=false", "-o", testPelicanBinary, "../cmd")
		buildCmd.Env = os.Environ()
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			buildErr = fmt.Errorf("failed to build pelican binary: %w\nOutput: %s", err, string(buildOutput))
		}
	})

	if buildErr != nil {
		t.Fatalf("Failed to build pelican binary: %v", buildErr)
	}

	return testPelicanBinary
}

// randomString generates a cryptographically random alphanumeric string.
func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// simulateUserApproval handles the device-code approval flow by logging in
// and approving the device code via the issuer's API.
func simulateUserApproval(t *testing.T, serverURL, namespace, userCode, password string) {
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

	nsBase := serverURL + "/api/v1.0/issuer/ns" + namespace
	verifyPageURL := fmt.Sprintf("%s/device?user_code=%s", nsBase, userCode)
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
	returnURL := redirectURL.Query().Get("returnURL")
	require.NotEmpty(t, returnURL, "Login redirect should include returnURL query parameter")
	assert.Contains(t, returnURL, "user_code="+userCode,
		"returnURL should reference the device verification page with the user_code")

	loginURL := serverURL + "/api/v1.0/auth/login"
	loginForm := url.Values{"user": {"testuser"}, "password": {password}}
	resp, err = browserClient.PostForm(loginURL, loginForm)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")

	resp, err = browserClient.Get(verifyPageURL)
	require.NoError(t, err)
	pageBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Device verify API should return 200 after login")

	var verifyResp struct {
		CSRFToken string `json:"csrf_token"`
		Namespace string `json:"namespace"`
	}
	require.NoError(t, json.Unmarshal(pageBody, &verifyResp), "GET /device should return valid JSON")
	require.NotEmpty(t, verifyResp.CSRFToken, "CSRF token should be returned in JSON response")

	approvePayload, _ := json.Marshal(map[string]string{
		"user_code":  userCode,
		"action":     "approve",
		"csrf_token": verifyResp.CSRFToken,
	})
	resp, err = browserClient.Post(nsBase+"/device", "application/json", bytes.NewReader(approvePayload))
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Approval should return 200: %s", string(body))

	var approveResp struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(body, &approveResp), "POST /device should return valid JSON")
	assert.Equal(t, "approved", approveResp.Status, "Approval response should have status=approved")
}

// transferTPCOriginConfig enables the embedded OIDC issuer and the transfer API
// on a POSIXv2 origin.  The AuthorizationTemplates grant the user read/write/create
// access under /$USER (namespace-relative paths).
const transferTPCOriginConfig = `
Origin:
  StorageType: posixv2
  EnableIssuer: true
  IssuerMode: embedded
  EnableTransferAPI: true
  EnableDirectReads: true
  Exports:
    - FederationPrefix: /data
      StoragePrefix: %s
      Capabilities: ["Reads", "Writes", "Listings", "DirectReads"]
Issuer:
  AuthorizationTemplates:
    - prefix: /$USER
      actions: ["read", "write", "create"]
Transfer:
  EnableOAuth2Clients: true
`

// setupFedForTransferTPC starts a federation with the transfer API enabled and
// creates users for authentication.
func setupFedForTransferTPC(t *testing.T) (ft *fed_test_utils.FedTest, adminPassword, testUserPassword string, dataDir string) {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

	htpasswdDir := t.TempDir()
	htpasswdFile := filepath.Join(htpasswdDir, "htpasswd")
	adminPassword = randomString(16)
	testUserPassword = randomString(16)

	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	testUserHash, err := bcrypt.GenerateFromPassword([]byte(testUserPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	htpasswdContent := fmt.Sprintf("admin:%s\ntestuser:%s\n", string(adminHash), string(testUserHash))
	require.NoError(t, os.WriteFile(htpasswdFile, []byte(htpasswdContent), 0600))
	require.NoError(t, param.Set(param.Server_UIPasswordFile, htpasswdFile))
	// The flow performs several web-UI logins (admin setup plus the simulated
	// device-code approvals); raise the rate limit so they are not throttled (429).
	require.NoError(t, param.Set(param.Server_UILoginRateLimit, 100))

	groupFileDir := t.TempDir()
	groupFilePath := filepath.Join(groupFileDir, "groups.json")
	require.NoError(t, os.WriteFile(groupFilePath, []byte(`{"testuser": [], "admin": []}`), 0600))
	require.NoError(t, param.SetRaw("Issuer.GroupSource", "file"))
	require.NoError(t, param.SetRaw("Issuer.GroupFile", groupFilePath))

	tmpDir := t.TempDir()
	dataDir = filepath.Join(tmpDir, "data-store")
	require.NoError(t, os.MkdirAll(dataDir, 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(dataDir, "testuser"), 0755))

	originConfig := fmt.Sprintf(transferTPCOriginConfig, dataDir)
	ft = fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	return
}

// createIssuerOAuthClient creates a token-exchange-enabled OIDC client on the
// embedded issuer's admin API.  Returns (clientID, clientSecret).
func createIssuerOAuthClient(t *testing.T, serverURL, adminPassword, namespace string) (string, string) {
	t.Helper()

	// The issuer admin API requires an authenticated admin session. Log in as
	// the "admin" htpasswd user (CheckAdmin grants admin to that username) and
	// reuse the resulting login cookie on the admin request.
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient := &http.Client{Transport: config.GetTransport(), Jar: jar}

	loginResp, err := httpClient.PostForm(serverURL+"/api/v1.0/auth/login",
		url.Values{"user": {"admin"}, "password": {adminPassword}})
	require.NoError(t, err)
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()
	require.Equal(t, http.StatusOK, loginResp.StatusCode,
		"Admin login failed: %s", string(loginBody))

	callbackURL := fmt.Sprintf("%s/api/v1.0/callback", serverURL)
	payload, _ := json.Marshal(map[string]interface{}{
		"grant_types": []string{
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"authorization_code",
			"refresh_token",
		},
		"redirect_uris": []string{callbackURL},
		"scopes": []string{
			"openid", "offline_access", "wlcg",
			"storage.read:/", "storage.modify:/", "storage.create:/",
		},
	})

	adminURL := fmt.Sprintf("%s/api/v1.0/issuer/admin/ns%s/clients", serverURL, namespace)
	resp, err := httpClient.Post(adminURL, "application/json", bytes.NewReader(payload))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"Failed to create issuer OAuth client: %s", string(body))

	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal(body, &result))
	require.NotEmpty(t, result.ClientID)
	require.NotEmpty(t, result.ClientSecret)
	t.Logf("Created issuer OAuth client: id=%s", result.ClientID)
	return result.ClientID, result.ClientSecret
}

// registerOAuthClientOnTransferServer registers an OAuth client on the transfer
// server so that token-exchange bootstrap is available for the given issuer.
func registerOAuthClientOnTransferServer(t *testing.T, serverURL, bearerToken, issuerURL, clientID, clientSecret string) {
	t.Helper()

	httpClient := &http.Client{Transport: config.GetTransport()}

	payload, _ := json.Marshal(map[string]string{
		"name":          "test-issuer-client",
		"issuer_url":    issuerURL,
		"client_id":     clientID,
		"client_secret": clientSecret,
		// grant_types must be populated so findOAuthClientForGrant can match
		// the client to a bootstrap flow (space-separated, per the API).
		"grant_types": "urn:ietf:params:oauth:grant-type:token-exchange authorization_code refresh_token",
	})

	apiURL := serverURL + "/api/v1.0/transfer/oauth-clients"
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode,
		"Failed to register OAuth client on transfer server: %s", string(body))
	t.Log("Registered OAuth client on transfer server for issuer:", issuerURL)
}

// generateTransferScopeToken creates a WLCG token with the pelican.transfer
// scope for authenticating with the transfer server API.
func generateTransferScopeToken(t *testing.T) string {
	t.Helper()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = 10 * time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test-admin"
	tokConf.AddAudienceAny()
	tokConf.AddScopes(token_scopes.Pelican_Transfer)

	tok, err := tokConf.CreateToken()
	require.NoError(t, err)
	return tok
}

// generateStorageToken creates a WLCG token with given storage scopes.
func generateStorageToken(t *testing.T, scopes ...token_scopes.ResourceScope) string {
	t.Helper()

	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokConf := token.NewWLCGToken()
	tokConf.Lifetime = 5 * time.Minute
	tokConf.Issuer = issuer
	tokConf.Subject = "test-verify"
	tokConf.AddAudienceAny()
	tokConf.AddResourceScopes(scopes...)

	tok, err := tokConf.CreateToken()
	require.NoError(t, err)
	return tok
}

// simulateAuthCodeApproval handles an OAuth2 authorization code URL by
// logging in (if needed) and following the redirect chain to the callback
// endpoint on the transfer server. This completes the authorization code
// bootstrap flow.
func simulateAuthCodeApproval(t *testing.T, serverURL, authorizeURL, password string) {
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

	// Step 0: If given the auth-code bootstrap start URL, follow its single
	// redirect to obtain the real issuer /authorize URL.
	if strings.Contains(authorizeURL, "/api/v1.0/callback/start/") {
		resp, err := browserClient.Get(authorizeURL)
		require.NoError(t, err)
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode,
			"Start URL should redirect to the issuer authorize URL")
		authorizeURL = resp.Header.Get("Location")
		require.NotEmpty(t, authorizeURL, "Start redirect should include a Location header")
		t.Logf("Auth code: resolved start URL to authorize URL: %s", authorizeURL)
	}

	// Step 1: GET the authorize URL while unauthenticated → redirect to login.
	resp, err := browserClient.Get(authorizeURL)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusTemporaryRedirect, resp.StatusCode,
		"Unauthenticated GET to authorize should redirect to login")
	t.Log("Auth code: unauthenticated redirect to login OK")

	// Step 2: POST login to get the login cookie.
	loginURL := serverURL + "/api/v1.0/auth/login"
	loginForm := url.Values{"user": {"testuser"}, "password": {password}}
	resp, err = browserClient.PostForm(loginURL, loginForm)
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")
	t.Log("Auth code: login OK as testuser")

	// Step 3: GET the authorize URL again (now authenticated) → redirect to
	// callback with authorization code.
	resp, err = browserClient.Get(authorizeURL)
	require.NoError(t, err)
	step3Body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("Auth code step 3: status=%d, body=%s, location=%s", resp.StatusCode, string(step3Body), resp.Header.Get("Location"))
	require.True(t, resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther,
		"Authenticated GET to authorize should redirect to callback, got %d", resp.StatusCode)
	callbackURL := resp.Header.Get("Location")
	require.NotEmpty(t, callbackURL, "Authorize redirect should include Location header")
	t.Logf("Auth code: redirect to callback: %s", callbackURL)

	// Step 4: Follow the redirect to the callback endpoint. The callback is
	// a public endpoint on the transfer server that exchanges the code for a
	// token and creates the credential.
	resp, err = browserClient.Get(callbackURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("Auth code step 4 (callback): status=%d, body=%s, location=%s", resp.StatusCode, string(body), resp.Header.Get("Location"))
	// The callback may redirect or return success directly.
	require.True(t, resp.StatusCode >= 200 && resp.StatusCode < 400,
		"Callback should succeed, got %d: %s", resp.StatusCode, string(body))
	t.Log("Auth code: callback completed successfully")
}

// TestTransferTPCViaOriginE2E exercises a third-party copy (TPC) through an
// origin that also serves the transfer API, using the CLI's --transfer-server
// flag with full device-code authentication.
//
// Architecture:
//
//	CLI subprocess --> origin (transfer API + data server)
//	  |
//	  +-- device code #1: authenticate with transfer server (pelican.transfer scope)
//	  +-- token exchange: bootstrap source credential (storage.read)
//	  +-- token exchange: bootstrap dest credential (storage.create)
//	  +-- POST /api/v1.0/transfer/jobs with credential IDs
//
// The test:
//  1. Starts a federation with origin + embedded issuer + transfer API
//  2. Seeds a source file on the origin
//  3. Creates a token-exchange OIDC client on the issuer and registers it
//     on the transfer server
//  4. Launches a CLI subprocess: pelican object copy --transfer-server <url>
//  5. Monitors stdout+stderr for device-code verification URLs and approves them
//  6. Verifies the destination file exists with correct content
func TestTransferTPCViaOriginE2E(t *testing.T) {
	ft, adminPassword, testUserPassword, _ := setupFedForTransferTPC(t)

	serverURL := param.Server_ExternalWebUrl.GetString()
	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	discoveryURL := param.Federation_DiscoveryUrl.GetString()
	t.Logf("Federation started. Server=%s Discovery=%s", serverURL, discoveryURL)

	// ---- Step 1: Seed a source file ----
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	seedToken := generateStorageToken(t,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/data/testuser"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/testuser"),
	)

	localTmpDir := t.TempDir()
	srcContent := "Hello from TPC E2E test -- " + randomString(16)
	srcFile := filepath.Join(localTmpDir, "tpc_source.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte(srcContent), 0644))

	srcURL := fmt.Sprintf("pelican://%s:%d/data/testuser/tpc_source.txt", hostname, port)
	uploadResults, err := client.DoPut(ft.Ctx, srcFile, srcURL, false,
		client.WithToken(seedToken))
	require.NoError(t, err, "Failed to seed source file")
	require.NotEmpty(t, uploadResults)
	t.Log("Source file seeded successfully")

	// ---- Step 2: Create issuer OAuth client for token exchange ----
	nsIssuerURL := serverURL + "/api/v1.0/issuer/ns/data"
	issuerClientID, issuerClientSecret := createIssuerOAuthClient(t, serverURL, adminPassword, "/data")

	// ---- Step 3: Register the issuer client on the transfer server ----
	transferToken := generateTransferScopeToken(t)
	registerOAuthClientOnTransferServer(t, serverURL, transferToken, nsIssuerURL, issuerClientID, issuerClientSecret)

	// Verify auth-methods reports token_exchange
	{
		httpClient := &http.Client{Transport: config.GetTransport()}
		authMethodsURL := fmt.Sprintf("%s/api/v1.0/transfer/auth-methods?issuer=%s", serverURL, nsIssuerURL)
		authMethodsReq, err := http.NewRequest(http.MethodGet, authMethodsURL, nil)
		require.NoError(t, err)
		authMethodsReq.Header.Set("Authorization", "Bearer "+transferToken)
		resp, err := httpClient.Do(authMethodsReq)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "auth-methods failed: %s", string(body))

		var authMethods struct {
			Methods []string `json:"methods"`
		}
		require.NoError(t, json.Unmarshal(body, &authMethods))
		assert.Contains(t, authMethods.Methods, "token_exchange",
			"auth-methods should include token_exchange after registering OAuth client")
		t.Logf("Auth methods for issuer: %v", authMethods.Methods)
	}

	// ---- Step 4: Launch CLI subprocess ----
	cliPath := getPelicanBinary(t)
	dstURL := fmt.Sprintf("pelican://%s:%d/data/testuser/tpc_dest.txt", hostname, port)

	// Use directread to bypass the cache (the test cache may not be fully functional).
	srcURLDirect := srcURL + "?directread"

	// Pre-create an empty credential file so the subprocess doesn't prompt
	// for a password when it first accesses the credential store.
	credFile := filepath.Join(localTmpDir, "client-credentials.pem")
	require.NoError(t, os.WriteFile(credFile, []byte(""), 0600))

	cmd := exec.Command(cliPath, "object", "copy",
		"--transfer-server", serverURL,
		"--wait",
		srcURLDirect, dstURL,
	)
	cmd.Env = append(os.Environ(),
		"PELICAN_FEDERATION_DISCOVERYURL="+discoveryURL,
		"PELICAN_TLSSKIPVERIFY=true",
		"PELICAN_SKIP_TERMINAL_CHECK=1",
		"PELICAN_LOGGING_DISABLEPROGRESSBARS=true",
		"PELICAN_CLIENT_CREDENTIALFILE="+credFile,
		"PELICAN_CLIENT_NOPASSWORD=1",
	)

	// Redirect stdin from /dev/null so the child doesn't try to read
	// a credential password from the real terminal.
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer devNull.Close()
	cmd.Stdin = devNull

	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start(), "Failed to start CLI subprocess")

	// Monitor both stdout and stderr for device code user_code patterns
	// and authorization code URLs.
	// Transfer bootstrap prints to stdout (fmt.Printf), while the oauth2
	// library prints to stderr.
	userCodeCh := make(chan deviceApproval, 8)
	authURLCh := make(chan string, 4)
	userCodeRe := regexp.MustCompile(`user_code=([A-Z0-9-]+)`)
	namespaceRe := regexp.MustCompile(`namespace=([^&\s]+)`)
	// Match either a direct issuer /authorize URL or the transfer server's
	// auth-code bootstrap start URL (which 302-redirects to /authorize).
	authURLRe := regexp.MustCompile(`(https://[^\s]+/(?:authorize\?|api/v1.0/callback/start/)[^\s]+)`)

	scanAndExtract := func(name string, reader io.Reader) {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			line := scanner.Text()
			t.Logf("CLI %s: %s", name, line)
			if matches := userCodeRe.FindStringSubmatch(line); len(matches) > 1 {
				// The device URL on the same line carries the issuer namespace
				// (e.g. namespace=%2F.transfer for the transfer-auth flow or
				// namespace=%2Fdata for the storage token-exchange flow).
				namespace := "/data"
				if nsMatch := namespaceRe.FindStringSubmatch(line); len(nsMatch) > 1 {
					if decoded, derr := url.QueryUnescape(nsMatch[1]); derr == nil {
						namespace = decoded
					}
				}
				t.Logf("Intercepted user_code from %s: %s (namespace=%s)", name, matches[1], namespace)
				userCodeCh <- deviceApproval{userCode: matches[1], namespace: namespace}
			}
			if matches := authURLRe.FindStringSubmatch(line); len(matches) > 1 {
				t.Logf("Intercepted authorize URL from %s: %s", name, matches[1])
				authURLCh <- matches[1]
			}
		}
	}

	go scanAndExtract("stdout", stdoutPipe)
	go scanAndExtract("stderr", stderrPipe)

	cmdDone := make(chan error, 1)
	go func() { cmdDone <- cmd.Wait() }()

	approvalTimeout := time.After(180 * time.Second)
	approvedCount := 0
	authCodeCount := 0
	var cmdErr error

	for {
		select {
		case code, ok := <-userCodeCh:
			if !ok {
				goto done
			}
			approvedCount++
			t.Logf("Approving user_code #%d: %s (namespace=%s)", approvedCount, code.userCode, code.namespace)
			simulateUserApproval(t, serverURL, code.namespace, code.userCode, testUserPassword)
		case authURL, ok := <-authURLCh:
			if !ok {
				goto done
			}
			authCodeCount++
			t.Logf("Handling authorize URL #%d: %s", authCodeCount, authURL)
			simulateAuthCodeApproval(t, serverURL, authURL, testUserPassword)
		case cmdErr = <-cmdDone:
			// Let any remaining codes drain briefly
			drainTimer := time.After(2 * time.Second)
		drainLoop:
			for {
				select {
				case code, ok := <-userCodeCh:
					if !ok {
						break drainLoop
					}
					approvedCount++
					t.Logf("Approving late user_code #%d: %s (namespace=%s)", approvedCount, code.userCode, code.namespace)
					simulateUserApproval(t, serverURL, code.namespace, code.userCode, testUserPassword)
				case authURL, ok := <-authURLCh:
					if !ok {
						break drainLoop
					}
					authCodeCount++
					t.Logf("Handling late authorize URL #%d: %s", authCodeCount, authURL)
					simulateAuthCodeApproval(t, serverURL, authURL, testUserPassword)
				case <-drainTimer:
					break drainLoop
				}
			}
			goto done
		case <-approvalTimeout:
			_ = cmd.Process.Kill()
			t.Fatal("Timed out waiting for CLI subprocess to complete")
		}
	}
done:
	t.Logf("CLI completed -- %d device code(s) approved, %d auth-code(s) approved", approvedCount, authCodeCount)
	require.True(t, approvedCount >= 1, "Expected at least 1 device code approval")
	require.NoError(t, cmdErr, "CLI subprocess should exit successfully")

	// ---- Step 5: Verify the destination file ----
	// Use directread to bypass the cache (which may not be functional in test)
	dstURLDirect := dstURL + "?directread"
	downloadFile := filepath.Join(localTmpDir, "downloaded_dest.txt")
	readToken := generateStorageToken(t,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/testuser"),
	)
	_, err = client.DoGet(ft.Ctx, dstURLDirect, downloadFile, false,
		client.WithToken(readToken))
	require.NoError(t, err, "DoGet should succeed for the TPC destination file")

	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, srcContent, string(downloadedContent),
		"Downloaded content from TPC destination must match the source")
	t.Log("TPC destination file verified -- content matches source")

	// Suppress unused variable warning for issuer
	_ = issuer
}

// TestTransferTPCDirectCredentialE2E exercises TPC by using the transfer
// server's REST API directly (without the CLI) to create credentials and
// submit a job.  This tests the transfer module's core API surface without
// depending on the CLI's bootstrap logic.
//
// Flow:
//  1. Seed a source file
//  2. Create an issuer OAuth client (token-exchange)
//  3. Register it on the transfer server
//  4. Use device code to get a user token from the issuer
//  5. Use token exchange to bootstrap a credential on the transfer server
//  6. Submit a transfer job
//  7. Poll until completion and verify the destination file
func TestTransferTPCDirectCredentialE2E(t *testing.T) {
	ft, adminPassword, testUserPassword, _ := setupFedForTransferTPC(t)

	serverURL := param.Server_ExternalWebUrl.GetString()
	hostname := param.Server_Hostname.GetString()
	port := param.Server_WebPort.GetInt()
	t.Logf("Federation started. Server=%s", serverURL)

	// ---- Step 1: Seed a source file ----
	seedToken := generateStorageToken(t,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Create, "/data/testuser"),
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/testuser"),
	)

	localTmpDir := t.TempDir()
	srcContent := "Direct TPC test -- " + randomString(16)
	srcFile := filepath.Join(localTmpDir, "tpc_direct_src.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte(srcContent), 0644))

	srcURL := fmt.Sprintf("pelican://%s:%d/data/testuser/tpc_direct_src.txt", hostname, port)
	_, err := client.DoPut(ft.Ctx, srcFile, srcURL, false,
		client.WithToken(seedToken))
	require.NoError(t, err, "Failed to seed source file")
	t.Log("Source file seeded")

	// ---- Step 2: Create issuer OAuth client ----
	nsIssuerURL := serverURL + "/api/v1.0/issuer/ns/data"
	issuerClientID, issuerClientSecret := createIssuerOAuthClient(t, serverURL, adminPassword, "/data")

	// ---- Step 3: Register on transfer server ----
	transferToken := generateTransferScopeToken(t)
	registerOAuthClientOnTransferServer(t, serverURL, transferToken, nsIssuerURL, issuerClientID, issuerClientSecret)

	// ---- Step 4: Get a user token from the issuer via device code ----
	issuerMeta, err := config.GetIssuerMetadata(nsIssuerURL)
	require.NoError(t, err)

	httpClient := &http.Client{Transport: config.GetTransport()}

	// Register a DCRP client for device code
	dcrpPayload, _ := json.Marshal(map[string]interface{}{
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types": []string{
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
		},
		"response_types": []string{"code"},
		"client_name":    "TPC Test Device Client",
		"scope":          "offline_access wlcg storage.read:/testuser storage.create:/testuser storage.modify:/testuser",
	})

	dcrpResp, err := httpClient.Post(issuerMeta.RegistrationURL, "application/json", bytes.NewReader(dcrpPayload))
	require.NoError(t, err)
	dcrpBody, _ := io.ReadAll(dcrpResp.Body)
	dcrpResp.Body.Close()
	require.Equal(t, http.StatusCreated, dcrpResp.StatusCode,
		"DCRP registration failed: %s", string(dcrpBody))

	var dcrpResult struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	require.NoError(t, json.Unmarshal(dcrpBody, &dcrpResult))
	t.Logf("DCRP client registered: %s", dcrpResult.ClientID)

	// Device authorization request
	deviceAuthPayload := fmt.Sprintf(
		"client_id=%s&scope=%s",
		dcrpResult.ClientID,
		"wlcg+offline_access+storage.read:/testuser+storage.create:/testuser+storage.modify:/testuser",
	)
	deviceAuthReq, err := http.NewRequest(
		http.MethodPost,
		issuerMeta.DeviceAuthURL,
		bytes.NewReader([]byte(deviceAuthPayload)),
	)
	require.NoError(t, err)
	deviceAuthReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deviceAuthReq.SetBasicAuth(dcrpResult.ClientID, dcrpResult.ClientSecret)
	deviceResp, err := httpClient.Do(deviceAuthReq)
	require.NoError(t, err)
	deviceBody, _ := io.ReadAll(deviceResp.Body)
	deviceResp.Body.Close()
	require.Equal(t, http.StatusOK, deviceResp.StatusCode,
		"Device auth request failed: %s", string(deviceBody))

	var deviceAuth struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int    `json:"expires_in"`
		Interval                int    `json:"interval"`
	}
	require.NoError(t, json.Unmarshal(deviceBody, &deviceAuth))
	require.NotEmpty(t, deviceAuth.DeviceCode)
	require.NotEmpty(t, deviceAuth.UserCode)
	t.Logf("Device auth: user_code=%s", deviceAuth.UserCode)

	// Simulate user approval
	simulateUserApproval(t, serverURL, "/data", deviceAuth.UserCode, testUserPassword)
	t.Log("Device code approved")

	// Poll for token
	var userAccessToken string
	require.Eventually(t, func() bool {
		tokenPayload := fmt.Sprintf(
			"grant_type=%s&device_code=%s&client_id=%s&client_secret=%s",
			"urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code",
			deviceAuth.DeviceCode, dcrpResult.ClientID, dcrpResult.ClientSecret,
		)
		tokenResp, tErr := httpClient.Post(
			issuerMeta.TokenURL,
			"application/x-www-form-urlencoded",
			bytes.NewReader([]byte(tokenPayload)),
		)
		if tErr != nil {
			return false
		}
		tokenBody, _ := io.ReadAll(tokenResp.Body)
		tokenResp.Body.Close()
		if tokenResp.StatusCode != http.StatusOK {
			return false
		}
		var tokenResult struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(tokenBody, &tokenResult) != nil {
			return false
		}
		userAccessToken = tokenResult.AccessToken
		return userAccessToken != ""
	}, 30*time.Second, 2*time.Second, "Token polling should succeed after approval")
	t.Logf("User token acquired (length=%d)", len(userAccessToken))

	// ---- Step 5: Bootstrap credential via token exchange ----
	tokenExchangePayload, _ := json.Marshal(map[string]string{
		"subject_token": userAccessToken,
		"issuer_url":    nsIssuerURL,
		"name":          "tpc-test-cred",
	})

	tokenExchangeReq, err := http.NewRequest(
		http.MethodPost,
		serverURL+"/api/v1.0/transfer/credentials/bootstrap/token-exchange",
		bytes.NewReader(tokenExchangePayload),
	)
	require.NoError(t, err)
	tokenExchangeReq.Header.Set("Content-Type", "application/json")
	tokenExchangeReq.Header.Set("Authorization", "Bearer "+transferToken)

	tokenExchangeResp, err := httpClient.Do(tokenExchangeReq)
	require.NoError(t, err)
	tokenExchangeBody, _ := io.ReadAll(tokenExchangeResp.Body)
	tokenExchangeResp.Body.Close()
	require.Equal(t, http.StatusCreated, tokenExchangeResp.StatusCode,
		"Token exchange bootstrap failed: %s", string(tokenExchangeBody))

	var credResult struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	require.NoError(t, json.Unmarshal(tokenExchangeBody, &credResult))
	require.NotEmpty(t, credResult.ID)
	t.Logf("Credential bootstrapped via token exchange: %s", credResult.ID)

	// ---- Step 6: Submit transfer job ----
	dstURL := fmt.Sprintf("pelican://%s:%d/data/testuser/tpc_direct_dest.txt", hostname, port)

	jobPayload, _ := json.Marshal(map[string]interface{}{
		"transfers": []map[string]interface{}{
			{
				"operation":   "copy",
				"source":      srcURL + "?directread",
				"destination": dstURL,
			},
		},
		"source_credential_id": credResult.ID,
		"dest_credential_id":   credResult.ID,
	})

	jobReq, err := http.NewRequest(
		http.MethodPost,
		serverURL+"/api/v1.0/transfer/jobs",
		bytes.NewReader(jobPayload),
	)
	require.NoError(t, err)
	jobReq.Header.Set("Content-Type", "application/json")
	jobReq.Header.Set("Authorization", "Bearer "+transferToken)

	jobResp, err := httpClient.Do(jobReq)
	require.NoError(t, err)
	jobBody, _ := io.ReadAll(jobResp.Body)
	jobResp.Body.Close()
	require.Equal(t, http.StatusCreated, jobResp.StatusCode,
		"Job submission failed: %s", string(jobBody))

	var jobResult struct {
		JobID  string `json:"job_id"`
		Status string `json:"status"`
	}
	require.NoError(t, json.Unmarshal(jobBody, &jobResult))
	require.NotEmpty(t, jobResult.JobID)
	t.Logf("Transfer job submitted: %s (status: %s)", jobResult.JobID, jobResult.Status)

	// ---- Step 7: Poll for completion ----
	var finalStatus string
	require.Eventually(t, func() bool {
		apiURL := serverURL + "/api/v1.0/transfer/jobs/" + jobResult.JobID
		req, rErr := http.NewRequest(http.MethodGet, apiURL, nil)
		if rErr != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+transferToken)

		resp, rErr := httpClient.Do(req)
		if rErr != nil {
			return false
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}

		var status struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		}
		if json.Unmarshal(body, &status) != nil {
			return false
		}

		t.Logf("Job %s status: %s", jobResult.JobID, status.Status)
		finalStatus = status.Status

		switch status.Status {
		case "completed":
			return true
		case "error", "failed", "cancelled":
			t.Fatalf("Transfer job %s failed: %s (error: %s)", jobResult.JobID, status.Status, status.Error)
		}
		return false
	}, 120*time.Second, 2*time.Second, "Transfer job should reach terminal state")

	assert.Equal(t, "completed", finalStatus, "Transfer job should complete successfully")

	// ---- Step 8: Verify destination file ----
	downloadFile := filepath.Join(localTmpDir, "direct_downloaded.txt")
	readToken := generateStorageToken(t,
		token_scopes.NewResourceScope(token_scopes.Wlcg_Storage_Read, "/data/testuser"),
	)

	dstURLDirect := dstURL + "?directread"
	_, err = client.DoGet(ft.Ctx, dstURLDirect, downloadFile, false,
		client.WithToken(readToken))
	require.NoError(t, err, "DoGet should succeed for the TPC destination file")

	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, srcContent, string(downloadedContent),
		"TPC destination content must match source")
	t.Log("Direct TPC credential bootstrap and job execution verified")
}
