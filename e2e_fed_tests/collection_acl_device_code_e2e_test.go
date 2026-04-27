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

// Collection-ACL → device-code → data-plane end-to-end test.
//
// This is the test that pins the design intent of collections: a user
// who has no AuthorizationTemplate-derived access to a namespace
// should still be able to read (or write) objects under that
// namespace if — and only if — they're a member of a group that's
// been granted a read (or write) ACL on a collection rooted at the
// namespace, and they obtained their token via the embedded issuer's
// real device-code flow.
//
// The chain has four moving parts and the test exercises all of them:
//
//	  Collection ACL
//	       ↓
//	  GetUserCollectionScopes (oa4mp/proxy.go, the bridge added in
//	    this commit) translates ACL → storage.* scope at issuer time
//	       ↓
//	  Device-code OAuth2 flow mints a real WLCG token carrying that
//	    scope (no shortcut: registration, device auth, approval,
//	    polling — all real)
//	       ↓
//	  Data-plane request through xrootd validates the storage.* scope
//	    against the requested object path
//
// The negative case is structurally important: before the ACL exists
// (or for users not in the ACL'd group) the same token-mint pipeline
// must NOT produce a storage scope for the collection's namespace.

package fed_tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	oauth2 "github.com/pelicanplatform/pelican/oauth2"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// collectionAclDeviceCodeOriginConfig configures a single posixv2 origin
// with the embedded issuer enabled. The crucial property: the
// AuthorizationTemplate only grants the user access to /$USER (the
// namespace-relative subdirectory matching their username). The
// /team subdirectory — where we'll later root a collection — is
// NOT covered by any template, so the only way for a user to read it
// is through a collection ACL.
const collectionAclDeviceCodeOriginConfig = `
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

// runDeviceCodeFlowForTestUser drives the full embedded-issuer
// device-code OAuth2 flow as testuser and returns the resulting
// access token's claims plus the raw token. Each call is independent —
// we re-register a client and re-mint a token, so a token issued
// before an ACL is granted reflects the pre-ACL world and a token
// issued after reflects the post-ACL world.
func runDeviceCodeFlowForTestUser(t *testing.T, ft *fed_test_utils.FedTest, password string) (accessToken string, claims map[string]interface{}) {
	t.Helper()
	serverURL := param.Server_ExternalWebUrl.GetString()

	issuerMeta, err := config.GetIssuerMetadata(serverURL)
	require.NoError(t, err)

	drcp := oauth2.DCRPConfig{
		ClientRegistrationEndpointURL: issuerMeta.RegistrationURL,
		Transport:                     config.GetTransport(),
		Metadata: oauth2.Metadata{
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
			ResponseTypes:           []string{"code"},
			ClientName:              "OSDF Command Line Client",
			Scopes: []string{
				"offline_access", "wlcg",
				"storage.read:/", "storage.modify:/", "storage.create:/",
			},
		},
	}
	dcrResp, err := drcp.Register()
	require.NoError(t, err)

	oauth2Config := oauth2.Config{
		ClientID:     dcrResp.ClientID,
		ClientSecret: dcrResp.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:       issuerMeta.AuthURL,
			TokenURL:      issuerMeta.TokenURL,
			DeviceAuthURL: issuerMeta.DeviceAuthURL,
		},
		// Request the broad scope set; the issuer's filtering will
		// substitute in only the narrower scopes the user is actually
		// permitted (template- + collection-ACL-derived).
		Scopes: []string{
			"wlcg", "offline_access",
			"storage.read:/", "storage.modify:/", "storage.create:/",
		},
	}

	httpClient := &http.Client{Transport: config.GetTransport()}
	ctx := context.WithValue(ft.Ctx, oauth2.HTTPClient, httpClient)
	deviceAuth, err := oauth2Config.AuthDevice(ctx)
	require.NoError(t, err)

	simulateUserApproval(t, serverURL, "/data", deviceAuth.UserCode, password)

	pollValues := url.Values{
		"client_id":   {dcrResp.ClientID},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceAuth.DeviceCode},
	}
	require.Eventually(t, func() bool {
		tok, err := oauth2.RetrieveToken(ctx, dcrResp.ClientID, dcrResp.ClientSecret,
			issuerMeta.TokenURL, pollValues)
		if err != nil {
			return false
		}
		accessToken = tok.AccessToken
		return true
	}, 30*time.Second, 2*time.Second, "device-code RetrieveToken should return a token after approval")

	require.NotEmpty(t, accessToken)
	nsIssuer := serverURL + "/api/v1.0/issuer/ns/data"
	claims = validateWLCGToken(t, accessToken, nsIssuer)
	return
}

// mintAdminCookie fabricates a login cookie scoped to admin so we
// can drive the /origin_ui/collections REST surface to create the
// collection and grant the ACL. We can't reuse the device-code
// token for this because the embedded issuer doesn't grant
// /origin_ui/collections-management scopes via the OAuth2 path —
// those endpoints are gated by the web-UI auth handler, which
// expects a login cookie.
func mintAdminCookie(t *testing.T, password string) (cookie *http.Cookie) {
	t.Helper()
	serverURL := param.Server_ExternalWebUrl.GetString()
	loginURL := serverURL + "/api/v1.0/auth/login"
	httpClient := &http.Client{Transport: config.GetTransport()}
	resp, err := httpClient.PostForm(loginURL, url.Values{"user": {"admin"}, "password": {password}})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "admin login should succeed")

	for _, c := range resp.Cookies() {
		if c.Name == "login" {
			cookie = c
			return
		}
	}
	t.Fatal("admin login response did not include a login cookie")
	return nil
}

// extractScopes pulls the "scope" claim out of token claims and
// splits it on whitespace. WLCG profile uses a space-separated string.
func extractScopes(claims map[string]interface{}) []string {
	s := extractScopeString(claims) // shared helper from device_code_e2e_test.go
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// TestCollectionAclDeviceCodeBridge exercises the negative-then-
// positive flip that is the entire point of the collection ACL bridge.
// Without ACL membership, the device-code-issued token must NOT
// authorize the namespace. With ACL membership (and only with), it
// must.
func TestCollectionAclDeviceCodeBridge(t *testing.T) {
	// We need to reset some shared state we don't normally need:
	// the htpasswd password is randomly generated per-fed, and we
	// need to keep a reference so we can mint the admin cookie too.
	// Bake adminPassword fetching into the setup. Since the existing
	// setupFedAndUsers helper hides that, we use our own wrapper.
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(func() { server_utils.ResetTestState() })

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
	require.NoError(t, param.Server_UIPasswordFile.Set(htpasswdFile))
	// The UI login endpoint defaults to 1 request per second per
	// client IP. This test logs in several times in quick succession
	// (testuser via simulateUserApproval, admin via mintAdminCookie,
	// then testuser again for the second device-code mint). Bump
	// the limit so we don't trip the 429.
	require.NoError(t, param.Server_UILoginRateLimit.Set(1000))

	groupFileDir := t.TempDir()
	groupFilePath := filepath.Join(groupFileDir, "groups.json")
	require.NoError(t, os.WriteFile(groupFilePath,
		[]byte(`{"testuser": ["team-readers"], "admin": []}`), 0600))
	require.NoError(t, param.Issuer_GroupSource.Set("file"))
	require.NoError(t, param.Issuer_GroupFile.Set(groupFilePath))

	require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin"}))

	// NewFedTest overrides StoragePrefix in the config with its own
	// per-export temp directory, so we have to set up files under
	// the *real* path (ft.Exports[0].StoragePrefix), not whatever
	// dummy path we hand the config. We pass /tmp/dummy here just
	// so the unmarshal succeeds; FedTest replaces it.
	dummyStoragePrefix := t.TempDir()
	originConfig := fmt.Sprintf(collectionAclDeviceCodeOriginConfig, dummyStoragePrefix)
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)
	require.GreaterOrEqual(t, len(ft.Exports), 1)
	storageRoot := ft.Exports[0].StoragePrefix

	serverURL := param.Server_ExternalWebUrl.GetString()
	t.Logf("Federation up at %s; storage root is %s", serverURL, storageRoot)

	// Pre-populate /data/team in the *real* backing directory.
	// 0o755 / 0o644 are sufficient because FedTest already chowned
	// storageRoot to the daemon user, so subdirectories created
	// underneath it are owned by us; the daemon user can traverse
	// because its own home dir IS storageRoot.
	teamDir := filepath.Join(storageRoot, "team")
	require.NoError(t, os.MkdirAll(teamDir, 0o755))
	teamFileContent := "treasure for collection-ACL members only"
	teamFilePath := filepath.Join(teamDir, "secret.txt")
	require.NoError(t, os.WriteFile(teamFilePath, []byte(teamFileContent), 0o644))

	// =====================================================================
	// Phase 1 — negative case: no ACL exists yet.
	// =====================================================================
	// testuser logs in via the device-code flow. Their token's only
	// AuthorizationTemplate-driven scope is for /testuser. Reading
	// /data/team/secret.txt must fail.
	preAclToken, preAclClaims := runDeviceCodeFlowForTestUser(t, ft, testUserPassword)
	preAclScopes := extractScopes(preAclClaims)
	t.Logf("Pre-ACL token scopes: %v", preAclScopes)

	assert.Equal(t, "testuser", preAclClaims["sub"])
	assert.Contains(t, preAclScopes, "storage.read:/testuser",
		"AuthorizationTemplate should still grant the user's own subdirectory")
	for _, s := range preAclScopes {
		assert.NotContains(t, s, "/team",
			"pre-ACL token must NOT contain any storage scope referencing /team — got %q", s)
	}

	// Read attempt against the data plane. We use a raw HTTP GET
	// against the origin's data endpoint rather than the Pelican
	// client, because the in-process client has access to the
	// origin's signing key and would mint a fresh token rather than
	// surface the authz failure.
	teamReadURL := fmt.Sprintf("%s/api/v1.0/origin/data/data/team/secret.txt", serverURL)
	req, err := http.NewRequest("GET", teamReadURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+preAclToken)
	httpClient := &http.Client{Transport: config.GetTransport()}
	negResp, err := httpClient.Do(req)
	require.NoError(t, err)
	negBody, _ := io.ReadAll(negResp.Body)
	_ = negResp.Body.Close()
	assert.True(t,
		negResp.StatusCode == http.StatusForbidden ||
			negResp.StatusCode == http.StatusUnauthorized,
		"pre-ACL read of /data/team/secret.txt must return 401 or 403, got %d (body: %s)",
		negResp.StatusCode, string(negBody))
	assert.NotContains(t, string(negBody), teamFileContent,
		"pre-ACL response body must not leak the file contents")

	// =====================================================================
	// Phase 2 — set up the collection: log in as admin, create a
	// collection rooted at /data/team, grant team-readers a read ACL.
	// =====================================================================
	adminCookie := mintAdminCookie(t, adminPassword)

	// Create the collection. Visibility is private so only ACLs
	// gate access — public collections would also pass via the
	// "any authenticated user can read" check, which would muddy
	// the test.
	createBody, _ := json.Marshal(map[string]interface{}{
		"name":       "team-shared",
		"namespace":  "/data/team",
		"visibility": "private",
	})
	createReq, _ := http.NewRequest("POST",
		serverURL+"/api/v1.0/origin_ui/collections", bytes.NewReader(createBody))
	createReq.AddCookie(adminCookie)
	createReq.Header.Set("Content-Type", "application/json")
	createResp, err := httpClient.Do(createReq)
	require.NoError(t, err)
	createRespBody, _ := io.ReadAll(createResp.Body)
	_ = createResp.Body.Close()
	require.Equal(t, http.StatusCreated, createResp.StatusCode,
		"collection create should succeed: %s", string(createRespBody))
	var createdCol struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(createRespBody, &createdCol))
	require.NotEmpty(t, createdCol.ID)
	t.Logf("Collection created: id=%s namespace=/data/team", createdCol.ID)

	// Grant team-readers a read ACL on it. We pass the group NAME
	// directly — the file-source group provider has testuser in
	// "team-readers", and that's what'll be in their token's groups
	// claim, so the ACL row's group_id must match that string.
	grantBody, _ := json.Marshal(map[string]string{
		"group_id": "team-readers",
		"role":     "read",
	})
	grantReq, _ := http.NewRequest("POST",
		serverURL+"/api/v1.0/origin_ui/collections/"+createdCol.ID+"/acl",
		bytes.NewReader(grantBody))
	grantReq.AddCookie(adminCookie)
	grantReq.Header.Set("Content-Type", "application/json")
	grantResp, err := httpClient.Do(grantReq)
	require.NoError(t, err)
	grantRespBody, _ := io.ReadAll(grantResp.Body)
	_ = grantResp.Body.Close()
	require.Equal(t, http.StatusNoContent, grantResp.StatusCode,
		"ACL grant should succeed: %s", string(grantRespBody))

	// =====================================================================
	// Phase 3 — positive case: re-mint a token for testuser. The
	// ACL bridge runs at issuer-time, so we need a *new* token to
	// pick up the freshly granted ACL.
	// =====================================================================
	postAclToken, postAclClaims := runDeviceCodeFlowForTestUser(t, ft, testUserPassword)
	postAclScopes := extractScopes(postAclClaims)
	t.Logf("Post-ACL token scopes: %v", postAclScopes)

	assert.Equal(t, "testuser", postAclClaims["sub"])
	// The bridge should have emitted a namespace-relative
	// storage.read scope. The issuer is per-namespace at /data, so
	// the collection rooted at /data/team becomes /team relative
	// to the issuer.
	assert.Contains(t, postAclScopes, "storage.read:/team",
		"post-ACL token must contain storage.read:/team (the namespace-relative form of /data/team)")

	// Read should now succeed. We use a raw HTTP GET against the
	// origin's data endpoint — the same path the negative case uses
	// — rather than the Pelican client. This keeps the test focused
	// on the bridge: does the origin allow this object read with
	// this token? Routing through the director/cache adds noise we
	// don't need (and can mask the result, since a freshly-written
	// origin file isn't in the cache yet).
	posReq, err := http.NewRequest("GET", teamReadURL, nil)
	require.NoError(t, err)
	posReq.Header.Set("Authorization", "Bearer "+postAclToken)
	posResp, err := httpClient.Do(posReq)
	require.NoError(t, err)
	posBody, _ := io.ReadAll(posResp.Body)
	_ = posResp.Body.Close()
	require.Equal(t, http.StatusOK, posResp.StatusCode,
		"post-ACL read of /data/team/secret.txt should succeed (got %d, body: %s)",
		posResp.StatusCode, string(posBody))
	assert.Equal(t, teamFileContent, string(posBody),
		"post-ACL response body must match the file's contents")

	// The post-ACL token should *not* have storage.modify:/team —
	// the ACL is read-only. Confirm a write attempt fails.
	for _, s := range postAclScopes {
		if s == "storage.modify:/team" || s == "storage.create:/team" {
			t.Errorf("read-only ACL leaked write scope: %s", s)
		}
	}

	teamWriteURL := fmt.Sprintf("%s/api/v1.0/origin/data/data/team/should-fail.txt", serverURL)
	wReq, err := http.NewRequest("PUT", teamWriteURL, bytes.NewReader([]byte("nope")))
	require.NoError(t, err)
	wReq.Header.Set("Authorization", "Bearer "+postAclToken)
	wResp, err := httpClient.Do(wReq)
	require.NoError(t, err)
	_, _ = io.ReadAll(wResp.Body)
	_ = wResp.Body.Close()
	assert.True(t,
		wResp.StatusCode == http.StatusForbidden ||
			wResp.StatusCode == http.StatusUnauthorized ||
			wResp.StatusCode == http.StatusMethodNotAllowed,
		"PUT to /data/team with read-only ACL must fail (got %d)", wResp.StatusCode)

	// =====================================================================
	// Phase 4 — upgrade the ACL to write. A new token should now
	// also carry storage.modify and storage.create, and a real
	// upload should succeed.
	// =====================================================================
	upgradeBody, _ := json.Marshal(map[string]string{
		"group_id": "team-readers",
		"role":     "write",
	})
	upgradeReq, _ := http.NewRequest("POST",
		serverURL+"/api/v1.0/origin_ui/collections/"+createdCol.ID+"/acl",
		bytes.NewReader(upgradeBody))
	upgradeReq.AddCookie(adminCookie)
	upgradeReq.Header.Set("Content-Type", "application/json")
	upgradeResp, err := httpClient.Do(upgradeReq)
	require.NoError(t, err)
	_ = upgradeResp.Body.Close()
	require.Equal(t, http.StatusNoContent, upgradeResp.StatusCode,
		"ACL upgrade to write should succeed")

	writeAclToken, writeAclClaims := runDeviceCodeFlowForTestUser(t, ft, testUserPassword)
	writeAclScopes := extractScopes(writeAclClaims)
	t.Logf("Write-ACL token scopes: %v", writeAclScopes)

	assert.Contains(t, writeAclScopes, "storage.read:/team")
	assert.Contains(t, writeAclScopes, "storage.modify:/team")
	assert.Contains(t, writeAclScopes, "storage.create:/team")

	// Real PUT against the origin's data endpoint. We bypass the
	// Pelican client for the same reason as the read test above:
	// directness keeps the test focused on the bridge and avoids
	// cache/director routing complications.
	uploadContent := "uploaded by collection-write-ACL holder"
	uploadDestURL := fmt.Sprintf("%s/api/v1.0/origin/data/data/team/uploaded.txt", serverURL)
	wReq2, err := http.NewRequest("PUT", uploadDestURL, bytes.NewReader([]byte(uploadContent)))
	require.NoError(t, err)
	wReq2.Header.Set("Authorization", "Bearer "+writeAclToken)
	wResp2, err := httpClient.Do(wReq2)
	require.NoError(t, err)
	wRespBody2, _ := io.ReadAll(wResp2.Body)
	_ = wResp2.Body.Close()
	require.True(t,
		wResp2.StatusCode >= 200 && wResp2.StatusCode < 300,
		"PUT after ACL upgrade to write should succeed (got %d, body: %s)",
		wResp2.StatusCode, string(wRespBody2))

	// And we can read what we wrote, via the same direct path.
	rbReq, err := http.NewRequest("GET", uploadDestURL, nil)
	require.NoError(t, err)
	rbReq.Header.Set("Authorization", "Bearer "+writeAclToken)
	rbResp, err := httpClient.Do(rbReq)
	require.NoError(t, err)
	rbBody, _ := io.ReadAll(rbResp.Body)
	_ = rbResp.Body.Close()
	require.Equal(t, http.StatusOK, rbResp.StatusCode,
		"GET of just-uploaded object should succeed")
	assert.Equal(t, uploadContent, string(rbBody),
		"round-trip content must match")

	// Sanity: the file actually landed on disk under the storage
	// prefix where the export points. This proves the request
	// traversed the full data path, not just the API gate.
	onDisk, err := os.ReadFile(filepath.Join(teamDir, "uploaded.txt"))
	require.NoError(t, err, "uploaded file should exist in the storage tree")
	assert.Equal(t, uploadContent, string(onDisk))

	t.Log("Collection-ACL device-code bridge verified end-to-end: " +
		"negative pre-ACL, positive read post-ACL, positive write after upgrade")
}
