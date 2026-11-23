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

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The namespace whose owner stores an auth state in the registry
const registryBackedNs = "/registry-backed"

type fedResponse struct {
	status  int
	header  http.Header
	cookies []*http.Cookie
	body    string
}

// fedAuth is what the registry's web APIs want from an administrator: the
// login cookie, and for every mutation the CSRF token they issued to that
// session together with the cookie the token is bound to
type fedAuth struct {
	login      *http.Cookie
	csrfToken  string
	csrfCookie *http.Cookie
}

func fedBase() string {
	return fmt.Sprintf("https://%s:%d", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
}

// fedRequest sends one request to the federation's web port (every module of
// a fed test shares it) without following redirects. A nil auth makes an
// anonymous request.
func fedRequest(ctx context.Context, method, path string, auth *fedAuth, body []byte) (fedResponse, error) {
	base := fedBase()
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return fedResponse{}, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != nil {
		req.AddCookie(auth.login)
		if auth.csrfToken != "" {
			req.Header.Set("X-CSRF-Token", auth.csrfToken)
			req.AddCookie(auth.csrfCookie)
			// The CSRF check also wants a same-origin Referer over https
			req.Header.Set("Referer", base+"/view/registry/")
		}
	}
	return fedDo(req)
}

// fedDo sends req without following redirects
func fedDo(req *http.Request) (fedResponse, error) {
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fedResponse{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fedResponse{}, err
	}
	return fedResponse{status: resp.StatusCode, header: resp.Header, cookies: resp.Cookies(), body: string(raw)}, nil
}

func mustFedRequest(t *testing.T, ctx context.Context, method, path string, auth *fedAuth, body []byte) fedResponse {
	t.Helper()
	resp, err := fedRequest(ctx, method, path, auth, body)
	require.NoError(t, err)
	return resp
}

// registryAdmin logs the "admin" user of the htpasswd file in through the
// password login, the way the other fed tests do; with no admin users or
// groups configured, that username is an administrator. The whoami call
// then yields the CSRF token every mutation must carry.
func registryAdmin(t *testing.T, ctx context.Context, password string) *fedAuth {
	t.Helper()
	form := url.Values{"user": {"admin"}, "password": {password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fedBase()+"/api/v1.0/auth/login", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	login, err := fedDo(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, login.status, login.body)
	auth := &fedAuth{}
	for _, c := range login.cookies {
		if c.Name == "login" {
			auth.login = c
		}
	}
	require.NotNil(t, auth.login, "login did not set the login cookie")

	who := mustFedRequest(t, ctx, http.MethodGet, "/api/v1.0/auth/whoami", auth, nil)
	require.Equal(t, http.StatusOK, who.status, who.body)
	require.Contains(t, who.body, `"authenticated":true`)
	auth.csrfToken = who.header.Get("X-CSRF-Token")
	require.NotEmpty(t, auth.csrfToken, "whoami did not issue a CSRF token")
	for _, c := range who.cookies {
		if c.Name == "_gorilla_csrf" {
			auth.csrfCookie = c
		}
	}
	require.NotNil(t, auth.csrfCookie, "whoami did not set the CSRF cookie")
	return auth
}

// registrationID finds the id of the registry row whose prefix satisfies match
func registrationID(t *testing.T, ctx context.Context, auth *fedAuth, match func(prefix string) bool) int {
	t.Helper()
	resp := mustFedRequest(t, ctx, http.MethodGet, "/api/v1.0/registry_ui/namespaces", auth, nil)
	require.Equal(t, http.StatusOK, resp.status, resp.body)
	var rows []struct {
		ID     int    `json:"id"`
		Prefix string `json:"prefix"`
	}
	require.NoError(t, json.Unmarshal([]byte(resp.body), &rows))
	for _, row := range rows {
		if match(row.Prefix) {
			return row.ID
		}
	}
	require.FailNowf(t, "registration not found", "rows: %s", resp.body)
	return 0
}

// listedFromRegistry reports whether the director's namespace list carries
// prefix with the from-registry mark, which it does once no origin advertises it
func listedFromRegistry(ctx context.Context, prefix string) bool {
	resp, err := fedRequest(ctx, http.MethodGet, "/api/v2.0/director/listNamespaces", nil, nil)
	if err != nil || resp.status != http.StatusOK {
		return false
	}
	var nss []struct {
		Path         string `json:"path"`
		FromRegistry bool   `json:"from-registry"`
	}
	if err := json.Unmarshal([]byte(resp.body), &nss); err != nil {
		return false
	}
	for _, ns := range nss {
		if ns.Path == prefix {
			return ns.FromRegistry
		}
	}
	return false
}

// originlessCount reads the director's counter of requests handled while no
// origin was online, for one result value
func originlessCount(result metrics.DirectorOriginlessResult) float64 {
	return testutil.ToFloat64(metrics.PelicanDirectorOriginlessRedirectsTotal.WithLabelValues(string(result)))
}

// TestRegistryBackedNamespaceServedFromCaches checks that a namespace whose
// owner stored an auth state in the registry stays readable after its only
// origin stops advertising: the director redirects to the cache that holds a
// copy, and says so when none does.
func TestRegistryBackedNamespaceServedFromCaches(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// The pure-Go cache answers the director's presence check for a complete copy
	require.NoError(t, param.Cache_EnableV2.Set(true))
	// Short-lived ads, so the origin drops out of the director a few seconds
	// after its advertisements stop being accepted
	require.NoError(t, param.Server_AdLifetime.SetString("5s"))
	// The registry administrator logs in with a password, so the htpasswd
	// file has to exist before the federation starts
	adminPassword := randomString(16)
	adminHash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	require.NoError(t, err)
	htpasswdFile := filepath.Join(t.TempDir(), "htpasswd")
	require.NoError(t, os.WriteFile(htpasswdFile, []byte("admin:"+string(adminHash)+"\n"), 0600))
	require.NoError(t, param.Server_UIPasswordFile.Set(htpasswdFile))

	originConfig := `
Origin:
  StorageType: posixv2
  Exports:
    - StoragePrefix: /<SHOULD BE OVERRIDDEN>
      FederationPrefix: ` + registryBackedNs + `
      # No DirectReads: every read goes through the cache, which is what fills it
      Capabilities: ["PublicReads", "Reads", "Listings"]
Director:
  # The production value. The outage path runs its own presence check regardless.
  CheckCachePresence: false
  RegistryQueryInterval: 1s
Registry:
  Institutions:
    - name: Test Institution
      id: https://example.org/inst/test
`
	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NoError(t, config.InitClient())

	storageDir := ft.Exports[0].StoragePrefix
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "cached.txt"), []byte("read while the origin was online"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(storageDir, "cold.txt"), []byte("never read through the cache"), 0644))

	objectPath := "/api/v1.0/director/object" + registryBackedNs + "/cached.txt"
	coldPath := "/api/v1.0/director/object" + registryBackedNs + "/cold.txt"

	// The cache registers with the director asynchronously; without
	// DirectReads the director cannot answer until it has
	require.Eventually(t, func() bool {
		resp, err := fedRequest(ft.Ctx, http.MethodGet, objectPath, nil, nil)
		return err == nil && resp.status == http.StatusTemporaryRedirect &&
			strings.Contains(resp.header.Get("Location"), "/api/v1.0/cache/data/")
	}, 30*time.Second, 500*time.Millisecond, "the director never redirected to the cache")

	// Read the object through the cache so the cache holds a copy
	discoveryHost := strings.TrimPrefix(param.Federation_DiscoveryUrl.GetString(), "https://")
	pelicanUrl := "pelican://" + discoveryHost + registryBackedNs + "/cached.txt"
	dest := filepath.Join(t.TempDir(), "cached.txt")
	_, err = client.DoCopy(ft.Ctx, pelicanUrl, dest, false)
	require.NoError(t, err)
	got, err := os.ReadFile(dest)
	require.NoError(t, err)
	require.Equal(t, "read while the origin was online", string(got))

	// The owner stores a public-read auth state on the namespace and an
	// administrator approves the registration
	admin := registryAdmin(t, ft.Ctx, adminPassword)
	nsID := registrationID(t, ft.Ctx, admin, func(p string) bool { return p == registryBackedNs })
	nsPath := fmt.Sprintf("/api/v1.0/registry_ui/namespaces/%d", nsID)

	row := mustFedRequest(t, ft.Ctx, http.MethodGet, nsPath, admin, nil)
	require.Equal(t, http.StatusOK, row.status, row.body)
	var reg map[string]any
	require.NoError(t, json.Unmarshal([]byte(row.body), &reg))
	adminMetadata, _ := reg["admin_metadata"].(map[string]any)
	require.NotNil(t, adminMetadata)
	adminMetadata["description"] = "served from caches while its origin is offline"
	adminMetadata["institution"] = "https://example.org/inst/test"
	// A map rather than server_structs.NamespaceAuthState: that type lives in
	// the registry change this test depends on, and this file must still
	// compile without it
	reg["auth_state"] = map[string]any{
		"capabilities":    map[string]bool{"PublicRead": true, "Read": true, "Listing": true},
		"tokenGeneration": []any{},
		"tokenIssuer":     []any{},
	}
	body, err := json.Marshal(reg)
	require.NoError(t, err)
	put := mustFedRequest(t, ft.Ctx, http.MethodPut, nsPath, admin, body)
	require.Equal(t, http.StatusOK, put.status, put.body)
	approve := mustFedRequest(t, ft.Ctx, http.MethodPatch, nsPath+"/approve", admin, nil)
	require.Equal(t, http.StatusOK, approve.status, approve.body)

	advertised := mustFedRequest(t, ft.Ctx, http.MethodGet, "/api/v1.0/registry/namespaces/advertised", nil, nil)
	require.Equal(t, http.StatusOK, advertised.status, advertised.body)
	require.Contains(t, advertised.body, `"path":"`+registryBackedNs+`"`)

	// Take the origin offline: without its server registration, the
	// director refuses its next advertisements and its current ad expires
	originID := registrationID(t, ft.Ctx, admin, func(p string) bool { return strings.HasPrefix(p, "/origins/") })
	deleted := mustFedRequest(t, ft.Ctx, http.MethodDelete, fmt.Sprintf("/api/v1.0/registry_ui/namespaces/%d", originID), admin, nil)
	require.Equal(t, http.StatusOK, deleted.status, deleted.body)

	require.Eventually(t, func() bool {
		return listedFromRegistry(ft.Ctx, registryBackedNs)
	}, 30*time.Second, 250*time.Millisecond, "the director kept listing the namespace from the origin's ad")

	redirectedBefore := originlessCount(metrics.OriginlessRedirected)
	noCopyBefore := originlessCount(metrics.OriginlessNoCopy)

	// The object the cache holds is still served, from the cache
	resp := mustFedRequest(t, ft.Ctx, http.MethodGet, objectPath, nil, nil)
	require.Equal(t, http.StatusTemporaryRedirect, resp.status, resp.body)
	assert.Contains(t, resp.header.Get("Location"), "/api/v1.0/cache/data/")
	assert.Contains(t, resp.header.Get("X-Pelican-Namespace"), "require-token=false")

	dest = filepath.Join(t.TempDir(), "cached-again.txt")
	_, err = client.DoCopy(ft.Ctx, pelicanUrl, dest, false)
	require.NoError(t, err)
	got, err = os.ReadFile(dest)
	require.NoError(t, err)
	assert.Equal(t, "read while the origin was online", string(got))

	// An object no cache holds cannot be served, and the answer says why
	resp = mustFedRequest(t, ft.Ctx, http.MethodGet, coldPath, nil, nil)
	require.Equal(t, http.StatusNotFound, resp.status, resp.body)
	assert.Contains(t, resp.body, "no origin is online and no cache reports a copy")

	// A request that needs the origin itself is not sent to a cache
	resp = mustFedRequest(t, ft.Ctx, http.MethodGet, "/api/v1.0/director/origin"+registryBackedNs+"/cached.txt", nil, nil)
	assert.Equal(t, http.StatusNotFound, resp.status, resp.body)

	assert.GreaterOrEqual(t, originlessCount(metrics.OriginlessRedirected)-redirectedBefore, float64(2))
	assert.GreaterOrEqual(t, originlessCount(metrics.OriginlessNoCopy)-noCopyBefore, float64(1))
}
