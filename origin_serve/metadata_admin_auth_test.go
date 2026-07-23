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

package origin_serve

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

// adminRoute is one method+path pair exposed by RegisterMetadataAdminAPI.
type adminRoute struct {
	method string
	path   string
}

// allAdminRoutes enumerates every endpoint RegisterMetadataAdminAPI mounts.
// Kept in one place so both auth tests iterate the complete surface — if a
// route is added without auth, these tests must be updated to see it.
func allAdminRoutes() []adminRoute {
	return []adminRoute{
		{http.MethodGet, "/api/v1.0/origin_ui/metadata_queue"},
		{http.MethodGet, "/api/v1.0/origin_ui/metadata_queue/_health"},
		{http.MethodGet, "/api/v1.0/origin_ui/metadata_queue/some-event-id"},
		{http.MethodDelete, "/api/v1.0/origin_ui/metadata_queue/some-event-id"},
		{http.MethodPost, "/api/v1.0/origin_ui/metadata_queue/some-event-id/retry"},
	}
}

// TestAdminQueueRoutesAreGuardedByMiddleware proves that EVERY admin route is
// registered behind the injected middleware — not just the read endpoints.
// The previous admin tests registered the API with no middleware at all, so a
// route accidentally mounted outside the auth group would have gone unnoticed.
// A sentinel middleware that aborts 401 must fire for every method+path.
func TestAdminQueueRoutesAreGuardedByMiddleware(t *testing.T) {
	// Install a controller so that, absent the middleware, the handlers would
	// return 2xx/404 (not 503) — making a gating miss unambiguous.
	installControllerForAdminTest(t)

	var sentinelHits int32
	sentinel := func(c *gin.Context) {
		atomic.AddInt32(&sentinelHits, 1)
		c.AbortWithStatus(http.StatusUnauthorized)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/api/v1.0/origin_ui")
	RegisterMetadataAdminAPI(rg, sentinel)
	srv := httptest.NewServer(r)
	defer srv.Close()

	routes := allAdminRoutes()
	for _, rt := range routes {
		t.Run(rt.method+"_"+rt.path, func(t *testing.T) {
			status := doAdminRequest(t, srv.URL, rt)
			if status != http.StatusUnauthorized {
				t.Fatalf("%s %s returned %d, want 401 — route is NOT behind the injected middleware",
					rt.method, rt.path, status)
			}
		})
	}
	if int(atomic.LoadInt32(&sentinelHits)) != len(routes) {
		t.Fatalf("sentinel middleware fired %d times, want %d (some route bypassed it)",
			sentinelHits, len(routes))
	}
}

// TestAdminQueueRejectsAnonymousWithRealMiddleware wires the endpoints with
// the SAME middleware production uses (web_ui.AuthHandler + AdminAuthHandler)
// and confirms an unauthenticated request is rejected on every route. This is
// the production gating (origin/origin_ui.go) exercised directly. Requests
// carry no Origin header, so the CSRF pre-check passes and the failure is the
// authentication check (401), not CSRF.
func TestAdminQueueRejectsAnonymousWithRealMiddleware(t *testing.T) {
	installControllerForAdminTest(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/api/v1.0/origin_ui")
	RegisterMetadataAdminAPI(rg, web_ui.AuthHandler, web_ui.AdminAuthHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for _, rt := range allAdminRoutes() {
		t.Run(rt.method+"_"+rt.path, func(t *testing.T) {
			status := doAdminRequest(t, srv.URL, rt)
			// An unauthenticated caller must never reach the handler. The real
			// AuthHandler returns 401; a 403 would also be a rejection. Anything
			// 2xx/3xx/404/503 means the request slipped past auth into the
			// handler.
			if status != http.StatusUnauthorized && status != http.StatusForbidden {
				t.Fatalf("%s %s returned %d, want 401/403 for an anonymous caller",
					rt.method, rt.path, status)
			}
		})
	}
}

// TestAdminQueueRejectsNonAdminBearerToken confirms the second half of the
// gating contract: a caller who authenticates successfully but is NOT an admin
// is rejected with 403 on every route. It mints a real, correctly-signed local
// bearer token whose subject is an ordinary (non-admin) user. AuthHandler
// accepts the token (issuer + signature + subject all valid), then
// AdminAuthHandler's CheckAdmin denies it. This exercises the exact
// AuthHandler → AdminAuthHandler chain production wires in origin/origin_ui.go.
func TestAdminQueueRejectsNonAdminBearerToken(t *testing.T) {
	installControllerForAdminTest(t)

	// A bearer token is validated as locally-minted: issuer must equal
	// config.GetLocalIssuerUrl() (derived from Server.ExternalWebUrl) and the
	// signature must verify against the origin's issuer JWKS.
	setStringParamForTest(t, param.Server_ExternalWebUrl, "https://test-origin.example:8444")
	setStringParamForTest(t, param.IssuerKeysDirectory, t.TempDir())

	// The bearer path resolves a userId from the DB only when
	// database.ServerDatabase is set; force it nil so the subject alone
	// authenticates the (non-admin) user deterministically.
	prevDB := database.ServerDatabase
	database.ServerDatabase = nil
	t.Cleanup(func() { database.ServerDatabase = prevDB })

	issuerURL := config.GetLocalIssuerUrl()
	tc := token.NewWLCGToken()
	tc.Lifetime = time.Minute
	tc.Issuer = issuerURL
	tc.Subject = "regular-user" // deliberately NOT "admin"
	tc.AddAudiences(issuerURL)
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	if err != nil {
		t.Fatalf("scope path: %v", err)
	}
	tc.AddScopes(readScope) // an ordinary scope; carries no admin authority
	tkn, err := tc.CreateToken()
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	gin.SetMode(gin.TestMode)
	r := gin.New()
	rg := r.Group("/api/v1.0/origin_ui")
	RegisterMetadataAdminAPI(rg, web_ui.AuthHandler, web_ui.AdminAuthHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for _, rt := range allAdminRoutes() {
		t.Run(rt.method+"_"+rt.path, func(t *testing.T) {
			status := doAdminRequestWithToken(t, srv.URL, rt, tkn)
			if status != http.StatusForbidden {
				t.Fatalf("%s %s returned %d for a non-admin bearer, want 403",
					rt.method, rt.path, status)
			}
		})
	}
}

func doAdminRequest(t *testing.T, base string, rt adminRoute) int {
	t.Helper()
	return doAdminRequestWithToken(t, base, rt, "")
}

func doAdminRequestWithToken(t *testing.T, base string, rt adminRoute, bearer string) int {
	t.Helper()
	req, err := http.NewRequest(rt.method, base+rt.path, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", rt.method, rt.path, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}
