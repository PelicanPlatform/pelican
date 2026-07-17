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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// TestE2E_InitializeHandlers_EventualPublish is the "true standalone origin"
// test: rather than hand-assembling the POSC + controller + webdav stack, it
// boots the real handler wiring via InitializeHandlers(ctx, exports) — the
// exact handlers.go path where the eventual-mode bug lived — with POSC on, a
// non-root export, eventual mode, a real SQLite ServerDatabase (migrations +
// batcher), and real token auth. An authenticated PUT flows through the
// registered gin routes; the assertion is that the object commits AND the
// metadata webhook fires with the federation-rooted path, exercising the
// production FilesystemForExists existence check end-to-end.
func TestE2E_InitializeHandlers_EventualPublish(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: boots real handler wiring + DB")
	}

	// Webhook receiver captures what the origin publishes.
	gotPath := make(chan string, 4)
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath <- objectPathFromBody(r)
		w.WriteHeader(http.StatusOK)
	}))
	defer receiver.Close()

	issuerURL := setupHTTPIssuer(t)

	// Origin params: enable POSC + eventual metadata publishing.
	setBoolParamForTest(t, param.Origin_Metadata_Enabled, true)
	setStringParamForTest(t, param.Origin_Metadata_Endpoint, receiver.URL)
	setStringParamForTest(t, param.Origin_Metadata_Mode, "eventual")
	setBoolParamForTest(t, param.Origin_Posc_Enabled, true)
	setDurationParamForTest(t, param.Origin_Metadata_MinBackoff, 10*time.Millisecond)
	setDurationParamForTest(t, param.Origin_Metadata_MaxBackoff, 200*time.Millisecond)

	// Real file-backed origin database (runs migrations that create
	// metadata_publish_queue) so the batcher + queue behave as in production.
	setStringParamForTest(t, param.Server_DbLocation, filepath.Join(t.TempDir(), "pelican.sqlite"))
	prevDB := database.ServerDatabase
	t.Cleanup(func() { database.ServerDatabase = prevDB })
	if err := database.InitServerDatabase(server_structs.OriginType); err != nil {
		t.Fatalf("init server database: %v", err)
	}

	storageDir := t.TempDir()
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/exp",
			StoragePrefix:    storageDir,
			IssuerUrls:       []string{issuerURL},
			Capabilities: server_structs.Capabilities{
				Reads:  true,
				Writes: true,
			},
		},
	}

	ResetHandlers()
	t.Cleanup(ResetHandlers)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := InitializeHandlers(ctx, exports); err != nil {
		t.Fatalf("InitializeHandlers: %v", err)
	}

	egrp := &errgroup.Group{}
	if err := InitAuthConfig(ctx, egrp, exports); err != nil {
		t.Fatalf("InitAuthConfig: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	if err := RegisterHandlers(router, false); err != nil {
		t.Fatalf("RegisterHandlers: %v", err)
	}
	srv := httptest.NewServer(router)
	defer srv.Close()

	// Authenticated PUT (writes always require a token).
	tkn := mintWriteToken(t, issuerURL)
	req, err := http.NewRequest(http.MethodPut, srv.URL+"/exp/data/run.dat", strings.NewReader("standalone-origin-payload"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tkn)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("PUT returned %d: %s", resp.StatusCode, string(body))
	}

	// The webhook must fire, with the federation-rooted path, proving the
	// real InitializeHandlers wiring (POSC close hook + eventual worker +
	// FilesystemForExists existence check) published the commit.
	select {
	case p := <-gotPath:
		if p != "/exp/data/run.dat" {
			t.Fatalf("webhook object path = %q, want /exp/data/run.dat", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("metadata webhook never fired through the real handler wiring")
	}
}

// setupHTTPIssuer stands up a plain-HTTP issuer that publishes the origin's
// OIDC discovery doc + JWKS. Plain HTTP (not TLS) so the origin's own auth
// config can fetch the JWKS without needing to trust a self-signed cert. It
// also sets IssuerKeysDirectory (generating the origin key) and
// Server.IssuerUrl so the production signer/verifier agree on the issuer.
func setupHTTPIssuer(t *testing.T) string {
	t.Helper()
	setStringParamForTest(t, param.IssuerKeysDirectory, t.TempDir())

	var issuerURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuerURL,
			"jwks_uri": issuerURL + "/.well-known/issuer.jwks",
		})
	})
	mux.HandleFunc("/.well-known/issuer.jwks", func(w http.ResponseWriter, r *http.Request) {
		jwks, err := config.GetIssuerPublicJWKS()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(jwks)
		_, _ = w.Write(data)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	issuerURL = srv.URL
	setStringParamForTest(t, param.Server_IssuerUrl, issuerURL)
	return issuerURL
}

// mintWriteToken produces a real WLCG token with read+create+modify scopes at
// "/", signed by the origin's issuer key — the same shape a client presents
// to write to the origin.
func mintWriteToken(t *testing.T, issuerURL string) string {
	t.Helper()
	tc := token.NewWLCGToken()
	tc.Lifetime = time.Minute
	tc.Issuer = issuerURL
	tc.Subject = "e2e-writer"
	tc.AddAudienceAny()
	for _, s := range []token_scopes.TokenScope{
		token_scopes.Wlcg_Storage_Read,
		token_scopes.Wlcg_Storage_Create,
		token_scopes.Wlcg_Storage_Modify,
	} {
		scoped, err := s.Path("/")
		if err != nil {
			t.Fatalf("scope path: %v", err)
		}
		tc.AddScopes(scoped)
	}
	tkn, err := tc.CreateToken()
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	return tkn
}

// The typed param setters below restore the previous value on cleanup so
// package-global config mutations don't leak into sibling tests. They use the
// typed .Set() (not viper.Set) because param getters read from a decoded
// config struct that viper.Set alone would not refresh.

func setStringParamForTest(t *testing.T, p param.StringParam, value string) {
	t.Helper()
	prev := p.GetString()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}

func setBoolParamForTest(t *testing.T, p param.BoolParam, value bool) {
	t.Helper()
	prev := p.GetBool()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}

func setDurationParamForTest(t *testing.T, p param.DurationParam, value time.Duration) {
	t.Helper()
	prev := p.GetDuration()
	if err := p.Set(value); err != nil {
		t.Fatalf("set %s: %v", p.GetName(), err)
	}
	t.Cleanup(func() { _ = p.Set(prev) })
}
