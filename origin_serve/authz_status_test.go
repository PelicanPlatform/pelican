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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// mockFederationRootForAuthz serves just enough federation metadata for a
// non-standalone origin to finish InitServer.
func mockFederationRootForAuthz(t *testing.T) string {
	t.Helper()
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/pelican-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		body, err := json.Marshal(pelican_url.FederationDiscovery{
			DiscoveryEndpoint: "https://fake-discovery.com",
			DirectorEndpoint:  "https://fake-director.com",
			RegistryEndpoint:  "https://fake-registry.com",
			BrokerEndpoint:    "https://fake-broker.com",
			JwksUri:           "https://fake-discovery.com/.well-known/issuer.jwks",
		})
		require.NoError(t, err)
		_, err = w.Write(body)
		require.NoError(t, err)
	}))
	t.Cleanup(svr.Close)
	return svr.URL
}

// TestAuthFailureStatusDependsOnStandaloneMode pins which status an origin
// returns when a caller presents a token that does not authorize the request.
//
// A standalone origin answers 403, which is what drives the token-hint retry in
// client/handle_http.go: it has already told the caller which issuer to use, so
// repeating the 401 would just loop.
//
// A federated origin must keep answering 401.  A 401 is the signal that tells
// rclone and similar clients to re-run their bearer_token_command and try again
// -- the same reason the director returns 401 for an expired token.  Promoting
// it to 403 federation-wide would turn a refreshable rejection into a permanent
// one for every existing deployment.
func TestAuthFailureStatusDependsOnStandaloneMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// An export that requires a token: readable, but not publicly readable.
	exports := []server_utils.OriginExport{
		{
			FederationPrefix: "/protected",
			StoragePrefix:    t.TempDir(),
			IssuerUrls:       []string{"https://test-issuer.example.com"},
			Capabilities: server_structs.Capabilities{
				Reads:  true,
				Writes: true,
			},
		},
	}

	// request runs one GET through authMiddleware and reports the response the
	// middleware settled on.  presentToken controls whether the caller brought a
	// credential at all.
	request := func(t *testing.T, standalone bool, presentToken bool) *httptest.ResponseRecorder {
		t.Helper()
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		egrp := &errgroup.Group{}

		if standalone {
			require.NoError(t, param.Origin_EnableStandaloneMode.Set(true))
			require.NoError(t, param.Origin_StorageType.Set("posixv2"))
		} else {
			// A federated origin refuses to start without a reachable
			// federation, so stand one up for it to discover.  Its certificate
			// is self-signed, hence the skipped verification.
			require.NoError(t, param.TLSSkipVerify.Set(true))
			require.NoError(t, param.Federation_DiscoveryUrl.Set(mockFederationRootForAuthz(t)))
		}
		require.NoError(t, config.InitServer(ctx, server_structs.OriginType))
		require.Equal(t, standalone, config.IsStandaloneOrigin(),
			"test setup must actually flip the standalone gate")

		require.NoError(t, InitAuthConfig(ctx, egrp, exports))

		engine := gin.New()
		engine.GET("/protected/*path", authMiddleware(), func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/protected/secret.txt", nil)
		if presentToken {
			// The contents do not matter: the middleware branches on whether a
			// credential was presented at all, and this one authorizes nothing.
			req.Header.Set("Authorization", "Bearer not.a.valid.token")
		}
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}

	t.Run("federated-origin-keeps-401-so-clients-refresh", func(t *testing.T) {
		rec := request(t, false, true)
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"a federated origin must keep returning 401 when a presented token is insufficient")

		// The X-Pelican-* namespace/issuer metadata is the director's to publish.
		// A federated origin that started volunteering it would leak the shape of
		// its namespaces (issuers, listability, whether a token is required) to
		// every unauthenticated caller, on every deployment that exists today.
		for name := range rec.Header() {
			assert.NotContains(t, strings.ToLower(name), "x-pelican-",
				"a federated origin must not emit director-owned token hints")
		}
	})

	t.Run("standalone-origin-returns-403", func(t *testing.T) {
		rec := request(t, true, true)
		assert.Equal(t, http.StatusForbidden, rec.Code,
			"a standalone origin distinguishes an insufficient token from no token at all")

		// The counterpart of the assertion above: with no director in the
		// federation these headers are the client's only route to the issuer.
		assert.NotEmpty(t, rec.Header().Get(server_structs.XPelNs{}.GetName()),
			"a standalone origin must tell the caller which namespace it hit")
		assert.NotEmpty(t, rec.Header().Values(server_structs.XPelAuth{}.GetName()),
			"a standalone origin must tell the caller which issuer to use")
	})

	t.Run("no-token-is-401-everywhere", func(t *testing.T) {
		assert.Equal(t, http.StatusUnauthorized, request(t, true, false).Code,
			"a caller that brought nothing gets 401 even on a standalone origin")
		assert.Equal(t, http.StatusUnauthorized, request(t, false, false).Code)
	})
}
