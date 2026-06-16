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

package transfer

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/oauth2/issuer"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// setupTransferOnlyServer brings up a standalone transfer server (no co-located
// origin or director): it configures the server as TransferType, registers the
// server-level local issuer via RegisterLocalIssuer (the standalone launch
// path), and registers the transfer API routes. This mirrors what
// launchers.LaunchModules does for the TransferType module.
func setupTransferOnlyServer(t *testing.T) *gin.Engine {
	t.Helper()
	server_utils.ResetTestState()
	resetTransferSecretKey()
	t.Cleanup(config.ResetConfig)
	gin.SetMode(gin.TestMode)

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		if err := egrp.Wait(); err != nil && err != context.Canceled {
			t.Log("Error waiting for errgroup:", err)
		}
	})

	tmpDir := t.TempDir()
	require.NoError(t, param.Set(param.ConfigDir, tmpDir))
	require.NoError(t, param.Set(param.IssuerKeysDirectory, filepath.Join(tmpDir, "issuer-keys")))
	require.NoError(t, param.Set(param.Server_UILoginRateLimit, 100))
	require.NoError(t, param.Set(param.Server_DbLocation, filepath.Join(tmpDir, "transfer.sqlite")))

	// Configure as a transfer-only server. There is intentionally no origin
	// export here, so GetLocalIssuerUrl() resolves to the bare external web URL.
	test_utils.MockFederationRoot(t, nil, nil)
	require.NoError(t, config.InitServer(ctx, server_structs.TransferType))
	require.NotEmpty(t, param.Server_ExternalWebUrl.GetString(), "external web URL must be set")

	// Use the real server-database initialization for the transfer server type,
	// which (after provisioning the shared embedded-issuer migrations) creates
	// the oidc_* tables the local issuer needs in addition to the transfer
	// tables.
	require.NoError(t, database.InitServerDatabase(server_structs.TransferType))
	t.Cleanup(func() {
		_ = database.ShutdownDB()
		database.ServerDatabase = nil
	})
	require.NoError(t, InitTransferDatabase())
	db := database.ServerDatabase

	tm := client_agent.NewTransferManager(ctx, 5, nil)
	engine := gin.New()
	engine.Use(gin.Recovery())

	// The two registrations a standalone transfer server performs.
	require.NoError(t, RegisterLocalIssuer(ctx, egrp, engine, db))
	require.NoError(t, registerTransferRoutes(ctx, engine, egrp, db, tm))
	return engine
}

// TestTransferOnlyServerLocalIssuer verifies that a standalone transfer server
// stands up its server-level local issuer: the transfer ping advertises it, its
// OIDC discovery document is reachable and identifies itself with the local
// issuer URL, and a pelican.transfer token minted by that issuer is accepted to
// submit a transfer job. Jobs are not run to completion.
func TestTransferOnlyServerLocalIssuer(t *testing.T) {
	engine := setupTransferOnlyServer(t)

	t.Run("PingAdvertisesLocalIssuer", func(t *testing.T) {
		w := doRequest(t, engine, "GET", "/api/v1.0/transfer/ping", nil, "")
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "transfer", resp["service"])
		assert.Equal(t, issuer.TransferIssuerServiceURL(), resp["issuer"],
			"ping should advertise the local issuer's discovery URL")
	})

	t.Run("LocalIssuerDiscoveryReachable", func(t *testing.T) {
		// The discovery document is served by the embedded-issuer routes under
		// the reserved /.transfer namespace and must identify itself with the
		// local issuer URL (what the transfer middleware's LocalIssuer check
		// trusts), not the per-namespace route path.
		discoveryPath := "/api/v1.0/issuer/ns" + issuer.TransferIssuerNamespace + "/.well-known/openid-configuration"
		w := doRequest(t, engine, "GET", discoveryPath, nil, "")
		require.Equal(t, http.StatusOK, w.Code, "Body: %s", w.Body.String())

		var disc map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &disc))
		assert.Equal(t, config.GetLocalIssuerUrl(), disc["issuer"],
			"discovery issuer must be the local issuer URL")
		// The endpoints clients need for the device-code bootstrap must be present.
		assert.NotEmpty(t, disc["device_authorization_endpoint"])
		assert.NotEmpty(t, disc["token_endpoint"])
		assert.NotEmpty(t, disc["registration_endpoint"])
	})

	t.Run("LocalIssuerTokenSubmitsJob", func(t *testing.T) {
		// Sanity: on a transfer-only server the local issuer is the bare
		// external web URL (no /api/v1.0/origin suffix).
		require.Equal(t, param.Server_ExternalWebUrl.GetString(), config.GetLocalIssuerUrl())

		tok := generateTransferToken(t, "transfer-user")
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{
					Operation:   "get",
					Source:      "pelican:///test/hello.txt",
					Destination: "/tmp/hello.txt",
				},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, tok)
		require.Equal(t, http.StatusCreated, w.Code, "Body: %s", w.Body.String())

		// The job is accepted and persisted; we do not run it to completion (the
		// pelican:// source is not reachable in this unit context, so the
		// in-memory manager may move it straight to a terminal state).
		var resp TransferJobResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.JobID, "an accepted job must return a job ID")
		assert.NotEmpty(t, resp.Status)
	})

	t.Run("UnauthenticatedJobRejected", func(t *testing.T) {
		jreq := TransferJobCreateRequest{
			Transfers: []TransferItem{
				{Operation: "get", Source: "pelican:///test/hello.txt", Destination: "/tmp/hello.txt"},
			},
		}
		w := doRequest(t, engine, "POST", "/api/v1.0/transfer/jobs", jreq, "")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}
