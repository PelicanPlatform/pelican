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
package web_ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	// Middleware to inject a test user
	r.Use(func(c *gin.Context) {
		c.Set("User", "testuser")
		c.Next()
	})

	originDowntimeAPI := r.Group("/api/v1.0/downtime")
	{
		originDowntimeAPI.POST("", HandleCreateDowntime)
		originDowntimeAPI.GET("", HandleGetDowntime)
		originDowntimeAPI.GET("/:uuid", HandleGetDowntimeByUUID)
		originDowntimeAPI.PUT("/:uuid", HandleUpdateDowntime)
		originDowntimeAPI.DELETE("/:uuid", HandleDeleteDowntime)
	}
	return r
}

func TestDowntime(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		config.ResetConfig()
	})

	// Initialize the mock database
	database.SetupMockDowntimeDB(t)
	defer database.TeardownMockDowntimeDB(t)

	require.NoError(t, param.Server_WebPort.Set(0))
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://mock-server.com"))
	require.NoError(t, param.Xrootd_Sitename.Set("mock-sitename"))

	dirName := t.TempDir()
	require.NoError(t, param.ConfigBase.Set(dirName))
	require.NoError(t, param.Logging_Level.Set("debug"))
	require.NoError(t, param.Origin_Port.Set(0))

	// This mock registry handles the downtime mirror operations for the test
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1.0/downtime/") {
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
	}))
	t.Cleanup(mockRegistry.Close)

	fInfo := &pelican_url.FederationDiscovery{
		RegistryEndpoint: mockRegistry.URL,
	}
	test_utils.MockFederationRoot(t, fInfo, nil)
	err := config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err)

	r := setupRouter()
	activeDowntime := server_structs.Downtime{
		ServerID:    "test-server-id",
		UUID:        "01952a2f-d4e7-7413-91d6-fdb025176c9f",
		CreatedBy:   "admin",
		Class:       "SCHEDULED",
		Description: "Scheduled maintenance",
		Severity:    "Outage (completely inaccessible)",
		StartTime:   time.Now().UTC().UnixMilli(),
		EndTime:     time.Now().UTC().Add(1 * time.Hour).UnixMilli(),
		CreatedAt:   time.Now().UTC().UnixMilli(),
		UpdatedAt:   time.Now().UTC().UnixMilli(),
	}
	pastDowntime := server_structs.Downtime{
		ServerID:    "test-server-id",
		UUID:        "01952a5a-fdc4-72a7-88e7-c98aaee5278d",
		CreatedBy:   "John Doe",
		Class:       "UNSCHEDULED",
		Description: "Power outage",
		Severity:    server_structs.Outage,
		StartTime:   time.Now().UTC().Add(-20 * time.Hour).UnixMilli(),
		EndTime:     time.Now().UTC().Add(-1 * time.Hour).UnixMilli(),
		CreatedAt:   time.Now().UTC().Add(-20 * time.Hour).UnixMilli(),
		UpdatedAt:   time.Now().UTC().Add(-20 * time.Hour).UnixMilli(),
	}
	err = database.InsertMockDowntime(activeDowntime)
	assert.NoError(t, err)
	err = database.InsertMockDowntime(pastDowntime)
	assert.NoError(t, err)

	t.Run("get-downtime-no-query-param", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1.0/downtime", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), activeDowntime.UUID)
	})

	t.Run("get-active-downtime", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1.0/downtime?status=incomplete", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), activeDowntime.UUID)
	})

	t.Run("get-all-downtime", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/api/v1.0/downtime?status=all", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp []server_structs.Downtime
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Len(t, resp, 2)
		assert.Contains(t, w.Body.String(), pastDowntime.UUID)
	})

	t.Run("create-active-downtime", func(t *testing.T) {
		incompleteDowntime := DowntimeInput{
			ServerID:    "test-server-id",
			Class:       "SCHEDULED",
			Description: "",
			Severity:    "Intermittent Outage (may be up for some of the time)",
			StartTime:   time.Now().UTC().Add(1 * time.Hour).UnixMilli(),
			EndTime:     time.Now().UTC().Add(9 * time.Hour).UnixMilli(),
		}
		body, _ := json.Marshal(incompleteDowntime)

		req, _ := http.NewRequest("POST", "/api/v1.0/downtime", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		t.Log("Downtime Creation Response: ", w.Body.String())
		assert.Equal(t, http.StatusOK, w.Code)
		var resp server_structs.Downtime
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "testuser", resp.CreatedBy)
		assert.Equal(t, incompleteDowntime.StartTime, resp.StartTime)
	})

	t.Run("get-downtime-by-uuid-and-update", func(t *testing.T) {
		// Fetch a downtime by UUID
		req, _ := http.NewRequest("GET", "/api/v1.0/downtime/"+activeDowntime.UUID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var fetchedDowntime server_structs.Downtime
		err := json.Unmarshal(w.Body.Bytes(), &fetchedDowntime)
		assert.NoError(t, err)
		assert.Equal(t, activeDowntime.UUID, fetchedDowntime.UUID)

		// Update the fetched downtime
		updatedDowntime := DowntimeInput{
			Severity: "No Significant Outage Expected (you shouldn't notice)",
		}

		body, _ := json.Marshal(updatedDowntime)
		req, err = http.NewRequest("PUT", "/api/v1.0/downtime/"+fetchedDowntime.UUID, bytes.NewBuffer(body))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Fetch the updated downtime to verify the update
		req, _ = http.NewRequest("GET", "/api/v1.0/downtime/"+activeDowntime.UUID, nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)

		var resp server_structs.Downtime
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, server_structs.NoSignificantOutageExpected, resp.Severity)
	})

	t.Run("update-downtime-with-invalid-uuid", func(t *testing.T) {
		updatedDowntime := DowntimeInput{
			Severity: "Outage (completely inaccessible)",
		}
		body, _ := json.Marshal(updatedDowntime)
		req, err := http.NewRequest("PUT", "/api/v1.0/downtime/dummy_UUID", bytes.NewBuffer(body))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "Downtime record not found")
	})

	t.Run("update-downtime-with-invalid-severity", func(t *testing.T) {
		updatedDowntime := DowntimeInput{
			Severity: "InvalidSeverity",
		}
		body, _ := json.Marshal(updatedDowntime)
		req, err := http.NewRequest("PUT", "/api/v1.0/downtime/"+activeDowntime.UUID, bytes.NewBuffer(body))
		assert.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "Invalid input downtime severity")
	})

	t.Run("delete-downtime", func(t *testing.T) {
		req, _ := http.NewRequest("DELETE", "/api/v1.0/downtime/"+activeDowntime.UUID, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestDowntimeMutationAuthorized is a regression test: at the Registry, a
// downtime may be updated or deleted only by its owner — the server whose
// registered-server token subject matches the downtime's ServerID for
// server-authored downtimes, or a federation admin for Registry-authored ones.
// The rules are identical for both actions, so every case runs under each.
func TestDowntimeMutationAuthorized(t *testing.T) {
	const victimID = "victim-server-id"
	tests := []struct {
		name             string
		atRegistry       bool
		source           string // downtime Source
		authMethod       string
		tokenSubject     string
		adminOwnsLocally bool // co-located deployment: this process runs the source service that created the downtime
		wantAllowed      bool
	}{
		// Off-Registry (an origin/cache's own web UI): the guard does not apply.
		{"local-ui-not-checked", false, "origin", "", "anything", false, true},

		// Registry-authored downtimes: admin cookie only.
		{"registry-sourced-admin-cookie-allowed", true, "registry", "admin-cookie", "", false, true},
		{"registry-sourced-server-token-denied", true, "registry", "registered-server-token", victimID, false, false},
		{"registry-sourced-no-auth-denied", true, "registry", "", "", false, false},

		// Server-authored downtimes: only the owning server token.
		{"server-sourced-matching-token-allowed", true, "origin", "registered-server-token", victimID, false, true},
		{"server-sourced-cache-matching-token-allowed", true, "cache", "registered-server-token", victimID, false, true},
		// The attack: a different registered server targets the victim's downtime.
		{"attack-server-sourced-mismatched-token-denied", true, "origin", "registered-server-token", "attacker-server-id", false, false},
		// A federation admin cannot mutate a *remote* server's downtime (read-only at the Registry).
		{"remote-server-sourced-admin-cookie-denied", true, "origin", "admin-cookie", "", false, false},
		// Empty/unknown source from a non-owning token still fails closed.
		{"empty-source-mismatched-token-denied", true, "", "registered-server-token", "attacker-server-id", false, false},

		// Co-located "federation in a box": the process also runs the source service
		// (or the source is unset), so the local admin owns the record.
		{"colocated-server-sourced-admin-allowed", true, "origin", "admin-cookie", "", true, true},
		{"colocated-empty-sourced-admin-allowed", true, "", "admin-cookie", "", true, true},
		// But a co-located admin still cannot claim a record whose token owner differs.
		{"colocated-still-blocks-mismatched-token", true, "origin", "registered-server-token", "attacker-server-id", true, false},
	}
	for _, action := range []string{"update", "delete"} {
		for _, tc := range tests {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				allowed, msg := downtimeMutationAuthorized(tc.atRegistry, tc.source, tc.authMethod, tc.tokenSubject, victimID, action, tc.adminOwnsLocally)
				assert.Equal(t, tc.wantAllowed, allowed)
				if tc.wantAllowed {
					assert.Empty(t, msg)
				} else {
					assert.NotEmpty(t, msg)
					assert.Contains(t, msg, action)
				}
			})
		}
	}
}

// TestDowntimeRegistryCreateOwnership exercises the create/upsert path at the
// Registry: a registered server's create is bound to its own identity (it cannot
// attribute a downtime to a victim or forge a Registry-authored one), and a POST
// to an existing UUID it does not own is rejected rather than silently rewriting
// the record.
func TestDowntimeRegistryCreateOwnership(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, egrp.Wait())
		config.ResetConfig()
	})

	database.SetupMockDowntimeDB(t)
	defer database.TeardownMockDowntimeDB(t)

	require.NoError(t, param.Server_WebPort.Set(0))
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://registry.example.org"))
	dirName := t.TempDir()
	require.NoError(t, param.ConfigBase.Set(dirName))
	require.NoError(t, param.Logging_Level.Set("debug"))

	// InitServer needs federation discovery resolved.
	mockRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(mockRegistry.Close)
	test_utils.MockFederationRoot(t, &pelican_url.FederationDiscovery{RegistryEndpoint: mockRegistry.URL}, nil)

	// Run as a Registry so the ownership binding/guard apply.
	require.NoError(t, config.InitServer(ctx, server_structs.RegistryType))

	// Router that authenticates the caller as a registered server.
	serverRouter := func(subject string) *gin.Engine {
		gin.SetMode(gin.TestMode)
		r := gin.Default()
		r.Use(func(c *gin.Context) {
			c.Set("AuthMethod", "registered-server-token")
			c.Set("TokenSubject", subject)
			c.Next()
		})
		r.POST("/api/v1.0/downtime", HandleCreateDowntime)
		r.POST("/api/v1.0/downtime/:uuid", HandleCreateDowntime)
		return r
	}

	validInput := func() DowntimeInput {
		return DowntimeInput{
			Source:    "origin",
			Class:     server_structs.SCHEDULED,
			Severity:  server_structs.Outage,
			StartTime: time.Now().UTC().Add(1 * time.Hour).UnixMilli(),
			EndTime:   time.Now().UTC().Add(2 * time.Hour).UnixMilli(),
		}
	}

	t.Run("create-binds-serverid-and-clears-name", func(t *testing.T) {
		in := validInput()
		in.ServerID = "victim-id"     // attacker-supplied
		in.ServerName = "victim-name" // attacker-supplied
		body, _ := json.Marshal(in)
		req, _ := http.NewRequest("POST", "/api/v1.0/downtime", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		serverRouter("server-A").ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp server_structs.Downtime
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "server-A", resp.ServerID, "ServerID must be bound to the authenticated token subject")
		assert.Empty(t, resp.ServerName, "body-supplied ServerName must be cleared")
	})

	t.Run("server-cannot-forge-registry-source", func(t *testing.T) {
		in := validInput()
		in.Source = "registry"
		body, _ := json.Marshal(in)
		req, _ := http.NewRequest("POST", "/api/v1.0/downtime", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		serverRouter("server-A").ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("cannot-upsert-another-servers-downtime", func(t *testing.T) {
		victim := server_structs.Downtime{
			UUID:      "0195aaaa-0000-7000-8000-000000000001",
			ServerID:  "server-B",
			Source:    "origin",
			CreatedBy: "b", UpdatedBy: "b",
			Class:     server_structs.SCHEDULED,
			Severity:  server_structs.Outage,
			StartTime: time.Now().UTC().Add(1 * time.Hour).UnixMilli(),
			EndTime:   time.Now().UTC().Add(2 * time.Hour).UnixMilli(),
		}
		require.NoError(t, database.InsertMockDowntime(victim))

		in := validInput()
		in.Description = "hijacked"
		body, _ := json.Marshal(in)
		req, _ := http.NewRequest("POST", "/api/v1.0/downtime/"+victim.UUID, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		serverRouter("server-A").ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code, "server-A must not overwrite server-B's downtime")

		got, err := database.GetDowntimeByUUID(victim.UUID)
		require.NoError(t, err)
		assert.Equal(t, "server-B", got.ServerID, "victim record owner unchanged")
		assert.NotEqual(t, "hijacked", got.Description, "victim record content unchanged")
	})
}
