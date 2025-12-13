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

	require.NoError(t, param.Set(param.Server_WebPort.GetName(), 0))
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), "https://mock-server.com"))
	require.NoError(t, param.Set(param.Xrootd_Sitename.GetName(), "mock-sitename"))

	dirName := t.TempDir()
	require.NoError(t, param.Set("ConfigDir", dirName))
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))
	require.NoError(t, param.Set(param.Origin_Port.GetName(), 0))

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
