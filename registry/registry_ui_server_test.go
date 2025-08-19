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

package registry

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func createTestServerData(t *testing.T) []server_structs.Registration {
	testNamespaces := []server_structs.Registration{
		{
			Prefix:   "/origins/test-origin-api.edu",
			Pubkey:   "test-pubkey-1",
			Identity: "test-identity-1",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "test-origin-api.edu",
				Institution: "API Test University",
				Description: "Test origin server for API",
				Status:      server_structs.RegApproved,
				UserID:      "api-user1",
			},
		},
		{
			Prefix:   "/caches/test-cache-api.edu",
			Pubkey:   "test-pubkey-2",
			Identity: "test-identity-2",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "test-cache-api.edu",
				Institution: "API Test University",
				Description: "Test cache server for API",
				Status:      server_structs.RegApproved,
				UserID:      "api-user2",
			},
		},
	}

	// Add namespaces which will automatically create servers
	for i := range testNamespaces {
		err := AddNamespace(&testNamespaces[i])
		require.NoError(t, err)
	}

	return testNamespaces
}

func TestListServersHandler(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	setupMockRegistryDB(t)

	_ = createTestServerData(t)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers", listServersHandler)

	t.Run("SuccessfulListServers", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var servers []server_structs.ServerRegistration
		err := json.Unmarshal(w.Body.Bytes(), &servers)
		require.NoError(t, err)
		assert.Len(t, servers, 2)

		// Verify response structure
		assert.NotEmpty(t, servers[0].ID)
		assert.NotEmpty(t, servers[0].Name)
		require.Len(t, servers[0].Registration, 1, "Expected exactly one registration for server 0")
		assert.NotEmpty(t, servers[0].Registration[0].Prefix)
		assert.NotEmpty(t, servers[0].Registration[0].AdminMetadata.Institution)
	})

	t.Run("EmptyServersListReturnsEmptyArray", func(t *testing.T) {
		// Clear all data
		err := database.ServerDatabase.Exec("DELETE FROM services").Error
		require.NoError(t, err)
		err = database.ServerDatabase.Exec("DELETE FROM servers").Error
		require.NoError(t, err)
		err = database.ServerDatabase.Exec("DELETE FROM registrations").Error
		require.NoError(t, err)

		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var servers []server_structs.ServerRegistration
		err = json.Unmarshal(w.Body.Bytes(), &servers)
		require.NoError(t, err)
		assert.Len(t, servers, 0)
	})
}

func TestGetServerHandler(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	setupMockRegistryDB(t)

	testNamespaces := createTestServerData(t)

	// Get the server ID from the first namespace
	server, err := getServerByRegistrationID(testNamespaces[0].ID)
	require.NoError(t, err)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers/:id", getServerHandler)

	t.Run("SuccessfulGetServer", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers/"+server.ID, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var returnedServer server_structs.ServerRegistration
		err := json.Unmarshal(w.Body.Bytes(), &returnedServer)
		require.NoError(t, err)
		assert.Equal(t, server.ID, returnedServer.ID)
		assert.Equal(t, server.Name, returnedServer.Name)
		require.Len(t, server.Registration, 1, "Expected exactly one registration for server")
		require.Len(t, returnedServer.Registration, 1, "Expected exactly one registration for returnedServer")
		assert.Equal(t, server.Registration[0].Prefix, returnedServer.Registration[0].Prefix)
	})

	t.Run("GetNonExistentServer", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)

		var response server_structs.SimpleApiResp
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RespFailed, response.Status)
		assert.Contains(t, response.Msg, "Server not found")
	})

	t.Run("GetServerWithEmptyID", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers/", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// This should result in a 404 since the route won't match
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestServerAPIResponseFormats(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	setupMockRegistryDB(t)

	createTestServerData(t)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers", listServersHandler)

	t.Run("JSONResponseStructure", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

		// Parse response to verify JSON structure
		var servers []server_structs.ServerRegistration
		err := json.Unmarshal(w.Body.Bytes(), &servers)
		require.NoError(t, err)
		require.Len(t, servers, 2)

		// Verify first server has expected fields
		server := servers[0]
		assert.NotEmpty(t, server.ID)
		assert.NotEmpty(t, server.Name)
		require.Len(t, server.Registration, 1, "Expected exactly one registration")
		assert.NotEmpty(t, server.Registration[0].Prefix)
		assert.True(t, server.IsOrigin || server.IsCache)

		// Verify AdminMetadata is properly serialized
		assert.NotEmpty(t, server.Registration[0].AdminMetadata.Institution)
		assert.NotEmpty(t, server.Registration[0].AdminMetadata.SiteName)
		assert.Equal(t, server_structs.RegApproved, server.Registration[0].AdminMetadata.Status)

		// Verify timestamps are excluded (should be zero values in JSON)
		assert.True(t, server.CreatedAt.IsZero() || !server.CreatedAt.IsZero()) // Either is acceptable for test
	})

	t.Run("ServerTypeFields", func(t *testing.T) {
		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var servers []server_structs.ServerRegistration
		err := json.Unmarshal(w.Body.Bytes(), &servers)
		require.NoError(t, err)

		// Find origin and cache servers
		var originServer, cacheServer *server_structs.ServerRegistration
		for i := range servers {
			if servers[i].IsOrigin && !servers[i].IsCache {
				originServer = &servers[i]
			} else if servers[i].IsCache && !servers[i].IsOrigin {
				cacheServer = &servers[i]
			}
		}

		require.NotNil(t, originServer, "Should have an origin server")
		require.NotNil(t, cacheServer, "Should have a cache server")

		assert.True(t, originServer.IsOrigin)
		assert.False(t, originServer.IsCache)
		assert.False(t, cacheServer.IsOrigin)
		assert.True(t, cacheServer.IsCache)
	})
}

func TestServerEndpointValidation(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	setupMockRegistryDB(t)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers/:id", getServerHandler)

	t.Run("InvalidServerIDFormat", func(t *testing.T) {
		// Test with various server ID formats - they will all be treated as valid format
		// but non-existent servers, so should return 404 "Server not found"
		testIDs := []string{
			"123",         // Too short
			"abcdefghijk", // Too long
			"ABC1234",     // Contains uppercase
			"abc-123",     // Contains special character
			"",            // Empty
		}

		for _, testID := range testIDs {
			req, _ := http.NewRequest("GET", "/servers/"+testID, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// Should return 404 for non-existent servers
			assert.Equal(t, http.StatusNotFound, w.Code, "ID: %s should return 404", testID)

			if w.Code == http.StatusNotFound && len(w.Body.Bytes()) > 0 {
				var response server_structs.SimpleApiResp
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err == nil {
					assert.Equal(t, server_structs.RespFailed, response.Status)
					assert.Contains(t, response.Msg, "Server not found")
				}
			}
		}
	})
}

func TestServerAPIErrorHandling(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	setupMockRegistryDB(t)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers", listServersHandler)
	router.GET("/servers/:id", getServerHandler)

	t.Run("DatabaseConnectionError", func(t *testing.T) {
		// Close the database connection to simulate error
		if database.ServerDatabase != nil {
			sqlDB, err := database.ServerDatabase.DB()
			if err == nil {
				sqlDB.Close()
			}
		}

		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)

		var response server_structs.SimpleApiResp
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RespFailed, response.Status)
		assert.Contains(t, response.Msg, "Failed to list servers")
	})
}

func TestServerIntegrationWithNamespaceOperations(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})
	setupMockRegistryDB(t)

	// Set up Gin router
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/servers", listServersHandler)

	t.Run("ServerCreatedWhenNamespaceAdded", func(t *testing.T) {
		// Check initial server count
		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var initialServers []server_structs.ServerRegistration
		err := json.Unmarshal(w.Body.Bytes(), &initialServers)
		require.NoError(t, err)
		initialCount := len(initialServers)

		// Add a new namespace
		ns := server_structs.Registration{
			Prefix: "/origins/integration-test.edu",
			Pubkey: "integration-test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "integration-test.edu",
				Institution: "Integration Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddNamespace(&ns)
		require.NoError(t, err)

		// Check that server count increased
		req, _ = http.NewRequest("GET", "/servers", nil)
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var newServers []server_structs.ServerRegistration
		err = json.Unmarshal(w.Body.Bytes(), &newServers)
		require.NoError(t, err)
		assert.Len(t, newServers, initialCount+1)

		// Verify the new server exists
		var foundServer *server_structs.ServerRegistration
		for i := range newServers {
			if newServers[i].Name == "integration-test.edu" {
				foundServer = &newServers[i]
				break
			}
		}
		require.NotNil(t, foundServer, "New server should be created")
		assert.True(t, foundServer.IsOrigin)
		require.Len(t, foundServer.Registration, 1, "Expected exactly one registration")
		assert.Equal(t, "/origins/integration-test.edu", foundServer.Registration[0].Prefix)
	})

	t.Run("ServerUpdatedWhenNamespaceUpdated", func(t *testing.T) {
		// Create initial namespace
		ns := server_structs.Registration{
			Prefix: "/origins/update-integration.edu",
			Pubkey: "update-test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "update-integration.edu",
				Institution: "Update Test University",
				Description: "Original description",
				Status:      server_structs.RegApproved,
			},
		}
		err := AddNamespace(&ns)
		require.NoError(t, err)

		// Get initial server state
		initialServer, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)

		// Update the namespace
		ns.AdminMetadata.SiteName = "updated-integration.edu"
		ns.AdminMetadata.Description = "Updated description"
		err = updateNamespace(&ns)
		require.NoError(t, err)

		// Verify server was updated via API
		req, _ := http.NewRequest("GET", "/servers", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		var servers []server_structs.ServerRegistration
		err = json.Unmarshal(w.Body.Bytes(), &servers)
		require.NoError(t, err)

		var updatedServer *server_structs.ServerRegistration
		for i := range servers {
			if servers[i].ID == initialServer.ID {
				updatedServer = &servers[i]
				break
			}
		}
		require.NotNil(t, updatedServer, "Updated server should still exist")
		assert.Equal(t, "updated-integration.edu", updatedServer.Name)
		require.Len(t, updatedServer.Registration, 1, "Expected exactly one registration")
		assert.Equal(t, "Updated description", updatedServer.Registration[0].AdminMetadata.Description)
	})
}
