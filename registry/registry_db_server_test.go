/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

func setupTestRegistryServerDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_registry.sqlite")

	// Set database location using viper
	viper.Set(param.Server_DbLocation.GetName(), dbPath)

	// Initialize the server database
	err := database.InitServerDatabase(server_structs.RegistryType)
	require.NoError(t, err)

	// Set the database connection for the registry package
	SetDB(database.ServerDatabase)
}

func teardownTestRegistryServerDB(t *testing.T) {
	// Clean up
	err := ShutdownRegistryDB()
	require.NoError(t, err)
}

func createTestNamespaces(t *testing.T) []server_structs.Namespace {
	testNamespaces := []server_structs.Namespace{
		{
			Prefix:   "/origins/test-origin-1.edu",
			Pubkey:   "test-pubkey-1",
			Identity: "test-identity-1",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "test-origin-1.edu",
				Institution: "Test University 1",
				Description: "Test origin server 1",
				Status:      server_structs.RegApproved,
				UserID:      "user1",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
		{
			Prefix:   "/caches/test-cache-1.edu",
			Pubkey:   "test-pubkey-2",
			Identity: "test-identity-2",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "test-cache-1.edu",
				Institution: "Test University 2",
				Description: "Test cache server 1",
				Status:      server_structs.RegApproved,
				UserID:      "user2",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		},
		{
			Prefix:   "/origins/test-origin-2.edu",
			Pubkey:   "test-pubkey-3",
			Identity: "test-identity-3",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "test-origin-2.edu",
				Institution: "Test University 1", // Same institution as first
				Description: "Test origin server 2",
				Status:      server_structs.RegApproved,
				UserID:      "user1",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
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

func TestServerNamespaceOperations(t *testing.T) {
	setupTestRegistryServerDB(t)
	defer teardownTestRegistryServerDB(t)

	testNamespaces := createTestNamespaces(t)

	t.Run("GetServerByNamespaceID", func(t *testing.T) {
		server, err := getServerByNamespaceID(testNamespaces[0].ID)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Equal(t, "test-origin-1.edu", server.Name)
		assert.True(t, server.IsOrigin)
		assert.False(t, server.IsCache)
		assert.Equal(t, "/origins/test-origin-1.edu", server.Prefix)
		assert.Equal(t, "Test University 1", server.AdminMetadata.Institution)
	})

	t.Run("GetServerByID", func(t *testing.T) {
		// First get the server ID
		serverByNs, err := getServerByNamespaceID(testNamespaces[0].ID)
		require.NoError(t, err)

		// Now get by server ID
		server, err := getServerByID(serverByNs.ID)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Equal(t, serverByNs.ID, server.ID)
		assert.Equal(t, "test-origin-1.edu", server.Name)
	})

	t.Run("ListServers", func(t *testing.T) {
		servers, err := listServers()
		require.NoError(t, err)
		assert.Len(t, servers, 3) // Should have 3 servers

		// Verify server types
		originCount := 0
		cacheCount := 0
		for _, server := range servers {
			if server.IsOrigin {
				originCount++
			}
			if server.IsCache {
				cacheCount++
			}
		}
		assert.Equal(t, 2, originCount)
		assert.Equal(t, 1, cacheCount)
	})

	t.Run("GetServerByNonExistentNamespaceID", func(t *testing.T) {
		server, err := getServerByNamespaceID(999)
		require.NoError(t, err) // The function doesn't return an error for non-existent records
		// Instead, it returns a server with empty ID
		assert.Empty(t, server.ID)
	})

	t.Run("GetServerByNonExistentID", func(t *testing.T) {
		server, err := getServerByID("nonexist")
		require.NoError(t, err) // The function doesn't return an error for non-existent records
		// Instead, it returns a server with empty ID
		assert.Empty(t, server.ID)
	})
}

func TestAddNamespaceCreatesServers(t *testing.T) {
	setupTestRegistryServerDB(t)
	defer teardownTestRegistryServerDB(t)

	t.Run("AddOriginServer", func(t *testing.T) {
		ns := server_structs.Namespace{
			Prefix: "/origins/new-origin.edu",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "new-origin.edu",
				Institution: "New University",
				Status:      server_structs.RegApproved,
			},
		}

		err := AddNamespace(&ns)
		require.NoError(t, err)

		// Verify server was created
		server, err := getServerByNamespaceID(ns.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.False(t, server.IsCache)
		assert.Equal(t, "new-origin.edu", server.Name)
	})

	t.Run("AddCacheServer", func(t *testing.T) {
		ns := server_structs.Namespace{
			Prefix: "/caches/new-cache.edu",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "new-cache.edu",
				Institution: "New University",
				Status:      server_structs.RegApproved,
			},
		}

		err := AddNamespace(&ns)
		require.NoError(t, err)

		// Verify server was created
		server, err := getServerByNamespaceID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
		assert.Equal(t, "new-cache.edu", server.Name)
	})

	t.Run("AddDualServerType", func(t *testing.T) {
		// Create first namespace as origin
		originNs := server_structs.Namespace{
			Prefix: "/origins/dual-server.edu",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "dual-server.edu",
				Institution: "Dual University",
				Status:      server_structs.RegApproved,
			},
		}

		err := AddNamespace(&originNs)
		require.NoError(t, err)

		// Create second namespace as cache for same server
		cacheNs := server_structs.Namespace{
			Prefix: "/caches/dual-server.edu",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "dual-server.edu",
				Institution: "Dual University",
				Status:      server_structs.RegApproved,
			},
		}

		err = AddNamespace(&cacheNs)
		require.NoError(t, err)

		// Verify server has both origin and cache capabilities
		server, err := getServerByNamespaceID(originNs.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.True(t, server.IsCache)

		// Verify both namespaces map to same server
		server2, err := getServerByNamespaceID(cacheNs.ID)
		require.NoError(t, err)
		assert.Equal(t, server.ID, server2.ID)
	})

	t.Run("SkipNonServerNamespace", func(t *testing.T) {
		ns := server_structs.Namespace{
			Prefix: "/regular/namespace",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "regular-namespace",
				Institution: "Regular University",
				Status:      server_structs.RegApproved,
			},
		}

		err := AddNamespace(&ns)
		require.NoError(t, err) // Should not error, just skip

		// Verify no server was created
		server, err := getServerByNamespaceID(ns.ID)
		require.NoError(t, err)    // Function doesn't error for non-existent records
		assert.Empty(t, server.ID) // But returns empty server
	})
}

func TestUpdateNamespaceWithServerTables(t *testing.T) {
	setupTestRegistryServerDB(t)
	defer teardownTestRegistryServerDB(t)

	// Create initial namespace
	ns := server_structs.Namespace{
		Prefix: "/origins/update-test.edu",
		Pubkey: "test-pubkey",
		AdminMetadata: server_structs.AdminMetadata{
			SiteName:    "update-test.edu",
			Institution: "Update University",
			Status:      server_structs.RegApproved,
		},
	}

	err := AddNamespace(&ns)
	require.NoError(t, err)

	t.Run("UpdateNamespaceAndServer", func(t *testing.T) {
		// Update the namespace
		ns.AdminMetadata.SiteName = "updated-test.edu"
		ns.AdminMetadata.Description = "Updated description"

		err := updateNamespace(&ns)
		require.NoError(t, err)

		// Verify server was updated
		server, err := getServerByNamespaceID(ns.ID)
		require.NoError(t, err)
		assert.Equal(t, "updated-test.edu", server.Name)
		assert.Equal(t, "Updated description", server.AdminMetadata.Description)
	})

	t.Run("UpdateServerTypeFlags", func(t *testing.T) {
		// Change to cache prefix (this would normally not happen in practice)
		ns.Prefix = "/caches/updated-test.edu"

		err := updateNamespace(&ns)
		require.NoError(t, err)

		// Verify server flags were updated
		server, err := getServerByNamespaceID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
	})
}

func TestServerTableConstraints(t *testing.T) {
	setupTestRegistryServerDB(t)
	defer teardownTestRegistryServerDB(t)

	t.Run("ServerNameUniqueness", func(t *testing.T) {
		// Create first namespace
		ns1 := server_structs.Namespace{
			Prefix: "/origins/unique-server.edu",
			Pubkey: "test-pubkey-1",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "unique-server.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err := AddNamespace(&ns1)
		require.NoError(t, err)

		// Try to create another namespace with same site name but different prefix
		ns2 := server_structs.Namespace{
			Prefix: "/caches/unique-server.edu", // Different prefix but same site name
			Pubkey: "test-pubkey-2",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "unique-server.edu", // Same site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}

		// This should succeed and update the existing server to be both origin and cache
		err = AddNamespace(&ns2)
		require.NoError(t, err)

		// Verify the server has both capabilities
		server, err := getServerByNamespaceID(ns1.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.True(t, server.IsCache)
	})

	t.Run("ForeignKeyConstraints", func(t *testing.T) {
		// Try to create service with non-existent namespace ID
		service := server_structs.Service{
			ServerID:    "test123",
			NamespaceID: 999, // Non-existent namespace
		}
		err := database.ServerDatabase.Create(&service).Error
		assert.Error(t, err) // Should fail due to foreign key constraint

		// Try to create endpoint with non-existent server ID
		endpoint := server_structs.Endpoint{
			ServerID: "nonexist",
			Endpoint: "https://test.edu:8443",
		}
		err = database.ServerDatabase.Create(&endpoint).Error
		assert.Error(t, err) // Should fail due to foreign key constraint

		// Try to create contact with non-existent server ID
		contact := server_structs.Contact{
			ServerID:    "nonexist",
			FullName:    "Test User",
			ContactInfo: "test@test.edu",
		}
		err = database.ServerDatabase.Create(&contact).Error
		assert.Error(t, err) // Should fail due to foreign key constraint
	})
}

func TestServerTableCascadeDelete(t *testing.T) {
	setupTestRegistryServerDB(t)
	defer teardownTestRegistryServerDB(t)

	// Create a namespace which will create a server
	ns := server_structs.Namespace{
		Prefix: "/origins/cascade-test.edu",
		Pubkey: "test-pubkey",
		AdminMetadata: server_structs.AdminMetadata{
			SiteName:    "cascade-test.edu",
			Institution: "Test University",
			Status:      server_structs.RegApproved,
		},
	}

	err := AddNamespace(&ns)
	require.NoError(t, err)

	// Get the server to create related records
	server, err := getServerByNamespaceID(ns.ID)
	require.NoError(t, err)

	// Create related records
	endpoint := server_structs.Endpoint{
		ServerID: server.ID,
		Endpoint: "https://cascade-test.edu:8443",
	}
	err = database.ServerDatabase.Create(&endpoint).Error
	require.NoError(t, err)

	contact := server_structs.Contact{
		ServerID:    server.ID,
		FullName:    "Test Admin",
		ContactInfo: "admin@cascade-test.edu",
	}
	err = database.ServerDatabase.Create(&contact).Error
	require.NoError(t, err)

	t.Run("CascadeDeleteOnServerDeletion", func(t *testing.T) {
		// Delete the server
		err := database.ServerDatabase.Delete(&server_structs.Server{}, "id = ?", server.ID).Error
		require.NoError(t, err)

		// Verify all related records were deleted
		var serviceCount, endpointCount, contactCount int64

		err = database.ServerDatabase.Model(&server_structs.Service{}).Where("server_id = ?", server.ID).Count(&serviceCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(0), serviceCount)

		err = database.ServerDatabase.Model(&server_structs.Endpoint{}).Where("server_id = ?", server.ID).Count(&endpointCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(0), endpointCount)

		err = database.ServerDatabase.Model(&server_structs.Contact{}).Where("server_id = ?", server.ID).Count(&contactCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(0), contactCount)
	})
}
