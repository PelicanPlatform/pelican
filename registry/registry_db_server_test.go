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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
)

func createTestNamespaces(t *testing.T) []server_structs.Registration {
	testNamespaces := []server_structs.Registration{
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
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	testNamespaces := createTestNamespaces(t)

	t.Run("getServerByRegistrationID", func(t *testing.T) {
		server, err := getServerByRegistrationID(testNamespaces[0].ID)
		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Equal(t, "test-origin-1.edu", server.Name)
		assert.True(t, server.IsOrigin)
		assert.False(t, server.IsCache)
		require.Len(t, server.Registration, 1, "Expected exactly one registration")
		assert.Equal(t, "/origins/test-origin-1.edu", server.Registration[0].Prefix)
		assert.Equal(t, "Test University 1", server.Registration[0].AdminMetadata.Institution)
	})

	t.Run("GetServerByID", func(t *testing.T) {
		// First get the server ID
		serverByNs, err := getServerByRegistrationID(testNamespaces[0].ID)
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
		server, err := getServerByRegistrationID(999)
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
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("AddOriginServer", func(t *testing.T) {
		ns := server_structs.Registration{
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
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.False(t, server.IsCache)
		assert.Equal(t, "new-origin.edu", server.Name)
	})

	t.Run("AddCacheServer", func(t *testing.T) {
		ns := server_structs.Registration{
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
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
		assert.Equal(t, "new-cache.edu", server.Name)
	})

	t.Run("AddDualServerType", func(t *testing.T) {
		// Create first namespace as origin
		originNs := server_structs.Registration{
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
		cacheNs := server_structs.Registration{
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
		server, err := getServerByRegistrationID(originNs.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.True(t, server.IsCache)

		// Verify both namespaces map to same server
		server2, err := getServerByRegistrationID(cacheNs.ID)
		require.NoError(t, err)
		assert.Equal(t, server.ID, server2.ID)
	})

	t.Run("SkipNonServerNamespace", func(t *testing.T) {
		ns := server_structs.Registration{
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
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)    // Function doesn't error for non-existent records
		assert.Empty(t, server.ID) // But returns empty server
	})
}

func TestUpdateNamespaceWithServerTables(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	// Create initial namespace
	ns := server_structs.Registration{
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
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.Equal(t, "updated-test.edu", server.Name)
		require.Len(t, server.Registration, 1, "Expected exactly one registration")
		assert.Equal(t, "Updated description", server.Registration[0].AdminMetadata.Description)
	})

	t.Run("UpdateServerTypeFlags", func(t *testing.T) {
		// Change to cache prefix (this would normally not happen in practice)
		ns.Prefix = "/caches/updated-test.edu"

		err := updateNamespace(&ns)
		require.NoError(t, err)

		// Verify server flags were updated
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
	})
}

func TestServerTableConstraints(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("ServerNameUniqueness", func(t *testing.T) {
		// Create first namespace
		ns1 := server_structs.Registration{
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
		ns2 := server_structs.Registration{
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
		server, err := getServerByRegistrationID(ns1.ID)
		require.NoError(t, err)
		assert.True(t, server.IsOrigin)
		assert.True(t, server.IsCache)
	})

	t.Run("ForeignKeyConstraints", func(t *testing.T) {
		// Try to create service with non-existent namespace ID
		service := server_structs.Service{
			ServerID:       "test123",
			RegistrationID: 999, // Non-existent namespace
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
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	// Create a namespace which will create a server
	ns := server_structs.Registration{
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
	server, err := getServerByRegistrationID(ns.ID)
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

func TestServerWithMultipleServices(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("ServerWithBothOriginAndCacheServices", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		// Create an origin registration for a server
		originReg := server_structs.Registration{
			Prefix: "/origins/dual-service.edu",
			Pubkey: "origin-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "testuser",
				SiteName:    "dual-service.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err := AddNamespace(&originReg)
		require.NoError(t, err, "Failed to add origin namespace")

		// Create a cache registration for the same server
		cacheReg := server_structs.Registration{
			Prefix: "/caches/dual-service.edu",
			Pubkey: "cache-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "testuser",
				SiteName:    "dual-service.edu", // Same site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddNamespace(&cacheReg)
		require.NoError(t, err, "Failed to add cache namespace")

		// Verify only one server was created (since they have the same site name)
		var serverCount int64
		err = database.ServerDatabase.Model(&server_structs.Server{}).Count(&serverCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(1), serverCount, "Expected exactly one server for both services")

		// Verify the server has both origin and cache flags set
		var server server_structs.Server
		err = database.ServerDatabase.Where("name = ?", "dual-service.edu").First(&server).Error
		require.NoError(t, err)
		assert.True(t, server.IsOrigin, "Server should be marked as origin")
		assert.True(t, server.IsCache, "Server should be marked as cache")

		// Verify two services were created
		var serviceCount int64
		err = database.ServerDatabase.Model(&server_structs.Service{}).Where("server_id = ?", server.ID).Count(&serviceCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(2), serviceCount, "Expected exactly two services for the server")

		// Test getServerByID returns both registrations
		serverReg, err := getServerByID(server.ID)
		require.NoError(t, err)
		require.NotNil(t, serverReg)
		assert.Equal(t, server.ID, serverReg.ID)
		assert.Equal(t, "dual-service.edu", serverReg.Name)
		assert.True(t, serverReg.IsOrigin)
		assert.True(t, serverReg.IsCache)

		// Verify both registrations are present
		require.Len(t, serverReg.Registration, 2, "Expected exactly two registrations")

		// Sort registrations by prefix for consistent testing
		registrations := serverReg.Registration
		if registrations[0].Prefix > registrations[1].Prefix {
			registrations[0], registrations[1] = registrations[1], registrations[0]
		}

		// Verify cache registration (comes first alphabetically)
		assert.Equal(t, "/caches/dual-service.edu", registrations[0].Prefix)
		assert.Equal(t, "cache-pubkey", registrations[0].Pubkey)
		assert.Equal(t, "Test University", registrations[0].AdminMetadata.Institution)

		// Verify origin registration
		assert.Equal(t, "/origins/dual-service.edu", registrations[1].Prefix)
		assert.Equal(t, "origin-pubkey", registrations[1].Pubkey)
		assert.Equal(t, "Test University", registrations[1].AdminMetadata.Institution)

		// Test getServerByRegistrationID works for both registrations
		originServer, err := getServerByRegistrationID(originReg.ID)
		require.NoError(t, err)
		require.Len(t, originServer.Registration, 2, "Expected both registrations when querying by origin ID")

		cacheServer, err := getServerByRegistrationID(cacheReg.ID)
		require.NoError(t, err)
		require.Len(t, cacheServer.Registration, 2, "Expected both registrations when querying by cache ID")

		// Both should return the same server
		assert.Equal(t, originServer.ID, cacheServer.ID)
		assert.Equal(t, serverReg.ID, originServer.ID)

		// Test listServers includes both registrations
		servers, err := listServers()
		require.NoError(t, err)
		require.Len(t, servers, 1, "Expected exactly one server in list")

		listedServer := servers[0]
		assert.Equal(t, server.ID, listedServer.ID)
		assert.True(t, listedServer.IsOrigin)
		assert.True(t, listedServer.IsCache)
		require.Len(t, listedServer.Registration, 2, "Listed server should have both registrations")
	})
}
