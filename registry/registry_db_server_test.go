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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
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
		err := AddRegistration(&testNamespaces[i])
		require.NoError(t, err)
	}

	return testNamespaces
}

func TestServerNamespaceOperations(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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

		err := AddRegistration(&ns)
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

		err := AddRegistration(&ns)
		require.NoError(t, err)

		// Verify server was created
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
		assert.Equal(t, "new-cache.edu", server.Name)
	})

	t.Run("AddDualServerType", func(t *testing.T) {
		// Generate a proper JWKS for the dual server test
		dualServerJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Create first namespace as origin
		originNs := server_structs.Registration{
			Prefix: "/origins/dual-server.edu",
			Pubkey: dualServerJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "dual-server.edu",
				Institution: "Dual University",
				Status:      server_structs.RegApproved,
			},
		}

		err = AddRegistration(&originNs)
		require.NoError(t, err)

		// Create second namespace as cache for same server
		cacheNs := server_structs.Registration{
			Prefix: "/caches/dual-server.edu",
			Pubkey: dualServerJWKS, // Same JWKS since it's the same server
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "dual-server.edu",
				Institution: "Dual University",
				Status:      server_structs.RegApproved,
			},
		}

		err = AddRegistration(&cacheNs)
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

		err := AddRegistration(&ns)
		require.NoError(t, err) // Should not error, just skip

		// Verify no server was created
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)    // Function doesn't error for non-existent records
		assert.Empty(t, server.ID) // But returns empty server
	})

	t.Run("EmptySiteNameShouldFail", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		testJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Try to create registration with empty site name
		reg := server_structs.Registration{
			Prefix: "/origins/empty-sitename.edu",
			Pubkey: testJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "testuser",
				SiteName:    "", // Empty site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&reg)
		assert.Error(t, err, "Should fail with empty site name")
		assert.Contains(t, err.Error(), "Site Name is required", "Error should mention site name requirement")
	})
}

func TestUpdateNamespaceWithServerTables(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
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

	err := AddRegistration(&ns)
	require.NoError(t, err)

	t.Run("UpdateNamespaceAndServer", func(t *testing.T) {
		// Update the namespace
		ns.AdminMetadata.SiteName = "updated-test.edu"
		ns.AdminMetadata.Description = "Updated description"

		err := updateRegistration(&ns)
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

		err := updateRegistration(&ns)
		require.NoError(t, err)

		// Verify server flags were updated
		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		assert.False(t, server.IsOrigin)
		assert.True(t, server.IsCache)
	})
}

func TestServerTableConstraints(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("ServerNameUniqueness", func(t *testing.T) {
		// Generate a proper JWKS for the unique server test
		uniqueServerJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Create first namespace
		ns1 := server_structs.Registration{
			Prefix: "/origins/unique-server.edu",
			Pubkey: uniqueServerJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "unique-server.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&ns1)
		require.NoError(t, err)

		// Try to create another namespace with same site name but different prefix
		ns2 := server_structs.Registration{
			Prefix: "/caches/unique-server.edu", // Different prefix but same site name
			Pubkey: uniqueServerJWKS,            // Same JWKS since it's the same server
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "unique-server.edu", // Same site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}

		// This should succeed and update the existing server to be both origin and cache
		err = AddRegistration(&ns2)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
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

	err := AddRegistration(&ns)
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
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("ServerWithBothOriginAndCacheWithSameName", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		testJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Create an origin registration for a server
		originReg := server_structs.Registration{
			Prefix: "/origins/dual-service.edu",
			Pubkey: testJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "testuser",
				SiteName:    "dual-service.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&originReg)
		require.NoError(t, err, "Failed to add origin namespace")

		// Create a cache registration for the same server
		cacheReg := server_structs.Registration{
			Prefix: "/caches/dual-service.edu",
			Pubkey: testJWKS, // Same pubkey since it's the same server
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "testuser",
				SiteName:    "dual-service.edu", // Same site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&cacheReg)
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
		assert.Equal(t, testJWKS, registrations[0].Pubkey)
		assert.Equal(t, "Test University", registrations[0].AdminMetadata.Institution)

		// Verify origin registration
		assert.Equal(t, "/origins/dual-service.edu", registrations[1].Prefix)
		assert.Equal(t, testJWKS, registrations[1].Pubkey)
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

	t.Run("DifferentPublicKeysForSameServerName", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		// Generate two different JWKS
		firstJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)
		secondJWKS, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Create first registration
		firstReg := server_structs.Registration{
			Prefix: "/origins/conflicted-server.edu",
			Pubkey: firstJWKS,
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "user1",
				SiteName:    "conflicted-server.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&firstReg)
		require.NoError(t, err, "First registration should succeed")

		// Try to create second registration with same site name but different pubkey
		secondReg := server_structs.Registration{
			Prefix: "/caches/conflicted-server.edu",
			Pubkey: secondJWKS, // Different pubkey
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "user2",                 // Different user
				SiteName:    "conflicted-server.edu", // Same site name
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&secondReg)
		assert.Error(t, err, "Should fail when trying to register same server name with different pubkey")
		assert.Contains(t, err.Error(), "already exists", "Error should mention server already exists")
	})

	t.Run("MultipleServersWithDifferentNames", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		jwks1, err := test_utils.GenerateJWKS()
		require.NoError(t, err)
		jwks2, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		// Create first server
		server1Reg := server_structs.Registration{
			Prefix: "/origins/server1.edu",
			Pubkey: jwks1,
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "user1",
				SiteName:    "server1.edu",
				Institution: "University 1",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&server1Reg)
		require.NoError(t, err, "First server registration should succeed")

		// Create second server with different name
		server2Reg := server_structs.Registration{
			Prefix: "/caches/server2.edu",
			Pubkey: jwks2,
			AdminMetadata: server_structs.AdminMetadata{
				UserID:      "user2",
				SiteName:    "server2.edu", // Different site name
				Institution: "University 2",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&server2Reg)
		require.NoError(t, err, "Second server registration should succeed")

		// Verify two servers were created
		var serverCount int64
		err = database.ServerDatabase.Model(&server_structs.Server{}).Count(&serverCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(2), serverCount, "Expected exactly two servers")

		// Verify servers have correct flags
		var servers []server_structs.Server
		err = database.ServerDatabase.Find(&servers).Error
		require.NoError(t, err)
		require.Len(t, servers, 2)

		// Find each server and verify flags
		var server1, server2 server_structs.Server
		for _, s := range servers {
			if s.Name == "server1.edu" {
				server1 = s
			} else if s.Name == "server2.edu" {
				server2 = s
			}
		}

		assert.True(t, server1.IsOrigin, "Server1 should be marked as origin")
		assert.False(t, server1.IsCache, "Server1 should not be marked as cache")

		assert.False(t, server2.IsOrigin, "Server2 should not be marked as origin")
		assert.True(t, server2.IsCache, "Server2 should be marked as cache")
	})
}

func testDowntimeForServer(serverID, serverName string) server_structs.Downtime {
	now := time.Now().UnixMilli()
	return server_structs.Downtime{
		UUID:        uuid.NewString(),
		ServerID:    serverID,
		ServerName:  serverName,
		CreatedBy:   "test-user",
		UpdatedBy:   "test-user",
		Source:      "registry",
		Class:       server_structs.SCHEDULED,
		Description: "unit test downtime",
		Severity:    server_structs.NoSignificantOutageExpected,
		StartTime:   now,
		EndTime:     now + 3600000,
	}
}

// TestDeleteRegistrationByID_RemovesDowntimes covers explicit downtime cleanup when the last
// service for a server is removed (no FK from downtimes to servers).
func TestDeleteRegistrationByID_RemovesDowntimes(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	t.Run("deletes-downtimes-when-last-service-removed", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		ns := server_structs.Registration{
			Prefix: "/origins/downtime-reg-delete.edu",
			Pubkey: "test-pubkey",
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "downtime-reg-delete.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err := AddRegistration(&ns)
		require.NoError(t, err)

		server, err := getServerByRegistrationID(ns.ID)
		require.NoError(t, err)
		require.NotEmpty(t, server.ID)

		dt := testDowntimeForServer(server.ID, server.Name)
		err = database.ServerDatabase.Create(&dt).Error
		require.NoError(t, err)

		err = deleteRegistrationByID(ns.ID)
		require.NoError(t, err)

		var downtimeCount int64
		err = database.ServerDatabase.Model(&server_structs.Downtime{}).Where("server_id = ?", server.ID).Count(&downtimeCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(0), downtimeCount)

		var serverCount int64
		err = database.ServerDatabase.Model(&server_structs.Server{}).Where("id = ?", server.ID).Count(&serverCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(0), serverCount)
	})

	t.Run("keeps-downtimes-when-other-service-remains", func(t *testing.T) {
		defer resetMockRegistryDB(t)

		jwks, err := test_utils.GenerateJWKS()
		require.NoError(t, err)

		originReg := server_structs.Registration{
			Prefix: "/origins/downtime-dual.edu",
			Pubkey: jwks,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "downtime-dual.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&originReg)
		require.NoError(t, err)

		cacheReg := server_structs.Registration{
			Prefix: "/caches/downtime-dual.edu",
			Pubkey: jwks,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:    "downtime-dual.edu",
				Institution: "Test University",
				Status:      server_structs.RegApproved,
			},
		}
		err = AddRegistration(&cacheReg)
		require.NoError(t, err)

		server, err := getServerByRegistrationID(originReg.ID)
		require.NoError(t, err)
		dt := testDowntimeForServer(server.ID, server.Name)
		err = database.ServerDatabase.Create(&dt).Error
		require.NoError(t, err)

		err = deleteRegistrationByID(originReg.ID)
		require.NoError(t, err)

		var downtimeCount int64
		err = database.ServerDatabase.Model(&server_structs.Downtime{}).Where("server_id = ?", server.ID).Count(&downtimeCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(1), downtimeCount)

		var serverCount int64
		err = database.ServerDatabase.Model(&server_structs.Server{}).Where("id = ?", server.ID).Count(&serverCount).Error
		require.NoError(t, err)
		assert.Equal(t, int64(1), serverCount)
	})
}

// TestApplyLoggingNamespaceAutoApproval verifies the helper extracted from
// keySignChallengeCommit that auto-approves logging namespace registrations
// when Registry.EnableAutoLoggingRegistration is true.
func TestApplyLoggingNamespaceAutoApproval(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	// genPubkeyJSON returns a JSON-encoded JWK set containing one freshly
	// generated ECDSA P-256 public key.
	genPubkeyJSON := func(t *testing.T) (string, jwk.Key) {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub, err := jwk.FromRaw(priv.PublicKey)
		require.NoError(t, err)
		require.NoError(t, jwk.AssignKeyID(pub))
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(pub))
		data, err := json.Marshal(set)
		require.NoError(t, err)
		return string(data), pub
	}

	t.Run("ApprovedOriginAutoApprovesLoggingNS", func(t *testing.T) {
		pubkeyJSON, _ := genPubkeyJSON(t)
		const sitename = "ApprovedAutoOrigin"
		originNs := server_structs.Registration{
			Prefix: "/origins/approved-auto-test.edu",
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		applyLoggingNamespaceAutoApproval(sitename, &loggingNs)

		assert.Equal(t, server_structs.RegApproved, loggingNs.AdminMetadata.Status)
		assert.Equal(t, "system", loggingNs.AdminMetadata.ApproverID)
		assert.False(t, loggingNs.AdminMetadata.ApprovedAt.IsZero())
	})

	t.Run("WrongKeyDoesNotAutoApprove", func(t *testing.T) {
		// Register origin with key A; attempt auto-approval with key B.
		// The approval should be denied even though the origin is approved.
		pubkeyJSONA, _ := genPubkeyJSON(t)
		pubkeyJSONB, _ := genPubkeyJSON(t)
		const sitename = "WrongKeyOrigin"
		originNs := server_structs.Registration{
			Prefix: "/origins/wrong-key-test.edu",
			Pubkey: pubkeyJSONA,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSONB, // different key from origin
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		applyLoggingNamespaceAutoApproval(sitename, &loggingNs)

		assert.Equal(t, server_structs.RegPending, loggingNs.AdminMetadata.Status,
			"mismatched key should not trigger auto-approval even when origin is approved")
	})

	t.Run("PendingOriginDoesNotAutoApproveLoggingNS", func(t *testing.T) {
		pubkeyJSON, _ := genPubkeyJSON(t)
		const sitename = "PendingAutoOrigin"
		originNs := server_structs.Registration{
			Prefix: "/origins/pending-auto-test.edu",
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		applyLoggingNamespaceAutoApproval(sitename, &loggingNs)

		assert.Equal(t, server_structs.RegPending, loggingNs.AdminMetadata.Status,
			"pending origin should not trigger auto-approval")
	})

	t.Run("UnknownSitenameDoesNotAutoApprove", func(t *testing.T) {
		pubkeyJSON, _ := genPubkeyJSON(t)
		const sitename = "GhostOrigin"
		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		applyLoggingNamespaceAutoApproval(sitename, &loggingNs)

		assert.Equal(t, server_structs.RegPending, loggingNs.AdminMetadata.Status,
			"unknown sitename should not trigger auto-approval")
	})
}

// TestCascadeApproveLoggingNamespace verifies that when an admin approves an
// origin's primary registration, a corresponding pending logging namespace is
// automatically approved by cascadeApproveLoggingNamespace.
func TestCascadeApproveLoggingNamespace(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	genPubkeyJSON := func(t *testing.T) string {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub, err := jwk.FromRaw(priv.PublicKey)
		require.NoError(t, err)
		require.NoError(t, jwk.AssignKeyID(pub))
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(pub))
		data, err := json.Marshal(set)
		require.NoError(t, err)
		return string(data)
	}

	t.Run("ApprovesLoggingNSAfterOriginApproved", func(t *testing.T) {
		pubkeyJSON := genPubkeyJSON(t)
		const sitename = "cascade-test.edu"

		// Register origin as pending (simulating startup before admin approval).
		originNs := server_structs.Registration{
			Prefix: "/origins/cascade-origin.edu",
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		// Register logging namespace — also pending because origin wasn't approved yet.
		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		require.NoError(t, AddRegistration(&loggingNs))

		// Simulate admin approving the origin's primary registration.
		require.NoError(t, updateRegistrationStatusById(originNs.ID, server_structs.RegApproved, "admin"))

		// Now trigger the cascade (in production this is called by updateNamespaceStatus).
		cascadeApproveLoggingNamespace(sitename)

		// The logging namespace should now be approved.
		updated, err := getRegistrationByPrefix(loggingNs.Prefix)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RegApproved, updated.AdminMetadata.Status)
		assert.Equal(t, "system", updated.AdminMetadata.ApproverID)
		assert.False(t, updated.AdminMetadata.ApprovedAt.IsZero())
	})

	t.Run("DoesNotOverwriteAlreadyApproved", func(t *testing.T) {
		pubkeyJSON := genPubkeyJSON(t)
		const sitename = "already-approved-origin.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/already-approved-host.edu",
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		approvedAt := time.Now().Add(-time.Hour)
		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName:   sitename,
				Status:     server_structs.RegApproved,
				ApproverID: "human-admin",
				ApprovedAt: approvedAt,
			},
		}
		require.NoError(t, AddRegistration(&loggingNs))

		// Cascade should be a no-op because logging NS is not pending.
		cascadeApproveLoggingNamespace(sitename)

		updated, err := getRegistrationByPrefix(loggingNs.Prefix)
		require.NoError(t, err)
		assert.Equal(t, "human-admin", updated.AdminMetadata.ApproverID,
			"already-approved logging namespace should not be overwritten by cascade")
	})

	t.Run("SkipsWhenNoLoggingNS", func(t *testing.T) {
		pubkeyJSON := genPubkeyJSON(t)
		const sitename = "no-logging-ns-origin.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/no-logging-ns-host.edu",
			Pubkey: pubkeyJSON,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		// Should not panic or error when no logging namespace exists.
		assert.NotPanics(t, func() { cascadeApproveLoggingNamespace(sitename) })
	})

	t.Run("SkipsKeyMismatch", func(t *testing.T) {
		pubkeyJSONA := genPubkeyJSON(t)
		pubkeyJSONB := genPubkeyJSON(t)
		const sitename = "key-mismatch-origin.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/key-mismatch-host.edu",
			Pubkey: pubkeyJSONA,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: pubkeyJSONB, // different key
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegPending,
			},
		}
		require.NoError(t, AddRegistration(&loggingNs))

		cascadeApproveLoggingNamespace(sitename)

		updated, err := getRegistrationByPrefix(loggingNs.Prefix)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RegPending, updated.AdminMetadata.Status,
			"key mismatch should prevent cascade approval")
	})
}

// TestCascadeUpdateLoggingNamespaceKey verifies that when an admin edits an
// origin's public key, the associated logging namespace's pubkey is updated
// in sync by cascadeUpdateLoggingNamespaceKey.
func TestCascadeUpdateLoggingNamespaceKey(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	setupMockRegistryDB(t)
	defer teardownMockRegistryDB(t)

	genPubkeyJSON := func(t *testing.T) string {
		t.Helper()
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pub, err := jwk.FromRaw(priv.PublicKey)
		require.NoError(t, err)
		require.NoError(t, jwk.AssignKeyID(pub))
		set := jwk.NewSet()
		require.NoError(t, set.AddKey(pub))
		data, err := json.Marshal(set)
		require.NoError(t, err)
		return string(data)
	}

	t.Run("UpdatesLoggingNSKeyWhenOriginKeyChanges", func(t *testing.T) {
		oldKey := genPubkeyJSON(t)
		newKey := genPubkeyJSON(t)
		const sitename = "key-update-origin.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/key-update-host.edu",
			Pubkey: oldKey,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: oldKey,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&loggingNs))

		// Cascade the new key to the logging namespace.
		cascadeUpdateLoggingNamespaceKey(sitename, newKey)

		updated, err := getRegistrationByPrefix(loggingNs.Prefix)
		require.NoError(t, err)
		assert.Equal(t, newKey, updated.Pubkey, "logging namespace pubkey should be updated to match new origin key")
	})

	t.Run("NoopWhenAlreadyInSync", func(t *testing.T) {
		key := genPubkeyJSON(t)
		const sitename = "in-sync-origin.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/in-sync-host.edu",
			Pubkey: key,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		loggingNs := server_structs.Registration{
			Prefix: server_structs.LoggingNamespaceForServer(sitename),
			Pubkey: key,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&loggingNs))

		// Should be a no-op — key is already the same.
		assert.NotPanics(t, func() { cascadeUpdateLoggingNamespaceKey(sitename, key) })

		updated, err := getRegistrationByPrefix(loggingNs.Prefix)
		require.NoError(t, err)
		assert.Equal(t, key, updated.Pubkey)
	})

	t.Run("NoopWhenNoLoggingNS", func(t *testing.T) {
		key := genPubkeyJSON(t)
		const sitename = "no-logging-ns-key-update.edu"

		originNs := server_structs.Registration{
			Prefix: "/origins/no-logging-key-host.edu",
			Pubkey: key,
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: sitename,
				Status:   server_structs.RegApproved,
			},
		}
		require.NoError(t, AddRegistration(&originNs))

		// Should not panic or error when no logging namespace exists.
		assert.NotPanics(t, func() { cascadeUpdateLoggingNamespaceKey(sitename, genPubkeyJSON(t)) })
	})
}
