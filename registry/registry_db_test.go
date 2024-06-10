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
	"context"
	"fmt"
	"testing"
	"time"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func migrateTopologyTestTable() error {
	err := db.AutoMigrate(&Topology{})
	if err != nil {
		return fmt.Errorf("failed to migrate topology table: %v", err)
	}
	return nil
}

func setupMockRegistryDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db = mockDB
	require.NoError(t, err, "Error setting up mock namespace DB")
	err = db.AutoMigrate(&server_structs.Namespace{})
	require.NoError(t, err, "Failed to migrate DB for namespace table")
	err = migrateTopologyTestTable()
	require.NoError(t, err, "Error creating topology table")
}

func resetNamespaceDB(t *testing.T) {
	err := db.Where("1 = 1").Delete(&server_structs.Namespace{}).Error
	require.NoError(t, err, "Error resetting namespace DB")
	err = db.Where("1 = 1").Delete(&Topology{}).Error
	require.NoError(t, err, "Error resetting topology DB")
}

func teardownMockNamespaceDB(t *testing.T) {
	err := ShutdownRegistryDB()
	require.NoError(t, err, "Error tearing down mock namespace DB")
}

func insertMockDBData(nss []server_structs.Namespace) error {
	return db.Create(&nss).Error
}

func getLastNamespaceId() (int, error) {
	var namespace server_structs.Namespace
	result := db.Select("id").Order("id DESC").First(&namespace)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return 0, errors.New("Empty database table.")
		} else {
			return 0, result.Error
		}
	}
	return namespace.ID, nil
}

// Compares expected Namespace slice against either a slice of Namespace ptr or just Namespace
func compareNamespaces(execpted []server_structs.Namespace, returned interface{}, woPubkey bool) bool {
	var normalizedReturned []server_structs.Namespace

	switch v := returned.(type) {
	case []server_structs.Namespace:
		normalizedReturned = v
	case []*server_structs.Namespace:
		for _, ptr := range v {
			if ptr != nil {
				normalizedReturned = append(normalizedReturned, *ptr)
			} else {
				// Handle nil pointers if necessary
				normalizedReturned = append(normalizedReturned, server_structs.Namespace{}) // or some default value
			}
		}
	default:
		return false
	}

	if len(execpted) != len(normalizedReturned) {
		return false
	}
	for idx, nssEx := range execpted {
		nssRt := normalizedReturned[idx]
		if nssEx.Prefix != nssRt.Prefix ||
			(!woPubkey && nssEx.Pubkey != nssRt.Pubkey) ||
			nssEx.Identity != nssRt.Identity ||
			nssEx.AdminMetadata != nssRt.AdminMetadata {
			return false
		}
	}
	return true
}

func mockNamespace(prefix, pubkey, identity string, adminMetadata server_structs.AdminMetadata) server_structs.Namespace {
	return server_structs.Namespace{
		Prefix:        prefix,
		Pubkey:        pubkey,
		Identity:      identity,
		AdminMetadata: adminMetadata,
	}
}

// Some genertic mock data function to be shared with other test
// functinos in this package. Please treat them as "constants"
var (
	mockNssWithNamespaces []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/test1", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
		mockNamespace("/test2", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
	}
	mockNssWithOrigins []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/origins/example.com", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
		mockNamespace("/origins/mockorigin.org", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
	}
	mockNssWithCaches []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/caches/random1", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
		mockNamespace("/caches/random2", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegApproved}),
	}
	mockNssWithNamespacesNotApproved []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/pending1", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
		mockNamespace("/pending2", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
	}
	mockNssWithOriginsNotApproved []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/origins/example.com", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
		mockNamespace("/origins/mockorigin.org", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
	}
	mockNssWithCachesNotApproved []server_structs.Namespace = []server_structs.Namespace{
		mockNamespace("/caches/pending1", "pubkey1", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
		mockNamespace("/caches/pending2", "pubkey2", "", server_structs.AdminMetadata{Status: server_structs.RegPending}),
	}
	mockNssWithMixed []server_structs.Namespace = func() (mixed []server_structs.Namespace) {
		mixed = append(mixed, mockNssWithNamespaces...)
		mixed = append(mixed, mockNssWithOrigins...)
		mixed = append(mixed, mockNssWithCaches...)
		return
	}()

	mockNssWithMixedNotApproved []server_structs.Namespace = func() (mixed []server_structs.Namespace) {
		mixed = append(mixed, mockNssWithNamespacesNotApproved...)
		mixed = append(mixed, mockNssWithOriginsNotApproved...)
		mixed = append(mixed, mockNssWithCachesNotApproved...)
		return
	}()

	mockCustomFields = map[string]interface{}{
		"key1": "value1",
		"key2": 2,
		"key3": true,
	}
)

func TestGetNamespaceById(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("return-error-with-empty-db", func(t *testing.T) {
		_, err := getNamespaceById(1)
		assert.Error(t, err)
	})

	t.Run("return-error-with-invalid-id", func(t *testing.T) {
		_, err := getNamespaceById(0)
		assert.Error(t, err)

		_, err = getNamespaceById(-1)
		assert.Error(t, err)
	})

	t.Run("return-namespace-with-correct-id", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "", "", server_structs.AdminMetadata{UserID: "foo"})
		mockNs.CustomFields = mockCustomFields
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)
		nss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))

		got, err := getNamespaceById(nss[0].ID)
		require.NoError(t, err, "Error getting namespace by ID")
		mockNs.ID = nss[0].ID
		assert.Equal(t, mockNs, *got)
	})

	t.Run("return-error-with-id-dne", func(t *testing.T) {
		err := insertMockDBData(mockNssWithNamespaces)
		require.NoError(t, err)
		defer resetNamespaceDB(t)
		_, err = getNamespaceById(100)
		assert.Error(t, err)
	})
}

func TestGetNamespaceStatusById(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("invalid-id", func(t *testing.T) {
		_, err := getNamespaceStatusById(0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid id")
	})

	t.Run("db-query-error", func(t *testing.T) {
		resetNamespaceDB(t)
		_, err := getNamespaceStatusById(1)
		require.Error(t, err)
	})

	t.Run("valid-id-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{mockNamespace("/foo", "", "", server_structs.AdminMetadata{})})
		require.NoError(t, err)
		lastId, err := getLastNamespaceId()
		require.NoError(t, err)
		status, err := getNamespaceStatusById(lastId)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RegUnknown, status)
	})

	t.Run("valid-id-non-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{mockNamespace("/foo", "", "", server_structs.AdminMetadata{Status: server_structs.RegApproved})})
		require.NoError(t, err)
		lastId, err := getLastNamespaceId()
		require.NoError(t, err)
		status, err := getNamespaceStatusById(lastId)
		require.NoError(t, err)
		assert.Equal(t, server_structs.RegApproved, status)
	})
}

func TestAddNamespace(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("set-default-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "pubkey", "identity", server_structs.AdminMetadata{UserID: "someone"})
		err := AddNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		// We can do this because we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.Unix(), got[0].AdminMetadata.CreatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.Unix(), got[0].AdminMetadata.UpdatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("override-restricted-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockCreateAt := time.Now().Add(time.Hour * 10)
		mockUpdatedAt := time.Now().Add(time.Minute * 20)
		mockNs := mockNamespace("/test", "pubkey", "identity", server_structs.AdminMetadata{UserID: "someone", CreatedAt: mockCreateAt, UpdatedAt: mockUpdatedAt})
		err := AddNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)

		assert.NotEqual(t, mockCreateAt.Unix(), mockNs.AdminMetadata.CreatedAt.Unix())
		assert.NotEqual(t, mockUpdatedAt.Unix(), mockNs.AdminMetadata.UpdatedAt.Unix())
		// We can do this because we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.Unix(), got[0].AdminMetadata.CreatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.Unix(), got[0].AdminMetadata.UpdatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("insert-data-integrity", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace(
			"/test",
			"pubkey",
			"identity",
			server_structs.AdminMetadata{
				UserID:                "someone",
				Description:           "Some description",
				SiteName:              "OSG",
				SecurityContactUserID: "security-001",
			})
		mockNs.CustomFields = mockCustomFields
		err := AddNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		assert.Equal(t, mockNs.Pubkey, got[0].Pubkey)
		assert.Equal(t, mockNs.Identity, got[0].Identity)
		assert.Equal(t, mockNs.AdminMetadata.Description, got[0].AdminMetadata.Description)
		assert.Equal(t, mockNs.AdminMetadata.SiteName, got[0].AdminMetadata.SiteName)
		assert.Equal(t, mockNs.AdminMetadata.SecurityContactUserID, got[0].AdminMetadata.SecurityContactUserID)
		assert.Equal(t, mockCustomFields, got[0].CustomFields)
	})
}

func TestUpdateNamespace(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("update-on-dne-entry-returns-error", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "", "", server_structs.AdminMetadata{})
		err := updateNamespace(&mockNs)
		assert.Error(t, err)
	})

	t.Run("update-preserve-internal-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "", "", server_structs.AdminMetadata{UserID: "foo"})
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)
		initialNss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(initialNss))
		initialNs := initialNss[0]
		assert.Equal(t, mockNs.Prefix, initialNs.Prefix)
		initialNs.AdminMetadata.UserID = "bar"
		initialNs.AdminMetadata.CreatedAt = time.Now().Add(10 * time.Hour)
		initialNs.AdminMetadata.UpdatedAt = time.Now().Add(10 * time.Hour)
		initialNs.AdminMetadata.Status = server_structs.RegApproved
		initialNs.AdminMetadata.ApproverID = "hacker"
		initialNs.AdminMetadata.ApprovedAt = time.Now().Add(10 * time.Hour)
		err = updateNamespace(initialNs)
		require.NoError(t, err)
		finalNss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(finalNss))
		finalNs := finalNss[0]
		assert.Equal(t, mockNs.Prefix, finalNs.Prefix)
		assert.Equal(t, initialNs.AdminMetadata.UserID, finalNs.AdminMetadata.UserID) // we now allow changes to UserID
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.Unix(), finalNs.AdminMetadata.CreatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.Status, finalNs.AdminMetadata.Status)
		assert.Equal(t, mockNs.AdminMetadata.ApprovedAt.Unix(), finalNs.AdminMetadata.ApprovedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.ApproverID, finalNs.AdminMetadata.ApproverID)
		// DB first changes initialNs.AdminMetadata.UpdatedAt then commit
		assert.Equal(t, initialNs.AdminMetadata.UpdatedAt.Unix(), finalNs.AdminMetadata.UpdatedAt.Unix())
	})
}

func TestUpdateNamespaceStatusById(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)
	t.Run("return-error-if-id-dne", func(t *testing.T) {
		defer resetNamespaceDB(t)
		err := insertMockDBData(mockNssWithNamespaces)
		require.NoError(t, err)
		err = updateNamespaceStatusById(100, server_structs.RegApproved, "random")
		assert.Error(t, err)
	})

	t.Run("return-error-if-invalid-approver-userId", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", server_structs.AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, server_structs.RegApproved, "")
		assert.Error(t, err)
	})

	t.Run("update-status-with-valid-input-for-approval", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", server_structs.AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, server_structs.RegApproved, "approver1")
		assert.NoError(t, err)
		got, err = getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		assert.Equal(t, server_structs.RegApproved, got[0].AdminMetadata.Status)
		assert.Equal(t, "approver1", got[0].AdminMetadata.ApproverID)
		assert.NotEqual(t, time.Time{}, got[0].AdminMetadata.ApprovedAt)
	})

	t.Run("deny-does-not-modify-approval-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", server_structs.AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		assert.NoError(t, err)
		got, err := getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, server_structs.RegDenied, "approver1")
		assert.NoError(t, err)
		got, err = getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		assert.Equal(t, server_structs.RegDenied, got[0].AdminMetadata.Status)
		assert.Equal(t, "", got[0].AdminMetadata.ApproverID)
		assert.Equal(t, time.Time{}, got[0].AdminMetadata.ApprovedAt)
	})
}

func TestGetNamespacesByFilter(t *testing.T) {
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("return-error-for-unsupported-operations", func(t *testing.T) {
		filterNsID := server_structs.Namespace{
			ID: 123,
		}

		_, err := getNamespacesByFilter(filterNsID, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field ID")

		filterNsCF := server_structs.Namespace{
			CustomFields: mockCustomFields,
		}
		_, err = getNamespacesByFilter(filterNsCF, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported custom fields")

		filterNsIdentity := server_structs.Namespace{
			Identity: "someIdentity",
		}

		_, err = getNamespacesByFilter(filterNsIdentity, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field Identity")

		filterNsPubKey := server_structs.Namespace{
			Pubkey: "somePubkey",
		}

		_, err = getNamespacesByFilter(filterNsPubKey, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field PubKey")

		// Now, for AdminMetadata filters to work, we need to have a valid object
		resetNamespaceDB(t)
		err = insertMockDBData([]server_structs.Namespace{{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}})
		require.NoError(t, err)

		filterNsCreateAt := server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				CreatedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsCreateAt, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field CreatedAt")

		filterNsUpdateAt := server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				UpdatedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsUpdateAt, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field UpdatedAt")

		filterNsApproveAt := server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				ApprovedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsApproveAt, "", false)
		require.Error(t, err, "Should return error for filtering against unsupported field ApprovedAt")
	})

	t.Run("filter-by-prefix-type", func(t *testing.T) {
		// Assuming mock data and insertMockDBData function exist
		resetNamespaceDB(t)
		err := insertMockDBData(mockNssWithMixed)
		require.NoError(t, err)

		filterNs := server_structs.Namespace{}
		gotNss, err := getNamespacesByFilter(filterNs, prefixForNamespace, false)
		require.NoError(t, err)
		assert.NotEmpty(t, gotNss, "Should return non-empty result for namespacePrefix")
		assert.True(t, compareNamespaces(mockNssWithNamespaces, gotNss, true), "Returned nssOrigins does not match")

		gotOrigins, err := getNamespacesByFilter(filterNs, prefixForOrigin, false)
		require.NoError(t, err)
		assert.NotEmpty(t, gotOrigins, "Should return non-empty result for originPrefix")
		assert.True(t, compareNamespaces(mockNssWithOrigins, gotOrigins, true), "Returned nssOrigins does not match")

		gotCaches, err := getNamespacesByFilter(filterNs, prefixForCache, false)
		require.NoError(t, err)
		assert.NotEmpty(t, gotCaches, "Should return non-empty result for cachePrefix")
		assert.True(t, compareNamespaces(mockNssWithCaches, gotCaches, true))
	})

	t.Run("filter-by-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				UserID:                "mockUserID",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}})
		require.NoError(t, err)

		filterNs := server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				Description: "description",
			},
		}

		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Description")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				SiteName: "Madison",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for SiteName")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				Institution: "123456",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Institution")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				SecurityContactUserID: "contactUserID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for SecurityContactUserID")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				ApproverID: "mockApproverID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for ApproverID")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				Status: server_structs.RegPending,
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Status")

		filterNs = server_structs.Namespace{
			AdminMetadata: server_structs.AdminMetadata{
				UserID: "mockUserID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for UserID")
	})

	t.Run("multiple-AND-match", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]server_structs.Namespace{{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}})
		require.NoError(t, err)

		filterNs := server_structs.Namespace{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}
		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for non-empty database without condition")
	})

	t.Run("fully-match", func(t *testing.T) {
		resetNamespaceDB(t)
		mockNs := server_structs.Namespace{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				UserID:                "mockUserID",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		filterNs := mockNs
		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for non-empty database without condition")
	})

	t.Run("no-match", func(t *testing.T) {
		resetNamespaceDB(t)
		mockNs := server_structs.Namespace{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				UserID:                "mockUserID",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}
		err := insertMockDBData([]server_structs.Namespace{mockNs})
		require.NoError(t, err)

		filterNs := mockNs
		filterNs.AdminMetadata.Status = server_structs.RegDenied
		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.Empty(t, namespaces)
	})

	t.Run("empty-db-returns-empty-results", func(t *testing.T) {
		resetNamespaceDB(t)

		filterNs := server_structs.Namespace{}
		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.Empty(t, namespaces, "Should return empty result for empty database")
	})

	t.Run("filter-legacy-result", func(t *testing.T) {
		resetNamespaceDB(t)
		mockLeg := server_structs.Namespace{
			Prefix: "/legacy/1",
		}
		mockNs := server_structs.Namespace{
			Prefix: "/bar",
			AdminMetadata: server_structs.AdminMetadata{
				Description:           "Mock description",
				UserID:                "mockUserID",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                server_structs.RegPending,
			},
		}
		err := insertMockDBData([]server_structs.Namespace{mockLeg, mockNs})
		require.NoError(t, err)

		filterNs := server_structs.Namespace{}
		// Filter out legacy namespaces
		namespaces, err := getNamespacesByFilter(filterNs, "", false)
		require.NoError(t, err)
		assert.Len(t, namespaces, 1)
		assert.Equal(t, mockNs.Prefix, namespaces[0].Prefix)
		assert.EqualValues(t, mockNs.AdminMetadata, namespaces[0].AdminMetadata)

		// Want legacy namespaces
		namespaces, err = getNamespacesByFilter(filterNs, "", true)
		require.NoError(t, err)
		assert.Len(t, namespaces, 1)
		assert.Equal(t, mockLeg.Prefix, namespaces[0].Prefix)
		assert.EqualValues(t, mockLeg.AdminMetadata, namespaces[0].AdminMetadata)
	})
}

func TestGetNamespaceJwksByPrefix(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("db-query-error", func(t *testing.T) {
		resetNamespaceDB(t)
		_, _, err := getNamespaceJwksByPrefix("/")
		require.Error(t, err)
	})

	t.Run("valid-prefix-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		mockJwks := jwk.NewSet()
		jwksByte, err := json.Marshal(mockJwks)
		require.NoError(t, err)

		err = insertMockDBData([]server_structs.Namespace{mockNamespace("/foo", string(jwksByte), "", server_structs.AdminMetadata{})})
		require.NoError(t, err)
		_, admin_meta, err := getNamespaceJwksByPrefix("/foo")
		require.NoError(t, err)
		assert.Equal(t, server_structs.AdminMetadata{}, *admin_meta)
	})

	t.Run("valid-prefix-non-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		mockJwks := jwk.NewSet()
		jwksByte, err := json.Marshal(mockJwks)
		require.NoError(t, err)

		err = insertMockDBData([]server_structs.Namespace{mockNamespace("/foo", string(jwksByte), "", server_structs.AdminMetadata{Status: server_structs.RegApproved})})
		require.NoError(t, err)
		_, admin_meta, err := getNamespaceJwksByPrefix("/foo")
		require.NoError(t, err)
		assert.Equal(t, server_structs.RegApproved, admin_meta.Status)
	})
}

func topologyMockup(t *testing.T, namespaces []string) *httptest.Server {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var namespaceList []map[string]string
		for _, ns := range namespaces {
			namespaceList = append(namespaceList, map[string]string{"path": ns})
		}

		jsonData, err := json.Marshal(map[string][]map[string]string{"namespaces": namespaceList})
		if err != nil {
			t.Fatal(err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonData))
	}))

	return svr
}

func TestRegistryTopology(t *testing.T) {
	viper.Reset()

	topoNamespaces := []string{"/topo/foo", "/topo/bar"}
	svr := topologyMockup(t, topoNamespaces)
	defer svr.Close()

	registryDB := t.TempDir()
	viper.Set("Registry.DbLocation", filepath.Join(registryDB, "test.sqlite"))
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	viper.Set("ConfigDir", t.TempDir())
	config.InitConfig()

	err := InitializeDB()
	require.NoError(t, err)
	defer func() {
		err := ShutdownRegistryDB()
		assert.NoError(t, err)
	}()

	// Set value so that config.GetPreferredPrefix() returns "OSDF"
	_, err = config.SetPreferredPrefix(config.OsdfPrefix)
	assert.NoError(t, err)

	//Test topology table population
	err = migrateTopologyTestTable()
	require.NoError(t, err)
	err = PopulateTopology(context.Background())
	require.NoError(t, err)

	// Check that topology namespace exists
	exists, err := topologyNamespaceExistsByPrefix("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that topology namespace exists
	exists, err = topologyNamespaceExistsByPrefix("/topo/bar")
	require.NoError(t, err)
	require.True(t, exists)

	// Add a test namespace so we can test that checkExists still works
	ns := server_structs.Namespace{
		ID:            0,
		Prefix:        "/regular/foo",
		Pubkey:        "",
		Identity:      "",
		AdminMetadata: server_structs.AdminMetadata{},
	}
	err = AddNamespace(&ns)
	require.NoError(t, err)

	// Check that the regular namespace exists
	exists, err = topologyNamespaceExistsByPrefix("/regular/foo")
	require.NoError(t, err)
	require.False(t, exists)

	// Check that a bad namespace doesn't exist
	exists, err = namespaceExistsByPrefix("/bad/namespace")
	require.NoError(t, err)
	require.False(t, exists)

	// No kill the old topo server, and remove a namespace
	svr.Close()
	svr.CloseClientConnections()

	topoNamespaces = []string{"/topo/foo", "/topo/baz"}
	svr = topologyMockup(t, topoNamespaces)
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	defer svr.Close()

	// Re-populate topo
	//Test topology table population
	err = PopulateTopology(context.Background())
	require.NoError(t, err)

	// Check that /topo/foo still exists
	exists, err = topologyNamespaceExistsByPrefix("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// And that /topo/baz was added
	exists, err = topologyNamespaceExistsByPrefix("/topo/baz")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that /topo/bar is gone
	exists, err = topologyNamespaceExistsByPrefix("/topo/bar")
	require.NoError(t, err)
	require.False(t, exists)

	viper.Reset()
}

func TestGetTopoPrefixString(t *testing.T) {
	t.Run("empty-arr", func(t *testing.T) {
		re := GetTopoPrefixString([]Topology{})
		assert.Empty(t, re)
	})

	t.Run("one-item", func(t *testing.T) {
		re := GetTopoPrefixString([]Topology{{Prefix: "/foo"}})
		assert.Equal(t, "/foo", re)
	})

	t.Run("multiple-items", func(t *testing.T) {
		re := GetTopoPrefixString([]Topology{{Prefix: "/foo"}, {Prefix: "/bar"}, {Prefix: "/barz"}})
		assert.Equal(t, "/foo, /bar, /barz", re)
	})
}
