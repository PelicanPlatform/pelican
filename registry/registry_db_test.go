/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"database/sql"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/spf13/viper"
)

func setupMockRegistryDB(t *testing.T) {
	mockDB, err := sql.Open("sqlite", ":memory:")
	db = mockDB
	require.NoError(t, err, "Error setting up mock namespace DB")
	err = createNamespaceTable()
	require.NoError(t, err, "Error creating namespace table")
	err = createTopologyTable()
	require.NoError(t, err, "Error creating topology table")
}

func resetNamespaceDB(t *testing.T) {
	_, err := db.Exec(`DELETE FROM namespace`)
	require.NoError(t, err, "Error resetting namespace DB")
}

func teardownMockNamespaceDB(t *testing.T) {
	err := db.Close()
	require.NoError(t, err, "Error tearing down mock namespace DB")
}

func insertMockDBData(nss []Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata, custom_fields) VALUES (?, ?, ?, ?, ?)`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, ns := range nss {
		adminMetaStr, err := json.Marshal(ns.AdminMetadata)
		if err != nil {
			if errRoll := tx.Rollback(); errRoll != nil {
				return errors.Wrap(errRoll, "Failed to rollback transaction")
			}
			return err
		}
		customFieldsStr, err := json.Marshal(ns.CustomFields)
		if err != nil {
			if errRoll := tx.Rollback(); errRoll != nil {
				return errors.Wrap(errRoll, "Failed to rollback transaction")
			}
			return err
		}

		_, err = tx.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, adminMetaStr, customFieldsStr)
		if err != nil {
			if errRoll := tx.Rollback(); errRoll != nil {
				return errors.Wrap(errRoll, "Failed to rollback transaction")
			}
			return err
		}
	}
	return tx.Commit()
}

func getLastNamespaceId() (int, error) {
	var lastID int
	err := db.QueryRow("SELECT id FROM namespace ORDER BY id DESC LIMIT 1").Scan(&lastID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, errors.New("Empty database table.")
		} else {
			return 0, err
		}
	}
	return lastID, nil
}

// Compares expected Namespace slice against either a slice of Namespace ptr or just Namespace
func compareNamespaces(execpted []Namespace, returned interface{}, woPubkey bool) bool {
	var normalizedReturned []Namespace

	switch v := returned.(type) {
	case []Namespace:
		normalizedReturned = v
	case []*Namespace:
		for _, ptr := range v {
			if ptr != nil {
				normalizedReturned = append(normalizedReturned, *ptr)
			} else {
				// Handle nil pointers if necessary
				normalizedReturned = append(normalizedReturned, Namespace{}) // or some default value
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

func mockNamespace(prefix, pubkey, identity string, adminMetadata AdminMetadata) Namespace {
	return Namespace{
		Prefix:        prefix,
		Pubkey:        pubkey,
		Identity:      identity,
		AdminMetadata: adminMetadata,
	}
}

// Some genertic mock data function to be shared with other test
// functinos in this package. Please treat them as "constants"
var (
	mockNssWithOrigins []Namespace = []Namespace{
		mockNamespace("/test1", "pubkey1", "", AdminMetadata{Status: Approved}),
		mockNamespace("/test2", "pubkey2", "", AdminMetadata{Status: Approved}),
	}
	mockNssWithCaches []Namespace = []Namespace{
		mockNamespace("/caches/random1", "pubkey1", "", AdminMetadata{Status: Approved}),
		mockNamespace("/caches/random2", "pubkey2", "", AdminMetadata{Status: Approved}),
	}
	mockNssWithOriginsNotApproved []Namespace = []Namespace{
		mockNamespace("/pending1", "pubkey1", "", AdminMetadata{Status: Pending}),
		mockNamespace("/pending2", "pubkey2", "", AdminMetadata{Status: Pending}),
	}
	mockNssWithCachesNotApproved []Namespace = []Namespace{
		mockNamespace("/caches/pending1", "pubkey1", "", AdminMetadata{Status: Pending}),
		mockNamespace("/caches/pending2", "pubkey2", "", AdminMetadata{Status: Pending}),
	}
	mockNssWithMixed []Namespace = func() (mixed []Namespace) {
		mixed = append(mixed, mockNssWithOrigins...)
		mixed = append(mixed, mockNssWithCaches...)
		return
	}()

	mockNssWithMixedNotApproved []Namespace = func() (mixed []Namespace) {
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

func TestNamespaceExistsByPrefix(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("return-false-for-prefix-dne", func(t *testing.T) {
		found, err := namespaceExistsByPrefix("/non-existed-namespace")
		require.NoError(t, err)
		assert.False(t, found)
	})

	t.Run("return-true-for-existing-ns", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]Namespace{{Prefix: "/foo"}})
		require.NoError(t, err)
		found, err := namespaceExistsByPrefix("/foo")
		require.NoError(t, err)
		assert.True(t, found)
	})
}

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
		mockNs := mockNamespace("/test", "", "", AdminMetadata{UserID: "foo"})
		mockNs.CustomFields = mockCustomFields
		err := insertMockDBData([]Namespace{mockNs})
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
		err := insertMockDBData(mockNssWithOrigins)
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
		err := insertMockDBData([]Namespace{mockNamespace("/foo", "", "", AdminMetadata{})})
		require.NoError(t, err)
		lastId, err := getLastNamespaceId()
		require.NoError(t, err)
		status, err := getNamespaceStatusById(lastId)
		require.NoError(t, err)
		assert.Equal(t, Unknown, status)
	})

	t.Run("valid-id-non-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]Namespace{mockNamespace("/foo", "", "", AdminMetadata{Status: Approved})})
		require.NoError(t, err)
		lastId, err := getLastNamespaceId()
		require.NoError(t, err)
		status, err := getNamespaceStatusById(lastId)
		require.NoError(t, err)
		assert.Equal(t, Approved, status)
	})
}

func TestAddNamespace(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("set-default-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone"})
		err := AddNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		// We can do this becuase we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.Unix(), got[0].AdminMetadata.CreatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.Unix(), got[0].AdminMetadata.UpdatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("override-restricted-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockCreateAt := time.Now().Add(time.Hour * 10)
		mockUpdatedAt := time.Now().Add(time.Minute * 20)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone", CreatedAt: mockCreateAt, UpdatedAt: mockUpdatedAt})
		err := AddNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)

		assert.NotEqual(t, mockCreateAt.Unix(), mockNs.AdminMetadata.CreatedAt.Unix())
		assert.NotEqual(t, mockUpdatedAt.Unix(), mockNs.AdminMetadata.UpdatedAt.Unix())
		// We can do this becuase we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.Unix(), got[0].AdminMetadata.CreatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.Unix(), got[0].AdminMetadata.UpdatedAt.Unix())
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("insert-data-integrity", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone", Description: "Some description", SiteName: "OSG", SecurityContactUserID: "security-001"})
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
		mockNs := mockNamespace("/test", "", "", AdminMetadata{})
		err := updateNamespace(&mockNs)
		assert.Error(t, err)
	})

	t.Run("update-preserve-internal-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "", "", AdminMetadata{UserID: "foo"})
		err := insertMockDBData([]Namespace{mockNs})
		require.NoError(t, err)
		initialNss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(initialNss))
		initialNs := initialNss[0]
		assert.Equal(t, mockNs.Prefix, initialNs.Prefix)
		initialNs.AdminMetadata.UserID = "bar"
		initialNs.AdminMetadata.CreatedAt = time.Now().Add(10 * time.Hour)
		initialNs.AdminMetadata.UpdatedAt = time.Now().Add(10 * time.Hour)
		initialNs.AdminMetadata.Status = Approved
		initialNs.AdminMetadata.ApproverID = "hacker"
		initialNs.AdminMetadata.ApprovedAt = time.Now().Add(10 * time.Hour)
		err = updateNamespace(initialNs)
		require.NoError(t, err)
		finalNss, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(finalNss))
		finalNs := finalNss[0]
		assert.Equal(t, mockNs.Prefix, finalNs.Prefix)
		assert.Equal(t, mockNs.AdminMetadata.UserID, finalNs.AdminMetadata.UserID)
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
		err := insertMockDBData(mockNssWithOrigins)
		require.NoError(t, err)
		err = updateNamespaceStatusById(100, Approved, "random")
		assert.Error(t, err)
	})

	t.Run("return-error-if-invalid-approver-userId", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]Namespace{mockNs})
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, Approved, "")
		assert.Error(t, err)
	})

	t.Run("update-status-with-valid-input-for-approval", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]Namespace{mockNs})
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, Approved, "approver1")
		assert.NoError(t, err)
		got, err = getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		assert.Equal(t, Approved, got[0].AdminMetadata.Status)
		assert.Equal(t, "approver1", got[0].AdminMetadata.ApproverID)
		assert.NotEqual(t, time.Time{}, got[0].AdminMetadata.ApprovedAt)
	})

	t.Run("deny-does-not-modify-approval-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)

		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone"})
		err := insertMockDBData([]Namespace{mockNs})
		assert.NoError(t, err)
		got, err := getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		err = updateNamespaceStatusById(got[0].ID, Denied, "approver1")
		assert.NoError(t, err)
		got, err = getAllNamespaces()
		assert.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		assert.Equal(t, Denied, got[0].AdminMetadata.Status)
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
		filterNsID := Namespace{
			ID: 123,
		}

		_, err := getNamespacesByFilter(filterNsID, "")
		require.Error(t, err, "Should return error for filtering against unsupported field ID")

		filterNsCF := Namespace{
			CustomFields: mockCustomFields,
		}
		_, err = getNamespacesByFilter(filterNsCF, "")
		require.Error(t, err, "Should return error for filtering against unsupported custom fields")

		filterNsIdentity := Namespace{
			Identity: "someIdentity",
		}

		_, err = getNamespacesByFilter(filterNsIdentity, "")
		require.Error(t, err, "Should return error for filtering against unsupported field Identity")

		filterNsPubKey := Namespace{
			Pubkey: "somePubkey",
		}

		_, err = getNamespacesByFilter(filterNsPubKey, "")
		require.Error(t, err, "Should return error for filtering against unsupported field PubKey")

		// Now, for AdminMetadata filters to work, we need to have a valid object
		resetNamespaceDB(t)
		err = insertMockDBData([]Namespace{{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}})
		require.NoError(t, err)

		filterNsCreateAt := Namespace{
			AdminMetadata: AdminMetadata{
				CreatedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsCreateAt, "")
		require.Error(t, err, "Should return error for filtering against unsupported field CreatedAt")

		filterNsUpdateAt := Namespace{
			AdminMetadata: AdminMetadata{
				UpdatedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsUpdateAt, "")
		require.Error(t, err, "Should return error for filtering against unsupported field UpdatedAt")

		filterNsApproveAt := Namespace{
			AdminMetadata: AdminMetadata{
				ApprovedAt: time.Now(),
			},
		}

		_, err = getNamespacesByFilter(filterNsApproveAt, "")
		require.Error(t, err, "Should return error for filtering against unsupported field ApprovedAt")
	})

	t.Run("filter-by-server-type", func(t *testing.T) {
		// Assuming mock data and insertMockDBData function exist
		resetNamespaceDB(t)
		err := insertMockDBData(append(mockNssWithOrigins, mockNssWithCaches...))
		require.NoError(t, err)

		filterNs := Namespace{}
		nssOrigins, err := getNamespacesByFilter(filterNs, OriginType)
		require.NoError(t, err)
		assert.NotEmpty(t, nssOrigins, "Should return non-empty result for OriginType")
		assert.True(t, compareNamespaces(mockNssWithOrigins, nssOrigins, true))

		nssCaches, err := getNamespacesByFilter(filterNs, CacheType)
		require.NoError(t, err)
		assert.NotEmpty(t, nssCaches, "Should return non-empty result for CacheType")
		assert.True(t, compareNamespaces(mockNssWithCaches, nssCaches, true))
	})

	t.Run("filter-by-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]Namespace{{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				UserID:                "mockUserID",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}})
		require.NoError(t, err)

		filterNs := Namespace{
			AdminMetadata: AdminMetadata{
				Description: "description",
			},
		}

		namespaces, err := getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Description")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				SiteName: "Madison",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for SiteName")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				Institution: "123456",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Institution")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				SecurityContactUserID: "contactUserID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for SecurityContactUserID")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				ApproverID: "mockApproverID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for ApproverID")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				Status: Pending,
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for Status")

		filterNs = Namespace{
			AdminMetadata: AdminMetadata{
				UserID: "mockUserID",
			},
		}
		namespaces, err = getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for UserID")
	})

	t.Run("multiple-AND-match", func(t *testing.T) {
		resetNamespaceDB(t)
		err := insertMockDBData([]Namespace{{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}})
		require.NoError(t, err)

		filterNs := Namespace{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}
		namespaces, err := getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for non-empty database without condition")
	})

	t.Run("fully-match", func(t *testing.T) {
		resetNamespaceDB(t)
		mockNs := Namespace{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				Description:           "Mock description",
				SiteName:              "UW-Madison",
				UserID:                "mockUserID",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}
		err := insertMockDBData([]Namespace{mockNs})
		require.NoError(t, err)

		filterNs := mockNs
		namespaces, err := getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.NotEmpty(t, namespaces, "Should return non-empty result for non-empty database without condition")
	})

	t.Run("no-match", func(t *testing.T) {
		resetNamespaceDB(t)
		mockNs := Namespace{
			Prefix: "/bar",
			AdminMetadata: AdminMetadata{
				Description:           "Mock description",
				UserID:                "mockUserID",
				SiteName:              "UW-Madison",
				Institution:           "123456",
				SecurityContactUserID: "contactUserID",
				ApproverID:            "mockApproverID",
				Status:                Pending,
			},
		}
		err := insertMockDBData([]Namespace{mockNs})
		require.NoError(t, err)

		filterNs := mockNs
		filterNs.AdminMetadata.Status = Denied
		namespaces, err := getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.Empty(t, namespaces, "Should return non-empty result for non-empty database without condition")
	})

	t.Run("empty-db-returns-empty-results", func(t *testing.T) {
		resetNamespaceDB(t)

		filterNs := Namespace{}
		namespaces, err := getNamespacesByFilter(filterNs, "")
		require.NoError(t, err)
		assert.Empty(t, namespaces, "Should return empty result for empty database")
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

		err = insertMockDBData([]Namespace{mockNamespace("/foo", string(jwksByte), "", AdminMetadata{})})
		require.NoError(t, err)
		_, admin_meta, err := getNamespaceJwksByPrefix("/foo")
		require.NoError(t, err)
		assert.Equal(t, AdminMetadata{}, *admin_meta)
	})

	t.Run("valid-prefix-non-empty-admin-metadata", func(t *testing.T) {
		resetNamespaceDB(t)
		mockJwks := jwk.NewSet()
		jwksByte, err := json.Marshal(mockJwks)
		require.NoError(t, err)

		err = insertMockDBData([]Namespace{mockNamespace("/foo", string(jwksByte), "", AdminMetadata{Status: Approved})})
		require.NoError(t, err)
		_, admin_meta, err := getNamespaceJwksByPrefix("/foo")
		require.NoError(t, err)
		assert.Equal(t, Approved, admin_meta.Status)
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
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	viper.Reset()

	topoNamespaces := []string{"/topo/foo", "/topo/bar"}
	svr := topologyMockup(t, topoNamespaces)
	defer svr.Close()

	registryDB := t.TempDir()
	viper.Set("Registry.DbLocation", filepath.Join(registryDB, "test.sqlite"))
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	config.InitConfig()

	err := InitializeDB(ctx)
	require.NoError(t, err)
	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
	}()

	// Set value so that config.GetPreferredPrefix() returns "OSDF"
	config.SetPreferredPrefix("OSDF")

	//Test topology table population
	err = createTopologyTable()
	require.NoError(t, err)
	err = PopulateTopology()
	require.NoError(t, err)

	// Check that topology namespace exists
	exists, err := namespaceExists("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that topology namespace exists
	exists, err = namespaceExists("/topo/bar")
	require.NoError(t, err)
	require.True(t, exists)

	// Add a test namespace so we can test that checkExists still works
	ns := Namespace{
		ID:            0,
		Prefix:        "/regular/foo",
		Pubkey:        "",
		Identity:      "",
		AdminMetadata: AdminMetadata{},
	}
	err = AddNamespace(&ns)
	require.NoError(t, err)

	// Check that the regular namespace exists
	exists, err = namespaceExists("/regular/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that a bad namespace doesn't exist
	exists, err = namespaceExists("/bad/namespace")
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
	err = PopulateTopology()
	require.NoError(t, err)

	// Check that /topo/foo still exists
	exists, err = namespaceExists("/topo/foo")
	require.NoError(t, err)
	require.True(t, exists)

	// And that /topo/baz was added
	exists, err = namespaceExists("/topo/baz")
	require.NoError(t, err)
	require.True(t, exists)

	// Check that /topo/bar is gone
	exists, err = namespaceExists("/topo/bar")
	require.NoError(t, err)
	require.False(t, exists)

	// Finally, check that /regular/foo survived
	exists, err = namespaceExists("/regular/foo")
	require.NoError(t, err)
	require.True(t, exists)

	viper.Reset()
}
