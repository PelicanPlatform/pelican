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
	createNamespaceTable()
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
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
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

		_, err = tx.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, adminMetaStr)
		if err != nil {
			if errRoll := tx.Rollback(); errRoll != nil {
				return errors.Wrap(errRoll, "Failed to rollback transaction")
			}
			return err
		}
	}
	return tx.Commit()
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
		mockNamespace("/test1", "pubkey1", "", AdminMetadata{}),
		mockNamespace("/test2", "pubkey2", "", AdminMetadata{}),
	}
	mockNssWithCaches []Namespace = []Namespace{
		mockNamespace("/caches/random1", "pubkey1", "", AdminMetadata{}),
		mockNamespace("/caches/random2", "pubkey2", "", AdminMetadata{}),
	}
	mockNssWithMixed []Namespace = func() (mixed []Namespace) {
		mixed = append(mixed, mockNssWithOrigins...)
		mixed = append(mixed, mockNssWithCaches...)
		return
	}()
)

func TestGetNamespacesById(t *testing.T) {
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

func TestGetNamespacesByUserID(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("empty-db-return-empty-array", func(t *testing.T) {
		nss, err := getNamespacesByUserID("foo")
		require.NoError(t, err)
		assert.Equal(t, 0, len(nss))
	})

	t.Run("return-empty-array-with-no-userid-entries", func(t *testing.T) {
		err := insertMockDBData(mockNssWithMixed)
		require.NoError(t, err)
		defer resetNamespaceDB(t)
		nss, err := getNamespacesByUserID("foo")
		require.NoError(t, err)
		assert.Equal(t, 0, len(nss))
	})

	t.Run("return-user-namespace-with-valid-userID", func(t *testing.T) {
		defer resetNamespaceDB(t)
		err := insertMockDBData(mockNssWithMixed)
		require.NoError(t, err)
		err = insertMockDBData([]Namespace{mockNamespace("/user1", "", "user1", AdminMetadata{UserID: "user1"})})
		require.NoError(t, err)
		nss, err := getNamespacesByUserID("user1")
		require.NoError(t, err)
		require.Equal(t, 1, len(nss))
		assert.Equal(t, "/user1", nss[0].Prefix)
	})

	t.Run("return-multiple-user-namespaces-with-valid-userID", func(t *testing.T) {
		defer resetNamespaceDB(t)
		err := insertMockDBData(mockNssWithMixed)
		require.NoError(t, err)
		err = insertMockDBData([]Namespace{mockNamespace("/user1", "", "user1", AdminMetadata{UserID: "user1"})})
		require.NoError(t, err)
		err = insertMockDBData([]Namespace{mockNamespace("/user1-2", "", "user1", AdminMetadata{UserID: "user1"})})
		require.NoError(t, err)
		nss, err := getNamespacesByUserID("user1")
		require.NoError(t, err)
		require.Equal(t, 2, len(nss))
		assert.Equal(t, "/user1", nss[0].Prefix)
		assert.Equal(t, "/user1-2", nss[1].Prefix)

	})
}

func TestAddNamespace(t *testing.T) {
	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("set-default-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone"})
		err := addNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)
		// We can do this becuase we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.UTC(), got[0].AdminMetadata.CreatedAt)
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.UTC(), got[0].AdminMetadata.UpdatedAt)
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("override-restricted-fields", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockCreateAt := time.Now().Add(time.Hour * 10)
		mockUpdatedAt := time.Now().Add(time.Minute * 20)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone", CreatedAt: mockCreateAt, UpdatedAt: mockUpdatedAt})
		err := addNamespace(&mockNs)
		require.NoError(t, err)
		got, err := getAllNamespaces()
		require.NoError(t, err)
		require.Equal(t, 1, len(got))
		assert.Equal(t, mockNs.Prefix, got[0].Prefix)

		assert.NotEqual(t, mockCreateAt.UTC(), mockNs.AdminMetadata.CreatedAt.UTC())
		assert.NotEqual(t, mockUpdatedAt.UTC(), mockNs.AdminMetadata.UpdatedAt.UTC())
		// We can do this becuase we pass the pointer of mockNs to addNamespce which
		// then modify the fields and insert into database
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.UTC(), got[0].AdminMetadata.CreatedAt)
		assert.Equal(t, mockNs.AdminMetadata.UpdatedAt.UTC(), got[0].AdminMetadata.UpdatedAt)
		assert.Equal(t, mockNs.AdminMetadata.Status, got[0].AdminMetadata.Status)
	})

	t.Run("insert-data-integrity", func(t *testing.T) {
		defer resetNamespaceDB(t)
		mockNs := mockNamespace("/test", "pubkey", "identity", AdminMetadata{UserID: "someone", Description: "Some description", SiteName: "OSG", SecurityContactUserID: "security-001"})
		err := addNamespace(&mockNs)
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
		assert.Equal(t, mockNs.AdminMetadata.CreatedAt.UTC(), finalNs.AdminMetadata.CreatedAt)
		assert.Equal(t, mockNs.AdminMetadata.Status, finalNs.AdminMetadata.Status)
		assert.Equal(t, mockNs.AdminMetadata.ApprovedAt.UTC(), finalNs.AdminMetadata.ApprovedAt)
		assert.Equal(t, mockNs.AdminMetadata.ApproverID, finalNs.AdminMetadata.ApproverID)
		// DB first changes initialNs.AdminMetadata.UpdatedAt then commit
		assert.Equal(t, initialNs.AdminMetadata.UpdatedAt.UTC(), finalNs.AdminMetadata.UpdatedAt)
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

// teardown must be called at the end of the test to close the in-memory SQLite db
func TestGetNamespacesByServerType(t *testing.T) {
	_, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	setupMockRegistryDB(t)
	defer teardownMockNamespaceDB(t)

	t.Run("wrong-server-type-gives-error", func(t *testing.T) {
		resetNamespaceDB(t)

		rss, err := getNamespacesByServerType("")
		require.Error(t, err, "No error returns when give empty server type")
		assert.Nil(t, rss, "Returns data when error is expected")

		rss, err = getNamespacesByServerType("random")
		require.Error(t, err, "No error returns when give random server type")
		assert.Nil(t, rss, "Returns data when error is expected")
	})

	t.Run("empty-db-returns-empty-list", func(t *testing.T) {
		resetNamespaceDB(t)

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(origins))

		caches, err := getNamespacesByServerType(CacheType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(caches))
	})

	t.Run("returns-origins-as-expected", func(t *testing.T) {
		resetNamespaceDB(t)

		err := insertMockDBData(mockNssWithOrigins)
		require.NoError(t, err)

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, len(mockNssWithOrigins), len(origins), "Returned namespace has wrong length")
		assert.True(t, compareNamespaces(mockNssWithOrigins, origins, false), "Returned namespaces does not match expected")

		caches, err := getNamespacesByServerType(CacheType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(caches), "Returned caches when only origins present in db")
	})

	t.Run("return-caches-as-expected", func(t *testing.T) {
		resetNamespaceDB(t)

		err := insertMockDBData(mockNssWithCaches)
		require.NoError(t, err)

		caches, err := getNamespacesByServerType(CacheType)
		require.NoError(t, err)
		assert.Equal(t, len(mockNssWithCaches), len(caches), "Returned namespace has wrong length")
		assert.True(t, compareNamespaces(mockNssWithCaches, caches, false), "Returned namespaces does not match expected")

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(origins), "Returned origins when only caches present in db")
	})

	t.Run("return-correctly-with-mixed-server-type", func(t *testing.T) {
		resetNamespaceDB(t)

		err := insertMockDBData(mockNssWithMixed)
		require.NoError(t, err)

		caches, err := getNamespacesByServerType(CacheType)
		require.NoError(t, err)
		assert.Equal(t, len(mockNssWithCaches), len(caches), "Returned caches namespace has wrong length")
		assert.True(t, compareNamespaces(mockNssWithCaches, caches, false), "Returned caches namespaces does not match expected")

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, len(mockNssWithOrigins), len(origins), "Returned origins namespace has wrong length")
		assert.True(t, compareNamespaces(mockNssWithOrigins, origins, false), "Returned origins namespaces does not match expected")
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
	err = addNamespace(&ns)
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

func TestCacheAdminTrue(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	registryDBDir := t.TempDir()
	viper.Set("Registry.DbLocation", registryDBDir)

	err := InitializeDB(ctx)
	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
	}()

	require.NoError(t, err, "error initializing registry database")

	adminTester := func(ns Namespace) func(t *testing.T) {
		return func(t *testing.T) {
			err = addNamespace(&ns)

			require.NoError(t, err, "error adding test cache to registry database")

			// This will return a serverCredsError if the AdminMetadata.Status != Approved, which we don't want to happen
			// For these tests, otherwise it will get a key parsing error as ns.Pubkey isn't a real jwk
			_, err = getNamespaceJwksByPrefix(ns.Prefix, true)
			require.NotErrorIsf(t, err, serverCredsErr, "error chain contains serverCredErr")

			require.ErrorContainsf(t, err, "Failed to parse pubkey as a jwks: failed to unmarshal JWK set: invalid character 'k' in literal true (expecting 'r')", "error doesn't contain jwks parsing error")
		}
	}

	var ns Namespace
	ns.Prefix = "/caches/test3"
	ns.Identity = "testident3"
	ns.Pubkey = "tkey"
	ns.AdminMetadata.Status = Approved

	t.Run("WithApproval", adminTester(ns))

	ns.Prefix = "/orig/test1"
	ns.Identity = "testident4"
	ns.Pubkey = "tkey"
	ns.AdminMetadata.Status = Pending

	t.Run("OriginNoApproval", adminTester(ns))

	ns.Prefix = "/orig/test2"
	ns.Identity = "testident5"
	ns.Pubkey = "tkey"
	ns.AdminMetadata = AdminMetadata{}

	t.Run("OriginEmptyApproval", adminTester(ns))

	viper.Reset()
}

func TestCacheAdminFalse(t *testing.T) {
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() { require.NoError(t, egrp.Wait()) }()
	defer cancel()

	registryDBDir := t.TempDir()
	viper.Set("Registry.DbLocation", registryDBDir)

	err := InitializeDB(ctx)
	defer func() {
		err := ShutdownDB()
		assert.NoError(t, err)
	}()

	require.NoError(t, err, "error initializing registry database")

	adminTester := func(ns Namespace) func(t *testing.T) {
		return func(t *testing.T) {
			err = addNamespace(&ns)
			require.NoError(t, err, "error adding test cache to registry database")

			// This will return a serverCredsError if the admin_approval == false check is triggered, which we want to happen
			_, err = getNamespaceJwksByPrefix(ns.Prefix, true)

			require.ErrorIs(t, err, serverCredsErr)
		}
	}

	var ns Namespace
	ns.Prefix = "/caches/test1"
	ns.Identity = "testident1"
	ns.Pubkey = "tkey"
	ns.AdminMetadata.Status = Pending

	t.Run("NoAdmin", adminTester(ns))

	ns.Prefix = "/caches/test2"
	ns.Identity = "testident2"
	ns.AdminMetadata = AdminMetadata{}

	t.Run("EmptyAdmin", adminTester(ns))

	viper.Reset()
}
