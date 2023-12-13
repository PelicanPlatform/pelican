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
	"database/sql"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/pelicanplatform/pelican/config"
	"github.com/spf13/viper"
)

func setupMockNamespaceDB() error {
	mockDB, err := sql.Open("sqlite", ":memory:")
	db = mockDB
	if err != nil {
		return err
	}
	createNamespaceTable()
	return nil
}

func resetNamespaceDB() error {
	_, err := db.Exec(`DELETE FROM namespace`)
	if err != nil {
		return err
	}
	return nil
}

func teardownMockNamespaceDB() {
	db.Close()
}

func insertMockDBData(nss []Namespace) error {
	query := `INSERT INTO namespace (prefix, pubkey, identity, admin_metadata) VALUES (?, ?, ?, ?)`
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, ns := range nss {
		_, err = tx.Exec(query, ns.Prefix, ns.Pubkey, ns.Identity, ns.AdminMetadata)
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

func mockNamespace(prefix, pubkey, identity, adminMetadata string) Namespace {
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
		mockNamespace("/test1", "pubkey1", "", ""),
		mockNamespace("/test2", "pubkey2", "", ""),
	}
	mockNssWithCaches []Namespace = []Namespace{
		mockNamespace("/caches/random1", "pubkey1", "", ""),
		mockNamespace("/caches/random2", "pubkey2", "", ""),
	}
	mockNssWithMixed []Namespace = func() (mixed []Namespace) {
		mixed = append(mixed, mockNssWithOrigins...)
		mixed = append(mixed, mockNssWithCaches...)
		return
	}()
)

// teardown must be called at the end of the test to close the in-memory SQLite db
func TestGetNamespacesByServerType(t *testing.T) {

	err := setupMockNamespaceDB()
	require.NoError(t, err, "Error setting up the mock namespace DB")
	defer teardownMockNamespaceDB()

	t.Run("wrong-server-type-gives-error", func(t *testing.T) {
		err := resetNamespaceDB()
		require.NoError(t, err)

		rss, err := getNamespacesByServerType("")
		require.Error(t, err, "No error returns when give empty server type")
		assert.Nil(t, rss, "Returns data when error is expected")

		rss, err = getNamespacesByServerType("random")
		require.Error(t, err, "No error returns when give random server type")
		assert.Nil(t, rss, "Returns data when error is expected")
	})

	t.Run("empty-db-returns-empty-list", func(t *testing.T) {
		err := resetNamespaceDB()
		require.NoError(t, err)

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(origins))

		caches, err := getNamespacesByServerType(CacheType)
		require.NoError(t, err)
		assert.Equal(t, 0, len(caches))
	})

	t.Run("returns-origins-as-expected", func(t *testing.T) {
		err := resetNamespaceDB()
		require.NoError(t, err)

		err = insertMockDBData(mockNssWithOrigins)
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
		err := resetNamespaceDB()
		require.NoError(t, err)

		err = insertMockDBData(mockNssWithCaches)
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
		err := resetNamespaceDB()
		require.NoError(t, err)

		err = insertMockDBData(mockNssWithMixed)
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
	viper.Reset()

	topoNamespaces := []string{"/topo/foo", "/topo/bar"}
	svr := topologyMockup(t, topoNamespaces)
	defer svr.Close()

	registryDB := t.TempDir()
	viper.Set("Registry.DbLocation", filepath.Join(registryDB, "test.sqlite"))
	viper.Set("Federation.TopologyNamespaceURL", svr.URL)
	config.InitConfig()

	err := InitializeDB()
	require.NoError(t, err)
	defer ShutdownDB()

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
		AdminMetadata: "",
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
