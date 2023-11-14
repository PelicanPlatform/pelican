package nsregistry

import (
	"database/sql"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
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
func compareNamespaces(execpted []Namespace, returned interface{}) bool {
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
			nssEx.Pubkey != nssRt.Pubkey ||
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
		for _, origins := range mockNssWithOrigins {
			mixed = append(mixed, origins)
		}

		for _, caches := range mockNssWithCaches {
			mixed = append(mixed, caches)
		}
		return
	}()
)

// teardown must be called at the end of the test to close the in-memory SQLite db
func TestGetNamespacesByServerType(t *testing.T) {

	setupMockNamespaceDB()
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
		assert.True(t, compareNamespaces(mockNssWithOrigins, origins), "Returned namespaces does not match expected")

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
		assert.True(t, compareNamespaces(mockNssWithCaches, caches), "Returned namespaces does not match expected")

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
		assert.True(t, compareNamespaces(mockNssWithCaches, caches), "Returned caches namespaces does not match expected")

		origins, err := getNamespacesByServerType(OriginType)
		require.NoError(t, err)
		assert.Equal(t, len(mockNssWithOrigins), len(origins), "Returned origins namespace has wrong length")
		assert.True(t, compareNamespaces(mockNssWithOrigins, origins), "Returned origins namespaces does not match expected")
	})
}
