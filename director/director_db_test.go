package director

import (
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

var (
	mockSS []ServerStatus = []ServerStatus{
		{UUID: uuid.NewString(), Name: "/4a334d532d69:8443", FilterType: tempAllowed},
		{UUID: uuid.NewString(), Name: "/my-origin.com/foo/Bar", FilterType: permFiltered},
		{UUID: uuid.NewString(), Name: "/my-cache.com/chtc", FilterType: permFiltered},
	}
)

func setupMockDirectorDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")
	err = db.AutoMigrate(&ServerStatus{})
	require.NoError(t, err, "Failed to migrate DB for Globus table")
}

func teardownMockDirectorDB(t *testing.T) {
	err := ShutdownDirectorDB()
	require.NoError(t, err, "Error tearing down mock director DB")
}

func insertMockDBData(ss []ServerStatus) error {
	return db.Create(&ss).Error
}

func TestDirectorDBBasics(t *testing.T) {
	server_utils.ResetTestState()
	setupMockDirectorDB(t)
	t.Cleanup(func() {
		teardownMockDirectorDB(t)
	})
	err := insertMockDBData(mockSS)
	require.NoError(t, err)

	t.Run("get-downtime", func(t *testing.T) {
		filterType, err := GetServerStatus(mockSS[1].Name)
		assert.Equal(t, filterType, permFiltered)
		require.NoError(t, err)
	})

	t.Run("get-all-downtime", func(t *testing.T) {
		statuses, err := GetAllServerStatuses()
		require.NoError(t, err)
		assert.Len(t, statuses, len(mockSS))
	})

	t.Run("set-downtime", func(t *testing.T) {
		err = SetServerStatus(mockSS[1].Name, tempAllowed)
		require.NoError(t, err)
		filterType, err := GetServerStatus(mockSS[1].Name)
		assert.Equal(t, filterType, tempAllowed)
		require.NoError(t, err)
	})

	t.Run("duplicate-name-insert", func(t *testing.T) {
		err := CreateServerStatus(mockSS[1].Name, tempAllowed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "UNIQUE constraint failed")
	})

	t.Run("delete-downtime-entry-from-directory-db", func(t *testing.T) {
		err = DeleteServerStatus(mockSS[0].Name)
		require.NoError(t, err, "Error deleting server status")

		_, err = GetServerStatus(mockSS[0].Name)
		assert.Error(t, err, "Expected error retrieving deleted server status")
	})
}
