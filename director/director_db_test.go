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
		{UUID: uuid.NewString(), URL: "https://4a334d532d69:8443", Downtime: false},
		{UUID: uuid.NewString(), URL: "https://my-origin.com:8443", Downtime: true},
		{UUID: uuid.NewString(), URL: "https://my-cache.com:8447"},
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

	downtime, err := GetServerDowntime(mockSS[1].URL)
	assert.True(t, downtime)
	require.NoError(t, err)

	err = SetServerDowntime(false, mockSS[1].URL)
	require.NoError(t, err)
	downtime, err = GetServerDowntime(mockSS[1].URL)
	assert.False(t, downtime)
	require.NoError(t, err)
}
