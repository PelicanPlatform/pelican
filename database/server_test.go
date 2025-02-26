package database

import (
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Test helper functions for Downtime
func setupMockDowntimeDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock downtime DB")
	err = ServerDatabase.AutoMigrate(&server_structs.Downtime{})
	require.NoError(t, err, "Failed to migrate DB for Downtime table")
}

func teardownMockDowntimeDB(t *testing.T) {
	err := ServerDatabase.Migrator().DropTable(&server_structs.Downtime{})
	require.NoError(t, err, "Error tearing down downtime DB")
}

func insertMockDowntime(d server_structs.Downtime) error {
	return ServerDatabase.Create(&d).Error
}

func TestCreateDowntime(t *testing.T) {
	config.ResetConfig()
	setupMockDowntimeDB(t)
	t.Cleanup(func() {
		teardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	t.Run("create-downtime-success", func(t *testing.T) {
		mockDowntime := server_structs.Downtime{
			UUID:        uuid.NewString(),
			CreatedBy:   "test_user",
			Class:       "SCHEDULED",
			Description: "Routine maintenance",
			Severity:    "Outage (completely inaccessible)",
			StartTime:   time.Now().UnixMilli(),
			EndTime:     time.Now().Add(1 * time.Hour).UnixMilli(),
		}
		err := createDowntime(&mockDowntime)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		require.NoError(t, err)
		assert.Equal(t, mockDowntime.UUID, retrieved.UUID)
		assert.Equal(t, mockDowntime.Description, retrieved.Description)
	})
}

func TestUpdateDowntime(t *testing.T) {
	config.ResetConfig()
	setupMockDowntimeDB(t)
	t.Cleanup(func() {
		teardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	mockDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "test_user",
		Class:       "UNSCHEDULED",
		Description: "Unexpected outage",
		Severity:    "Severe (most services down)",
		StartTime:   time.Now().UnixMilli(),
		EndTime:     time.Now().Add(2 * time.Hour).UnixMilli(),
	}
	err := insertMockDowntime(mockDowntime)
	require.NoError(t, err)

	t.Run("update-existing-downtime", func(t *testing.T) {
		updatedFields := server_structs.Downtime{
			Description: "Planned upgrade",
			Severity:    "Intermittent Outage (may be up for some of the time)",
		}
		err := updateDowntime(mockDowntime.UUID, &updatedFields)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		require.NoError(t, err)
		assert.Equal(t, "Planned upgrade", retrieved.Description)
		assert.Equal(t, server_structs.IntermittentOutage, retrieved.Severity)
	})
}

func TestGetActiveDowntimes(t *testing.T) {
	config.ResetConfig()
	setupMockDowntimeDB(t)
	t.Cleanup(func() {
		teardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	currentTime := time.Now().UTC().UnixMilli()
	activeDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "admin",
		Class:       "SCHEDULED",
		Description: "Active issue",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   currentTime - 3600000, // Started an hour ago
		EndTime:     currentTime + 3600000, // Ends in an hour
	}
	pastDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "admin",
		Class:       "UNSCHEDULED",
		Description: "Resolved issue",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   currentTime - 7200000, // Started two hours ago
		EndTime:     currentTime - 3600000, // Ended an hour ago
	}

	err := insertMockDowntime(activeDowntime)
	require.NoError(t, err)
	err = insertMockDowntime(pastDowntime)
	require.NoError(t, err)

	t.Run("fetch-active-downtimes", func(t *testing.T) {
		activeEntries, err := GetActiveDowntimes()
		require.NoError(t, err)
		assert.Len(t, activeEntries, 1)
		assert.Equal(t, activeDowntime.UUID, activeEntries[0].UUID)
	})

	t.Run("fetch-specific-downtime-by-uuid", func(t *testing.T) {
		get, err := getDowntimeByUUID(activeDowntime.UUID)
		require.NoError(t, err)
		assert.Equal(t, activeDowntime.UUID, get.UUID)
	})
}

func TestDeleteDowntime(t *testing.T) {
	config.ResetConfig()
	setupMockDowntimeDB(t)
	t.Cleanup(func() {
		teardownMockDowntimeDB(t)
		config.ResetConfig()
	})

	mockDowntime := server_structs.Downtime{
		UUID:        uuid.NewString(),
		CreatedBy:   "test_user",
		Class:       "SCHEDULED",
		Description: "Temporary downtime",
		Severity:    "No Significant Outage Expected (you shouldn't notice)",
		StartTime:   time.Now().UnixMilli(),
		EndTime:     time.Now().Add(30 * time.Minute).UnixMilli(),
	}
	err := insertMockDowntime(mockDowntime)
	require.NoError(t, err)

	t.Run("delete-existing-downtime", func(t *testing.T) {
		err := deleteDowntime(mockDowntime.UUID)
		require.NoError(t, err)

		var retrieved server_structs.Downtime
		err = ServerDatabase.First(&retrieved, "uuid = ?", mockDowntime.UUID).Error
		assert.Error(t, err) // Expect record not found
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}
