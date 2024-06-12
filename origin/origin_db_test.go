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

package origin

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

const (
	mockRefreshTok1 = "randomtokenstirng123"
	mockRefreshTok2 = "randomtokenstirng456"
	mockRefreshTok3 = "randomtokenstirng789"
	mockRefreshTok4 = "randomtokenstirng101112"
)

var (
	mockGC []GlobusCollection = []GlobusCollection{
		{UUID: uuid.NewString(), Name: "mock1", ServerURL: "https://mock1.org", RefreshToken: mockRefreshTok1},
		{UUID: uuid.NewString(), Name: "mock2", ServerURL: "https://mock2.org", RefreshToken: mockRefreshTok2},
		{UUID: uuid.NewString(), Name: "mock3", ServerURL: "https://mock3.org", RefreshToken: mockRefreshTok3},
		{UUID: uuid.NewString(), Name: "mock4", ServerURL: "https://mock4.org", RefreshToken: mockRefreshTok4},
	}
)

// Setup helper functions
func setupMockOriginDB(t *testing.T) {
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	db = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")
	err = db.AutoMigrate(&GlobusCollection{})
	require.NoError(t, err, "Failed to migrate DB for Globus table")

	// Setup encryption
	tmp := t.TempDir()
	keyName := filepath.Join(tmp, "issuer.key")
	viper.Set(param.IssuerKey.GetName(), keyName)

	// Also update the refresh token to be encrpted
	for idx := range mockGC {
		encrypted, err := config.EncryptString(mockGC[idx].RefreshToken)
		require.NoError(t, err)
		mockGC[idx].RefreshToken = encrypted
	}
}

func resetGlobusTable(t *testing.T) {
	err := db.Where("1 = 1").Delete(&GlobusCollection{}).Error
	require.NoError(t, err, "Error resetting Globus table")
}

func teardownMockOriginDB(t *testing.T) {
	mockGC[0].RefreshToken = mockRefreshTok1
	mockGC[1].RefreshToken = mockRefreshTok2
	mockGC[2].RefreshToken = mockRefreshTok3
	mockGC[3].RefreshToken = mockRefreshTok4

	err := ShutdownOriginDB()
	require.NoError(t, err, "Error tearing down mock namespace DB")
}

func insertMockDBData(gc []GlobusCollection) error {
	return db.Create(&gc).Error
}

func compareCollection(a, b GlobusCollection) bool {
	return a.UUID == b.UUID && a.Name == b.Name && a.ServerURL == b.ServerURL
}

// End of helper functions

func TestCollectionExistsByUUID(t *testing.T) {
	setupMockOriginDB(t)
	t.Cleanup(func() {
		teardownMockOriginDB(t)
	})
	err := insertMockDBData(mockGC)
	require.NoError(t, err)

	t.Run("UUID-exists", func(t *testing.T) {
		ok, err := collectionExistsByUUID(mockGC[0].UUID)
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("UUID-DNE", func(t *testing.T) {
		ok, err := collectionExistsByUUID(uuid.NewString())
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("random-UUID", func(t *testing.T) {
		ok, err := collectionExistsByUUID("abcde")
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("empty-UUID", func(t *testing.T) {
		ok, err := collectionExistsByUUID("")
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestGetCollectionByUUID(t *testing.T) {
	viper.Reset()
	setupMockOriginDB(t)
	t.Cleanup(func() {
		viper.Reset()
		teardownMockOriginDB(t)
	})
	err := insertMockDBData(mockGC)
	require.NoError(t, err)

	t.Run("get-existing-collection", func(t *testing.T) {
		get, err := getCollectionByUUID(mockGC[0].UUID)
		require.NoError(t, err)
		assert.True(t, compareCollection(mockGC[0], *get), fmt.Sprintf("Expected: %#v\nGot: %#v", mockGC[0], *get))
		// Refresh token is encrypted in the mock data, but the get result is decrypted
		assert.Equal(t, mockRefreshTok1, get.RefreshToken)
	})

	t.Run("collection-DNE", func(t *testing.T) {
		get, err := getCollectionByUUID(uuid.NewString())
		require.Error(t, err)
		assert.Nil(t, get)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})

	t.Run("empty-UUID", func(t *testing.T) {
		get, err := getCollectionByUUID("")
		require.Error(t, err)
		assert.Nil(t, get)
		assert.True(t, errors.Is(err, gorm.ErrRecordNotFound))
	})
}

func TestCreateCollection(t *testing.T) {
	viper.Reset()
	setupMockOriginDB(t)
	t.Cleanup(func() {
		viper.Reset()
		teardownMockOriginDB(t)
	})

	t.Run("create-collection-returns-no-err", func(t *testing.T) {
		mockGCCreate := GlobusCollection{
			UUID:         uuid.NewString(),
			Name:         "mock1",
			ServerURL:    "https://mock1.org",
			RefreshToken: mockRefreshTok1,
		}
		err := createCollection(&mockGCCreate)
		require.NoError(t, err)
		get, err := getCollectionByUUID(mockGCCreate.UUID)
		require.NoError(t, err)
		assert.True(t, compareCollection(mockGCCreate, *get))
		assert.Equal(t, mockRefreshTok1, get.RefreshToken)
	})

	t.Run("create-collection-wo-token-returns-no-err", func(t *testing.T) {
		resetGlobusTable(t)

		mockGCCreate := GlobusCollection{
			UUID:      uuid.NewString(),
			Name:      "mock1",
			ServerURL: "https://mock1.org",
		}
		err := createCollection(&mockGCCreate)
		require.NoError(t, err)
		get, err := getCollectionByUUID(mockGCCreate.UUID)
		require.NoError(t, err)
		assert.True(t, compareCollection(mockGCCreate, *get))
		assert.Empty(t, get.RefreshToken)
	})
}

func TestUpdateCollection(t *testing.T) {
	viper.Reset()
	setupMockOriginDB(t)
	t.Cleanup(func() {
		viper.Reset()
		teardownMockOriginDB(t)
	})

	mockGCCreate := GlobusCollection{
		UUID:         uuid.NewString(),
		Name:         "mock1",
		ServerURL:    "https://mock1.org",
		RefreshToken: mockRefreshTok1,
	}
	err := createCollection(&mockGCCreate)
	require.NoError(t, err)
	ok, err := collectionExistsByUUID(mockGCCreate.UUID)
	require.NoError(t, err)
	assert.True(t, ok)

	err = updateCollection(mockGCCreate.UUID, &GlobusCollection{ServerURL: "https://new.org"})
	require.NoError(t, err)

	get, err := getCollectionByUUID(mockGCCreate.UUID)
	require.NoError(t, err)
	mockGCCreate.ServerURL = "https://new.org"
	assert.True(t, compareCollection(mockGCCreate, *get))
	assert.Equal(t, mockRefreshTok1, get.RefreshToken)
}

func TestDeleteCollectionByUUID(t *testing.T) {
	viper.Reset()
	setupMockOriginDB(t)
	t.Cleanup(func() {
		viper.Reset()
		teardownMockOriginDB(t)
	})

	mockGCCreate := GlobusCollection{
		UUID:         uuid.NewString(),
		Name:         "mock1",
		ServerURL:    "https://mock1.org",
		RefreshToken: mockRefreshTok1,
	}
	err := createCollection(&mockGCCreate)
	require.NoError(t, err)
	ok, err := collectionExistsByUUID(mockGCCreate.UUID)
	require.NoError(t, err)
	assert.True(t, ok)

	err = deleteCollectionByUUID(mockGCCreate.UUID)
	require.NoError(t, err)

	ok, err = collectionExistsByUUID(mockGCCreate.UUID)
	require.NoError(t, err)
	assert.False(t, ok)
}
