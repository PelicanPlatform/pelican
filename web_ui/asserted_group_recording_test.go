/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package web_ui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/glebarez/sqlite"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The `Issuer.GroupSource: file` provider is reached from three places:
// generateUserGroupInfo (OIDC callback), the password-login handler, and
// the init-code admin login. Reconciling the asserted names into group
// records therefore lives inside generateGroupInfo itself rather than at
// each call site — without that, a group that only ever comes from the
// file has no ID, and granting a collection ACL to it is rejected as an
// unknown subject.
func TestGroupFileSourceRecordsAssertedGroups(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	groupFile := filepath.Join(t.TempDir(), "groups.json")
	require.NoError(t, os.WriteFile(groupFile,
		[]byte(`{"testuser": ["team-readers", "team-writers"]}`), 0o600))
	require.NoError(t, param.Issuer_GroupFile.Set(groupFile))
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://example.com"))

	prevDB := database.ServerDatabase
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	t.Cleanup(func() { database.ServerDatabase = prevDB })
	migrateTestDB(t)
	require.NoError(t, database.BootstrapAdminAndBackfillOwners(mockDB))

	groups, err := generateGroupInfo("testuser")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"team-readers", "team-writers"}, groups)

	var recorded []database.Group
	require.NoError(t, mockDB.Order("name").Find(&recorded).Error)
	require.Len(t, recorded, 2)
	for _, g := range recorded {
		assert.Equal(t, database.GroupSourceFile, g.Source,
			"the record must name the provider that asserted it, not a generic 'external'")
		assert.NotEmpty(t, g.OwnerID, "asserted groups are owned by the built-in admin")
	}

	// A group the file never mentions is not invented.
	other, err := generateGroupInfo("nobody")
	require.NoError(t, err)
	assert.Empty(t, other)
	var count int64
	require.NoError(t, mockDB.Model(&database.Group{}).Count(&count).Error)
	assert.EqualValues(t, 2, count)
}
