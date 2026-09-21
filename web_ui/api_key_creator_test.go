//go:build !windows

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

// api_keys.created_by is an authorization input, not an audit string:
// api_token.Verify re-intersects a key's persisted scopes against that
// user's current effective scopes on every call.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/glebarez/sqlite"

	"github.com/pelicanplatform/pelican/api_token"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestAPIKeyCreatorScopesDoNotFollowAUsername(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	prevDB := database.ServerDatabase
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	t.Cleanup(func() { database.ServerDatabase = prevDB })
	migrateTestDB(t)

	alice := &database.User{
		ID: "u-alice", Username: "alice", Sub: "alice@idp",
		Issuer: "https://idp.example", Status: database.UserStatusActive,
	}
	require.NoError(t, mockDB.Create(alice).Error)
	require.NoError(t, database.GrantUserScope(mockDB, alice.ID,
		token_scopes.Server_CollectionAdmin, database.CreatorSelf()))

	// The hook resolves a User.ID and nothing else.
	assert.Contains(t, effectiveScopeStrings(t, alice.ID), token_scopes.Server_CollectionAdmin.String())
	assert.Empty(t, effectiveScopeStrings(t, alice.Username),
		"a username must not resolve through this hook; the column holds IDs")

	// Alice is deleted. Her ID is spent forever, so a key created_by
	// that ID can never be re-attributed.
	require.NoError(t, database.DeleteUser(mockDB, alice.ID, alice.ID, true))
	assert.Empty(t, effectiveScopeStrings(t, alice.ID),
		"a deleted creator confers nothing, so their keys lose every user-grantable scope")

	// Somebody new is onboarded under the released username and given
	// the same scope. The old key's created_by still names the OLD ID,
	// so it stays dead — this is the regression the username fallback
	// used to open.
	newAlice := &database.User{
		ID: "u-new-alice", Username: "alice", Sub: "new-alice@idp",
		Issuer: "https://idp.example", Status: database.UserStatusActive,
	}
	require.NoError(t, mockDB.Create(newAlice).Error)
	require.NoError(t, database.GrantUserScope(mockDB, newAlice.ID,
		token_scopes.Server_CollectionAdmin, database.CreatorSelf()))

	assert.Empty(t, effectiveScopeStrings(t, alice.ID),
		"reusing the username must not revive the deleted account's API keys")
	assert.Contains(t, effectiveScopeStrings(t, newAlice.ID), token_scopes.Server_CollectionAdmin.String())
}

// effectiveScopeStrings exercises the hook api_token.Verify calls to
// re-derive a key creator's current authority — the package init in
// scopes.go installs it.
func effectiveScopeStrings(t *testing.T, createdBy string) []string {
	t.Helper()
	require.NotNil(t, api_token.EffectiveScopesForUser)
	scopes := api_token.EffectiveScopesForUser(createdBy)
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		out = append(out, s.String())
	}
	return out
}
