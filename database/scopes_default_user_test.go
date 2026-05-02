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

package database

// Tests for the operator-configured default-scopes-for-new-users
// pipeline:
//
//   - DefaultUserScopesFromConfig parses + validates the config knob.
//   - ApplyDefaultUserScopes is the create-time hook called by every
//     user-creation path.
//   - BackfillNewUserDefaultScopes is the one-shot startup pass that
//     applies the same defaults to pre-existing accounts.
//
// All three are coupled to Server.NewUserDefaultScopes (and to the
// scope-grantability allow-list in token_scopes), so the tests
// manipulate the param directly to exercise the boundaries.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// withDefaultScopesConfig sets Server.NewUserDefaultScopes for the
// duration of a test and restores the previous value on cleanup.
// Tests that exercise the hook need the param value to flip
// per-subtest, but they also share the param table with the rest of
// the test run; restoring is the polite thing to do.
func withDefaultScopesConfig(t *testing.T, scopes []string) {
	t.Helper()
	prev := param.Server_NewUserDefaultScopes.GetStringSlice()
	require.NoError(t, param.Server_NewUserDefaultScopes.Set(scopes))
	t.Cleanup(func() {
		_ = param.Server_NewUserDefaultScopes.Set(prev)
	})
}

// migrateCounter adds the Counter table to a setupCollectionTestDB
// fixture. The collection-level helper doesn't migrate it because
// nothing in the rest of that suite touches the counters; the
// backfill does.
func migrateCounter(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&Counter{}))
}

func TestDefaultUserScopesFromConfig(t *testing.T) {
	t.Run("empty config returns empty slice", func(t *testing.T) {
		withDefaultScopesConfig(t, nil)
		got, err := DefaultUserScopesFromConfig()
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("valid grantable scope round-trips", func(t *testing.T) {
		withDefaultScopesConfig(t, []string{"web_ui.access"})
		got, err := DefaultUserScopesFromConfig()
		require.NoError(t, err)
		assert.Equal(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, got)
	})

	t.Run("blank entries are skipped, surrounding whitespace trimmed", func(t *testing.T) {
		withDefaultScopesConfig(t, []string{"  web_ui.access  ", "", "  "})
		got, err := DefaultUserScopesFromConfig()
		require.NoError(t, err)
		assert.Equal(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, got)
	})

	t.Run("non-grantable scope is rejected", func(t *testing.T) {
		// storage.read is a data-plane scope, deliberately not in
		// token_scopes.UserGrantableScopes; an operator must never be
		// able to put it in the new-user-default list.
		withDefaultScopesConfig(t, []string{"storage.read"})
		_, err := DefaultUserScopesFromConfig()
		assert.ErrorIs(t, err, ErrUngrantableScope)
	})

	t.Run("multiple grantable scopes preserved in order", func(t *testing.T) {
		withDefaultScopesConfig(t, []string{"web_ui.access", "monitoring.query"})
		got, err := DefaultUserScopesFromConfig()
		require.NoError(t, err)
		assert.Equal(t, []token_scopes.TokenScope{
			token_scopes.WebUi_Access,
			token_scopes.Monitoring_Query,
		}, got)
	})
}

func TestCreateUserAppliesDefaultScopes(t *testing.T) {
	t.Run("creates the user and grants the configured scope", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withDefaultScopesConfig(t, []string{"web_ui.access"})

		user, err := CreateUser(db, "alice", "alice@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err)

		rows, err := ListUserScopes(db, user.ID)
		require.NoError(t, err)
		require.Len(t, rows, 1, "configured default should produce exactly one user_scopes row")
		assert.Equal(t, token_scopes.WebUi_Access, rows[0].Scope)
	})

	t.Run("misconfigured non-grantable scope is logged-and-skipped, user still created", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		// storage.read is non-grantable. The hook must not fail user
		// creation just because the config carries a bad value — the
		// startup backfill is also tolerant of this so the operator
		// gets a chance to fix the config without losing the account.
		withDefaultScopesConfig(t, []string{"storage.read"})

		user, err := CreateUser(db, "bob", "bob@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err, "bad config must not break user creation")
		require.NotNil(t, user)

		rows, err := ListUserScopes(db, user.ID)
		require.NoError(t, err)
		assert.Empty(t, rows, "non-grantable config must not produce any user_scopes row")
	})

	t.Run("local-user path also picks up the defaults", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withDefaultScopesConfig(t, []string{"web_ui.access"})

		user, err := CreateLocalUser(db, "carol", "Carol the Local", "https://example.com", CreatorSelf())
		require.NoError(t, err)
		rows, err := ListUserScopes(db, user.ID)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, token_scopes.WebUi_Access, rows[0].Scope)
	})

	t.Run("OIDC bootstrap path also picks up the defaults", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		withDefaultScopesConfig(t, []string{"web_ui.access"})

		user, err := LookupOrBootstrapUser(db, "dan@oidc", "https://idp.example.com",
			"Dan", []string{"dan"})
		require.NoError(t, err)
		rows, err := ListUserScopes(db, user.ID)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, token_scopes.WebUi_Access, rows[0].Scope)
	})
}

func TestBackfillNewUserDefaultScopes(t *testing.T) {
	t.Run("grants the configured baseline to every existing user, exactly once", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		migrateCounter(t, db)

		// Seed two users *without* the auto-grant being active so we
		// simulate "pre-existing accounts from before the knob existed".
		// We do that by switching the config off, creating users, then
		// flipping it on for the backfill.
		withDefaultScopesConfig(t, nil)
		alice, err := CreateUser(db, "alice", "alice@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err)
		bob, err := CreateUser(db, "bob", "bob@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err)
		// Sanity-check: no scopes yet.
		for _, id := range []string{alice.ID, bob.ID} {
			rows, _ := ListUserScopes(db, id)
			require.Empty(t, rows)
		}

		// Now set the knob and run the backfill.
		withDefaultScopesConfig(t, []string{"web_ui.access"})
		require.NoError(t, BackfillNewUserDefaultScopes(db))

		for _, id := range []string{alice.ID, bob.ID} {
			rows, err := ListUserScopes(db, id)
			require.NoError(t, err)
			require.Len(t, rows, 1)
			assert.Equal(t, token_scopes.WebUi_Access, rows[0].Scope)
		}

		// Second call must be a no-op even if the config changes.
		// "Operator added monitoring.query a year later" must NOT
		// silently grant it to every existing user — that's the
		// design contract documented on the function.
		withDefaultScopesConfig(t, []string{"web_ui.access", "monitoring.query"})
		require.NoError(t, BackfillNewUserDefaultScopes(db))
		for _, id := range []string{alice.ID, bob.ID} {
			rows, err := ListUserScopes(db, id)
			require.NoError(t, err)
			assert.Len(t, rows, 1, "second backfill must not grant new defaults")
			assert.Equal(t, token_scopes.WebUi_Access, rows[0].Scope)
		}
	})

	t.Run("misconfigured non-grantable scope skips the backfill but does not crash", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		migrateCounter(t, db)

		withDefaultScopesConfig(t, nil)
		alice, err := CreateUser(db, "alice", "alice@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err)

		// Misconfiguration. Backfill must not fail server startup —
		// it returns nil and leaves the counter unset so a subsequent
		// (corrected) startup retries.
		withDefaultScopesConfig(t, []string{"storage.read"})
		require.NoError(t, BackfillNewUserDefaultScopes(db))

		rows, err := ListUserScopes(db, alice.ID)
		require.NoError(t, err)
		assert.Empty(t, rows)

		// Counter must be absent (we use ErrRecordNotFound as the
		// signal) so the next start tries again.
		var counter Counter
		err = db.Where("key = ?", newUserDefaultScopesBackfillKey).First(&counter).Error
		assert.Error(t, err, "misconfigured run must NOT mark complete")
	})

	t.Run("empty default list still marks complete (avoids re-scanning Users every startup)", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		migrateCounter(t, db)

		withDefaultScopesConfig(t, nil)
		_, err := CreateUser(db, "alice", "alice@oidc", "https://idp.example.com", CreatorSelf())
		require.NoError(t, err)

		require.NoError(t, BackfillNewUserDefaultScopes(db))
		var counter Counter
		require.NoError(t, db.Where("key = ?", newUserDefaultScopesBackfillKey).First(&counter).Error)
		assert.Equal(t, 1, counter.Value, "completion marker must be written even with no scopes to grant")
	})
}
