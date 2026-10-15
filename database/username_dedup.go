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

import (
	"database/sql"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database/utils"
	"github.com/pelicanplatform/pelican/param"
)

// Startup cleanup for the universal migration that makes usernames
// globally unique (*_global_unique_username.sql, v7.27), plus the rule
// that keeps the built-in admin bound to this server afterwards.
//
// Before that migration a username only had to be unique per issuer, so a
// database could legitimately hold two live rows with the same username.
// Two producers have been seen in the field (issue #3824):
//
//   - A change to Server.ExternalWebUrl. Password login keyed the local
//     account on (sub, issuer = ExternalWebUrl), so the first login after
//     the URL changed created a second "admin" row and the old one was
//     never removed.
//   - The GHSA-rpfr-x88x-xwcw mitigation script, which inserted a
//     placeholder row (username, <OIDC issuer>) for the built-in admin and
//     every Server.UIAdminUsers entry so an OIDC login could not claim the
//     name under the old rule.
//
// The migration is plain SQL and cannot know which row the operator
// means, so it fails with "UNIQUE constraint failed: users.username" and
// the server crash-loops at startup. This file resolves the duplicates in
// Go, where Server.ExternalWebUrl is known, immediately before that
// migration runs (prepareForGlobalUniqueUsernames).
//
// # The built-in admin
//
// The username "admin" alone grants server.admin (see
// EffectiveScopesForIdentity in web_ui), and BootstrapAdminAndBackfillOwners
// exists so that the only live "admin" row is the one keyed on this
// server's Server.ExternalWebUrl. So "admin" is not deduplicated by
// ranking at all: every live "admin" row whose issuer is not the current
// ExternalWebUrl is soft-deleted, duplicate or not, and the bootstrap
// mints the local row afterwards when none is left. No existing row is
// ever adopted or re-keyed, so no heuristic about what a row "looks like"
// is involved. The same rule runs after the migrations at every startup
// (retireNonLocalAdminRowsAtStartup, next to the bootstrap in
// collection.go), so a later ExternalWebUrl change heals itself the same
// way instead of locking password login out.
//
// Nothing that referenced a retired "admin" row is moved: server.admin
// does not depend on ownership, and an API key's scopes are recomputed
// from its creator row on every use, so keys minted by a retired admin
// row fail closed and have to be re-minted. The retirement logs them.
//
// # Other usernames
//
// Survivor selection, per username, in order:
//
//  1. The row whose issuer is the current Server.ExternalWebUrl. It is
//     the only local-account row password login can reach.
//  2. A real row over a placeholder row (sub prefixed with
//     protectivePlaceholderSubPrefix): when a placeholder shares its
//     username with any other row, the placeholder loses. No identity
//     provider asserts such a sub, so nobody can log in as it.
//  3. The most recent last_login_at, with never-logged-in rows last.
//  4. The newest created_at. The newest row sits under the issuer string
//     most recently in use (an IdP's current spelling of `iss`, or the
//     latest ExternalWebUrl), so it is the one a future login can still
//     reach. Rows that still tie keep the query order (a stable sort), so
//     the choice is deterministic.
//
// Every other row is soft-deleted rather than renamed, and its group
// memberships are removed as DeleteUser would. For both producers above
// nothing can log in as it: password login reaches only (username,
// ExternalWebUrl), and no identity provider asserts a placeholder sub. A
// real OIDC row that loses re-enrolls under a suffixed username on its
// next login.
//
// Two v7.26 username references are then re-homed, because the
// migrations that turn them into user IDs would bind them wrongly:
//
//   - collections.owner_id: 20260429000000 fills it while the duplicates
//     are still live, so it may point at a losing row. Collections owned
//     by a loser move to the survivor.
//   - api_keys.created_by: 20260917110000 binds a key to the live row of
//     that username created before the key. A key's scopes are recomputed
//     from its creator on every use, so a key minted by a loser must not
//     end up on the survivor. Only keys the survivor alone could have
//     minted (created after the survivor's row and before the earliest
//     losing row that could have had a session) are bound to it; every
//     other key under that username is set to created_by = '' so it fails
//     closed, and is logged so its owner can re-mint it. Placeholder rows
//     never had a session, so they do not count as such a losing row.

// protectivePlaceholderSubPrefix marks user rows written by the
// GHSA-rpfr-x88x-xwcw mitigation script (mitigate-user-escalation.sh).
const protectivePlaceholderSubPrefix = "__PROTECTIVE_PLACEHOLDER__"

// globalUniqueUsernameMigrationSuffix is the file-name suffix of the
// universal migration this cleanup must precede. Its version is read from
// the embedded file name rather than hard-coded, so a renumber on a
// release branch cannot leave this step pointing at the wrong migration.
const globalUniqueUsernameMigrationSuffix = "_global_unique_username.sql"

// liveUsernameIndexName is the partial unique index that migration
// creates. Its presence means the global rule already holds.
const liveUsernameIndexName = "idx_user_username_live"

// globalUniqueUsernameMigrationVersion returns the goose version of the
// *_global_unique_username.sql universal migration.
func globalUniqueUsernameMigrationVersion() (int64, error) {
	entries, err := fs.ReadDir(EmbedUniversalMigrations, "universal_migrations")
	if err != nil {
		return 0, errors.Wrap(err, "failed to list the embedded universal migrations")
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, globalUniqueUsernameMigrationSuffix) {
			continue
		}
		version, err := strconv.ParseInt(strings.TrimSuffix(name, globalUniqueUsernameMigrationSuffix), 10, 64)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to parse the migration version from %q", name)
		}
		return version, nil
	}
	return 0, errors.Errorf("no universal migration named *%s was found", globalUniqueUsernameMigrationSuffix)
}

// liveUsernameIndexExists reports whether the global-unique-username
// migration has already been applied to this database.
func liveUsernameIndexExists(db *gorm.DB) (bool, error) {
	var count int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?", liveUsernameIndexName).
		Scan(&count).Error; err != nil {
		return false, errors.Wrapf(err, "failed to check for index %s", liveUsernameIndexName)
	}
	return count > 0, nil
}

// prepareForGlobalUniqueUsernames brings the database up to the migration
// immediately before the global-unique-username migration, then resolves
// any usernames that are still shared by several live rows so that
// migration can create its unique index. It is a no-op once the index
// exists. Call it before the universal migrations run.
//
// Stopping one migration short first is what guarantees the columns the
// cleanup reads and writes (last_login_at, deleted_at) exist: a v7.26
// database (last universal migration 20260220120000) does not have them
// yet when startup begins.
func prepareForGlobalUniqueUsernames(sqlDB *sql.DB, db *gorm.DB) error {
	applied, err := liveUsernameIndexExists(db)
	if err != nil {
		return err
	}
	if applied {
		return nil
	}

	version, err := globalUniqueUsernameMigrationVersion()
	if err != nil {
		return err
	}
	current, err := utils.MigrateDBUpTo(sqlDB, EmbedUniversalMigrations, "universal_migrations", version-1)
	if err != nil {
		return errors.Wrapf(err, "failed to run the universal migrations preceding version %d", version)
	}
	// The cleanup is written against the schema just before that
	// migration; leave a database already past it alone.
	if current >= version {
		log.Warnf("Database is at migration %d but has no %s; skipping the duplicate-username cleanup",
			current, liveUsernameIndexName)
		return nil
	}

	if _, err := dedupLiveUsernames(db, param.Server_ExternalWebUrl.GetString()); err != nil {
		return errors.Wrap(err, "failed to resolve duplicate usernames ahead of the global-unique-username migration")
	}
	return nil
}

// liveUserRow is the subset of a users row the survivor selection needs.
// It is read with raw SQL because the User model describes the fully
// migrated table, which this code runs before.
type liveUserRow struct {
	ID          string
	Username    string
	Sub         string
	Issuer      string
	LastLoginAt *time.Time
	CreatedAt   time.Time
}

func (r liveUserRow) isPlaceholder() bool {
	return strings.HasPrefix(r.Sub, protectivePlaceholderSubPrefix)
}

// rankLiveUserRows orders candidates sharing one username so that the
// row to keep comes first. See the file comment for the rule.
func rankLiveUserRows(rows []liveUserRow, localIssuer string) {
	isLocal := func(r liveUserRow) bool {
		return localIssuer != "" && r.Issuer == localIssuer
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if la, lb := isLocal(a), isLocal(b); la != lb {
			return la
		}
		if pa, pb := a.isPlaceholder(), b.isPlaceholder(); pa != pb {
			return !pa
		}
		switch {
		case a.LastLoginAt != nil && b.LastLoginAt == nil:
			return true
		case a.LastLoginAt == nil && b.LastLoginAt != nil:
			return false
		case a.LastLoginAt != nil && b.LastLoginAt != nil && !a.LastLoginAt.Equal(*b.LastLoginAt):
			return a.LastLoginAt.After(*b.LastLoginAt)
		}
		return a.CreatedAt.After(b.CreatedAt)
	})
}

// sqliteTimestamp formats a time the way SQLite's date functions and the
// migrations' text comparisons read it: UTC, second precision, no zone.
func sqliteTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// tombstoneUsers soft-deletes the given rows and removes their group
// memberships, as DeleteUser does on the migrated schema. Group
// memberships have been keyed by user ID since v7.26, so they would
// otherwise linger and render as nameless members.
func tombstoneUsers(tx *gorm.DB, ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if err := tx.Exec("DELETE FROM group_members WHERE user_id IN ?", ids).Error; err != nil {
		return errors.Wrap(err, "failed to remove group memberships of retired users")
	}
	res := tx.Exec("UPDATE users SET deleted_at = ?, updated_at = ? WHERE id IN ? AND deleted_at IS NULL", now, now, ids)
	if res.Error != nil {
		return errors.Wrap(res.Error, "failed to soft-delete retired users")
	}
	if res.RowsAffected != int64(len(ids)) {
		return errors.Errorf("expected to soft-delete %d user rows, affected %d", len(ids), res.RowsAffected)
	}
	return nil
}

// retireNonLocalAdminRows soft-deletes every live "admin" row whose
// issuer is not localIssuer, so that the only "admin" row left is the one
// this server bootstraps under its own ExternalWebUrl (or none, in which
// case BootstrapAdminAndBackfillOwners creates it after the migrations).
// It runs on the pre-migration schema inside the dedup transaction and
// returns the number of rows retired.
func retireNonLocalAdminRows(tx *gorm.DB, localIssuer string, now time.Time) (int, error) {
	var rows []liveUserRow
	if err := tx.Raw(`
		SELECT id, username, sub, issuer, last_login_at, created_at
		FROM users
		WHERE username = ? AND deleted_at IS NULL AND issuer <> ?
		ORDER BY id`, builtinAdminUsername, localIssuer).Scan(&rows).Error; err != nil {
		return 0, errors.Wrap(err, "failed to list built-in admin rows under other issuers")
	}
	if len(rows) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
		log.Warnf("Retiring %q row %s (sub %q, issuer %q, placeholder=%t): its issuer is not Server.ExternalWebUrl (%q), "+
			"and the built-in admin is bootstrapped under that URL",
			builtinAdminUsername, r.ID, r.Sub, r.Issuer, r.isPlaceholder(), localIssuer)
	}
	if err := warnAdminKeysLeftUnattributed(tx, localIssuer); err != nil {
		return 0, err
	}
	if err := tombstoneUsers(tx, ids, now); err != nil {
		return 0, err
	}
	return len(ids), nil
}

// warnAdminKeysLeftUnattributed names the API keys created under the
// username "admin" that 20260917110000 will not be able to attribute to
// the local admin row, because that row does not exist yet or was created
// after the key. Those keys fail closed from then on. The comparison is
// the migration's own text comparison, so the prediction matches it.
func warnAdminKeysLeftUnattributed(tx *gorm.DB, localIssuer string) error {
	var local []struct {
		ID        string
		CreatedAt string
	}
	if err := tx.Raw("SELECT id, created_at FROM users WHERE username = ? AND issuer = ? AND deleted_at IS NULL",
		builtinAdminUsername, localIssuer).Scan(&local).Error; err != nil {
		return errors.Wrap(err, "failed to look up the local built-in admin row")
	}
	query := "SELECT id, name FROM api_keys WHERE created_by = ?"
	args := []interface{}{builtinAdminUsername}
	if len(local) > 0 {
		query += " AND created_at < ?"
		args = append(args, local[0].CreatedAt)
	}
	var keys []struct {
		ID   string
		Name string
	}
	if err := tx.Raw(query, args...).Scan(&keys).Error; err != nil {
		return errors.Wrap(err, "failed to list API keys created by the built-in admin")
	}
	for _, k := range keys {
		log.Warnf("API key %s (%q) was created under username %q before this server's own %q row existed; "+
			"it cannot be attributed to that row and will carry no user scopes after the upgrade. Re-mint it.",
			k.ID, k.Name, builtinAdminUsername, builtinAdminUsername)
	}
	return nil
}

// bindAPIKeysToSurvivor re-homes the API keys created under username
// (a v7.26 created_by value) onto the survivor when the survivor alone
// could have minted them, and clears the rest so they fail closed. See
// the file comment.
func bindAPIKeysToSurvivor(tx *gorm.DB, username string, survivor liveUserRow, losers []liveUserRow) error {
	var cutoff *time.Time
	for _, l := range losers {
		if l.isPlaceholder() {
			continue
		}
		if cutoff == nil || l.CreatedAt.Before(*cutoff) {
			c := l.CreatedAt
			cutoff = &c
		}
	}

	var bound *gorm.DB
	if cutoff == nil {
		// Only placeholders lost, and a placeholder never had a session,
		// so every key under this username is the survivor's.
		bound = tx.Exec("UPDATE api_keys SET created_by = ? WHERE created_by = ?", survivor.ID, username)
	} else {
		bound = tx.Exec(`UPDATE api_keys SET created_by = ?
			WHERE created_by = ?
			  AND julianday(created_at) >= julianday(?)
			  AND julianday(created_at) < julianday(?)`,
			survivor.ID, username, sqliteTimestamp(survivor.CreatedAt), sqliteTimestamp(*cutoff))
	}
	if bound.Error != nil {
		return errors.Wrapf(bound.Error, "failed to bind API keys created by %q to user %s", username, survivor.ID)
	}
	if bound.RowsAffected > 0 {
		log.Infof("Bound %d API key(s) created under username %q to user %s", bound.RowsAffected, username, survivor.ID)
	}

	var ambiguous []struct {
		ID   string
		Name string
	}
	if err := tx.Raw("SELECT id, name FROM api_keys WHERE created_by = ?", username).Scan(&ambiguous).Error; err != nil {
		return errors.Wrapf(err, "failed to list unattributable API keys created by %q", username)
	}
	if len(ambiguous) == 0 {
		return nil
	}
	for _, k := range ambiguous {
		log.Warnf("API key %s (%q) was created under username %q while more than one account could use that name; "+
			"it cannot be attributed to the surviving account and will carry no user scopes. Re-mint it.",
			k.ID, k.Name, username)
	}
	if err := tx.Exec("UPDATE api_keys SET created_by = '' WHERE created_by = ?", username).Error; err != nil {
		return errors.Wrapf(err, "failed to clear unattributable API keys created by %q", username)
	}
	return nil
}

// dedupLiveUsernames applies the admin rule, then soft-deletes every
// other live users row that shares its username with another live row,
// keeping one survivor per username as chosen by rankLiveUserRows.
// localIssuer is the current Server.ExternalWebUrl (empty when unset, in
// which case "admin" is resolved like any other username). It returns
// the number of rows soft-deleted. All changes happen in one transaction.
func dedupLiveUsernames(db *gorm.DB, localIssuer string) (int, error) {
	deleted := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()

		if localIssuer == "" {
			log.Warnf("Server.ExternalWebUrl is not set, so the %q row belonging to this server cannot be told apart; "+
				"%q is resolved like any other duplicate username", builtinAdminUsername, builtinAdminUsername)
		} else {
			retired, err := retireNonLocalAdminRows(tx, localIssuer, now)
			if err != nil {
				return err
			}
			deleted += retired
		}

		var rows []liveUserRow
		if err := tx.Raw(`
			SELECT id, username, sub, issuer, last_login_at, created_at
			FROM users
			WHERE deleted_at IS NULL
			  AND username IN (
			      SELECT username FROM users
			      WHERE deleted_at IS NULL
			      GROUP BY username HAVING count(*) > 1
			  )
			ORDER BY username, id`).Scan(&rows).Error; err != nil {
			return errors.Wrap(err, "failed to list users with duplicate usernames")
		}
		if len(rows) == 0 {
			return nil
		}

		byUsername := make(map[string][]liveUserRow)
		usernames := []string{}
		for _, r := range rows {
			if _, seen := byUsername[r.Username]; !seen {
				usernames = append(usernames, r.Username)
			}
			byUsername[r.Username] = append(byUsername[r.Username], r)
		}

		for _, username := range usernames {
			candidates := byUsername[username]
			rankLiveUserRows(candidates, localIssuer)
			survivor := candidates[0]
			losers := candidates[1:]
			loserIDs := make([]string, 0, len(losers))
			for _, loser := range losers {
				loserIDs = append(loserIDs, loser.ID)
				log.Warnf("Resolving duplicate username %q ahead of the global-unique-username migration: "+
					"keeping user %s (sub %q, issuer %q) and soft-deleting user %s (sub %q, issuer %q, placeholder=%t)",
					username, survivor.ID, survivor.Sub, survivor.Issuer, loser.ID, loser.Sub, loser.Issuer, loser.isPlaceholder())
			}

			// Skip a collection whose name the survivor already owns;
			// 20260916120000 makes (owner_id, name) unique.
			owned := tx.Exec(`UPDATE collections SET owner_id = ?
				WHERE owner = ? AND owner_id IN ?
				  AND NOT EXISTS (SELECT 1 FROM collections c WHERE c.owner_id = ? AND c.name = collections.name)`,
				survivor.ID, username, loserIDs, survivor.ID)
			if owned.Error != nil {
				return errors.Wrapf(owned.Error, "failed to move collections owned by %q to user %s", username, survivor.ID)
			}
			if owned.RowsAffected > 0 {
				log.Infof("Moved %d collection(s) of username %q to user %s", owned.RowsAffected, username, survivor.ID)
			}

			if err := bindAPIKeysToSurvivor(tx, username, survivor, losers); err != nil {
				return err
			}

			if err := tombstoneUsers(tx, loserIDs, now); err != nil {
				return errors.Wrapf(err, "failed to retire duplicate rows for username %q", username)
			}
			deleted += len(loserIDs)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		log.Warnf("Soft-deleted %d user row(s) that shared a username with another live row or held %q under another issuer; "+
			"usernames are globally unique from this version on", deleted, builtinAdminUsername)
	}
	return deleted, nil
}
