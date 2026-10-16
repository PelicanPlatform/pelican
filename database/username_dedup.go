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

// Before v7.27 a username was unique only per issuer, so the migration that
// makes it globally unique (*_global_unique_username.sql) fails on databases
// holding the same username twice (issue #3824). prepareForGlobalUniqueUsernames
// resolves those duplicates first: "admin" follows ensureBuiltinAdmin's rule,
// and every other username keeps one row chosen by rankLiveUserRows.

// protectivePlaceholderSubPrefix marks rows written by the
// GHSA-rpfr-x88x-xwcw mitigation script.
const protectivePlaceholderSubPrefix = "__PROTECTIVE_PLACEHOLDER__"

const globalUniqueUsernameMigrationSuffix = "_global_unique_username.sql"

const liveUsernameIndexName = "idx_user_username_live"

// globalUniqueUsernameMigrationVersion reads the migration's version from its
// file name, so a renumber on a release branch cannot desync this step.
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

func liveUsernameIndexExists(db *gorm.DB) (bool, error) {
	var count int64
	if err := db.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?", liveUsernameIndexName).
		Scan(&count).Error; err != nil {
		return false, errors.Wrapf(err, "failed to check for index %s", liveUsernameIndexName)
	}
	return count > 0, nil
}

// prepareForGlobalUniqueUsernames migrates to the version just before the
// global-unique-username migration, so last_login_at and deleted_at exist,
// then resolves duplicate usernames. A no-op once that migration has run.
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

// liveUserRow is read with raw SQL because the User model describes the
// fully migrated table.
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

// rankLiveUserRows puts the row to keep first: the one on the current
// ExternalWebUrl, then a non-placeholder, then the latest login, then the
// newest row.
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

// tombstoneUsers soft-deletes rows and drops their group memberships, as
// DeleteUser does on the migrated schema.
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

// settleBuiltinAdmin applies ensureBuiltinAdmin's rule on the pre-migration
// schema: keep one sub = "admin" row, moved to localIssuer, retire every other
// "admin" row, and insert the row if none is left.
func settleBuiltinAdmin(tx *gorm.DB, localIssuer string, now time.Time) (int, error) {
	var rows []liveUserRow
	if err := tx.Raw(`
		SELECT id, username, sub, issuer, last_login_at, created_at
		FROM users
		WHERE username = ? AND deleted_at IS NULL
		ORDER BY id`, builtinAdminUsername).Scan(&rows).Error; err != nil {
		return 0, errors.Wrap(err, "failed to list built-in admin rows")
	}
	var candidates, retired []liveUserRow
	for _, r := range rows {
		if r.Sub == builtinAdminUsername {
			candidates = append(candidates, r)
		} else {
			retired = append(retired, r)
		}
	}
	var kept *liveUserRow
	if len(candidates) > 0 {
		rankLiveUserRows(candidates, localIssuer)
		kept = &candidates[0]
		retired = append(retired, candidates[1:]...)
	}

	if len(retired) > 0 {
		ids := make([]string, 0, len(retired))
		for _, r := range retired {
			ids = append(ids, r.ID)
			log.Warnf("Retiring %q row %s (sub %q, issuer %q): only the built-in admin may hold that username",
				builtinAdminUsername, r.ID, r.Sub, r.Issuer)
		}
		if err := bindOrClearAPIKeys(tx, builtinAdminUsername, kept, retired); err != nil {
			return 0, err
		}
		if err := tombstoneUsers(tx, ids, now); err != nil {
			return 0, err
		}
	}

	if localIssuer == "" {
		return len(retired), nil
	}
	if kept == nil {
		slug, err := generateSlug()
		if err != nil {
			return 0, err
		}
		if err := tx.Exec("INSERT INTO users (id, username, sub, issuer, created_by) VALUES (?, ?, ?, ?, ?)",
			slug, builtinAdminUsername, builtinAdminUsername, localIssuer, CreatorSelfEnrolled).Error; err != nil {
			return 0, errors.Wrap(err, "failed to create the built-in admin row")
		}
	} else if kept.Issuer != localIssuer {
		log.Warnf("Moving the built-in admin %s from issuer %q to %q", kept.ID, kept.Issuer, localIssuer)
		if err := tx.Exec("UPDATE users SET issuer = ? WHERE id = ?", localIssuer, kept.ID).Error; err != nil {
			return 0, errors.Wrap(err, "failed to move the built-in admin to the current issuer")
		}
	}
	return len(retired), nil
}

// bindOrClearAPIKeys settles API keys that v7.26 recorded under username. A
// key goes to kept only if created at or after kept's row and before the
// earliest retired row, placeholders included; the rest get an empty
// created_by and fail closed.
func bindOrClearAPIKeys(tx *gorm.DB, username string, kept *liveUserRow, retired []liveUserRow) error {
	type apiKeyRef struct {
		ID   string
		Name string
	}
	if kept != nil {
		retiredIDs := make([]string, 0, len(retired))
		for _, r := range retired {
			retiredIDs = append(retiredIDs, r.ID)
		}
		query := `SELECT id, name FROM api_keys
			WHERE created_by = ?
			  AND julianday(created_at) >= (SELECT julianday(created_at) FROM users WHERE id = ?)`
		args := []interface{}{username, kept.ID}
		if len(retiredIDs) > 0 {
			query += `
			  AND julianday(created_at) < (SELECT min(julianday(created_at)) FROM users WHERE id IN ?)
			  AND NOT EXISTS (SELECT 1 FROM users WHERE id IN ? AND julianday(created_at) IS NULL)`
			args = append(args, retiredIDs, retiredIDs)
		}
		var bound []apiKeyRef
		if err := tx.Raw(query+" ORDER BY id", args...).Scan(&bound).Error; err != nil {
			return errors.Wrapf(err, "failed to find API keys created by %q that belong to user %s", username, kept.ID)
		}
		if len(bound) > 0 {
			boundIDs := make([]string, 0, len(bound))
			for _, k := range bound {
				boundIDs = append(boundIDs, k.ID)
				log.Infof("API key %s (%q), created under username %q, is bound to user %s", k.ID, k.Name, username, kept.ID)
			}
			if err := tx.Exec("UPDATE api_keys SET created_by = ? WHERE id IN ?", kept.ID, boundIDs).Error; err != nil {
				return errors.Wrapf(err, "failed to bind API keys created by %q to user %s", username, kept.ID)
			}
		}
	}

	var cleared []apiKeyRef
	if err := tx.Raw("SELECT id, name FROM api_keys WHERE created_by = ? ORDER BY id", username).Scan(&cleared).Error; err != nil {
		return errors.Wrapf(err, "failed to list unattributable API keys created by %q", username)
	}
	if len(cleared) == 0 {
		return nil
	}
	for _, k := range cleared {
		log.Warnf("API key %s (%q) was created under username %q, which more than one account held; "+
			"it cannot be attributed to the remaining account and will carry no user scopes. Re-mint it.",
			k.ID, k.Name, username)
	}
	if err := tx.Exec("UPDATE api_keys SET created_by = '' WHERE created_by = ?", username).Error; err != nil {
		return errors.Wrapf(err, "failed to clear unattributable API keys created by %q", username)
	}
	return nil
}

// dedupLiveUsernames settles "admin", then keeps one live row per other
// shared username and soft-deletes the rest, in one transaction. It returns
// the number of rows soft-deleted.
func dedupLiveUsernames(db *gorm.DB, localIssuer string) (int, error) {
	deleted := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		now := time.Now().UTC()

		retired, err := settleBuiltinAdmin(tx, localIssuer, now)
		if err != nil {
			return err
		}
		deleted += retired

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

			// 20260916120000 makes (owner_id, name) unique, so skip names the survivor already owns.
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

			if err := bindOrClearAPIKeys(tx, username, &survivor, losers); err != nil {
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
		log.Warnf("Soft-deleted %d user row(s) to make usernames globally unique", deleted)
	}
	return deleted, nil
}
