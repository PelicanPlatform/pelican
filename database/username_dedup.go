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

// Pre-migration cleanup for the universal migration that makes usernames
// globally unique (*_global_unique_username.sql, v7.27).
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
// migration runs.
//
// Survivor selection, per username, in order:
//
//  1. The row whose issuer is the current Server.ExternalWebUrl. It is
//     the only local-account row password login and the admin bootstrap
//     can reach.
//  2. A real row over a placeholder row (sub prefixed with
//     protectivePlaceholderSubPrefix): when a placeholder shares its
//     username with any other row, the placeholder loses. No identity
//     provider asserts such a sub, so nobody can log in as it.
//  3. The most recent last_login_at, with never-logged-in rows last.
//  4. The oldest created_at, then the ID, so the choice is deterministic.
//
// Every other row is soft-deleted rather than renamed: nothing can log in
// as it (OIDC login resolves by (sub, issuer), password login by
// (username, ExternalWebUrl)), and a renamed row would only linger as a
// stale account in the user list. API keys keep working because the
// request path resolves their subject against the live row by username.

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
// cleanup reads and writes (last_login_at, deleted_at) exist: a database
// upgraded straight from a release older than v7.26 does not have them
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
	if err := utils.MigrateDBUpTo(sqlDB, EmbedUniversalMigrations, "universal_migrations", version-1); err != nil {
		return errors.Wrapf(err, "failed to run the universal migrations preceding version %d", version)
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
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
}

// dedupLiveUsernames soft-deletes every live users row that shares its
// username with another live row, keeping one survivor per username as
// chosen by rankLiveUserRows. localIssuer is the current
// Server.ExternalWebUrl (empty when unset). It returns the number of rows
// soft-deleted. All changes happen in one transaction.
func dedupLiveUsernames(db *gorm.DB, localIssuer string) (int, error) {
	deleted := 0
	err := db.Transaction(func(tx *gorm.DB) error {
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

		now := time.Now().UTC()
		for _, username := range usernames {
			candidates := byUsername[username]
			rankLiveUserRows(candidates, localIssuer)
			survivor := candidates[0]
			loserIDs := make([]string, 0, len(candidates)-1)
			for _, loser := range candidates[1:] {
				loserIDs = append(loserIDs, loser.ID)
				log.Warnf("Resolving duplicate username %q ahead of the global-unique-username migration: "+
					"keeping user %s (sub %q, issuer %q) and soft-deleting user %s (sub %q, issuer %q, placeholder=%t)",
					username, survivor.ID, survivor.Sub, survivor.Issuer, loser.ID, loser.Sub, loser.Issuer, loser.isPlaceholder())
			}
			// "admin" is the literal the admin bootstrap keys on; see
			// BootstrapAdminAndBackfillOwners.
			if username == "admin" && localIssuer != "" && survivor.Issuer != localIssuer {
				log.Warnf("The surviving %q row (issuer %q) does not match Server.ExternalWebUrl (%q); "+
					"the built-in admin bootstrap cannot create its own row while that username is taken, "+
					"so password login as %q may fail until an administrator reconciles the row",
					username, survivor.Issuer, localIssuer, username)
			}
			res := tx.Exec("UPDATE users SET deleted_at = ?, updated_at = ? WHERE id IN ? AND deleted_at IS NULL",
				now, now, loserIDs)
			if res.Error != nil {
				return errors.Wrapf(res.Error, "failed to soft-delete duplicate rows for username %q", username)
			}
			if res.RowsAffected != int64(len(loserIDs)) {
				return errors.Errorf("expected to soft-delete %d duplicate rows for username %q, affected %d",
					len(loserIDs), username, res.RowsAffected)
			}
			deleted += len(loserIDs)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if deleted > 0 {
		log.Warnf("Soft-deleted %d user row(s) that shared a username with another live row; "+
			"usernames are globally unique from this version on", deleted)
	}
	return deleted, nil
}
