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
	"encoding/json"
	"regexp"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// This file serves as the db migration for v26.0 and could be removed later.

// cilogonSubjectRegexp matches the owner encoding the registry used before the
// 7.27 user model: the raw CILogon OIDC `sub` claim of the user who registered,
// e.g. http://cilogon.org/serverA/users/12345.
var cilogonSubjectRegexp = regexp.MustCompile(`^https?://cilogon\.org/server[A-Za-z0-9]+/users/[0-9]+$`)

// migrateLegacyRegistrationOwners re-homes registrations whose
// admin_metadata.user_id still holds a raw CILogon subject onto the Pelican
// user ID of the account carrying that subject, so the ownership checks
// (which compare Pelican user IDs only) recognise the original registrant.
//
// Only registrations whose owner value looks like a CILogon subject are
// considered; rows with an empty owner, a Pelican user ID, or any other
// value are left untouched (those are handled through other paths, e.g.
// self claiming link or an admin-minted ownership-transfer invite). A
// subject is only resolved when exactly one live user carries it; an
// ambiguous subject present under several issuers is skipped with a warning.
func migrateLegacyRegistrationOwners(db *gorm.DB) error {
	type candidate struct {
		id     int
		prefix string
		sub    string
	}

	// Read the raw JSON: legacy rows may carry an empty or malformed
	// admin_metadata column that the GORM JSON serializer would reject.
	var candidates []candidate
	subjects := make(map[string]struct{})
	if err := func() error {
		rows, err := db.Raw("SELECT id, prefix, admin_metadata FROM registrations").Rows()
		if err != nil {
			return errors.Wrap(err, "failed to list registrations")
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id     int
				prefix string
				meta   sql.NullString
			)
			if err := rows.Scan(&id, &prefix, &meta); err != nil {
				return errors.Wrap(err, "failed to scan registration row")
			}
			if !meta.Valid || meta.String == "" {
				continue
			}
			var parsed struct {
				UserID string `json:"user_id"`
			}
			if err := json.Unmarshal([]byte(meta.String), &parsed); err != nil {
				log.Debugf("Skipping registration %d (%s): admin_metadata is not valid JSON: %v", id, prefix, err)
				continue
			}
			if parsed.UserID == "" || !cilogonSubjectRegexp.MatchString(parsed.UserID) {
				continue
			}
			candidates = append(candidates, candidate{id: id, prefix: prefix, sub: parsed.UserID})
			subjects[parsed.UserID] = struct{}{}
		}
		return rows.Err()
	}(); err != nil {
		return err
	}
	if len(candidates) == 0 {
		log.Debug("No registrations owned by a legacy CILogon subject; nothing to migrate")
		return nil
	}

	// Resolve subjects to Pelican user IDs. The users table is unique on
	// (sub, issuer), so one subject can exist under several issuers; such
	// subjects cannot be attributed to a single account and are skipped.
	// Soft-deleted users are excluded by GORM automatically.
	subjectList := make([]string, 0, len(subjects))
	for sub := range subjects {
		subjectList = append(subjectList, sub)
	}
	var users []User
	if err := db.Select("id", "sub", "issuer").Where("sub IN ?", subjectList).Find(&users).Error; err != nil {
		return errors.Wrap(err, "failed to look up users by subject")
	}
	subToUserID := make(map[string]string, len(users))
	ambiguous := make(map[string]bool)
	for _, u := range users {
		if _, seen := subToUserID[u.Sub]; seen {
			ambiguous[u.Sub] = true
			continue
		}
		subToUserID[u.Sub] = u.ID
	}

	rewritten, unresolved, skippedAmbiguous := 0, 0, 0
	if err := db.Transaction(func(tx *gorm.DB) error {
		for _, c := range candidates {
			if ambiguous[c.sub] {
				skippedAmbiguous++
				log.Warnf("Not re-homing registration %d (%s): legacy owner %s matches more than one user account", c.id, c.prefix, c.sub)
				continue
			}
			userID, ok := subToUserID[c.sub]
			if !ok {
				unresolved++
				continue
			}
			// json_set rewrites only the user_id key and leaves the rest of the
			// stored metadata byte-for-byte as it was.
			if err := tx.Exec(
				"UPDATE registrations SET admin_metadata = json_set(admin_metadata, '$.user_id', ?) WHERE id = ?",
				userID, c.id,
			).Error; err != nil {
				return errors.Wrapf(err, "failed to re-home registration %d (%s)", c.id, c.prefix)
			}
			rewritten++
			log.Infof("Re-homed registration %d (%s) from legacy owner %s to Pelican user %s", c.id, c.prefix, c.sub, userID)
		}
		return nil
	}); err != nil {
		return err
	}

	log.Infof("Legacy registration owner migration: %d re-homed, %d waiting for the owner's first login, %d ambiguous",
		rewritten, unresolved, skippedAmbiguous)
	return nil
}
