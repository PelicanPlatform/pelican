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

// This file is the *only* place in the codebase where the bcrypt
// password hash leaves the database.
//
// The User struct intentionally does not carry a PasswordHash field;
// every general user lookup (GetUserByID, ListUsers, joined preloads,
// JSON responses, ...) is structurally incapable of returning the hash.
// To verify or update a password you must reach into one of the
// helpers here.
//
// Why this matters: the hash is a credential. Any code path that
// surfaces it — JSON responses, log lines, deep copies into other
// structs, debug dumps — risks leaking it. Removing the field from
// User makes the leak impossible by construction; the only Go types
// that hold the hash live in this file and stay package-private.

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// userCredential mirrors the users table but exposes only the columns
// involved in password-based authentication. Stays unexported so no
// caller outside this file can construct or hold one.
//
// The PasswordHash gorm tags match the production migration
// (20260424180000_add_user_password_hash.sql): NOT NULL DEFAULT '',
// so AutoMigrate-driven test setups produce the same shape as a
// goose-migrated database.
type userCredential struct {
	ID           string `gorm:"primaryKey"`
	PasswordHash string `gorm:"column:password_hash;not null;default:''"`
}

// TableName ties this struct to the same physical table as User; we
// just project a much narrower column set out of it.
func (userCredential) TableName() string { return "users" }

// AutoMigrateCredentialsForTests runs GORM AutoMigrate on the
// credential view of the users table so test setups (which build their
// schema from struct tags rather than running goose migrations) end
// up with the password_hash column. The User struct intentionally has
// no PasswordHash field; this is the only public way for tests
// outside the database package to get the column without reaching
// into the migration files.
//
// Production code should not call this — production schema is created
// by the goose migrations under database/universal_migrations.
func AutoMigrateCredentialsForTests(db *gorm.DB) error {
	return db.AutoMigrate(&userCredential{})
}

// SetUserPassword stores a bcrypt hash of plaintext as the user's local
// password. Pass an empty plaintext to clear the password (disable
// local login for that account).
func SetUserPassword(db *gorm.DB, userID, plaintext string) error {
	hash := ""
	if plaintext != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		hash = string(hashed)
	}
	res := db.Model(&userCredential{}).Where("id = ?", userID).Update("password_hash", hash)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// VerifyUserPassword looks up a user by (username, issuer) and verifies
// the supplied plaintext against the stored bcrypt hash. The hash itself
// never escapes this function. Returns ErrInvalidPassword for any
// failure mode (unknown user, no password set, inactive, mismatch) so
// callers cannot distinguish them.
//
// The returned *User goes through the standard GetUserByID pipeline,
// which means it carries no PasswordHash field — only the
// HasPassword bool that callers are allowed to see.
func VerifyUserPassword(db *gorm.DB, username, plaintext, issuer string) (*User, error) {
	var cred userCredential
	res := db.Model(&userCredential{}).
		Select("id, password_hash").
		Where("username = ? AND issuer = ?", username, issuer).
		Limit(1).
		Find(&cred)
	if res.Error != nil {
		return nil, res.Error
	}
	if res.RowsAffected == 0 || cred.ID == "" {
		return nil, ErrInvalidPassword
	}
	if cred.PasswordHash == "" {
		return nil, ErrInvalidPassword
	}
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(plaintext)); err != nil {
		return nil, ErrInvalidPassword
	}
	user, err := GetUserByID(db, cred.ID)
	if err != nil {
		return nil, err
	}
	if user.Status == UserStatusInactive {
		return nil, ErrInvalidPassword
	}
	return user, nil
}

// applyHashInTx writes a precomputed bcrypt hash to the user's credential
// row inside an existing transaction. Used by the password-invite
// redemption flow so the hash write and the link-redeemed update commit
// atomically.
func applyHashInTx(tx *gorm.DB, userID, hashed string) error {
	res := tx.Model(&userCredential{}).Where("id = ?", userID).Update("password_hash", hashed)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// userHasPassword reports whether the given user has a non-empty
// password_hash on disk. Used by User.AfterFind to populate the derived
// HasPassword field without ever loading the hash itself.
//
// The query selects only a single boolean projection — the hash bytes
// are not transferred over the connection or read into Go memory.
func userHasPassword(tx *gorm.DB, userID string) (bool, error) {
	if userID == "" {
		return false, nil
	}
	var hp bool
	if err := tx.Table("users").
		Select("password_hash <> ''").
		Where("id = ?", userID).
		Limit(1).
		Scan(&hp).Error; err != nil {
		return false, err
	}
	return hp, nil
}

// usersWithPassword returns the subset of supplied user IDs that have a
// non-empty password_hash. Batching avoids an N+1 when the caller is
// hydrating HasPassword for a list of users (admin user table, group
// member preloads). Same security property as userHasPassword: the hash
// itself is never read into Go memory.
func usersWithPassword(tx *gorm.DB, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var rows []struct {
		ID string
	}
	if err := tx.Table("users").
		Select("id").
		Where("id IN ? AND password_hash <> ''", ids).
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, r := range rows {
		out[r.ID] = true
	}
	return out, nil
}
