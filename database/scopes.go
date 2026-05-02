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

// First-class user/group scopes. Each call to EffectiveScopes computes
// the union of scopes assigned directly to a user, scopes assigned to
// groups the user is a database-recorded member of, and scopes
// assigned to groups whose *name* appears in the caller's
// cookie-asserted wlcg.groups list (so an OIDC-asserted group still
// confers its scopes even when membership isn't recorded in
// group_members).
//
// The set of legal scope values comes from
// token_scopes.UserGrantableScopes — the scope_generator emits that
// list from docs/scopes.yaml entries with userGrantable: true. Stored
// scopes outside that set are ignored at evaluation time so a config
// drift can't accidentally hand out a data-plane (wlcg/scitokens) or
// inter-server scope through the user-management surface.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// UserScope is one row in the user_scopes table — a scope granted
// directly to a single user.
type UserScope struct {
	UserID       string                  `gorm:"primaryKey" json:"userId"`
	Scope        token_scopes.TokenScope `gorm:"primaryKey;column:scope" json:"scope"`
	GrantedBy    string                  `gorm:"not null;default:'unknown'" json:"grantedBy"`
	AuthMethod   AuthMethod              `gorm:"not null;default:''" json:"authMethod"`
	AuthMethodID string                  `gorm:"not null;default:''" json:"authMethodId,omitempty"`
	GrantedAt    time.Time               `gorm:"not null;default:CURRENT_TIMESTAMP" json:"grantedAt"`
}

// GroupScope is one row in the group_scopes table — a scope granted
// to all members of a group.
type GroupScope struct {
	GroupID      string                  `gorm:"primaryKey" json:"groupId"`
	Scope        token_scopes.TokenScope `gorm:"primaryKey;column:scope" json:"scope"`
	GrantedBy    string                  `gorm:"not null;default:'unknown'" json:"grantedBy"`
	AuthMethod   AuthMethod              `gorm:"not null;default:''" json:"authMethod"`
	AuthMethodID string                  `gorm:"not null;default:''" json:"authMethodId,omitempty"`
	GrantedAt    time.Time               `gorm:"not null;default:CURRENT_TIMESTAMP" json:"grantedAt"`
}

// ErrUngrantableScope is returned by GrantUserScope / GrantGroupScope
// when the supplied scope is not in token_scopes.UserGrantableScopes.
// Hard-coding the allow-list at the boundary stops a misconfigured
// admin tool from inserting a data-plane scope into the management
// tables.
var ErrUngrantableScope = errors.New("scope is not user-grantable; only management scopes can be assigned to users or groups")

// validateGrantable rejects scopes that callers must not be able to
// assign through this API.
func validateGrantable(scope token_scopes.TokenScope) error {
	if !token_scopes.IsUserGrantable(scope) {
		return fmt.Errorf("%w: %s", ErrUngrantableScope, scope.String())
	}
	return nil
}

// GrantUserScope adds a scope to a user. Idempotent: granting the
// same scope twice is a no-op (the existing row is preserved).
func GrantUserScope(db *gorm.DB, userID string, scope token_scopes.TokenScope, granter Creator) error {
	if userID == "" {
		return errors.New("userID is required")
	}
	if err := validateGrantable(scope); err != nil {
		return err
	}
	row := UserScope{
		UserID:       userID,
		Scope:        scope,
		GrantedBy:    creatorOrUnknown(granter.UserID),
		AuthMethod:   granter.AuthMethod,
		AuthMethodID: granter.AuthMethodID,
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

// DefaultUserScopesFromConfig parses Server.NewUserDefaultScopes into a
// validated TokenScope slice. Each entry must be user-grantable
// (token_scopes.IsUserGrantable) — operators can't bootstrap a new
// account with a data-plane (wlcg.*, scitokens.*) or inter-server
// scope through this knob. Returns ErrUngrantableScope (wrapped) on
// the first bad entry; ApplyDefaultUserScopes / the startup backfill
// surface that as a logged warning rather than a hard failure so a
// misconfigured value doesn't take the whole server out of service.
//
// An empty / unset config returns an empty slice (no auto-grants).
func DefaultUserScopesFromConfig() ([]token_scopes.TokenScope, error) {
	raw := param.Server_NewUserDefaultScopes.GetStringSlice()
	out := make([]token_scopes.TokenScope, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ts := token_scopes.TokenScope(s)
		if !token_scopes.IsUserGrantable(ts) {
			return nil, fmt.Errorf("%w: %s", ErrUngrantableScope, s)
		}
		out = append(out, ts)
	}
	return out, nil
}

// ApplyDefaultUserScopes grants the operator-configured baseline
// scopes (Server.NewUserDefaultScopes, default web_ui.access) to a
// freshly-created user. Called from each user-creation path so a new
// account starts with the same baseline regardless of how it was
// minted.
//
// Errors are logged but never returned: failing to grant a baseline
// scope must not void the user record itself, and any operator-side
// misconfiguration would already have surfaced in startup logs via
// the backfill's validation pass. The startup backfill also runs as
// a safety net for any user a transient grant failure missed here.
func ApplyDefaultUserScopes(db *gorm.DB, userID string, granter Creator) {
	if userID == "" {
		return
	}
	scopes, err := DefaultUserScopesFromConfig()
	if err != nil {
		log.Warnf("Skipping default-scope grant for new user %s: %v", userID, err)
		return
	}
	for _, s := range scopes {
		if err := GrantUserScope(db, userID, s, granter); err != nil {
			log.Warnf("Failed to grant default scope %s to user %s: %v", s, userID, err)
		}
	}
}

// newUserDefaultScopesBackfillKey is the Counter row that records
// whether BackfillNewUserDefaultScopes has run on this database. The
// `_v1` suffix lets a future migration force a re-run by bumping the
// key (e.g., if a follow-up changes the backfill semantics).
const newUserDefaultScopesBackfillKey = "new_user_default_scopes_backfill_v1"

// BackfillNewUserDefaultScopes grants the operator-configured
// Server.NewUserDefaultScopes to every existing user account, ONCE
// per server installation. Subsequent runs are no-ops via the
// counters row keyed by newUserDefaultScopesBackfillKey.
//
// The backfill exists because the auto-grant path triggers only at
// user-creation time. Pre-existing users (created before the knob
// existed, or before its current default) wouldn't otherwise pick up
// the baseline scope; this gives them the same starting posture a
// new account would receive on the same server.
//
// Subsequent edits to Server.NewUserDefaultScopes do NOT propagate
// retroactively — by design. The backfill is a one-time fixup, not
// a continuous reconciliation; "I added a baseline scope after
// running for a year" must not silently grant that scope to every
// existing account. Operators who want that behavior should grant
// the scope to a relevant group instead.
func BackfillNewUserDefaultScopes(db *gorm.DB) error {
	// Already run? No-op.
	var counter Counter
	err := db.Where("key = ?", newUserDefaultScopesBackfillKey).First(&counter).Error
	if err == nil && counter.Value > 0 {
		return nil
	}
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	scopes, err := DefaultUserScopesFromConfig()
	if err != nil {
		// Misconfiguration — skip the backfill but don't crash startup.
		// The operator sees the error in the startup logs and can fix
		// the config; we'll re-attempt on the next start because the
		// counter row was never written.
		log.Warnf("Skipping NewUserDefaultScopes backfill (will retry next startup): %v", err)
		return nil
	}

	// Grant the configured baseline to every user. Even when there's
	// nothing to grant we still mark complete below so the lookup +
	// User scan don't repeat on every startup.
	granter := Creator{UserID: CreatorUnknown}
	var users []User
	if err := db.Find(&users).Error; err != nil {
		return err
	}
	granted := 0
	for _, u := range users {
		for _, s := range scopes {
			if grantErr := GrantUserScope(db, u.ID, s, granter); grantErr != nil {
				log.Warnf("Backfill: failed to grant %s to user %s: %v", s, u.ID, grantErr)
				continue
			}
			granted++
		}
	}
	if len(scopes) > 0 {
		log.Infof("NewUserDefaultScopes backfill: granted %d scope rows across %d users", granted, len(users))
	} else {
		log.Debugf("NewUserDefaultScopes backfill: no default scopes configured; marking complete without changes")
	}

	return db.Save(&Counter{Key: newUserDefaultScopesBackfillKey, Value: 1}).Error
}

// RevokeUserScope removes a scope grant. Returns gorm.ErrRecordNotFound
// when the row didn't exist so callers can distinguish "noop revoke"
// from "actually removed".
func RevokeUserScope(db *gorm.DB, userID string, scope token_scopes.TokenScope) error {
	res := db.Where("user_id = ? AND scope = ?", userID, scope).Delete(&UserScope{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListUserScopes returns all scope grants for a single user.
func ListUserScopes(db *gorm.DB, userID string) ([]UserScope, error) {
	var rows []UserScope
	if err := db.Where("user_id = ?", userID).Order("scope").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// GrantGroupScope adds a scope to a group. Same idempotency contract
// as GrantUserScope.
func GrantGroupScope(db *gorm.DB, groupID string, scope token_scopes.TokenScope, granter Creator) error {
	if groupID == "" {
		return errors.New("groupID is required")
	}
	if err := validateGrantable(scope); err != nil {
		return err
	}
	row := GroupScope{
		GroupID:      groupID,
		Scope:        scope,
		GrantedBy:    creatorOrUnknown(granter.UserID),
		AuthMethod:   granter.AuthMethod,
		AuthMethodID: granter.AuthMethodID,
	}
	return db.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error
}

// RevokeGroupScope removes a scope grant on a group.
func RevokeGroupScope(db *gorm.DB, groupID string, scope token_scopes.TokenScope) error {
	res := db.Where("group_id = ? AND scope = ?", groupID, scope).Delete(&GroupScope{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListGroupScopes returns all scope grants for a single group.
func ListGroupScopes(db *gorm.DB, groupID string) ([]GroupScope, error) {
	var rows []GroupScope
	if err := db.Where("group_id = ?", groupID).Order("scope").Find(&rows).Error; err != nil {
		return nil, err
	}
	return rows, nil
}

// EffectiveScopes returns the union of every scope that applies to
// the supplied user. Sources, in order:
//
//  1. user_scopes for userID (direct grants).
//  2. group_scopes for every group the user is a row-member of
//     (transitive via group_members).
//  3. group_scopes for every group whose `name` is in
//     externalGroupNames — i.e. a group asserted by the caller's
//     login cookie (wlcg.groups, sourced from OIDC or htpasswd).
//
// The result is deduplicated and filtered to the user-grantable
// allow-list, so a stale row referencing a no-longer-grantable scope
// does not leak through. EffectiveScopes does NOT consult any config
// (Server.UIAdminUsers, etc.) — the admin-bootstrap path populates
// user_scopes/group_scopes from those settings at startup, so the
// runtime evaluation has a single source of truth.
//
// userID may be empty when the caller is unauthenticated; the
// function returns nil in that case.
func EffectiveScopes(db *gorm.DB, userID string, externalGroupNames []string) ([]token_scopes.TokenScope, error) {
	if userID == "" && len(externalGroupNames) == 0 {
		return nil, nil
	}
	seen := map[token_scopes.TokenScope]struct{}{}
	out := []token_scopes.TokenScope{}

	add := func(scope string) {
		s := token_scopes.TokenScope(scope)
		if !token_scopes.IsUserGrantable(s) {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// 1. Direct user_scopes.
	if userID != "" {
		var userRows []struct {
			Scope string
		}
		if err := db.Table("user_scopes").
			Select("scope").
			Where("user_id = ?", userID).
			Scan(&userRows).Error; err != nil {
			return nil, err
		}
		for _, r := range userRows {
			add(r.Scope)
		}
	}

	// 2. group_scopes for groups the user belongs to via group_members.
	if userID != "" {
		var memberRows []struct {
			Scope string
		}
		if err := db.Table("group_scopes").
			Select("group_scopes.scope").
			Joins("JOIN group_members ON group_members.group_id = group_scopes.group_id").
			Where("group_members.user_id = ?", userID).
			Scan(&memberRows).Error; err != nil {
			return nil, err
		}
		for _, r := range memberRows {
			add(r.Scope)
		}
	}

	// 3. group_scopes for OIDC-asserted group names. Filter at SQL time
	// so an asserted name that doesn't correspond to a real group
	// produces no rows (mirrors ListGroupsVisibleToUser's stance:
	// "external assertions only count when they map to a known group").
	if len(externalGroupNames) > 0 {
		var extRows []struct {
			Scope string
		}
		if err := db.Table("group_scopes").
			Select("group_scopes.scope").
			Joins("JOIN groups ON groups.id = group_scopes.group_id").
			Where("groups.name IN ?", externalGroupNames).
			Scan(&extRows).Error; err != nil {
			return nil, err
		}
		for _, r := range extRows {
			add(r.Scope)
		}
	}

	return out, nil
}

// HasEffectiveScope is a convenience wrapper for "does this user have
// scope X" — the most common shape of the call. Returns false on any
// DB error after logging would be added by the caller; we don't have
// a logger here, so callers that care about distinguishing
// "definitely no" from "couldn't tell" should use EffectiveScopes
// directly.
func HasEffectiveScope(db *gorm.DB, userID string, externalGroupNames []string, scope token_scopes.TokenScope) bool {
	scopes, err := EffectiveScopes(db, userID, externalGroupNames)
	if err != nil {
		return false
	}
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
