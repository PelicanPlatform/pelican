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

package oa4mp

// Regression: token-mint scope emission must respect DB-stored
// group memberships, not just cookie-asserted wlcg.groups. Mirrors
// the same fix on the listing path (see
// database/collection_db_membership_acl_test.go) — without it, a
// user added to a group via the management UI gets the row in their
// listing but their freshly-minted SciToken carries no
// storage.* scope for the corresponding namespace, so the data
// plane silently rejects every read/write.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/database"
)

func TestGetUserCollectionScopes_DBMembership(t *testing.T) {
	db := newCollectionTestDB(t)
	// Need group_members + groups for the membership lookup.
	require.NoError(t, db.AutoMigrate(&database.Group{}, &database.GroupMember{}))

	// Bob owns "alpha" and grants writers ACL to "alpha-writers".
	// Carol is added to alpha-writers via the management UI — her
	// wlcg.groups (cookie-asserted) is intentionally empty in this
	// test to simulate htpasswd login.
	require.NoError(t, db.Create(&database.Group{
		ID: "g-w", Name: "alpha-writers", CreatedBy: "u-bob", OwnerID: "u-bob",
	}).Error)
	require.NoError(t, db.Create(&database.GroupMember{
		GroupID: "g-w", UserID: "u-carol", AddedBy: "u-bob",
	}).Error)
	seedCollection(t, db, "c-alpha", "/data/alpha")
	seedACL(t, db, "c-alpha", "alpha-writers", database.AclRoleWrite, nil)

	// Pass empty cookie groups but a real userID. The expansion in
	// GetUserCollectionScopes should pick up Carol's DB membership
	// and emit the storage scopes for /data/alpha.
	scopes, matched, err := GetUserCollectionScopes(db, "carol", "u-carol", nil, "")
	require.NoError(t, err)

	assert.Contains(t, scopes, "storage.read:/data/alpha",
		"DB-stored membership in alpha-writers must produce storage.read at token-mint time")
	assert.Contains(t, scopes, "storage.modify:/data/alpha",
		"write ACL must extend to storage.modify on the data plane")
	assert.Contains(t, scopes, "collection.read:c-alpha")
	assert.Contains(t, scopes, "collection.modify:c-alpha")
	// matchedGroups feeds wlcg.groups on the minted token; the
	// DB-derived group's NAME (not slug) is what consumers compare.
	assert.Contains(t, matched, "alpha-writers",
		"DB-membership-resolved group should appear in matchedGroups for the wlcg.groups claim")
}
