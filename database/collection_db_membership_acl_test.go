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

// Regression: ACL evaluation must respect DB-stored group memberships,
// not just cookie-asserted wlcg.groups. A user added to a group via
// the management UI ("alpha-writers") should see ACL'd collections
// in their listing IMMEDIATELY, without re-logging-in or requiring
// the operator to set Issuer.GroupSource: internal. Previously the
// ACL gate consulted only cookie-asserted groups, so a user with
// htpasswd login (no wlcg.groups in the cookie) was invisible to
// every ACL row regardless of DB membership.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestACLViaDBMembership(t *testing.T) {
	t.Run("user added to writers group sees the collection without cookie assertion", func(t *testing.T) {
		db := setupCollectionTestDB(t)

		// Bob owns "alpha" with a writers ACL granted to "alpha-writers".
		require.NoError(t, db.Create(&User{
			ID: "u-bob", Username: "bob", Sub: "bob@oidc",
			Issuer: "https://idp.example.com", Status: UserStatusActive,
		}).Error)
		require.NoError(t, db.Create(&User{
			ID: "u-carol", Username: "carol", Sub: "carol@oidc",
			Issuer: "https://idp.example.com", Status: UserStatusActive,
		}).Error)
		writers := &Group{
			ID: "g-writers", Name: "alpha-writers",
			CreatedBy: "u-bob", OwnerID: "u-bob",
		}
		require.NoError(t, db.Create(writers).Error)
		// Carol is added to alpha-writers via the management UI —
		// recorded in group_members. NOTE: her cookie's wlcg.groups
		// does NOT carry "alpha-writers"; that's the bug we're
		// pinning down.
		require.NoError(t, db.Create(&GroupMember{
			GroupID: "g-writers", UserID: "u-carol", AddedBy: "u-bob",
		}).Error)

		coll := &Collection{
			ID: "c-alpha", Name: "alpha",
			Owner: "bob", OwnerID: "u-bob",
			Namespace: "/data/alpha", Visibility: VisibilityPrivate,
			ACLs: []CollectionACL{{
				CollectionID: "c-alpha",
				GroupID:      "alpha-writers",
				Role:         AclRoleWrite,
				GrantedBy:    "u-bob",
			}},
		}
		require.NoError(t, db.Create(coll).Error)

		// Carol passes nil for cookie-asserted groups (htpasswd login,
		// no wlcg.groups). She must still see the collection because
		// her DB membership puts her in alpha-writers, which has the
		// write ACL.
		err := validateACL(db, coll, "carol", "u-carol", nil, token_scopes.Collection_Read)
		assert.NoError(t, err,
			"DB-stored membership in alpha-writers must satisfy the ACL even without a cookie assertion")
		err = validateACL(db, coll, "carol", "u-carol", nil, token_scopes.Collection_Modify)
		assert.NoError(t, err, "write ACL covers Collection_Modify too")

		// And the listing endpoint surfaces the row for Carol.
		got, err := ListCollections(db, "carol", "u-carol", nil, false)
		require.NoError(t, err)
		ids := map[string]struct{}{}
		for _, c := range got {
			ids[c.ID] = struct{}{}
		}
		_, sawAlpha := ids["c-alpha"]
		assert.True(t, sawAlpha, "ListCollections must surface ACL'd rows via DB membership")
	})

	t.Run("non-member of any DB group sees nothing", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		// Single private collection with an ACL granted to a group
		// nobody belongs to.
		writers := &Group{ID: "g-w", Name: "w", CreatedBy: "u-x", OwnerID: "u-x"}
		require.NoError(t, db.Create(writers).Error)
		require.NoError(t, db.Create(&Collection{
			ID: "c-private", Name: "p",
			Owner: "owner", OwnerID: "u-x",
			Namespace: "/p", Visibility: VisibilityPrivate,
			ACLs: []CollectionACL{{
				CollectionID: "c-private", GroupID: "w",
				Role: AclRoleRead, GrantedBy: "u-x",
			}},
		}).Error)
		require.NoError(t, db.Create(&User{
			ID: "u-stranger", Username: "stranger", Sub: "s@oidc",
			Issuer: "https://idp.example.com", Status: UserStatusActive,
		}).Error)

		got, err := ListCollections(db, "stranger", "u-stranger", nil, false)
		require.NoError(t, err)
		assert.Empty(t, got, "a user with no membership and no ACL must see no private collections")
	})
}
