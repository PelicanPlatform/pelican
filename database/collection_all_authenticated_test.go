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

// Tests for the all-authenticated-users virtual ACL group. The
// sentinel `@authenticated` lets a single ACL row grant access to
// every signed-in caller without listing every real group. The
// runtime contract:
//
//   - validateACL: any caller with a non-empty username or User.ID
//     matches an ACL row whose GroupID is the sentinel.
//   - ListCollections: same — the listing returns collections that
//     grant the sentinel even when the caller has no group membership.
//   - Anonymous callers (both username and userID empty) do NOT match
//     the sentinel; the design phrase is "all *authenticated* users".

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/token_scopes"
)

func TestAllAuthenticatedUsersSentinel(t *testing.T) {
	t.Run("sentinel never collides with a valid identifier", func(t *testing.T) {
		// The sentinel begins with `@`, which ValidateIdentifier rejects
		// (identifiers must start with an alphanumeric). This is the
		// invariant that makes the sentinel safe — no real group can
		// ever be named `@authenticated`.
		assert.Error(t, ValidateIdentifier(AllAuthenticatedUsersACLGroup),
			"sentinel must fail the identifier validator so no real group can collide")
		assert.True(t, IsACLGroupVirtual(AllAuthenticatedUsersACLGroup))
		assert.False(t, IsACLGroupVirtual("real-group"))
	})

	t.Run("validateACL admits any authenticated caller via the sentinel", func(t *testing.T) {
		db := setupCollectionTestDB(t)

		coll := &Collection{
			ID:         "c-private",
			Name:       "private",
			Owner:      "owner",
			OwnerID:    "u-owner",
			Namespace:  "/secret",
			Visibility: VisibilityPrivate,
			ACLs: []CollectionACL{
				{
					CollectionID: "c-private",
					GroupID:      AllAuthenticatedUsersACLGroup,
					Role:         AclRoleRead,
					GrantedBy:    "u-owner",
				},
			},
		}
		require.NoError(t, db.Create(coll).Error)

		// Caller "alice" has NO group memberships and is NOT the owner.
		// Without the sentinel her validateACL would return ErrForbidden;
		// with it, she gets read access via the all-authenticated path.
		err := validateACL(db, coll, "alice", "u-alice", nil, token_scopes.Collection_Read)
		assert.NoError(t, err, "authenticated caller must match the sentinel")

		// Same row should NOT confer Modify — sentinel grant is read-only.
		err = validateACL(db, coll, "alice", "u-alice", nil, token_scopes.Collection_Modify)
		assert.ErrorIs(t, err, ErrForbidden,
			"sentinel matches the role on the row only — read here, not write")
	})

	t.Run("anonymous caller does NOT match the sentinel", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		coll := &Collection{
			ID:         "c-anon",
			Name:       "anon",
			Owner:      "owner",
			OwnerID:    "u-owner",
			Namespace:  "/secret",
			Visibility: VisibilityPrivate,
			ACLs: []CollectionACL{
				{
					CollectionID: "c-anon",
					GroupID:      AllAuthenticatedUsersACLGroup,
					Role:         AclRoleRead,
					GrantedBy:    "u-owner",
				},
			},
		}
		require.NoError(t, db.Create(coll).Error)

		// Both username and User.ID empty: anonymous bearer-token call
		// without a user binding. The sentinel must NOT match.
		err := validateACL(db, coll, "", "", nil, token_scopes.Collection_Read)
		assert.ErrorIs(t, err, ErrForbidden,
			"the design says 'all authenticated users' — an anonymous caller must not match")
	})

	t.Run("ListCollections surfaces sentinel-granted private collections to authenticated callers", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		// Two private collections: one with a sentinel ACL, one without.
		// A caller with no ownership / admin / membership relationship
		// should see exactly the sentinel-granted one.
		require.NoError(t, db.Create(&Collection{
			ID:         "c-open",
			Name:       "open",
			Owner:      "owner",
			OwnerID:    "u-owner",
			Namespace:  "/p1",
			Visibility: VisibilityPrivate,
			ACLs: []CollectionACL{{
				CollectionID: "c-open",
				GroupID:      AllAuthenticatedUsersACLGroup,
				Role:         AclRoleRead,
				GrantedBy:    "u-owner",
			}},
		}).Error)
		require.NoError(t, db.Create(&Collection{
			ID:         "c-closed",
			Name:       "closed",
			Owner:      "owner",
			OwnerID:    "u-owner",
			Namespace:  "/p2",
			Visibility: VisibilityPrivate,
		}).Error)

		got, err := ListCollections(db, "alice", "u-alice", nil, false /* isAdmin */)
		require.NoError(t, err)
		ids := map[string]struct{}{}
		for _, c := range got {
			ids[c.ID] = struct{}{}
		}
		_, sawOpen := ids["c-open"]
		_, sawClosed := ids["c-closed"]
		assert.True(t, sawOpen, "sentinel-granted private collection must be listed")
		assert.False(t, sawClosed,
			"private collection without a matching ACL must stay hidden — sentinel does not implicitly open everything")
	})
}
