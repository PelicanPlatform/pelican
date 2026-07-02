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

// Share-intersection tests for GetUserCollectionScopes. The token-mint
// pipeline is responsible for clamping a share recipient's scopes by
// the share OWNER's CURRENT access to the parent collection — the
// design (docs/collections-design.md) mandates that revocation
// propagate so a downgraded share owner cannot keep delegating.
//
// Every test seeds a parent + a share, gives a recipient an ACL on
// the share, and asserts the scopes minted for the recipient.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
)

// seedParent inserts a parent collection with the given owner. ACLs
// are added separately via seedACL.
func seedParent(t *testing.T, db *gorm.DB, id, namespace, ownerUsername, ownerUserID string) {
	t.Helper()
	require.NoError(t, db.Create(&database.Collection{
		ID:            id,
		Name:          id,
		Owner:         ownerUsername,
		OwnerID:       ownerUserID,
		Namespace:     namespace,
		Visibility:    database.VisibilityPrivate,
		EnableSharing: true,
	}).Error)
}

// seedShare inserts a share row pointing at a parent. The share is
// owned by the user the recipient is "delegating from"; recipients
// then get ACL grants on the share.
func seedShare(t *testing.T, db *gorm.DB, id, namespace, ownerUsername, ownerUserID, parentID string) {
	t.Helper()
	require.NoError(t, db.Create(&database.Collection{
		ID:                 id,
		Name:               id,
		Owner:              ownerUsername,
		OwnerID:            ownerUserID,
		Namespace:          namespace,
		Visibility:         database.VisibilityPrivate,
		ParentCollectionID: parentID,
	}).Error)
}

func TestGetUserCollectionScopes_ShareIntersection(t *testing.T) {
	t.Run("recipient-read clamped to share-owner-read on parent", func(t *testing.T) {
		db := newCollectionTestDB(t)
		// Parent owned by Bob; Bob has implicit owner-role.
		seedParent(t, db, "parent-1", "/data/parent", "bob", "bob-id")
		// Share owned by Bob, namespace within parent.
		seedShare(t, db, "share-1", "/data/parent/sub", "bob", "bob-id", "parent-1")
		// Carol gets read on the share.
		seedACL(t, db, "share-1", "carol-readers", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "carol", "", []string{"carol-readers"}, "")
		require.NoError(t, err)

		// share.access pinned to the share's collection ID — the data
		// plane reads this and impersonates Bob (the share owner) for
		// objects under /data/parent/sub.
		assert.Contains(t, scopes, "share.access:/share-1",
			"share.access:/<id> must be emitted on every share-recipient token")
		// Storage scopes scoped to the SHARE'S namespace.
		assert.Contains(t, scopes, "storage.read:/data/parent/sub")
		assert.NotContains(t, scopes, "storage.modify:/data/parent/sub")
	})

	t.Run("recipient-write clamped to share-owner-read", func(t *testing.T) {
		db := newCollectionTestDB(t)
		// Bob owns the parent — owner role on parent is implicit.
		// Build a parent NOT owned by Bob but where Bob has only read
		// via an ACL row, so the clamp downgrades the recipient.
		seedParent(t, db, "parent-2", "/data/p2", "alice", "alice-id")
		seedACL(t, db, "parent-2", "user-bob", database.AclRoleRead, nil)
		// Bob creates a share and grants Carol *write* on it.
		seedShare(t, db, "share-2", "/data/p2/sub", "bob", "bob-id", "parent-2")
		seedACL(t, db, "share-2", "carol-writers", database.AclRoleWrite, nil)
		// EffectiveCollectionRole synthesises the personal `user-bob`
		// group inside the helper so we don't need a User row — the
		// helper queries the User row only via group_members joins,
		// and missing-table errors are tolerated (the helper falls
		// back to the personal-group + sentinel synthesis path).

		scopes, _, err := GetUserCollectionScopes(db, "carol", "", []string{"carol-writers"}, "")
		require.NoError(t, err)

		assert.Contains(t, scopes, "share.access:/share-2")
		// Carol asked for write but Bob can only read on the parent —
		// must clamp down to read.
		assert.Contains(t, scopes, "storage.read:/data/p2/sub")
		assert.NotContains(t, scopes, "storage.modify:/data/p2/sub",
			"share owner with parent-read must NOT pass write through to recipient")
	})

	t.Run("share-owner with no parent access kills all scopes", func(t *testing.T) {
		db := newCollectionTestDB(t)
		// Parent owned by Alice; Bob has no ACL relationship.
		seedParent(t, db, "parent-3", "/data/p3", "alice", "alice-id")
		// Bob (somehow) created a share earlier when he had access;
		// that access was later revoked.
		seedShare(t, db, "share-3", "/data/p3/x", "bob", "bob-id", "parent-3")
		seedACL(t, db, "share-3", "carol-readers", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "carol", "", []string{"carol-readers"}, "")
		require.NoError(t, err)

		// Management plane: Carol still gets collection.read on the
		// share (she has ACL on the row) — the design's intersection
		// is about *data plane*, not about hiding the share's
		// existence from someone the share owner already let in.
		assert.Contains(t, scopes, "collection.read:share-3")
		// Data plane: NO storage scope and NO share.access — both are
		// pointless when the share owner can't read the underlying
		// data anyway.
		assert.NotContains(t, scopes, "storage.read:/data/p3/x")
		assert.NotContains(t, scopes, "share.access:/share-3")
	})

	t.Run("non-share collection emits no share.access", func(t *testing.T) {
		db := newCollectionTestDB(t)
		seedCollection(t, db, "regular", "/data/regular")
		seedACL(t, db, "regular", "physics", database.AclRoleRead, nil)

		scopes, _, err := GetUserCollectionScopes(db, "alice", "", []string{"physics"}, "")
		require.NoError(t, err)

		assert.Contains(t, scopes, "storage.read:/data/regular")
		for _, s := range scopes {
			assert.NotContains(t, s, "share.access",
				"share.access must only appear on actual shares (parent_collection_id != '')")
		}
	})
}
