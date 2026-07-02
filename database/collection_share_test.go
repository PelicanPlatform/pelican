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

// Tests for the share data-model invariants enforced by CreateShare.
// The HTTP-level handler covers authz / multi-user-backend gating; the
// DB layer is responsible for the structural checks: parent must
// exist, parent.EnableSharing must be true, namespace must be a
// prefix-or-equal of the parent's, share-of-share is rejected.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCreateShare(t *testing.T) {
	mkParent := func(t *testing.T, db *gorm.DB, enableSharing bool) *Collection {
		t.Helper()
		p := &Collection{
			ID:            "p1",
			Name:          "parent",
			Owner:         "alice",
			OwnerID:       "u-alice",
			Namespace:     "/data/parent",
			Visibility:    VisibilityPrivate,
			EnableSharing: enableSharing,
		}
		require.NoError(t, db.Create(p).Error)
		return p
	}

	t.Run("happy path: equal namespace, owner is the caller", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)

		share, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "share-of-parent",
			Description:        "for bob",
			Namespace:          "", // default to parent's namespace
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "bob",
			OwnerID:            "u-bob",
		})
		require.NoError(t, err)
		assert.Equal(t, "p1", share.ParentCollectionID)
		assert.Equal(t, "u-bob", share.OwnerID)
		assert.Equal(t, "/data/parent", share.Namespace,
			"empty namespace must default to the parent's namespace")
		assert.False(t, share.EnableSharing,
			"share-of-share must be off by default — recursive sharing isn't supported")
	})

	t.Run("happy path: descendant namespace", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)

		share, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "subset",
			Namespace:          "/data/parent/subset",
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "bob",
			OwnerID:            "u-bob",
		})
		require.NoError(t, err)
		assert.Equal(t, "/data/parent/subset", share.Namespace)
	})

	t.Run("rejects namespace outside the parent", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)

		_, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "escape",
			Namespace:          "/elsewhere",
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "bob",
			OwnerID:            "u-bob",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path-descendant")
	})

	t.Run("rejects look-alike prefix that isn't a sub-path", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)

		_, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "lookalike",
			// /data/parent2 starts with the same string but isn't a
			// sub-path of /data/parent — guard against the classic
			// strings.HasPrefix bug.
			Namespace:     "/data/parent2",
			Visibility:    VisibilityPrivate,
			OwnerUsername: "bob",
			OwnerID:       "u-bob",
		})
		require.Error(t, err)
	})

	t.Run("ErrSharingDisabled when the parent did not opt in", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, false /* enableSharing */)

		_, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "nope",
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "bob",
			OwnerID:            "u-bob",
		})
		assert.ErrorIs(t, err, ErrSharingDisabled)
	})

	t.Run("rejects shares of shares", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)
		// Mint a first-level share manually with parent_collection_id set.
		// We skip CreateShare here so we can stamp ParentCollectionID
		// on a row that itself has EnableSharing == true (an operator
		// might have flipped that on a share by accident — the guard
		// must still trigger).
		share := &Collection{
			ID:                 "s1",
			Name:               "first-level",
			Owner:              "bob",
			OwnerID:            "u-bob",
			Namespace:          "/data/parent",
			Visibility:         VisibilityPrivate,
			ParentCollectionID: "p1",
			EnableSharing:      true,
		}
		require.NoError(t, db.Create(share).Error)

		_, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "s1",
			Name:               "second-level",
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "carol",
			OwnerID:            "u-carol",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "share of an existing share")
	})

	t.Run("ListCollectionShares returns children visible to the caller", func(t *testing.T) {
		db := setupCollectionTestDB(t)
		mkParent(t, db, true)
		// Owner-by-bob private share — bob sees it; carol does not.
		_, err := CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "bob-share",
			Namespace:          "/data/parent/bob",
			Visibility:         VisibilityPrivate,
			OwnerUsername:      "bob",
			OwnerID:            "u-bob",
		})
		require.NoError(t, err)
		// Public share — anyone sees it.
		_, err = CreateShare(db, CreateShareReq{
			ParentCollectionID: "p1",
			Name:               "public-share",
			Namespace:          "/data/parent/pub",
			Visibility:         VisibilityPublic,
			OwnerUsername:      "alice",
			OwnerID:            "u-alice",
		})
		require.NoError(t, err)

		got, err := ListCollectionShares(db, "p1", "bob", "u-bob", nil, false)
		require.NoError(t, err)
		ids := map[string]struct{}{}
		for _, c := range got {
			ids[c.Name] = struct{}{}
		}
		_, sawBob := ids["bob-share"]
		_, sawPublic := ids["public-share"]
		assert.True(t, sawBob, "owner sees their own share")
		assert.True(t, sawPublic, "public share visible to everyone")

		// Carol, with no access, sees only the public one.
		got, err = ListCollectionShares(db, "p1", "carol", "u-carol", nil, false)
		require.NoError(t, err)
		ids = map[string]struct{}{}
		for _, c := range got {
			ids[c.Name] = struct{}{}
		}
		_, sawBob = ids["bob-share"]
		_, sawPublic = ids["public-share"]
		assert.False(t, sawBob, "private share owned by someone else must stay hidden")
		assert.True(t, sawPublic)
	})
}
