//go:build server || client

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func issuerOf(t *testing.T, db *gorm.DB, identityID string) string {
	t.Helper()
	var ident UserIdentity
	require.NoError(t, db.First(&ident, "id = ?", identityID).Error)
	return ident.Issuer
}

// adoptInternalIssuer moves identities written under the server's own URL —
// the current one and the older one the built-in admin still records — and
// leaves everyone else's alone.
func TestAdoptInternalIssuer(t *testing.T) {
	const currentURL = "https://origin.example.test"
	const staleURL = "https://old-origin.example.test"
	const idp = "https://idp.example.test"

	db := setupCollectionTestDB(t)
	setExternalWebURL(t, currentURL)

	// The built-in admin is still on the URL the server used to answer to.
	require.NoError(t, db.Create(&User{ID: "u-admin", Username: "admin", CreatedBy: CreatorSelfEnrolled}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-admin", UserID: "u-admin", Sub: "admin", Issuer: staleURL}).Error)
	// A local account written under the same stale URL.
	require.NoError(t, db.Create(&User{ID: "u-bob", Username: "bob", CreatedBy: CreatorSelfEnrolled}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-bob", UserID: "u-bob", Sub: "bob", Issuer: staleURL}).Error)
	// One written under the URL the server answers to now.
	require.NoError(t, db.Create(&User{ID: "u-carol", Username: "carol", CreatedBy: CreatorSelfEnrolled}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-carol", UserID: "u-carol", Sub: "carol", Issuer: currentURL}).Error)
	// And an OIDC identity, which must not be touched.
	require.NoError(t, db.Create(&User{ID: "u-dave", Username: "dave", CreatedBy: CreatorSelfEnrolled}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-dave", UserID: "u-dave", Sub: "dave-oidc", Issuer: idp}).Error)

	require.NoError(t, adoptInternalIssuer(db))

	assert.Equal(t, InternalIssuer, issuerOf(t, db, "i-admin"))
	assert.Equal(t, InternalIssuer, issuerOf(t, db, "i-bob"), "a stale URL is found through the admin's own identity")
	assert.Equal(t, InternalIssuer, issuerOf(t, db, "i-carol"))
	assert.Equal(t, idp, issuerOf(t, db, "i-dave"), "an external identity is left where it is")

	// Idempotent: a second pass has nothing left to move.
	require.NoError(t, adoptInternalIssuer(db))
	assert.Equal(t, InternalIssuer, issuerOf(t, db, "i-admin"))
	assert.Equal(t, idp, issuerOf(t, db, "i-dave"))
}

// An account that already holds an internal identity keeps it; the stale row
// is reported rather than forced through the one-identity-per-issuer index.
func TestAdoptInternalIssuerLeavesCollidingRow(t *testing.T) {
	const currentURL = "https://origin.example.test"

	db := setupCollectionTestDB(t)
	setExternalWebURL(t, currentURL)

	require.NoError(t, db.Create(&User{ID: "u-bob", Username: "bob", CreatedBy: CreatorSelfEnrolled}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-live", UserID: "u-bob", Sub: "bob", Issuer: InternalIssuer}).Error)
	require.NoError(t, db.Create(&UserIdentity{ID: "i-stale", UserID: "u-bob", Sub: "bob-old", Issuer: currentURL}).Error)

	require.NoError(t, adoptInternalIssuer(db), "a collision must not fail startup")
	assert.Equal(t, InternalIssuer, issuerOf(t, db, "i-live"))
	assert.Equal(t, currentURL, issuerOf(t, db, "i-stale"), "the stale row stays put for an admin to unlink")
}
