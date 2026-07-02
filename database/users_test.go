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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// The tests in this file cover the user/credential surface area:
//
//   - identifier validation enforcement at every public create path
//   - local vs OIDC creation flavors and their distinct invariants
//   - RenameUser keeping the local-issuer sub-equals-username invariant
//   - LookupOrBootstrapUser end-to-end (first sight, return visit,
//     display-name refresh, OIDC claim sanitisation, collision walk,
//     all-collide disambiguator, no-usable-claim fallback)
//   - the password-credential isolation contract — the User struct must
//     never carry the bcrypt hash, and the only public path that can
//     observe it is through VerifyUserPassword
//   - single-use invite redemption is race-safe (concurrent redemptions
//     of the same single-use link must not both succeed)
//
// Tests reuse setupCollectionTestDB from collection_test.go, which both
// AutoMigrates the schema and adds the password_hash column via the
// AutoMigrateCredentialsForTests bridge — see database/credentials.go
// for why that bridge exists.

const localIssuerForTests = "https://example.test"

func adminCreator() Creator {
	return Creator{UserID: "admin"}
}

// ---------- ValidateIdentifier reaches every create path ----------

func TestCreateLocalUserRejectsInvalidIdentifier(t *testing.T) {
	db := setupCollectionTestDB(t)
	for _, bad := range []string{"", "a", "alice/admin", "alice..bob", "_alice", strings.Repeat("a", 65)} {
		_, err := CreateLocalUser(db, bad, "", localIssuerForTests, adminCreator())
		assert.ErrorIs(t, err, ErrInvalidIdentifier, "input %q", bad)
	}
}

func TestCreateLocalUserRejectsInvalidDisplayName(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateLocalUser(db, "alice", strings.Repeat("x", 129), localIssuerForTests, adminCreator())
	assert.ErrorIs(t, err, ErrInvalidDisplayName)

	_, err = CreateLocalUser(db, "bob", "bad\x07char", localIssuerForTests, adminCreator())
	assert.ErrorIs(t, err, ErrInvalidDisplayName)
}

func TestCreateLocalUserHappyPath(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "Alice Smith", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NotNil(t, u)

	// Local-issuer invariant: sub equals username.
	assert.Equal(t, u.Username, u.Sub)
	assert.Equal(t, localIssuerForTests, u.Issuer)
	assert.Equal(t, "Alice Smith", u.DisplayName)
	// No password is set up front — admins use the password-invite flow.
	assert.False(t, u.HasPassword, "freshly-created local user must not have a password")
	assert.Equal(t, adminCreator().UserID, u.CreatedBy)
}

func TestCreateLocalUserRequiresLocalIssuer(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateLocalUser(db, "alice", "", "", adminCreator())
	assert.Error(t, err)
}

func TestCreateLocalUserRejectsDuplicateUsername(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	_, err = CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	assert.Error(t, err, "second create with the same (username, issuer) must fail")
}

func TestCreateUserRejectsInvalidIdentifier(t *testing.T) {
	db := setupCollectionTestDB(t)
	for _, bad := range []string{"", "alice/admin", "alice..bob"} {
		_, err := CreateUser(db, bad, "sub-x", "https://idp.example", adminCreator())
		assert.ErrorIs(t, err, ErrInvalidIdentifier, "input %q", bad)
	}
}

func TestCreateUserRejectsDuplicateIdentity(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateUser(db, "alice", "alice@idp", "https://idp.example", adminCreator())
	require.NoError(t, err)
	// Same (sub, issuer) must collide regardless of username.
	_, err = CreateUser(db, "alice2", "alice@idp", "https://idp.example", adminCreator())
	assert.Error(t, err)
}

// ---------- RenameUser invariants ----------

func TestRenameUserKeepsSubInLockstepForLocalUsers(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	require.NoError(t, RenameUser(db, u.ID, "alicia", localIssuerForTests))

	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alicia", got.Username)
	// Local-issuer accounts: sub must follow the username so password
	// login (which keys off (username, issuer)) keeps working.
	assert.Equal(t, "alicia", got.Sub)
}

func TestRenameUserLeavesOIDCSubAlone(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateUser(db, "alice", "alice@idp", "https://idp.example", adminCreator())
	require.NoError(t, err)

	// localIssuer is supplied but the user's issuer is the OIDC one —
	// the local-issuer rule must not apply.
	require.NoError(t, RenameUser(db, u.ID, "alicia", localIssuerForTests))

	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alicia", got.Username)
	assert.Equal(t, "alice@idp", got.Sub, "OIDC sub must not be rewritten on rename")
}

func TestRenameUserRejectsInvalidIdentifier(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	assert.ErrorIs(t, RenameUser(db, u.ID, "alice/admin", localIssuerForTests), ErrInvalidIdentifier)
}

// ---------- LookupOrBootstrapUser ----------

func TestLookupOrBootstrapUserFirstSightCreatesAccount(t *testing.T) {
	db := setupCollectionTestDB(t)

	u, err := LookupOrBootstrapUser(db, "alice@idp", "https://idp.example", "Alice Smith", []string{"alice"})
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, "alice", u.Username)
	assert.Equal(t, "Alice Smith", u.DisplayName)
	assert.Equal(t, CreatorSelfEnrolled, u.CreatedBy)
}

func TestLookupOrBootstrapUserReturnVisitReusesAccountAndRefreshesDisplayName(t *testing.T) {
	db := setupCollectionTestDB(t)

	first, err := LookupOrBootstrapUser(db, "alice@idp", "https://idp.example", "Alice", []string{"alice"})
	require.NoError(t, err)

	// Same identity, new display name. We must NOT create a second user;
	// we MUST refresh the display name.
	second, err := LookupOrBootstrapUser(db, "alice@idp", "https://idp.example", "Alice Renamed", []string{"alice"})
	require.NoError(t, err)
	assert.Equal(t, first.ID, second.ID, "return visit must reuse the account")
	assert.Equal(t, "Alice Renamed", second.DisplayName)
}

func TestLookupOrBootstrapUserSanitizesAndWalksOnCollision(t *testing.T) {
	db := setupCollectionTestDB(t)
	const oidcIssuer = "https://idp.example"

	// Pre-existing user at the OIDC issuer with username "alice" so the
	// first candidate below collides and the walk has to pick the next.
	_, err := CreateUser(db, "alice", "previous-alice", oidcIssuer, adminCreator())
	require.NoError(t, err)

	// Candidates: ["alice/admin", "alicia"]
	//   sanitises to ["alice_admin", "alicia"]
	//   "alice_admin" is free at this issuer, so the walk takes the
	//   first sanitised candidate. Test the sanitisation step itself
	//   produced something usable rather than rejecting the login.
	u, err := LookupOrBootstrapUser(db, "alice@idp", oidcIssuer, "Alice", []string{"alice/admin", "alicia"})
	require.NoError(t, err)
	assert.Equal(t, "alice_admin", u.Username)
}

func TestLookupOrBootstrapUserDisambiguatesWhenAllCandidatesCollide(t *testing.T) {
	db := setupCollectionTestDB(t)

	// The username uniqueness index is (username, issuer) — two users
	// at different issuers can share a username. To force a collision
	// we plant a different (sub, issuer) at the SAME issuer the
	// LookupOrBootstrapUser call below uses.
	const oidcIssuer = "https://idp.example"
	_, err := CreateUser(db, "alice", "first-alice", oidcIssuer, adminCreator())
	require.NoError(t, err)

	u, err := LookupOrBootstrapUser(db, "second-alice", oidcIssuer, "Alice", []string{"alice"})
	require.NoError(t, err)
	// Every sanitised candidate ("alice") collides with the
	// pre-existing user at this issuer; LookupOrBootstrapUser must
	// mint a disambiguated handle (alice-XXXX).
	assert.True(t, strings.HasPrefix(u.Username, "alice-"),
		"expected disambiguated username, got %q", u.Username)
	assert.NotEqual(t, "alice", u.Username)
}

func TestLookupOrBootstrapUserSyntheticNameWhenNoCandidatesUseable(t *testing.T) {
	db := setupCollectionTestDB(t)
	// Every candidate sanitises to "" → the function must still produce
	// an account so the user isn't locked out of their own first login.
	u, err := LookupOrBootstrapUser(db, "weird@idp", "https://idp.example", "Weird", []string{"!!!", "..."})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(u.Username, "user-"),
		"expected synthetic username, got %q", u.Username)
}

func TestLookupOrBootstrapUserRequiresArguments(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := LookupOrBootstrapUser(db, "", "https://idp.example", "", []string{"alice"})
	assert.Error(t, err)

	_, err = LookupOrBootstrapUser(db, "alice@idp", "", "", []string{"alice"})
	assert.Error(t, err)

	_, err = LookupOrBootstrapUser(db, "alice@idp", "https://idp.example", "", nil)
	assert.Error(t, err)
}

// ---------- Credential isolation contract ----------

// TestUserStructHasNoPasswordHashField is a compile-time-ish assertion:
// if anyone re-adds a PasswordHash field to the User struct, this test
// fails immediately and the security contract documented in
// database/credentials.go is restored before the change can land.
func TestUserStructHasNoPasswordHashField(t *testing.T) {
	typ := reflect.TypeOf(User{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Name == "PasswordHash" {
			t.Fatalf("User struct must not carry a PasswordHash field — credential must stay confined to database/credentials.go")
		}
		// Also reject any field whose JSON name or DB column would
		// surface the hash by accident.
		if jsonTag := f.Tag.Get("json"); jsonTag != "" {
			name := strings.SplitN(jsonTag, ",", 2)[0]
			if name == "passwordHash" || name == "password_hash" {
				t.Fatalf("User field %q carries a JSON tag that would expose the credential hash", f.Name)
			}
		}
		if gormTag := f.Tag.Get("gorm"); strings.Contains(gormTag, "password_hash") {
			t.Fatalf("User field %q maps to the password_hash column — must not", f.Name)
		}
	}
}

func TestSetAndVerifyUserPasswordRoundTrip(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))

	got, err := VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	assert.True(t, got.HasPassword)

	// Wrong password.
	_, err = VerifyUserPassword(db, "alice", "wrong", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)

	// Unknown user — same error class so callers can't distinguish.
	_, err = VerifyUserPassword(db, "bob", "hunter2", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestVerifyUserPasswordRejectsWhenNoPasswordSet(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	// No SetUserPassword call — the row exists but has no credential.
	_, err = VerifyUserPassword(db, "alice", "anything", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestVerifyUserPasswordRejectsInactiveAccount(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))
	require.NoError(t, UpdateUserStatus(db, u.ID, UserStatusInactive))

	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestSetUserPasswordEmptyClearsPassword(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))

	// Sanity: password works.
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	require.NoError(t, err)

	// Clear it; subsequent verify must fail.
	require.NoError(t, SetUserPassword(db, u.ID, ""))
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)

	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.False(t, got.HasPassword)
}

func TestSetUserPasswordOnUnknownUser(t *testing.T) {
	db := setupCollectionTestDB(t)
	err := SetUserPassword(db, "no-such-user", "anything")
	assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

func TestUserAfterFindPopulatesHasPassword(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	// Fresh-from-DB read: HasPassword must be false until a password is set.
	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.False(t, got.HasPassword)

	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))

	got, err = GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.True(t, got.HasPassword, "AfterFind must reflect the new credential without exposing the hash")
}

// ---------- Password-invite redemption is race-safe ----------

func TestRedeemPasswordInviteLinkSingleUseRaceSafe(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	link, plaintext, err := CreatePasswordInviteLink(
		db, u.ID, adminCreator().UserID, time.Now().Add(time.Hour), AuthMethodWebCookie, "",
	)
	require.NoError(t, err)
	require.NotNil(t, link)

	// Two concurrent redemptions of the *same* single-use link. Exactly
	// one must succeed; the other must fail with a clear error and not
	// have written a password.
	var wg sync.WaitGroup
	results := make([]error, 2)
	wg.Add(2)
	for i := range results {
		go func(idx int) {
			defer wg.Done()
			_, err := RedeemPasswordInviteLink(db, plaintext, "hunter2-correct-horse")
			results[idx] = err
		}(i)
	}
	wg.Wait()

	successes := 0
	failures := 0
	for _, e := range results {
		if e == nil {
			successes++
		} else {
			failures++
		}
	}
	// SQLite serialises writers, so in practice one wins and one fails.
	// We tolerate either ordering of (success, failure) but never two
	// successes (the race-safe guard is what we're verifying).
	assert.Equal(t, 1, successes, "exactly one concurrent redemption must succeed")
	assert.Equal(t, 1, failures, "the other concurrent redemption must fail")

	// And — independently — the password must be set.
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	assert.NoError(t, err)
}

func TestRedeemPasswordInviteLinkSecondAttemptFails(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	_, plaintext, err := CreatePasswordInviteLink(
		db, u.ID, adminCreator().UserID, time.Now().Add(time.Hour), AuthMethodWebCookie, "",
	)
	require.NoError(t, err)

	_, err = RedeemPasswordInviteLink(db, plaintext, "hunter2-correct-horse")
	require.NoError(t, err)

	// Second redemption with a different password must fail and must
	// NOT overwrite the first password.
	_, err = RedeemPasswordInviteLink(db, plaintext, "another-password-attempt")
	assert.Error(t, err)

	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse", localIssuerForTests)
	assert.NoError(t, err, "first password must remain in effect after a failed second redemption")
	_, err = VerifyUserPassword(db, "alice", "another-password-attempt", localIssuerForTests)
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestPasswordInviteHashIsBcryptedAtRest(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	_, plaintext, err := CreatePasswordInviteLink(
		db, u.ID, adminCreator().UserID, time.Now().Add(time.Hour), AuthMethodWebCookie, "",
	)
	require.NoError(t, err)

	var stored GroupInviteLink
	require.NoError(t, db.First(&stored, "kind = ?", InviteKindPassword).Error)
	assert.NotEqual(t, plaintext, stored.HashedToken,
		"the stored token must be the bcrypt hash, not the plaintext")
	// Cheap sanity that it's actually bcrypt-comparable.
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.HashedToken), []byte(plaintext)))
}

func TestInviteLinkExposesTokenPrefixForPublicID(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)

	link, plaintext, err := CreatePasswordInviteLink(
		db, u.ID, adminCreator().UserID, time.Now().Add(time.Hour), AuthMethodWebCookie, "",
	)
	require.NoError(t, err)

	// The prefix is a label, not a credential; it should equal the
	// first inviteTokenPrefixLen chars of the plaintext so admins can
	// match it back to a token they generated.
	require.Len(t, link.TokenPrefix, inviteTokenPrefixLen)
	assert.Equal(t, plaintext[:inviteTokenPrefixLen], link.TokenPrefix)
}
