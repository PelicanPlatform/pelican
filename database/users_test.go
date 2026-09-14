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

	// The local identity is an ordinary row in user_identities like any
	// other, with sub == username at the local issuer.
	identities, err := ListUserIdentities(db, u.ID)
	require.NoError(t, err)
	require.Len(t, identities, 1)
	assert.Equal(t, u.Username, identities[0].Sub)
	assert.Equal(t, localIssuerForTests, identities[0].Issuer)
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

// Usernames are a GLOBAL authorization handle, not per-issuer: because
// admin matching is issuer-blind (web_ui/scopes.go), a name must back at
// most one live account across the whole server. Enforced by the partial
// unique index idx_user_username_live (migration 20260812000000).
func TestUsernameIsGloballyUniqueAcrossIssuers(t *testing.T) {
	db := setupCollectionTestDB(t)

	// An OIDC account claims "alice" under CILogon.
	oidc, err := CreateUser(db, "alice", "cilogon-sub-123", "https://cilogon.org", adminCreator())
	require.NoError(t, err)
	require.Equal(t, "alice", oidc.Username)

	// A local password account for "alice" (different issuer, different
	// sub) must be refused — otherwise both collapse into one issuer-blind
	// authz identity.
	_, err = CreateLocalUser(db, "alice", "Alice Local", localIssuerForTests, adminCreator())
	assert.Error(t, err, "local 'alice' must not coexist with OIDC 'alice'")

	// An admin-created OIDC account under yet another issuer must also be
	// refused.
	_, err = CreateUser(db, "alice", "gh-sub-1", "https://github.com", adminCreator())
	assert.Error(t, err, "cross-issuer duplicate username must be rejected")

	// First-login bootstrap under a *different* issuer whose derived
	// username also resolves to "alice" must disambiguate rather than
	// create a second live "alice" (pre-fix this produced a duplicate).
	u, err := LookupOrBootstrapUser(db, "gh-sub-2", "https://github.com", "Alice GH", []string{"alice"})
	require.NoError(t, err)
	assert.NotEqual(t, "alice", u.Username)
	assert.True(t, strings.HasPrefix(u.Username, "alice-"), "expected disambiguated name, got %q", u.Username)
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

func TestRenameUserLeavesLocalIdentityAlone(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NoError(t, SetUserPassword(db, u.ID, "correct horse battery staple"))

	require.NoError(t, RenameUser(db, u.ID, "alicia"))

	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alicia", got.Username)

	// The identity keeps the sub it was created with. Nothing needs it kept
	// in lockstep any more: password login resolves by username, which is
	// globally unique.
	identities, err := ListUserIdentities(db, u.ID)
	require.NoError(t, err)
	require.Len(t, identities, 1)
	assert.Equal(t, "alice", identities[0].Sub)

	// The rename must not lock the user out.
	verified, err := VerifyUserPassword(db, "alicia", "correct horse battery staple")
	require.NoError(t, err)
	assert.Equal(t, u.ID, verified.ID)
}

func TestRenameUserLeavesOIDCSubAlone(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateUser(db, "alice", "alice@idp", "https://idp.example", adminCreator())
	require.NoError(t, err)

	require.NoError(t, RenameUser(db, u.ID, "alicia"))

	got, err := GetUserByID(db, u.ID)
	require.NoError(t, err)
	assert.Equal(t, "alicia", got.Username)

	identities, err := ListUserIdentities(db, u.ID)
	require.NoError(t, err)
	require.Len(t, identities, 1)
	assert.Equal(t, "alice@idp", identities[0].Sub, "an issuer's subject is not ours to rewrite")
}

func TestRenameUserRejectsInvalidIdentifier(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	assert.ErrorIs(t, RenameUser(db, u.ID, "alice/admin"), ErrInvalidIdentifier)
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

	got, err := VerifyUserPassword(db, "alice", "hunter2-correct-horse")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, u.ID, got.ID)
	assert.True(t, got.HasPassword)

	// Wrong password.
	_, err = VerifyUserPassword(db, "alice", "wrong")
	assert.ErrorIs(t, err, ErrInvalidPassword)

	// Unknown user — same error class so callers can't distinguish.
	_, err = VerifyUserPassword(db, "bob", "hunter2")
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestVerifyUserPasswordRejectsWhenNoPasswordSet(t *testing.T) {
	db := setupCollectionTestDB(t)
	_, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	// No SetUserPassword call — the row exists but has no credential.
	_, err = VerifyUserPassword(db, "alice", "anything")
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestVerifyUserPasswordRejectsInactiveAccount(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))
	require.NoError(t, UpdateUserStatus(db, u.ID, UserStatusInactive))

	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse")
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestSetUserPasswordEmptyClearsPassword(t *testing.T) {
	db := setupCollectionTestDB(t)
	u, err := CreateLocalUser(db, "alice", "", localIssuerForTests, adminCreator())
	require.NoError(t, err)
	require.NoError(t, SetUserPassword(db, u.ID, "hunter2-correct-horse"))

	// Sanity: password works.
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse")
	require.NoError(t, err)

	// Clear it; subsequent verify must fail.
	require.NoError(t, SetUserPassword(db, u.ID, ""))
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse")
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
	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse")
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

	_, err = VerifyUserPassword(db, "alice", "hunter2-correct-horse")
	assert.NoError(t, err, "first password must remain in effect after a failed second redemption")
	_, err = VerifyUserPassword(db, "alice", "another-password-attempt")
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

// ---------- identity unification ----------
//
// These pin the properties the two-table split could not hold. Both invariants
// are now ordinary unique indexes on user_identities, so they apply to every
// writer rather than only to the ones that remembered to check.

// TestLookupOrBootstrapUserFindsLinkedIdentity is the regression for the bug
// that motivated unification: LookupOrBootstrapUser consulted only the users
// table, so an identity an admin had *linked* was invisible to it and the
// user's next sign-in minted a second account instead of logging them in.
func TestLookupOrBootstrapUserFindsLinkedIdentity(t *testing.T) {
	db := setupCollectionTestDB(t)
	const kc = "https://keycloak.example.org/realms/proj"

	alice, err := LookupOrBootstrapUser(db, "cilogon-sub", "https://cilogon.org", "Alice", []string{"alice"})
	require.NoError(t, err)

	// An admin links alice's identity at a second issuer.
	_, err = CreateUserIdentity(db, alice.ID, "kc-sub", kc)
	require.NoError(t, err)

	// Signing in through that issuer must land on alice's account.
	viaLogin, err := LookupOrBootstrapUser(db, "kc-sub", kc, "Alice", []string{"alice"})
	require.NoError(t, err)
	assert.Equal(t, alice.ID, viaLogin.ID, "a linked identity must resolve to the account it was linked to")

	var count int64
	require.NoError(t, db.Model(&User{}).Count(&count).Error)
	assert.EqualValues(t, 1, count, "signing in with a linked identity must not create a second account")
}

func TestCreateUserIdentityRejectsIdentityLinkedElsewhere(t *testing.T) {
	db := setupCollectionTestDB(t)
	const kc = "https://keycloak.example.org/realms/proj"

	alice, err := LookupOrBootstrapUser(db, "a-sub", "https://cilogon.org", "Alice", []string{"alice"})
	require.NoError(t, err)
	bob, err := LookupOrBootstrapUser(db, "kc-sub", kc, "Bob", []string{"bob"})
	require.NoError(t, err)

	_, err = CreateUserIdentity(db, alice.ID, "kc-sub", kc)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityClaimed)

	// The identity still resolves to its original owner.
	got, err := GetUserByIdentity(db, "kc-sub", kc)
	require.NoError(t, err)
	assert.Equal(t, bob.ID, got.ID)
}

func TestCreateUserIdentityRejectsSecondIdentityAtSameIssuer(t *testing.T) {
	db := setupCollectionTestDB(t)
	const idp = "https://idp.example.org"

	alice, err := LookupOrBootstrapUser(db, "a-sub", idp, "Alice", []string{"alice"})
	require.NoError(t, err)

	// One identity per issuer per user — otherwise two people could share an
	// account by each linking their own subject at the same IdP.
	_, err = CreateUserIdentity(db, alice.ID, "different-sub", idp)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIssuerAlreadyLinked)
}

// TestAdoptUserIdentityMovesIdentity covers the correction path that used to
// require deleting an account: with one table, moving an identity is a
// single-row update.
func TestAdoptUserIdentityMovesIdentity(t *testing.T) {
	db := setupCollectionTestDB(t)
	const kc = "https://keycloak.example.org/realms/proj"

	alice, err := LookupOrBootstrapUser(db, "cilogon-sub", "https://cilogon.org", "Alice", []string{"alice"})
	require.NoError(t, err)
	// A mis-enrollment: the same person auto-enrolled as a separate account.
	stray, err := LookupOrBootstrapUser(db, "kc-sub", kc, "Alice", []string{"alice-kc"})
	require.NoError(t, err)

	moved, err := AdoptUserIdentity(db, alice.ID, "kc-sub", kc)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, moved.UserID)

	got, err := GetUserByIdentity(db, "kc-sub", kc)
	require.NoError(t, err)
	assert.Equal(t, alice.ID, got.ID, "the identity must now resolve to alice")

	// The stray account still exists — adopting an identity is not a delete,
	// so anything it owns is preserved for the admin to deal with separately.
	_, err = GetUserByID(db, stray.ID)
	assert.NoError(t, err)
}

func TestAdoptUserIdentityRefusesIssuerCollision(t *testing.T) {
	db := setupCollectionTestDB(t)
	const kc = "https://keycloak.example.org/realms/proj"

	alice, err := LookupOrBootstrapUser(db, "alice-kc", kc, "Alice", []string{"alice"})
	require.NoError(t, err)
	_, err = LookupOrBootstrapUser(db, "bob-kc", kc, "Bob", []string{"bob"})
	require.NoError(t, err)

	// Alice already has an identity at this issuer; taking Bob's would give
	// her two, which is the invariant the (user_id, issuer) index protects.
	_, err = AdoptUserIdentity(db, alice.ID, "bob-kc", kc)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIssuerAlreadyLinked)
}

func TestDeleteUserIdentityGuardsLastCredential(t *testing.T) {
	db := setupCollectionTestDB(t)
	const idp = "https://idp.example.org"

	alice, err := LookupOrBootstrapUser(db, "a-sub", idp, "Alice", []string{"alice"})
	require.NoError(t, err)
	identities, err := ListUserIdentities(db, alice.ID)
	require.NoError(t, err)
	require.Len(t, identities, 1)

	// No password and no other identity: unlinking would lock the account out.
	err = DeleteUserIdentity(db, identities[0].ID, alice.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLastCredential)

	// With a password set, the same unlink is allowed — every identity is
	// removable now, including the one that used to live on the user row.
	require.NoError(t, SetUserPassword(db, alice.ID, "correct horse battery staple"))
	require.NoError(t, DeleteUserIdentity(db, identities[0].ID, alice.ID))

	remaining, err := ListUserIdentities(db, alice.ID)
	require.NoError(t, err)
	assert.Empty(t, remaining)
}

func TestDeleteUserIdentityAllowsUnlinkWhenAnotherRemains(t *testing.T) {
	db := setupCollectionTestDB(t)

	alice, err := LookupOrBootstrapUser(db, "a-sub", "https://idp-one.example", "Alice", []string{"alice"})
	require.NoError(t, err)
	second, err := CreateUserIdentity(db, alice.ID, "a-sub-2", "https://idp-two.example")
	require.NoError(t, err)

	require.NoError(t, DeleteUserIdentity(db, second.ID, alice.ID))
	remaining, err := ListUserIdentities(db, alice.ID)
	require.NoError(t, err)
	assert.Len(t, remaining, 1)
}

// TestDeleteUserFreesIdentityForReEnrollment is the regression for the orphaned-
// identity bug: DeleteUser soft-deletes the user row but must hard-delete its
// identities, or the (sub, issuer) stays reserved by the non-partial unique
// index and the same person can never sign in again.
func TestDeleteUserFreesIdentityForReEnrollment(t *testing.T) {
	db := setupCollectionTestDB(t)
	const iss = "https://idp.example.org"

	alice, err := LookupOrBootstrapUser(db, "alice-sub", iss, "Alice", []string{"alice"})
	require.NoError(t, err)

	require.NoError(t, DeleteUser(db, alice.ID, "admin", true))

	// No identity row should survive the delete.
	var count int64
	require.NoError(t, db.Model(&UserIdentity{}).Where("sub = ? AND issuer = ?", "alice-sub", iss).Count(&count).Error)
	assert.EqualValues(t, 0, count, "the deleted user's identity must not linger")

	// The same person can enroll again — previously this failed with a
	// UNIQUE violation surfaced as "could not allocate a unique username".
	reAlice, err := LookupOrBootstrapUser(db, "alice-sub", iss, "Alice", []string{"alice"})
	require.NoError(t, err, "re-enrollment after deletion must succeed")
	assert.NotEqual(t, alice.ID, reAlice.ID, "re-enrollment mints a fresh account")
}

// TestGetOrCreateLocalUserAfterRename covers htpasswd (or local-password) login
// for an account an admin has renamed. The identity keeps its original sub while
// the username moves, so a bare username lookup misses and the re-link collides
// on the issuer — the function must recognize that and return the account rather
// than erroring, which would lock the user out.
func TestGetOrCreateLocalUserAfterRename(t *testing.T) {
	db := setupCollectionTestDB(t)
	const localIssuer = "https://origin.example"

	u, err := CreateLocalUser(db, "alice", "", localIssuer, adminCreator())
	require.NoError(t, err)
	require.NoError(t, RenameUser(db, u.ID, "alicia"))

	// htpasswd login by the NEW username must resolve to the same account.
	got, err := GetOrCreateLocalUser(db, "alicia", localIssuer, CreatorSelf())
	require.NoError(t, err, "a renamed local account must still be resolvable by username")
	assert.Equal(t, u.ID, got.ID)

	// And it must not have spuriously created a second account.
	var count int64
	require.NoError(t, db.Model(&User{}).Count(&count).Error)
	assert.EqualValues(t, 1, count)
}
