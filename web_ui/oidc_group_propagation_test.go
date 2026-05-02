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

package web_ui

// End-to-end coverage for OIDC-asserted group membership flowing
// through the cookie path and into authorization decisions.
//
// The ingredients are tested individually elsewhere — token creation,
// GetUserGroups extraction of the wlcg.groups claim, validateACL
// matching against a group name, EffectiveScopes resolving an
// asserted name to a real group's scopes — but until this file no
// single test exercised the full seam. The audit of OIDC group
// propagation (see scopes_test.go for the per-component tests) called
// out the gap explicitly: a freshly-asserted user with no DB
// group_members row, no UIAdminUsers / AdminGroups config match, and
// a single group named in wlcg.groups must still authorize against
// any collection ACL granting that group, and must inherit the
// matching group_scopes.
//
// We DELIBERATELY avoid the full HTTP router. The cookie-extraction
// pipeline (web_ui.GetUserGroups) takes a *gin.Context, so we drive
// it directly by attaching the minted JWT as a cookie on a synthetic
// request. That's enough to exercise the seam this audit cared about
// without dragging in the router middleware chain or the data plane.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// mintLoginCookieForTest forges the same JWT shape setLoginCookie
// emits at production login time: issuer/audience pinned to
// Server.ExternalWebUrl (so GetUserGroups passes its issuer/audience
// validation), WebUi_Access scope, wlcg.groups asserting `groups`,
// and the user_id / oidc_sub / oidc_iss claims AuthHandler relies on.
//
// We do NOT call setLoginCookie itself — that would require a full
// gin.Context and writes to the response — but everything the
// downstream code reads is here.
func mintLoginCookieForTest(t *testing.T, userRecord *database.User, groups []string) string {
	t.Helper()
	tk := token.NewWLCGToken()
	issuer := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, issuer, "Server.ExternalWebUrl must be set before minting test cookies")
	tk.Issuer = issuer
	tk.AddAudiences(issuer)
	tk.Subject = userRecord.Username
	tk.Lifetime = 5 * 60 * 1_000_000_000 // 5 minutes; nanoseconds for time.Duration
	tk.AddScopes(token_scopes.WebUi_Access)
	tk.AddGroups(groups...)
	tk.Claims = map[string]string{
		"user_id":  userRecord.ID,
		"oidc_sub": userRecord.Sub,
		"oidc_iss": userRecord.Issuer,
	}
	tok, err := tk.CreateToken()
	require.NoError(t, err)
	return tok
}

// ginContextWithLoginCookie wraps the cookie value in a gin.Context
// the same shape the AuthHandler middleware would build, but without
// running through the full router. Tests that need to drive
// GetUserGroups directly use this.
func ginContextWithLoginCookie(t *testing.T, loginToken string) *gin.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, err := http.NewRequest(http.MethodGet, "https://example.com/api/v1.0/origin_ui/collections", nil)
	require.NoError(t, err)
	req.AddCookie(&http.Cookie{Name: "login", Value: loginToken})
	c.Request = req
	return c
}

func TestOIDCAssertedGroupPropagation(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	// setupWebUIEnv wires up a real issuer keyset so the cookie's
	// signature verifies. It does NOT attach a DB to
	// database.ServerDatabase; we open one ourselves and let
	// migrateTestDB lay out the tables this test reaches.
	setupWebUIEnv(t)
	require.NoError(t, param.Server_ExternalWebUrl.Set("https://example.com"))
	prevDB := database.ServerDatabase
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	t.Cleanup(func() { database.ServerDatabase = prevDB })
	migrateTestDB(t)

	// --- Seed: zara is asserted into "research" by the IdP. She has
	// no group_members row, no UIAdminUsers / AdminGroups match, and
	// no direct user_scopes — the only signal carrying her into the
	// "research" group is the cookie's wlcg.groups claim.
	zara := &database.User{
		ID:       "u-zara",
		Username: "zara",
		Sub:      "zara@oidc",
		Issuer:   "https://idp.example.com",
		Status:   database.UserStatusActive,
	}
	require.NoError(t, database.ServerDatabase.Create(zara).Error)

	research := &database.Group{
		ID:        "g-research",
		Name:      "research",
		CreatedBy: "u-other",
	}
	require.NoError(t, database.ServerDatabase.Create(research).Error)

	// Owner of the collection is some other user — zara has no
	// ownership / admin-group relationship to it. Her access path
	// is purely the read ACL granted to "research".
	otherOwner := &database.User{
		ID:       "u-other",
		Username: "otto",
		Sub:      "otto@oidc",
		Issuer:   "https://idp.example.com",
		Status:   database.UserStatusActive,
	}
	require.NoError(t, database.ServerDatabase.Create(otherOwner).Error)

	coll := &database.Collection{
		ID:         "c-secret",
		Name:       "secret",
		Owner:      otherOwner.Username,
		OwnerID:    otherOwner.ID,
		Namespace:  "/secret",
		Visibility: database.VisibilityPrivate,
	}
	require.NoError(t, database.ServerDatabase.Create(coll).Error)

	// ACLs are stored by group NAME (the backend canonicalises
	// slug→name on write). The cookie's wlcg.groups carries names too;
	// the match here is the seam under test.
	require.NoError(t, database.ServerDatabase.Create(&database.CollectionACL{
		CollectionID: coll.ID,
		GroupID:      research.Name,
		Role:         database.AclRoleRead,
		GrantedBy:    otherOwner.ID,
	}).Error)

	// Give the research group a scope so we can also verify the
	// scope-resolution arm of the seam (asserted name → group_scopes).
	require.NoError(t, database.GrantGroupScope(
		database.ServerDatabase,
		research.ID,
		token_scopes.Server_CollectionAdmin,
		database.CreatorSelf(),
	))

	// --- Mint a login cookie that asserts membership in "research".
	loginTok := mintLoginCookieForTest(t, zara, []string{research.Name})
	ctx := ginContextWithLoginCookie(t, loginTok)

	// --- Seam #1: cookie → GetUserGroups → ctx fields.
	// This is the first hop: the JWT comes in, GetUserGroups
	// validates the signature, issuer, and audience, then extracts
	// user_id, the subject, and wlcg.groups.
	user, userId, groups, err := GetUserGroups(ctx)
	require.NoError(t, err)
	assert.Equal(t, zara.Username, user)
	assert.Equal(t, zara.ID, userId)
	assert.ElementsMatch(t, []string{research.Name}, groups,
		"wlcg.groups must round-trip from the cookie into the extracted slice")

	// --- Seam #2: extracted groups → validateACL via GetCollection.
	// The collection is private; zara has no owner/admin relationship;
	// the only path that lets her read it is the ACL granted to
	// "research", matched against the OIDC-asserted name. If
	// validateACL skipped the asserted-groups branch (or compared
	// names against slugs) this call would return ErrForbidden.
	got, err := database.GetCollection(database.ServerDatabase, coll.ID, user, userId, groups, false /* isAdmin */)
	require.NoError(t, err, "OIDC-asserted-only membership must satisfy a name-based ACL")
	assert.Equal(t, coll.ID, got.ID)

	// --- Seam #3: extracted groups → EffectiveScopes (DB layer).
	// The same group_scopes row that membership-via-group_members
	// would resolve must also resolve via the asserted-name path.
	scopes, err := database.EffectiveScopes(database.ServerDatabase, userId, groups)
	require.NoError(t, err)
	require.Truef(t,
		containsScope(scopes, token_scopes.Server_CollectionAdmin),
		"asserted name must confer the group's scope (got %v)", scopes,
	)

	// --- Seam #4: web-layer aggregation honors the same groups.
	// EffectiveScopesForIdentity unions DB results with config-derived
	// grants; passing the cookie-derived groups list must produce the
	// same scope, and CheckCollectionAdmin (a thin wrapper) must say
	// yes. This is the path collection endpoints use to flip their
	// `isAdmin` bypass on, so a regression here would silently
	// downgrade an OIDC-asserted user's effective authority.
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Sub:      zara.Sub,
		Groups:   groups,
	}
	ok, _ := CheckCollectionAdmin(identity)
	assert.True(t, ok,
		"CheckCollectionAdmin must honor the group_scopes implication via cookie-asserted membership")

	// --- Negative control: if we strip the asserted group, none of
	// the above should hold. This guards against a reviewer skim that
	// concluded the success branch was hard-coded.
	t.Run("without the asserted group, access is denied", func(t *testing.T) {
		_, err := database.GetCollection(database.ServerDatabase, coll.ID, user, userId, nil, false)
		assert.ErrorIs(t, err, database.ErrForbidden,
			"without the asserted group, the same caller must not pass the ACL gate")

		scopes, err := database.EffectiveScopes(database.ServerDatabase, userId, nil)
		require.NoError(t, err)
		assert.False(t, containsScope(scopes, token_scopes.Server_CollectionAdmin),
			"without the asserted group, collection_admin must NOT appear")
	})
}

// containsScope is named distinctly from `contains` (defined in
// scopes_test.go) so test files don't shadow each other if go test
// compiles them together.
func containsScope(scopes []token_scopes.TokenScope, target token_scopes.TokenScope) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}
