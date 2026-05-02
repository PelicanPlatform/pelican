//go:build !windows

package origin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	tempPasswdFile *os.File
	router         *gin.Engine
)

func generateToken(t *testing.T, scopes []token_scopes.TokenScope, subject string, groups ...string) string {
	tk := token.NewWLCGToken()
	issuer := param.Server_ExternalWebUrl.GetString()
	require.NotEmpty(t, issuer, "Server External Web URL must be set for tests")
	tk.Issuer = issuer
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(param.Server_ExternalWebUrl.GetString())
	tk.AddScopes(scopes...)
	if len(groups) > 0 {
		tk.AddGroups(groups...)
	}
	// Add OIDC claims required by GetUserGroups
	tk.Claims = map[string]string{
		"user_id": subject,
	}
	tok, err := tk.CreateToken()
	require.NoError(t, err, "Failed to create token")

	// AuthHandler revalidates the user record on every cookie read;
	// without a backing User row the cookie 401s with "Your account
	// has been deactivated" before the handler under test even runs.
	// Idempotent: the OnConflict-DoNothing means tests minting many
	// tokens for the same subject only get one row.
	if database.ServerDatabase != nil {
		_, aupVersion, _ := web_ui.CurrentAUPVersion()
		require.NoError(t, database.ServerDatabase.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&database.User{
				ID:         subject,
				Username:   subject,
				Sub:        subject,
				Issuer:     "https://example.com",
				Status:     database.UserStatusActive,
				AUPVersion: aupVersion,
			}).Error)
	}

	return tok
}

func TestCollectionsAPI(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	gin.SetMode(gin.TestMode)
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() {
		if err := egrp.Wait(); err != nil {
			t.Fatal("Error waiting for errgroup: ", err)
		}
	}()
	defer cancel()

	testCfgDir := t.TempDir()
	require.NoError(t, param.ConfigDir.Set(testCfgDir))

	// set a temporary password file:
	tempFile, err := os.CreateTemp("", "web-ui-passwd")
	require.NoError(t, err, "Failed to create temp web-ui-passwd file")
	tempPasswdFile = tempFile

	// Override viper default for testing
	require.NoError(t, param.Server_UIPasswordFile.Set(tempPasswdFile.Name()))

	// Make a testing issuer.jwk file to get a cookie
	tempJWKDir := t.TempDir()

	// Override viper default for testing
	require.NoError(t, param.IssuerKeysDirectory.Set(filepath.Join(tempJWKDir, "issuer-keys")))

	require.NoError(t, param.Server_UILoginRateLimit.Set(100))

	// Set up origin exports
	exportDir := t.TempDir()
	err = os.WriteFile(filepath.Join(exportDir, "test-origin"), []byte("test"), 0644)
	require.NoError(t, err)

	exportDir2 := t.TempDir()

	require.NoError(t, param.Origin_StorageType.Set("posix"))
	require.NoError(t, param.Origin_Exports.Set([]map[string]interface{}{
		{
			"StoragePrefix":    exportDir,
			"FederationPrefix": "/test1",
			"SentinelLocation": "test-origin",
		},
		{
			"StoragePrefix":    exportDir2,
			"FederationPrefix": "/test2",
		},
	}))

	require.NoError(t, param.Server_UIAdminUsers.Set([]string{"admin-user"}))
	// The cookie path on POST /collections / GET /collections (admin
	// list) now requires server.web_admin or server.collection_admin
	// in the caller's effective scope set — without this, every
	// logged-in user could create or list every collection. Bearer
	// API tokens with explicit collection.create still pass through
	// (covered separately below). The two test subjects that drive
	// the "cookie create" path become collection admins so the
	// existing scenarios (lifecycle, ACL flows) keep exercising the
	// happy path; tests that target the rejection case
	// (e.g. unprivileged caller forbidden) get added explicitly.
	require.NoError(t, param.Server_CollectionAdminUsers.Set([]string{
		"test-user",
		"test-user-owner",
		// Used by owner-sees-own-private-collection-in-listing and
		// admin-group-member-sees-collection-in-listing — both pin
		// the post-rewrite ListCollections visibility paths
		// (owner-by-ID, admin-group membership).
		"owner-listing-user",
		"ag-owner-user",
	}))

	test_utils.MockFederationRoot(t, nil, nil)
	err = config.InitServer(ctx, server_structs.OriginType)
	require.NoError(t, err, "failed to init server config")

	router = gin.Default()

	// Configure Web API
	err = web_ui.ConfigureServerWebAPI(ctx, router, egrp)
	require.NoError(t, err, "Failed to configure server web API")

	routerGroup := router.Group("/api/v1.0/origin_ui")
	err = RegisterOriginWebAPI(routerGroup)
	require.NoError(t, err)

	// set up database
	mockDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	database.ServerDatabase = mockDB
	require.NoError(t, err, "Error setting up mock origin DB")

	err = database.ServerDatabase.AutoMigrate(&database.Collection{})
	require.NoError(t, err, "Failed to migrate DB for collections table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMember{})
	require.NoError(t, err, "Failed to migrate DB for collection members table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionMetadata{})
	require.NoError(t, err, "Failed to migrate DB for collection metadata table")
	err = database.ServerDatabase.AutoMigrate(&database.CollectionACL{})
	require.NoError(t, err, "Failed to migrate DB for collection ACLs table")
	err = database.ServerDatabase.AutoMigrate(&database.Group{})
	require.NoError(t, err, "Failed to migrate DB for groups table")
	err = database.ServerDatabase.AutoMigrate(&database.GroupMember{})
	require.NoError(t, err, "Failed to migrate DB for group members table")
	err = database.ServerDatabase.AutoMigrate(&database.User{})
	require.NoError(t, err, "Failed to migrate DB for users table")
	err = database.ServerDatabase.AutoMigrate(&database.GroupInviteLink{})
	require.NoError(t, err, "Failed to migrate DB for group invite links table")
	err = database.ServerDatabase.AutoMigrate(&database.UserIdentity{})
	require.NoError(t, err, "Failed to migrate DB for user identities table")

	t.Run("create-delete-collection", func(t *testing.T) {
		createReq := CreateCollectionReq{
			Name:        "test",
			Description: "test",
			Namespace:   "/test1",
			Visibility:  "public",
			Metadata:    map[string]string{"key": "value"},
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)

		token := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create, token_scopes.Collection_Delete}, "test-user")

		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		var createCollectionResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createCollectionResp)
		assert.NoError(t, err)
		collectionID := createCollectionResp["id"]
		assert.NotEmpty(t, collectionID)

		// Delete the collection
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))
	})

	t.Run("unprivileged-cookie-cannot-create-collection", func(t *testing.T) {
		// Pins the security contract: a logged-in user without
		// server.web_admin or server.collection_admin must not be
		// able to create a collection through the web UI cookie path.
		// Before this gate existed, every cookie carried web_ui.access
		// and the verify path fell through to "authenticated → ok".
		createReq := CreateCollectionReq{
			Name:        "rogue-create",
			Description: "should be refused",
			Namespace:   "/test1",
			Visibility:  "public",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		// "rogue-user" is in NEITHER Server.UIAdminUsers nor
		// Server.CollectionAdminUsers in this suite's setup; they
		// have web_ui.access on the cookie (every authenticated user
		// does) but no management scope.
		token := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "rogue-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code,
			"a cookie without collection_admin must be refused at the create gate (body: %s)",
			recorder.Body.String())
		assert.Contains(t, recorder.Body.String(), "server.collection_admin",
			"the rejection message should name the missing scope so the admin understands why")
	})

	t.Run("explicit-bearer-collection-create-bypasses-cookie-gate", func(t *testing.T) {
		// Pins the dual contract: even though the cookie path
		// requires server.collection_admin, an API client presenting
		// a bearer token with EXPLICIT collection.create scope still
		// works — that's the OA4MP / device-flow path. The bearer
		// token here carries collection.create directly, with no
		// web_ui.access fallback, so the new gate's
		// hasExplicitBearerCollectionScope branch must accept it.
		createReq := CreateCollectionReq{
			Name:        "via-bearer-create",
			Description: "should be accepted",
			Namespace:   "/test1",
			Visibility:  "public",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		// The subject is a non-admin user — what authorizes the
		// request is the explicit collection.create scope on the
		// bearer token, not the user's role.
		token := generateToken(t, []token_scopes.TokenScope{token_scopes.Collection_Create}, "bearer-create-subject")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusCreated, recorder.Code,
			"a bearer token with explicit collection.create must still authorize (body: %s)",
			recorder.Body.String())
	})

	t.Run("admin-group-grants-full-management-authority", func(t *testing.T) {
		// Pins the new ownership-model contract: setting
		// Collection.AdminID gives every member of that group
		// management authority on the collection — they can patch
		// metadata, grant/revoke ACLs, and manage the admin group
		// itself, all without needing an explicit ACL row. They
		// CANNOT transfer ownership or delete the collection — those
		// stay owner-exclusive (covered by the negative-control
		// assertions at the end of this subtest plus the dedicated
		// write-acl-cannot-transfer-ownership test below).
		//
		// Setup: collection-admin creates a private collection;
		// system admin creates a group; the admin-id is set on the
		// collection.
		colReq := CreateCollectionReq{
			Name:       "admin-group-probe",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, err := json.Marshal(colReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		ownerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user-owner")
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code,
			"setup: collection create must succeed (body: %s)", recorder.Body.String())
		var colResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&colResp))
		probeID := colResp["id"]
		require.NotEmpty(t, probeID)

		// Create the admin group as a system admin (system-admin
		// gating is what /groups POST requires).
		groupName := "admin-probe-group"
		grpReq := map[string]string{"name": groupName}
		body, err = json.Marshal(grpReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)
		adminToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code,
			"setup: admin group create (body: %s)", recorder.Body.String())
		var grpResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&grpResp))
		groupID := grpResp["id"]
		require.NotEmpty(t, groupID)

		// Owner sets adminId on the collection.
		patchReq := UpdateCollectionReq{AdminID: &groupID}
		body, err = json.Marshal(patchReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+probeID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code,
			"setup: PATCH adminId (body: %s)", recorder.Body.String())

		// A member of the admin group (asserted via wlcg.groups on
		// the cookie) — NO ACL row, NO collection_admin scope —
		// must be able to PATCH the collection.
		groupMemberToken := generateToken(t,
			[]token_scopes.TokenScope{token_scopes.WebUi_Access},
			"admin-group-member", groupName)
		updateName := "renamed-by-admin-group"
		updateReq := UpdateCollectionReq{Name: &updateName}
		body, err = json.Marshal(updateReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+probeID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupMemberToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code,
			"a member of the admin group must be able to PATCH the collection without any other authority (body: %s)",
			recorder.Body.String())

		// Negative control: a user NOT in the admin group, with no
		// ACL and no admin scope, must still 404.
		rogueToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "outsider")
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+probeID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"a non-member without an ACL must still be refused (body: %s)",
			recorder.Body.String())

		// Same admin-group member must NOT be able to transfer
		// ownership or delete the collection. Those two operations
		// stay owner-only — otherwise an admin-group member could
		// seize or destroy the collection out from under the
		// rightful owner. Build on the setup above (probe is owned
		// by test-user-owner, admin-group-member is in the admin
		// group via groupName).
		stolenOwner := "admin-group-member-stealing"
		patchOwner := UpdateCollectionReq{OwnerID: &stolenOwner}
		body, err = json.Marshal(patchOwner)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+probeID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupMemberToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"an admin-group member must NOT be able to transfer ownership (body: %s)",
			recorder.Body.String())

		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+probeID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupMemberToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"an admin-group member must NOT be able to delete the collection (body: %s)",
			recorder.Body.String())
	})

	t.Run("write-acl-cannot-transfer-ownership", func(t *testing.T) {
		// Per the ownership-model rewrite, transferring ownership and
		// re-assigning the admin group are restricted to existing
		// owner / admin-group / collection_admin. A holder of a
		// write ACL — who can normally modify the collection's name
		// or description — must NOT be able to PATCH ownerId or
		// adminId. The DB layer re-gates those two fields above the
		// generic Modify check.
		colReq := CreateCollectionReq{
			Name:       "transfer-probe",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, err := json.Marshal(colReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		ownerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user-owner")
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, "body: %s", recorder.Body.String())
		var colResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&colResp))
		probeID := colResp["id"]

		// Grant a write ACL to a group, then try to PATCH ownerId
		// from a member of that group. The PATCH must fail (403/404
		// — current handler returns 404 for the ErrForbidden path).
		writeGroup := "write-only-group"
		grpReq := map[string]string{"name": writeGroup}
		body, err = json.Marshal(grpReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)
		adminToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, "body: %s", recorder.Body.String())

		grant := map[string]string{"groupId": writeGroup, "role": "write"}
		body, err = json.Marshal(grant)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections/"+probeID+"/acl", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, "body: %s", recorder.Body.String())

		stolenOwner := "attacker-user-id"
		patch := UpdateCollectionReq{OwnerID: &stolenOwner}
		body, err = json.Marshal(patch)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+probeID, bytes.NewReader(body))
		require.NoError(t, err)
		writeToken := generateToken(t,
			[]token_scopes.TokenScope{token_scopes.WebUi_Access},
			"write-only-user", writeGroup)
		req.AddCookie(&http.Cookie{Name: "login", Value: writeToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"a write-ACL holder must NOT be able to PATCH ownerId (body: %s)",
			recorder.Body.String())
	})

	t.Run("admin-cookie-sees-other-users-private-collection", func(t *testing.T) {
		// Pins the global-visibility contract: a system admin /
		// collection admin sees every collection in the list, even
		// ones for which they hold no read ACL. Before this bypass,
		// an admin investigating a report couldn't see the collection
		// causing trouble unless they also had ACL — which made
		// admin-as-investigator unworkable.
		//
		// Step 1: collection-admin "test-user-owner" creates a
		// PRIVATE collection (no public read; only its
		// owner-user-group ACL, which only test-user-owner is in).
		createReq := CreateCollectionReq{
			Name:       "admin-visibility-probe",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		ownerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user-owner")
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code,
			"setup: owner must be able to create the probe collection (body: %s)",
			recorder.Body.String())
		var createResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&createResp))
		probeID := createResp["id"]
		require.NotEmpty(t, probeID)

		// Step 2: a system admin (Server.UIAdminUsers) lists
		// collections via cookie. Without the admin bypass, the
		// listing only contains collections the admin's user-group
		// has a read ACL on — i.e. nothing — so the probe is
		// invisible. With the bypass, the probe shows up.
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections", nil)
		require.NoError(t, err)
		adminToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code,
			"admin list call must succeed (body: %s)", recorder.Body.String())
		var listResp []map[string]interface{}
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&listResp))
		seenIDs := make([]string, 0, len(listResp))
		for _, c := range listResp {
			if id, ok := c["id"].(string); ok {
				seenIDs = append(seenIDs, id)
			}
		}
		assert.Contains(t, seenIDs, probeID,
			"a system admin must see other users' private collections in the listing — that's the whole point of the admin visibility bypass")

		// Step 3: same admin opens the collection page directly.
		// GetCollection's admin bypass mirrors the list bypass.
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+probeID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code,
			"admin GET /collections/:id on a private collection must succeed (body: %s)",
			recorder.Body.String())

		// Step 4 (negative control): a non-admin, non-ACL user gets
		// 404 on the same probe — the bypass must not leak to
		// ordinary users.
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+probeID, nil)
		require.NoError(t, err)
		// "rogue-user" is in no admin list and no group with ACL on
		// the probe.
		rogueToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "rogue-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"a non-admin without an ACL must still get 404 on a private collection — admin bypass is for admins only")
	})

	t.Run("owner-sees-own-private-collection-in-listing", func(t *testing.T) {
		// Pins the fix for the demo bug where, after an ownership
		// transfer, the new owner's "my collections" page came up
		// empty. The cause was that ListCollections only returned
		// public-or-ACL'd rows; owner-by-ID was never queried, so the
		// only thing tying a private collection to its owner —
		// the OwnerID column — was invisible to the listing layer.
		//
		// (Per the ownership-model rewrite, CreateCollection no
		// longer auto-mints a `user-<owner>` AclRoleOwner row, so
		// the legacy "owner shows up because of their auto-ACL"
		// shortcut is gone too.)
		createReq := CreateCollectionReq{
			Name:       "owner-listing-probe",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		ownerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "owner-listing-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code,
			"setup: owner must be able to create the probe (body: %s)", recorder.Body.String())
		var createResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&createResp))
		probeID := createResp["id"]
		require.NotEmpty(t, probeID)

		// The owner lists collections — the probe MUST appear.
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code,
			"owner list call must succeed (body: %s)", recorder.Body.String())
		var listResp []map[string]interface{}
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&listResp))
		seenIDs := make([]string, 0, len(listResp))
		for _, c := range listResp {
			if id, ok := c["id"].(string); ok {
				seenIDs = append(seenIDs, id)
			}
		}
		assert.Contains(t, seenIDs, probeID,
			"owner must see their own private collection in the listing — without this, post-transfer users get an empty 'my collections' page")

		// Negative control: a different non-admin, non-ACL user
		// must not see the probe just because the listing also
		// looks at owner_id.
		stranger := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "owner-listing-stranger")
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: stranger})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code)
		var strangerList []map[string]interface{}
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&strangerList))
		for _, c := range strangerList {
			if id, _ := c["id"].(string); id == probeID {
				t.Errorf("a non-owner, non-ACL stranger must NOT see %q in their listing", probeID)
			}
		}
	})

	t.Run("admin-group-member-sees-collection-in-listing", func(t *testing.T) {
		// Members of a collection's admin group have full management
		// authority on the row; the listing has to include it for
		// them to actually exercise that authority. Mirrors the
		// management-side admin-group bypass in
		// CallerIsCollectionOwnerOrAdmin.
		//
		// We exercise both membership-discovery paths: the GroupMember
		// row (DB-driven) and the cookie-asserted groups slice
		// (IdP-driven). One subtest each would be ideal but the
		// existing test scaffolding gives us a single router; we
		// cover the GroupMember path here and the cookie path
		// implicitly via the existing test-collection-acls suite.

		// Step 1: create a group.
		groupName := "ag-listing-group"
		gReq := map[string]string{"name": groupName, "description": "admin-group listing probe"}
		body, _ := json.Marshal(gReq)
		req, _ := http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		adminTok := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: adminTok})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, "group create: %s", recorder.Body.String())
		var grpResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&grpResp))
		groupID := grpResp["id"]
		require.NotEmpty(t, groupID)

		// Step 2: insert a GroupMember row directly. Going through
		// the API would require a second token + the membership flow;
		// the listing-visibility behavior we want to pin is
		// independent of how the membership got there.
		require.NoError(t, database.ServerDatabase.Create(&database.GroupMember{
			GroupID: groupID,
			UserID:  "ag-member-user",
		}).Error)

		// Step 3: the collection-owner creates a private collection
		// and sets that group as the AdminID.
		colReq := CreateCollectionReq{
			Name:       "ag-listing-probe",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, _ = json.Marshal(colReq)
		req, _ = http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		ownerTok := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "ag-owner-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerTok})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, "create collection: %s", recorder.Body.String())
		var colResp map[string]string
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&colResp))
		colID := colResp["id"]
		require.NotEmpty(t, colID)

		// Set the admin group on the collection.
		patchReq := UpdateCollectionReq{AdminID: &groupID}
		body, _ = json.Marshal(patchReq)
		req, _ = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+colID, bytes.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerTok})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, "set adminId: %s", recorder.Body.String())

		// Step 4: the GroupMember user lists collections. The probe
		// MUST appear — they're an admin-group member, even though
		// they have no read ACL row and the collection is private.
		memberTok := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "ag-member-user")
		req, _ = http.NewRequest("GET", "/api/v1.0/origin_ui/collections", nil)
		req.AddCookie(&http.Cookie{Name: "login", Value: memberTok})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusOK, recorder.Code)
		var memberList []map[string]interface{}
		require.NoError(t, json.NewDecoder(recorder.Body).Decode(&memberList))
		seenIDs := make([]string, 0, len(memberList))
		for _, c := range memberList {
			if id, ok := c["id"].(string); ok {
				seenIDs = append(seenIDs, id)
			}
		}
		assert.Contains(t, seenIDs, colID,
			"admin-group member must see the collection in their listing")
	})

	t.Run("create-collection-with-invalid-visibility", func(t *testing.T) {
		createReq := CreateCollectionReq{
			Name:        "test-invalid-visibility",
			Description: "test",
			Namespace:   "/test1",
			Visibility:  "invalid",
			Metadata:    map[string]string{"key": "value"},
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)

		token := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user")

		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
	})

	t.Run("create-collection-with-unconfigured-namespace", func(t *testing.T) {
		createReq := CreateCollectionReq{
			Name:        "test-unconfigured-namespace",
			Description: "test",
			Namespace:   "/unconfigured",
			Visibility:  "public",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		token := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
	})

	// The following block of subtests pins the contract that
	// collections are NOT limited to the top-level federation
	// prefix of an export — they may live anywhere within an
	// exported namespace tree. Per ticket #3298 ("the faculty member
	// will get a new collection or namespace prefix that is
	// associated with a group owned by the faculty"), operators want
	// a single export of, say, /test1 to host a fleet of collections
	// at /test1/projectA, /test1/projectB/2026, etc., without having
	// to declare each as its own export. The standalone helper has
	// dense unit coverage in collections_namespace_test.go; these
	// tests exercise the same boundary through the live HTTP handler.

	// makeCreateRequest is a tiny helper so each sub-namespace case
	// stays focused on the assertion (status code) rather than on
	// JSON+HTTP boilerplate.
	makeCreateRequest := func(t *testing.T, name, namespace string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(CreateCollectionReq{
			Name:        name,
			Description: "subset-namespace test",
			Namespace:   namespace,
			Visibility:  "public",
		})
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		token := generateToken(t, []token_scopes.TokenScope{
			token_scopes.WebUi_Access,
			token_scopes.Collection_Create,
		}, "test-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		return recorder
	}

	t.Run("create-collection-at-immediate-sub-namespace", func(t *testing.T) {
		// /test1 is exported; /test1/projectA is one path-segment
		// deep — the most common "I want a collection inside a
		// shared export" shape.
		r := makeCreateRequest(t, "test-sub-immediate", "/test1/projectA")
		assert.Equal(t, http.StatusCreated, r.Code,
			"a collection rooted one segment below an exported prefix must be accepted (body: %s)", r.Body.String())

		// Round-trip the namespace to confirm the row stored the
		// requested sub-path verbatim, not a normalized version.
		var resp map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&resp))
		require.NotEmpty(t, resp["id"])
		col, err := database.GetCollection(database.ServerDatabase, resp["id"], "test-user", "", nil, false)
		require.NoError(t, err)
		assert.Equal(t, "/test1/projectA", col.Namespace)
	})

	t.Run("create-collection-at-deep-sub-namespace", func(t *testing.T) {
		// Operators may want a deeper tree (per-team, per-year, ...)
		// inside a single export. There is no depth limit by design.
		r := makeCreateRequest(t, "test-sub-deep", "/test1/team/2026/data")
		assert.Equal(t, http.StatusCreated, r.Code,
			"deeper sub-paths under an export must be accepted (body: %s)", r.Body.String())
	})

	t.Run("create-collections-at-sibling-sub-namespaces", func(t *testing.T) {
		// Two collections at distinct sub-paths of the same export
		// must both succeed — there's nothing about the first one
		// that forecloses the second.
		r1 := makeCreateRequest(t, "test-sub-sibling-A", "/test1/siblingA")
		assert.Equal(t, http.StatusCreated, r1.Code,
			"first sibling collection should be accepted (body: %s)", r1.Body.String())
		r2 := makeCreateRequest(t, "test-sub-sibling-B", "/test1/siblingB")
		assert.Equal(t, http.StatusCreated, r2.Code,
			"second sibling collection at a different sub-path of the same export must also be accepted (body: %s)", r2.Body.String())
	})

	t.Run("create-collection-under-second-export", func(t *testing.T) {
		// The fixture ships two exports (/test1 and /test2). Each
		// gets its own sub-namespace acceptance independently.
		r := makeCreateRequest(t, "test-second-export-sub", "/test2/run3")
		assert.Equal(t, http.StatusCreated, r.Code,
			"a sub-path of the second export must be accepted regardless of state under the first (body: %s)", r.Body.String())
	})

	t.Run("create-collection-rejected-when-prefix-is-just-a-string-prefix", func(t *testing.T) {
		// `/test1xxx` shares a string prefix with `/test1` but is
		// NOT a path-descendant of it (no `/` separator after the
		// matched portion). Acceptance here would let an operator
		// trivially escape the boundary of an exported namespace.
		r := makeCreateRequest(t, "test-prefix-lookalike", "/test1xxx")
		assert.Equal(t, http.StatusBadRequest, r.Code,
			"a non-descendant lookalike must be rejected even though it shares a string prefix (body: %s)", r.Body.String())
	})

	t.Run("create-collection-rejected-when-namespace-is-relative", func(t *testing.T) {
		// The ACL layer expects absolute paths; defensively reject
		// at the create boundary so we don't store a row that would
		// fail every subsequent member-URL check.
		r := makeCreateRequest(t, "test-relative-namespace", "test1/projectA")
		assert.Equal(t, http.StatusBadRequest, r.Code,
			"a relative namespace (no leading /) must be rejected (body: %s)", r.Body.String())
	})

	t.Run("create-collection-without-permission", func(t *testing.T) {
		createReq := CreateCollectionReq{
			Name:        "test-no-perms",
			Description: "test",
			Namespace:   "/test1",
			Visibility:  "public",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		token := generateToken(t, []token_scopes.TokenScope{token_scopes.Monitoring_Query}, "test-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
	})

	t.Run("test-collection-lifecycle", func(t *testing.T) {
		// 1. Create a collection
		createReq := CreateCollectionReq{
			Name:        "test-lifecycle",
			Description: "test lifecycle",
			Namespace:   "/test1",
			Visibility:  "public",
		}
		body, err := json.Marshal(createReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)

		token := generateToken(t, []token_scopes.TokenScope{
			token_scopes.WebUi_Access,
			token_scopes.Collection_Create,
			token_scopes.Collection_Read,
			token_scopes.Collection_Modify,
			token_scopes.Collection_Delete},
			"test-user",
		)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
		var createResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createResp)
		require.NoError(t, err)
		collectionID := createResp["id"]
		require.NotEmpty(t, collectionID)

		// 2. List collections and verify the new one is there
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))

		var listResp []ListCollectionRes
		err = json.NewDecoder(recorder.Body).Decode(&listResp)
		require.NoError(t, err)
		found := false
		for _, col := range listResp {
			if col.ID == collectionID {
				found = true
				assert.Equal(t, "test-lifecycle", col.Name)
				break
			}
		}
		assert.True(t, found, "collection was not found in list")

		// 3. Get the specific collection
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
		var getResp GetCollectionRes
		err = json.NewDecoder(recorder.Body).Decode(&getResp)
		require.NoError(t, err)
		assert.Equal(t, "test-lifecycle", getResp.Name)
		assert.Equal(t, "test lifecycle", getResp.Description)

		// 4. Update the collection
		updatedDesc := "updated description"
		updateReq := UpdateCollectionReq{
			Description: &updatedDesc,
		}
		body, err = json.Marshal(updateReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+collectionID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on PATCH, body: %s", recorder.Code, recorder.Body.String()))

		// Verify the update
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
		var updatedResp GetCollectionRes
		err = json.NewDecoder(recorder.Body).Decode(&updatedResp)
		require.NoError(t, err)
		assert.Equal(t, "updated description", updatedResp.Description)

		// 5. Delete the collection
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))

		// 6. Verify the collection is gone
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))
	})

	t.Run("test-collection-acls", func(t *testing.T) {
		// 1. Create a group
		groupName := "test-group"
		createGroupReq := map[string]string{"name": groupName, "description": "test group"}
		body, err := json.Marshal(createGroupReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)

		adminToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin-user")
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
		var createGroupResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createGroupResp)
		require.NoError(t, err)
		groupID := createGroupResp["id"]
		require.NotEmpty(t, groupID)

		// 2. Create a private collection
		createColReq := CreateCollectionReq{
			Name:       "test-private-collection",
			Namespace:  "/test1",
			Visibility: "private",
		}
		body, err = json.Marshal(createColReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections", bytes.NewReader(body))
		require.NoError(t, err)
		createToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create, token_scopes.Collection_Delete}, "test-user-owner", groupName)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))
		var createColResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createColResp)
		require.NoError(t, err)
		collectionID := createColResp["id"]
		require.NotEmpty(t, collectionID)

		// 3. Grant the group read access to the collection
		grantAclReq := map[string]string{"group_id": groupID, "role": "read"}
		body, err = json.Marshal(grantAclReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections/"+collectionID+"/acl", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // The owner grants the ACL
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		// 4. A user not in the group cannot read the collection
		rogueToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read}, "rogue-user", "some-other-group")
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))

		// 5. A user in the group can read the collection
		groupToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read}, "group-user", groupName)
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code, fmt.Sprintf("unexpected status %d on GET, body: %s", recorder.Code, recorder.Body.String()))

		// 6. Grant the group write access to the collection
		grantAclReq = map[string]string{"group_id": groupID, "role": "write"}
		body, err = json.Marshal(grantAclReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections/"+collectionID+"/acl", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // The owner grants the ACL
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		// 7. A user not in the group cannot update the collection
		updatedDesc := "rogue update"
		updateReq := UpdateCollectionReq{Description: &updatedDesc}
		body, err = json.Marshal(updateReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+collectionID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code, fmt.Sprintf("unexpected status %d on PATCH, body: %s", recorder.Code, recorder.Body.String()))

		// 8. A user in the group (with the modify role) can update the collection
		updatedDesc = "group update"
		updateReq = UpdateCollectionReq{Description: &updatedDesc}
		body, err = json.Marshal(updateReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+collectionID, bytes.NewReader(body))
		require.NoError(t, err)
		groupWriteToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify}, "group-user-write", groupName)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupWriteToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on PATCH, body: %s", recorder.Code, recorder.Body.String()))

		// 9. Make the group the collection's admin group. With the
		//    ownership-model rewrite, the AclRoleOwner ACL is gone;
		//    "this group has day-to-day management authority" is now
		//    expressed by setting Collection.AdminID. Members of the
		//    admin group can manage members and ACLs and edit the
		//    collection — but transferring ownership and deleting are
		//    owner-exclusive (see steps 11/12 below).
		patchReq := UpdateCollectionReq{AdminID: &groupID}
		body, err = json.Marshal(patchReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+collectionID, bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // The owner sets adminId
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on PATCH adminId, body: %s", recorder.Code, recorder.Body.String()))

		// 10. A user not in the group cannot delete the collection
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))

		// 11. An admin-group member CANNOT delete the collection.
		//     Deletion is owner-exclusive — admin-group members
		//     stop short of "destroy the collection out from under
		//     the rightful owner" (the security report that
		//     produced this gate). They get the same 404 a non-
		//     member would.
		groupOwnerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Delete}, "group-user-owner", groupName)
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupOwnerToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code,
			"admin-group members must NOT be able to delete the collection (body: %s)",
			recorder.Body.String())

		// 12. The actual owner CAN delete the collection.
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // owner
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code,
			"the owner must be able to delete their collection (body: %s)",
			recorder.Body.String())
	})
}
