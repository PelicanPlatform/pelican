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
		col, err := database.GetCollection(database.ServerDatabase, resp["id"], "test-user", nil)
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

		// 9. Grant owner access to the group
		grantAclReq = map[string]string{"group_id": groupID, "role": "owner"}
		body, err = json.Marshal(grantAclReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections/"+collectionID+"/acl", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // The owner grants the ACL
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on POST, body: %s", recorder.Code, recorder.Body.String()))

		// 10. A user not in the group cannot delete the collection
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))

		// 11. A user in the group can delete the collection
		groupOwnerToken := generateToken(t, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Delete}, "group-user-owner", groupName)
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupOwnerToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code, fmt.Sprintf("unexpected status %d on DELETE, body: %s", recorder.Code, recorder.Body.String()))
	})
}
