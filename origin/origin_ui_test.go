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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

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

func generateToken(ctx context.Context, scopes []token_scopes.TokenScope, subject string) (string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", err
	}
	tk := token.NewWLCGToken()
	tk.Issuer = fedInfo.DiscoveryEndpoint
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(fedInfo.DiscoveryEndpoint)
	tk.AddScopes(scopes...)
	tok, err := tk.CreateToken()
	if err != nil {
		return "", err
	}
	return tok, nil
}

func generateTokenWithGroups(ctx context.Context, scopes []token_scopes.TokenScope, subject string, groups []string) (string, error) {
	fedInfo, err := config.GetFederation(ctx)
	if err != nil {
		return "", err
	}
	tk := token.NewWLCGToken()
	tk.Issuer = fedInfo.DiscoveryEndpoint
	tk.Subject = subject
	tk.Lifetime = 5 * time.Minute
	tk.AddAudiences(fedInfo.DiscoveryEndpoint)
	tk.AddScopes(scopes...)
	tk.AddGroups(groups...)
	tok, err := tk.CreateToken()
	if err != nil {
		return "", err
	}
	return tok, nil
}

func TestCollectionsAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() {
		if err := egrp.Wait(); err != nil {
			t.Logf("Failure when shutting down service: %s", err)
			os.Exit(1)
		}
	}()
	defer cancel()

	//set a temporary password file:
	tempFile, err := os.CreateTemp("", "web-ui-passwd")
	if err != nil {
		fmt.Println("Failed to setup web-ui-passwd file")
		os.Exit(1)
	}
	tempPasswdFile = tempFile

	//Override viper default for testing
	viper.Set("Server.UIPasswordFile", tempPasswdFile.Name())

	//Make a testing issuer.jwk file to get a cookie
	tempJWKDir, err := os.MkdirTemp("", "tempDir")
	if err != nil {
		fmt.Println("Error making temp jwk dir")
		os.Exit(1)
	}
	//Override viper default for testing
	viper.Set(param.IssuerKeysDirectory.GetName(), filepath.Join(tempJWKDir, "issuer-keys"))

	// Ensure we load up the default configs.
	dirname, err := os.MkdirTemp("", "tmpDir")
	if err != nil {
		fmt.Println("Error making temp config dir")
		os.Exit(1)
	}
	viper.Set("ConfigDir", dirname)
	viper.Set("Server.UILoginRateLimit", 100)

	// Set up origin exports
	exportDir, err := os.MkdirTemp("", "test-export")
	require.NoError(t, err)
	//The defer call to remove the directory and its contents is commented out because it was causing a race condition with the file watcher.
	//defer os.RemoveAll(exportDir)
	err = os.WriteFile(filepath.Join(exportDir, "test-origin"), []byte("test"), 0644)
	require.NoError(t, err)

	viper.Set("Origin.StorageType", "posix")
	viper.Set("Origin.Exports", []map[string]interface{}{
		{
			"StoragePrefix":    exportDir,
			"FederationPrefix": "/test1",
			"SentinelLocation": "test-origin",
		},
		{
			"StoragePrefix":    "/test2",
			"FederationPrefix": "/test2",
		},
	})

	if err := config.InitServer(ctx, server_structs.OriginType); err != nil {
		fmt.Println("Failed to configure the test module")
		os.Exit(1)
	}

	//Get keys
	_, err = config.GetIssuerPublicJWKS()
	if err != nil {
		fmt.Println("Error issuing jwks")
		os.Exit(1)
	}
	router = gin.Default()

	//Configure Web API
	err = web_ui.ConfigureServerWebAPI(ctx, router, egrp)
	if err != nil {
		fmt.Println("Error configuring web UI")
		os.Exit(1)
	}
	err = RegisterOriginWebAPI(router)
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

		token, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create, token_scopes.Collection_Delete}, "test-user")
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusCreated, recorder.Code)

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
		assert.Equal(t, http.StatusNoContent, recorder.Code)
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

		token, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user")
		require.NoError(t, err)

		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
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
		token, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create}, "test-user")
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
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
		token, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.Monitoring_Query}, "test-user")
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code)
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

		token, err := generateToken(ctx, []token_scopes.TokenScope{
			token_scopes.WebUi_Access,
			token_scopes.Collection_Create,
			token_scopes.Collection_Read,
			token_scopes.Collection_Modify,
			token_scopes.Collection_Delete},
			"test-user",
		)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)
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
		assert.Equal(t, http.StatusOK, recorder.Code)

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
		assert.Equal(t, http.StatusOK, recorder.Code)
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
		assert.Equal(t, http.StatusNoContent, recorder.Code)

		// Verify the update
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code)
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
		assert.Equal(t, http.StatusNoContent, recorder.Code)

		// 6. Verify the collection is gone
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: token})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code)
	})

	t.Run("test-collection-acls", func(t *testing.T) {
		// 1. Create a group
		groupName := "test-group"
		createGroupReq := map[string]string{"name": groupName, "description": "test group"}
		body, err := json.Marshal(createGroupReq)
		require.NoError(t, err)
		req, err := http.NewRequest("POST", "/api/v1.0/groups", bytes.NewReader(body))
		require.NoError(t, err)

		adminToken, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "admin")
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: adminToken})
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)
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
		createToken, err := generateTokenWithGroups(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create, token_scopes.Collection_Delete}, "test-user-owner", []string{groupName})
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)
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
		require.Equal(t, http.StatusNoContent, recorder.Code)

		// 4. A user not in the group cannot read the collection
		rogueToken, err := generateTokenWithGroups(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read}, "rogue-user", []string{"some-other-group"})
		require.NoError(t, err)
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code)

		// 5. A user in the group can read the collection
		groupToken, err := generateTokenWithGroups(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read}, "group-user", []string{groupName})
		require.NoError(t, err)
		req, err = http.NewRequest("GET", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusOK, recorder.Code)

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
		require.Equal(t, http.StatusNoContent, recorder.Code)

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
		assert.Equal(t, http.StatusNotFound, recorder.Code)

		// 8. A user in the group can update the collection
		updatedDesc = "group update"
		updateReq = UpdateCollectionReq{Description: &updatedDesc}
		body, err = json.Marshal(updateReq)
		require.NoError(t, err)
		req, err = http.NewRequest("PATCH", "/api/v1.0/origin_ui/collections/"+collectionID, bytes.NewReader(body))
		require.NoError(t, err)
		groupWriteToken, err := generateTokenWithGroups(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify}, "group-user-write", []string{groupName})
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupWriteToken})
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code)

		// 9. Grant the group owner access to the collection
		grantAclReq = map[string]string{"group_id": groupID, "role": "owner"}
		body, err = json.Marshal(grantAclReq)
		require.NoError(t, err)
		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/collections/"+collectionID+"/acl", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: createToken}) // The owner grants the ACL
		req.Header.Set("Content-Type", "application/json")
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusNoContent, recorder.Code)

		// 10. A user not in the group cannot delete the collection
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: rogueToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNotFound, recorder.Code)

		// 11. A user in the group can delete the collection
		groupOwnerToken, err := generateTokenWithGroups(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Delete}, "group-user-owner", []string{groupName})
		require.NoError(t, err)
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/collections/"+collectionID, nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: groupOwnerToken})
		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code)
	})
}
