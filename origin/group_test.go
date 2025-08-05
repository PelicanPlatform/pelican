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
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

func TestGroupManagementAPI(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	defer func() {
		if err := egrp.Wait(); err != nil {
			fmt.Println("Failure when shutting down service:", err)
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
	t.Run("test-group-lifecycle", func(t *testing.T) {
		// 1. Create a group as 'owner-user'
		groupName := "test-group-lifecycle"
		createGroupReq := map[string]string{"name": groupName, "description": "test group"}
		body, err := json.Marshal(createGroupReq)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "/api/v1.0/origin_ui/groups", bytes.NewReader(body))
		require.NoError(t, err)

		ownerToken, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "owner-user")
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusCreated, recorder.Code)

		var createGroupResp map[string]string
		err = json.NewDecoder(recorder.Body).Decode(&createGroupResp)
		require.NoError(t, err)
		groupID := createGroupResp["id"]
		require.NotEmpty(t, groupID)

		// 2. Add a member to the group as 'owner-user'
		addMemberReq := map[string]string{"member": "new-member"}
		body, err = json.Marshal(addMemberReq)
		require.NoError(t, err)

		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/groups/"+groupID+"/members", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})
		req.Header.Set("Content-Type", "application/json")

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code)

		// 3. Try to add a member as a different user ('other-user') - should fail
		otherToken, err := generateToken(ctx, []token_scopes.TokenScope{token_scopes.WebUi_Access}, "other-user")
		require.NoError(t, err)

		req, err = http.NewRequest("POST", "/api/v1.0/origin_ui/groups/"+groupID+"/members", bytes.NewReader(body))
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: otherToken})
		req.Header.Set("Content-Type", "application/json")

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code)

		// 4. Try to remove a member as 'other-user' - should fail
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/groups/"+groupID+"/members?member=new-member", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: otherToken})

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusForbidden, recorder.Code)

		// 5. Remove the member from the group as 'owner-user'
		req, err = http.NewRequest("DELETE", "/api/v1.0/origin_ui/groups/"+groupID+"/members?member=new-member", nil)
		require.NoError(t, err)
		req.AddCookie(&http.Cookie{Name: "login", Value: ownerToken})

		recorder = httptest.NewRecorder()
		router.ServeHTTP(recorder, req)
		assert.Equal(t, http.StatusNoContent, recorder.Code)
	})
}
