package origin

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_utils"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

type CreateCollectionReq struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Visibility  string            `json:"visibility"`
	Metadata    map[string]string `json:"metadata"`
	Namespace   string            `json:"namespace"`
}

type UpdateCollectionReq struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Visibility  *string `json:"visibility"`
}

type MetadataValue struct {
	Value string `json:"value"`
}

type GrantAclReq struct {
	GroupID   string     `json:"group_id"`
	Role      string     `json:"role"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type RevokeAclReq struct {
	GroupID string `json:"group_id"`
	Role    string `json:"role"`
}

type AddCollectionMembersReq struct {
	Members []string `json:"members"`
}

type RemoveCollectionMembersReq struct {
	Members []string `json:"members"`
}

func handleCreateCollection(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Create},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req CreateCollectionReq
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	if req.Name == "" || req.Namespace == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "A name and namespace for the collection are required",
		})
		return
	}

	// Validate that the namespace is one that this origin exports
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		log.Errorf("Failed to get origin exports: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to validate namespace",
		})
		return
	}
	validNamespace := false
	for _, export := range exports {
		if export.FederationPrefix == req.Namespace {
			validNamespace = true
			break
		}
	}
	if !validNamespace {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Namespace '%s' is not a valid export for this origin", req.Namespace),
		})
		return
	}

	user, _, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	visibility := database.Visibility(strings.ToLower(req.Visibility))
	if visibility != database.VisibilityPublic && visibility != database.VisibilityPrivate {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "A collection's visibility must be either 'private' or 'public'",
		})
		return
	}

	coll, err := database.CreateCollectionWithMetadata(database.ServerDatabase, req.Name, req.Description, user, req.Namespace, visibility, req.Metadata)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create collection: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusCreated, coll)
}

func handleUpdateCollection(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req UpdateCollectionReq
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	var visibility database.Visibility
	if req.Visibility != nil {
		v := database.Visibility(strings.ToLower(*req.Visibility))
		if v != database.VisibilityPublic && v != database.VisibilityPrivate {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "A collection's visibility must be either 'private' or 'public'",
			})
			return
		}
		visibility = v
	}

	var visPtr *database.Visibility
	if req.Visibility != nil {
		visPtr = &visibility
	}

	err = database.UpdateCollection(database.ServerDatabase, ctx.Param("id"), user, groups, req.Name, req.Description, visPtr)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to update collection: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRemoveCollectionMembers(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req RemoveCollectionMembersReq
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.RemoveCollectionMembers(database.ServerDatabase, ctx.Param("id"), req.Members, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to remove collection members: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRemoveCollectionMember(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	encodedObjectURL := ctx.Param("encoded_object_url")
	objectURL, err := url.PathUnescape(encodedObjectURL)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid encoded object URL: %v", err),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.RemoveCollectionMembers(database.ServerDatabase, ctx.Param("id"), []string{objectURL}, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to remove collection member: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleAddCollectionMembers(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}

	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req AddCollectionMembersReq
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	// validate the members are valid pelican URLs
	for _, member := range req.Members {
		if _, err := pelican_url.Parse(member, []pelican_url.ParseOption{}, []pelican_url.DiscoveryOption{}); err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid member URL: %v", err),
			})
			return
		}
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.AddCollectionMembers(database.ServerDatabase, ctx.Param("id"), req.Members, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to add collection members: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleListCollectionMembers(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	sinceStr := ctx.Query("since")
	var since *time.Time
	if sinceStr != "" {
		t, err := time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid 'since' timestamp format. Use ISO8601",
			})
			return
		}
		since = &t
	}

	limitStr := ctx.Query("limit")
	limit := 100 // default
	if limitStr != "" {
		l, err := strconv.Atoi(limitStr)
		if err != nil || l <= 0 {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid 'limit' parameter. Must be a positive integer",
			})
			return
		}
		if l > 1000 {
			limit = 1000 // max
		} else {
			limit = l
		}
	}

	members, err := database.GetCollectionMembers(database.ServerDatabase, ctx.Param("id"), user, groups, since, limit)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list collection members: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, members)
}

func handleGetCollectionMetadata(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	metadata, err := database.GetCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get collection metadata: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, metadata)
}

func handlePutCollectionMetadata(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	key := ctx.Param("key")
	if key == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Metadata key is required",
		})
		return
	}

	var value string
	contentType := ctx.ContentType()
	if contentType == "application/json" {
		var mv MetadataValue
		if err := ctx.ShouldBindJSON(&mv); err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid JSON body: %v", err),
			})
			return
		}
		value = mv.Value
	} else {
		bodyBytes, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to read request body",
			})
			return
		}
		value = string(bodyBytes)
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.UpsertCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, groups, key, value)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to put collection metadata: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleDeleteCollectionMetadata(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	key := ctx.Param("key")
	if key == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Metadata key is required",
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.DeleteCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, groups, key)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to delete collection metadata: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleGetCollection(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	coll, err := database.GetCollection(database.ServerDatabase, ctx.Param("id"), user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get collection: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, coll)
}

func handleDeleteCollection(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Delete},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
		return
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.DeleteCollection(database.ServerDatabase, ctx.Param("id"), user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to delete collection: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleGetCollectionAcls(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Read},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	acls, err := database.GetCollectionAcls(database.ServerDatabase, ctx.Param("id"), user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get collection acls: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, acls)
}

func handleGrantCollectionAcl(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req GrantAclReq
	err = ctx.ShouldBindJSON(&req)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	if req.GroupID == "" || req.Role == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "GroupID and role are required",
		})
		return
	}

	role := database.AclRole(req.Role)
	if role != database.AclRoleRead && role != database.AclRoleWrite && role != database.AclRoleOwner {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid role. Must be one of 'read', 'write', or 'owner'",
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.GrantCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, groups, req.GroupID, role, req.ExpiresAt)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to grant collection acl: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRevokeCollectionAcl(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, token_scopes.Collection_Modify},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var principal, roleStr string

	if ctx.Request.Method == "DELETE" && ctx.Request.Header.Get("Content-Type") == "application/json" {
		var req RevokeAclReq
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid request body: %v", err),
			})
			return
		}
		principal = req.GroupID
		roleStr = req.Role
	} else {
		principal = ctx.Query("group_id")
		roleStr = ctx.Query("role")
	}

	if principal == "" || roleStr == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "GroupID and role are required",
		})
		return
	}

	role := database.AclRole(roleStr)
	if role != database.AclRoleRead && role != database.AclRoleWrite && role != database.AclRoleOwner {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid role. Must be one of 'read', 'write', or 'owner'",
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}

	err = database.RevokeCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, groups, principal, role)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to revoke collection acl: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

type CreateGroupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AddGroupMemberReq struct {
	Member string `json:"member"`
}

func handleCreateGroup(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access}, // Or a new scope for group management
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req CreateGroupReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	if req.Name == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Group name is required",
		})
		return
	}

	user, _, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify group creator",
		})
		return
	}

	group, err := database.CreateGroup(database.ServerDatabase, req.Name, req.Description, user, nil)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create group: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusCreated, group)
}

func handleAddGroupMember(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access}, // Or a new scope for group management
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req AddGroupMemberReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	if req.Member == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Group member is required",
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user adding member",
		})
		return
	}

	err = database.AddGroupMember(database.ServerDatabase, ctx.Param("id"), req.Member, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to add group member: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRemoveGroupMember(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access}, // Or a new scope for group management
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	member := ctx.Query("member")
	if member == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Group member is required",
		})
		return
	}

	user, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user removing member",
		})
		return
	}

	err = database.RemoveGroupMember(database.ServerDatabase, ctx.Param("id"), member, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to remove group member: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}
