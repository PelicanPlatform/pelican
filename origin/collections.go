package origin

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

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
}

type AddCollectionMembersReq struct {
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

	if req.Name == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "A name for the collection is required",
		})
		return
	}

	owner, _, err := web_ui.GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user from context: %v", err),
		})
	}
	if owner == "" {
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

	coll, err := database.CreateCollectionWithMetadata(database.ServerDatabase, req.Name, req.Description, owner, visibility, req.Metadata)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create collection: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    fmt.Sprintf("Collection created with ID %s", coll.ID),
	})
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

	err = database.AddCollectionMembers(database.ServerDatabase, ctx.Param("id"), req.Members, user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to add collection members: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Collection members added",
	})
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

	coll, err := database.GetCollection(database.ServerDatabase, ctx.Param("id"), user)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get collection: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, coll)
}
