package web_ui

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type CreateGroupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type AddGroupMemberReq struct {
	UserID string `json:"userId"`
}

func handleListGroups(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	groups, err := database.ListGroups(database.ServerDatabase)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list groups",
		})
		return
	}

	ctx.JSON(http.StatusOK, groups)
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

	_, userId, _, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify group creator",
		})
		return
	}

	group, err := database.CreateGroup(database.ServerDatabase, req.Name, req.Description, userId, nil)
	if err != nil {
		if errors.Is(err, database.ErrReservedGroupPrefix) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Group name cannot start with 'user-'",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create group: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusCreated, group)
}

func handleListGroupMembers(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}
	group, err := database.GetGroupWithMembers(database.ServerDatabase, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get group members: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, group.Members)
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

	if req.UserID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user_id is required",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user adding member",
		})
		return
	}
	if userId == "" {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unable to determine user identity for group management",
		})
		return
	}

	// Check if user is admin (allows bypassing ownership check)
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := CheckAdmin(identity)

	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}
	err = database.AddGroupMember(database.ServerDatabase, id, req.UserID, userId, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to add members to this group",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to add group member: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

type AddUserReq struct {
	Username string `json:"username"`
	Sub      string `json:"sub"`
	Issuer   string `json:"issuer"`
}

func handleAddUser(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access}, // Or a new scope for user management
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req AddUserReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	if req.Username == "" || req.Sub == "" || req.Issuer == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Username, sub, and issuer are required",
		})
		return
	}

	user, err := database.CreateUser(database.ServerDatabase, req.Username, req.Sub, req.Issuer)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create user: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"id": user.ID})
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

	memberUserId := ctx.Param("userId")
	if memberUserId == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "userId path parameter is required",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user removing member",
		})
		return
	}
	if userId == "" {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unable to determine user identity for group management",
		})
		return
	}

	// Check if user is admin (allows bypassing ownership check)
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := CheckAdmin(identity)

	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}
	err = database.RemoveGroupMember(database.ServerDatabase, id, memberUserId, userId, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group or member not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to remove members from this group",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to remove group member: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleListUsers(ctx *gin.Context) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access},
	}
	status, ok, err := token.Verify(ctx, authOption)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	users, err := database.ListUsers(database.ServerDatabase)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list users",
		})
		return
	}

	ctx.JSON(http.StatusOK, users)
}
