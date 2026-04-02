package web_ui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
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

type UpdateGroupReq struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type UpdateGroupOwnershipReq struct {
	OwnerID   *string              `json:"ownerId"`
	AdminID   *string              `json:"adminId"`
	AdminType *database.AdminType  `json:"adminType"`
}

type CreateInviteLinkReq struct {
	IsSingleUse bool   `json:"isSingleUse"`
	ExpiresIn   string `json:"expiresIn"` // Duration string, e.g. "168h", "7d"
}

type RedeemInviteLinkReq struct {
	Token string `json:"token"`
}

type UpdateUserStatusReq struct {
	Status      *database.UserStatus `json:"status"`
	DisplayName *string              `json:"displayName"`
}

type RecordAUPAgreementReq struct {
	Version string `json:"version"`
}

type AddUserIdentityReq struct {
	Sub    string `json:"sub"`
	Issuer string `json:"issuer"`
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

func handleGetGroup(ctx *gin.Context) {
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
				Msg:    fmt.Sprintf("Failed to get group: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, group)
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

func handleUpdateGroup(ctx *gin.Context) {
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

	var req UpdateGroupReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify group updater",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	if err := database.UpdateGroup(database.ServerDatabase, id, req.Name, req.Description, userId, isAdmin); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to update this group",
			})
		} else if errors.Is(err, database.ErrReservedGroupPrefix) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Group name cannot start with 'user-'",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update group: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
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

func handleGetUser(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	user, err := database.GetUserByID(database.ServerDatabase, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get user: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, user)
}

type UpdateUserReq struct {
	Username *string `json:"username"`
	Sub      *string `json:"sub"`
	Issuer   *string `json:"issuer"`
}

func handleUpdateUser(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	var req UpdateUserReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	// Get the requestor's identity for authorization
	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user updater",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	// Verify authorization: only the user themselves or an admin can update
	if !isAdmin && userId != id {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to update this user",
		})
		return
	}

	// Ensure the user exists so we can return 404 for unknown IDs.
	if _, err := database.GetUserByID(database.ServerDatabase, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update user: %v", err),
			})
		}
		return
	}

	if err := database.UpdateUser(database.ServerDatabase, id, req.Username, req.Sub, req.Issuer); err != nil {
		// Map uniqueness and validation-type errors to 400, others to 500.
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "user shares either username or (sub and iss) with another") {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    msg,
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update user: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleDeleteGroup(ctx *gin.Context) {
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

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify group deleter",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	if err := database.DeleteGroup(database.ServerDatabase, id, userId, isAdmin); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to delete this group",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to delete group: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleDeleteUser(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user deleter",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	if err := database.DeleteUser(database.ServerDatabase, id, userId, isAdmin); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to delete this user",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to delete user: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// --- Group Ownership Handlers ---

func handleUpdateGroupOwnership(ctx *gin.Context) {
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

	var req UpdateGroupOwnershipReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	if err := database.UpdateGroupOwnership(database.ServerDatabase, id, req.OwnerID, req.AdminID, req.AdminType, userId, isAdmin); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "only the group owner can change ownership settings",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update group ownership: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// --- Group Invite Link Handlers ---

func handleCreateGroupInviteLink(ctx *gin.Context) {
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

	groupID := ctx.Param("id")
	if groupID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}

	var req CreateInviteLinkReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	// Default expiration from config (duration string)
	var expDuration time.Duration
	if req.ExpiresIn != "" {
		parsed, parseErr := time.ParseDuration(req.ExpiresIn)
		if parseErr != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid expiresIn duration format (e.g. '168h', '24h')",
			})
			return
		}
		expDuration = parsed
	} else {
		expDuration = param.Server_GroupInviteLinkExpiration.GetDuration()
		if expDuration <= 0 {
			expDuration = 168 * time.Hour // 7 days
		}
	}
	expiresAt := time.Now().Add(expDuration)

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	link, plainToken, err := database.CreateGroupInviteLink(database.ServerDatabase, groupID, userId, expiresAt, req.IsSingleUse, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to create invite links for this group",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to create invite link: %v", err),
			})
		}
		return
	}

	// Return the link metadata along with the plaintext token (shown only once)
	type InviteLinkResponse struct {
		database.GroupInviteLink
		InviteToken string `json:"inviteToken"`
	}
	ctx.JSON(http.StatusCreated, InviteLinkResponse{
		GroupInviteLink: *link,
		InviteToken:     plainToken,
	})
}

func handleListGroupInviteLinks(ctx *gin.Context) {
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

	groupID := ctx.Param("id")
	if groupID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}

	links, err := database.ListGroupInviteLinks(database.ServerDatabase, groupID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list invite links: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, links)
}

func handleRevokeGroupInviteLink(ctx *gin.Context) {
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

	linkID := ctx.Param("linkId")
	if linkID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "invite link id is required",
		})
		return
	}

	user, userId, groups, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	})

	if err := database.RevokeGroupInviteLink(database.ServerDatabase, linkID, userId, isAdmin); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invite link not found",
			})
		} else if errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you do not have permission to revoke this invite link",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to revoke invite link: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRedeemGroupInviteLink(ctx *gin.Context) {
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

	var req RedeemInviteLinkReq
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "invite token is required",
		})
		return
	}

	_, userId, _, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}

	if err := database.RedeemGroupInviteLink(database.ServerDatabase, req.Token, userId); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invite link not found",
			})
		} else {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Successfully joined the group",
	})
}

// --- User Status / AUP Handlers ---

func handleUpdateUserStatus(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	var req UpdateUserStatusReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	if req.Status != nil {
		if err := database.UpdateUserStatus(database.ServerDatabase, id, *req.Status); err != nil {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update user status: %v", err),
			})
			return
		}
	}

	if req.DisplayName != nil {
		if err := database.UpdateUserDisplayName(database.ServerDatabase, id, *req.DisplayName); err != nil {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update display name: %v", err),
			})
			return
		}
	}

	ctx.Status(http.StatusNoContent)
}

func handleRecordAUPAgreement(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	var req RecordAUPAgreementReq
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Version == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "AUP version is required",
		})
		return
	}

	if err := database.RecordAUPAgreement(database.ServerDatabase, id, req.Version); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to record AUP agreement: %v", err),
		})
		return
	}

	ctx.Status(http.StatusNoContent)
}

// --- User Identity Handlers ---

func handleListUserIdentities(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	identities, err := database.ListUserIdentities(database.ServerDatabase, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list identities: %v", err),
		})
		return
	}

	ctx.JSON(http.StatusOK, identities)
}

func handleAddUserIdentity(ctx *gin.Context) {
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
			Msg:    "user id is required",
		})
		return
	}

	var req AddUserIdentityReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	if req.Sub == "" || req.Issuer == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "sub and issuer are required",
		})
		return
	}

	identity, err := database.CreateUserIdentity(database.ServerDatabase, id, req.Sub, req.Issuer)
	if err != nil {
		if strings.Contains(err.Error(), "already associated") {
			ctx.JSON(http.StatusConflict, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to add identity: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusCreated, identity)
}

func handleDeleteUserIdentity(ctx *gin.Context) {
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

	userID := ctx.Param("id")
	identityID := ctx.Param("identityId")
	if userID == "" || identityID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id and identity id are required",
		})
		return
	}

	if err := database.DeleteUserIdentity(database.ServerDatabase, identityID, userID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to delete identity: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// handleCreateUserOnboardingInvite creates an invite link for onboarding users
// without adding them to a specific group. Only user admins or system admins can use this.
func handleCreateUserOnboardingInvite(ctx *gin.Context) {
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

	user, userId, groups, verifyErr := GetUserGroups(ctx)
	if verifyErr != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}

	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isUserAdmin, msg := CheckUserAdmin(identity)
	if !isUserAdmin {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    msg,
		})
		return
	}

	var req CreateInviteLinkReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}

	var expDuration time.Duration
	if req.ExpiresIn != "" {
		parsed, parseErr := time.ParseDuration(req.ExpiresIn)
		if parseErr != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid expiresIn duration format (e.g. '168h', '24h')",
			})
			return
		}
		expDuration = parsed
	} else {
		expDuration = param.Server_GroupInviteLinkExpiration.GetDuration()
		if expDuration <= 0 {
			expDuration = 168 * time.Hour
		}
	}
	expiresAt := time.Now().Add(expDuration)

	link, plainToken, createErr := database.CreateUserOnboardingInviteLink(database.ServerDatabase, userId, expiresAt, req.IsSingleUse)
	if createErr != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create invite link: %v", createErr),
		})
		return
	}

	type InviteLinkResponse struct {
		database.GroupInviteLink
		InviteToken string `json:"inviteToken"`
	}
	ctx.JSON(http.StatusCreated, InviteLinkResponse{
		GroupInviteLink: *link,
		InviteToken:     plainToken,
	})
}
