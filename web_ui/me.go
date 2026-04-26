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

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
)

// Handlers under /me/* are scoped to the *calling user* — they never accept a
// :id path parameter for a different user. The corresponding /users/:id and
// /groups/:id endpoints are admin-only; /me/* is the self-service surface so
// non-admins can manage their own account and group memberships.

// callerID resolves the requesting user's ID from the auth context, or aborts
// the request with a 401-style error and returns "" if no identity is set.
func callerID(ctx *gin.Context) string {
	id := ctx.GetString("UserId")
	if id == "" {
		// AuthHandler should have set this; if it isn't, something upstream
		// is misconfigured. 500 is more accurate than 401 here.
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unable to determine caller identity",
		})
		return ""
	}
	return id
}

// GET /me — return the calling user's own record.
func handleGetMe(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
		return
	}
	user, err := database.GetUserByID(database.ServerDatabase, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get user: %v", err),
		})
		return
	}
	ctx.JSON(http.StatusOK, user)
}

// UpdateMeReq is the body for PATCH /me. Only displayName is mutable
// self-service; username/sub/issuer changes go through admin endpoints.
type UpdateMeReq struct {
	DisplayName *string `json:"displayName"`
}

// PATCH /me — currently allows updating the calling user's display name.
func handleUpdateMe(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
		return
	}
	var req UpdateMeReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}
	if req.DisplayName == nil {
		// Nothing to change — succeed quietly.
		ctx.Status(http.StatusNoContent)
		return
	}
	if err := database.UpdateUserDisplayName(database.ServerDatabase, id, *req.DisplayName); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to update display name: %v", err),
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}

// POST /me/aup — record the calling user's agreement to the current AUP.
func handleRecordMyAUPAgreement(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
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

// GET /me/groups — list groups the calling user is a member of.
func handleListMyGroups(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
		return
	}
	groups, err := database.GetMemberGroups(database.ServerDatabase, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list groups: %v", err),
		})
		return
	}
	ctx.JSON(http.StatusOK, groups)
}

// DELETE /me/groups/:id — leave a group. The caller cannot leave a group
// they own; ownership must be transferred first.
func handleLeaveMyGroup(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
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
	if err := database.LeaveGroup(database.ServerDatabase, groupID, id); err != nil {
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "you are not a member of that group (or it does not exist)",
			})
		case errors.Is(err, database.ErrForbidden):
			ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "the group's owner cannot leave the group; transfer ownership first",
			})
		default:
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to leave group: %v", err),
			})
		}
		return
	}
	ctx.Status(http.StatusNoContent)
}

// GET /me/identities — list the calling user's *secondary* OIDC
// identities (rows in user_identities). The user's *primary* identity
// (the sub/issuer carried on the User row itself) is intentionally
// not in this list: callers can read it from GET /me. The split
// matches the contract that a user may unlink secondaries but not
// the primary.
func handleListMyIdentities(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
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

// DELETE /me/identities/:id — self-unlink a *secondary* identity. The
// caller's primary identity (on the User row) cannot be unlinked here;
// removing it would either lock the user out (local accounts) or break
// the OIDC linkage that the cookie was issued against. Admins handle
// primary changes.
//
// Authorization: the row must belong to the caller. We pass callerID
// to DeleteUserIdentity so it returns NotFound (rather than success)
// for an identity that exists but belongs to someone else — same
// observable behavior, no information leak.
func handleUnlinkMyIdentity(ctx *gin.Context) {
	caller := callerID(ctx)
	if caller == "" {
		return
	}
	identityID := ctx.Param("id")
	if identityID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "identity id is required",
		})
		return
	}
	if err := database.DeleteUserIdentity(database.ServerDatabase, identityID, caller); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "identity not found (or it isn't yours)",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to unlink identity: %v", err),
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}
