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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

// passwordInviteCreateReq is the body for POST /users/:id/password-invite.
// Optional ExpiresIn lets the admin shorten the default lifetime; the
// default tracks Server.GroupInviteLinkExpiration so the operator only
// needs to configure one timeout.
type passwordInviteCreateReq struct {
	ExpiresIn string `json:"expiresIn"`
}

// handleCreatePasswordInvite mints a single-use password-set link for a
// user and returns its plaintext token (shown exactly once). The admin
// passes the resulting link to the user out-of-band; the user clicks it
// and sets their own password, which the admin never sees.
//
// Authorization: route is admin-walled (see /users/* in ui.go), so the
// handler doesn't repeat the check. We also accept user-administrators
// here so a user-admin can onboard non-privileged accounts without going
// through a system admin.
func handleCreatePasswordInvite(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id is required",
		})
		return
	}
	caller, callerID, callerGroups, err := GetUserGroups(ctx)
	if err != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	identity := UserIdentity{
		Username: caller,
		ID:       callerID,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := CheckAdmin(identity)
	isUserAdmin, _ := CheckUserAdmin(identity)
	if !isAdmin && !isUserAdmin {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to create password invites",
		})
		return
	}
	// User admins must not be able to mint setup links for system admins —
	// otherwise a user admin could effectively claim a system admin
	// account. Only system admins may do that.
	if !isAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot mint password invites for system admin accounts",
		})
		return
	}

	var req passwordInviteCreateReq
	// Empty body is fine — defaults apply.
	_ = ctx.ShouldBindJSON(&req)

	expDuration := param.Server_GroupInviteLinkExpiration.GetDuration()
	if expDuration <= 0 {
		expDuration = 168 * time.Hour
	}
	if req.ExpiresIn != "" {
		parsed, perr := time.ParseDuration(req.ExpiresIn)
		if perr != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("invalid expiresIn duration: %v", perr),
			})
			return
		}
		expDuration = parsed
	}
	expiresAt := time.Now().Add(expDuration)

	authMethod, authMethodID := captureAuthMethod(ctx)
	link, plainToken, err := database.CreatePasswordInviteLink(
		database.ServerDatabase, id, callerID, expiresAt, authMethod, authMethodID,
	)
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
			Msg:    fmt.Sprintf("Failed to create password invite: %v", err),
		})
		return
	}
	type response struct {
		database.GroupInviteLink
		InviteToken string `json:"inviteToken"`
	}
	ctx.JSON(http.StatusCreated, response{
		GroupInviteLink: *link,
		InviteToken:     plainToken,
	})
}

// handleListPasswordInvites returns every password invite (live or
// historical, including redeemed/revoked) targeting a given user. Used by
// the admin UI to surface "this user already has 2 outstanding setup
// links" so admins don't keep minting new ones uncontrolled.
func handleListPasswordInvites(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id is required",
		})
		return
	}
	links, err := database.ListPasswordInvitesForUser(database.ServerDatabase, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list password invites: %v", err),
		})
		return
	}
	ctx.JSON(http.StatusOK, links)
}

// inviteInfoResp is the safe-for-public projection of an invite link:
// just enough for the redemption UI to render the right form.
//
// For group invites we surface the group's *name* and *display name* in
// addition to its opaque ID so the confirm-join page can tell the user
// which group they are about to join. Without this, the UI can only say
// "the group attached to this invite" — which is dangerously vague when
// the same user might hold links to several groups in flight at once.
// The token-bearer already proved possession of the token, so the group
// identity is no more sensitive than its existence.
type inviteInfoResp struct {
	Kind             database.InviteKind `json:"kind"`
	ExpiresAt        time.Time           `json:"expiresAt"`
	IsSingleUse      bool                `json:"isSingleUse"`
	GroupID          string              `json:"groupId,omitempty"`
	GroupName        string              `json:"groupName,omitempty"`
	GroupDisplayName string              `json:"groupDisplayName,omitempty"`
	// CollectionID + CollectionName + CollectionNamespace are
	// populated when Kind == InviteKindCollectionOwnership. The
	// namespace (path prefix) is the load-bearing detail —
	// "accept ownership of gamma" doesn't tell the redeemer
	// whether they're claiming /research/dataset-A or /test/foo;
	// always render the namespace alongside the friendly name on
	// the confirm page.
	CollectionID        string `json:"collectionId,omitempty"`
	CollectionName      string `json:"collectionName,omitempty"`
	CollectionNamespace string `json:"collectionNamespace,omitempty"`
}

// handleGetInviteInfo lets the redemption UI peek at a token *without*
// consuming it: it returns the kind and expiration so the page can
// render a password form (for password invites) or a join-this-group
// confirmation (for group invites). Token in query string.
//
// Authentication is intentionally absent — possession of the token is
// the only credential, the same as the redeem endpoints. We deliberately
// do NOT leak the creator or target user here. The group's name and
// display name ARE included for group-kind invites — without them the
// confirm-join UI can only say "some group" and the user has no way to
// tell which group the invite refers to before clicking Accept.
func handleGetInviteInfo(ctx *gin.Context) {
	tok := ctx.Query("token")
	if tok == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "token query parameter is required",
		})
		return
	}
	link, err := database.LookupInviteLinkByToken(database.ServerDatabase, tok)
	if err != nil {
		// Always 404 — don't distinguish "expired" from "wrong token";
		// the difference would let an attacker probe for valid tokens.
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "invite not found",
		})
		return
	}
	resp := inviteInfoResp{
		Kind:        link.Kind,
		ExpiresAt:   link.ExpiresAt,
		IsSingleUse: link.IsSingleUse,
		GroupID:     link.GroupID,
	}
	if link.Kind == database.InviteKindGroup && link.GroupID != "" {
		// Resolve the group's labels. Errors are non-fatal: the redeem
		// page can still render with the bare ID, just less helpfully.
		if cards, lookupErr := database.GetGroupCards(database.ServerDatabase, []string{link.GroupID}); lookupErr == nil {
			if c, ok := cards[link.GroupID]; ok {
				resp.GroupName = c.Name
			}
		}
		if grp, lookupErr := database.GetGroupWithMembers(database.ServerDatabase, link.GroupID); lookupErr == nil {
			resp.GroupDisplayName = grp.DisplayName
		}
	}
	if link.Kind == database.InviteKindCollectionOwnership && link.CollectionID != "" {
		// Resolve the collection's name + namespace so the confirm
		// page can say "Accept ownership of <name> (<namespace>)?".
		// Errors are non-fatal — the page still renders with the
		// bare ID.
		var coll database.Collection
		if err := database.ServerDatabase.Select("id", "name", "namespace").Where("id = ?", link.CollectionID).First(&coll).Error; err == nil {
			resp.CollectionID = coll.ID
			resp.CollectionName = coll.Name
			resp.CollectionNamespace = coll.Namespace
		}
	}
	ctx.JSON(http.StatusOK, resp)
}

// passwordRedeemReq is the body for POST /invites/redeem/password.
type passwordRedeemReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// handleRedeemPasswordInvite consumes a password-set token and applies the
// supplied password to the link's target user. There is no auth on this
// endpoint by design — the token is the credential. We *do* require some
// minimum password length so the user doesn't end up with a one-character
// password through this flow.
func handleRedeemPasswordInvite(ctx *gin.Context) {
	var req passwordRedeemReq
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "token and password are required",
		})
		return
	}
	if len(req.Password) < 8 {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "password must be at least 8 characters",
		})
		return
	}
	if _, err := database.RedeemPasswordInviteLink(database.ServerDatabase, req.Token, req.Password); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invite not found, expired, or already used",
			})
			return
		}
		log.Warningf("Password invite redemption failed: %v", err)
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}
	ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
		Status: server_structs.RespOK,
		Msg:    "Password set; you may now log in with your new password",
	})
}

// handleClearUserPassword wipes a user's local password hash, disabling
// password login for that account without ever revealing the password.
// Useful for admins responding to compromise: lock the account out of
// password-based login while leaving any linked OIDC identities intact.
//
// This endpoint does NOT *set* a password — that intentionally has no
// admin-side equivalent. To re-enable password login, mint a
// password-set invite (POST /users/{id}/password-invite) and let the
// user pick a new one.
//
// Authorization mirrors handleCreatePasswordInvite: system admins or
// user admins; user admins cannot clear a system admin's password.
func handleClearUserPassword(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id is required",
		})
		return
	}
	caller, callerID, callerGroups, err := GetUserGroups(ctx)
	if err != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	identity := UserIdentity{
		Username: caller,
		ID:       callerID,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := CheckAdmin(identity)
	isUserAdmin, _ := CheckUserAdmin(identity)
	if !isAdmin && !isUserAdmin {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to clear passwords",
		})
		return
	}
	if !isAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot clear a system admin's password",
		})
		return
	}

	if err := database.SetUserPassword(database.ServerDatabase, id, ""); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
			return
		}
		log.Warningf("Failed to clear password for user %s: %v", id, err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to clear password: %v", err),
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}
