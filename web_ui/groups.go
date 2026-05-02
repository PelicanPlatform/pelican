package web_ui

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

type CreateGroupReq struct {
	// Name is the machine-readable group identifier. Goes into policy
	// strings, admin-group lists, and ACL grants. Validated by
	// ValidateIdentifier.
	Name string `json:"name"`
	// DisplayName is the human-friendly label rendered in the UI.
	// Optional; UIs typically fall back to Name when empty.
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description"`
	// CreatedForCollectionID ties the new group to a specific collection's
	// onboarding pass. Set by the collection-onboarding form so a later
	// ownership transfer of that collection cascades to its onboarded
	// groups; empty for standalone group creation.
	CreatedForCollectionID string `json:"createdForCollectionId,omitempty"`
}

// GroupView wraps a database.Group with resolved user/group summaries for
// owner, admin (when adminType=user), createdBy, and (when adminType=group)
// the admin group itself. The frontend renders these as
// "Display Name (username)" without needing follow-up lookups, and without
// requiring user-listing privileges.
type GroupView struct {
	database.Group
	OwnerUser     *database.UserCard  `json:"ownerUser,omitempty"`
	AdminUser     *database.UserCard  `json:"adminUser,omitempty"`
	AdminGroup    *database.GroupCard `json:"adminGroup,omitempty"`
	CreatedByUser *database.UserCard  `json:"createdByUser,omitempty"`
}

// enrichGroups resolves the user/group cards referenced by a slice of groups
// in two batched queries (one for users, one for admin groups), then folds
// the results back into a GroupView slice in the same order.
func enrichGroups(db *gorm.DB, groups []database.Group) ([]GroupView, error) {
	userIDSet := map[string]struct{}{}
	groupIDSet := map[string]struct{}{}
	for i := range groups {
		g := &groups[i]
		if g.OwnerID != "" {
			userIDSet[g.OwnerID] = struct{}{}
		}
		if g.CreatedBy != "" {
			userIDSet[g.CreatedBy] = struct{}{}
		}
		if g.AdminID != "" {
			switch g.AdminType {
			case database.AdminTypeUser:
				userIDSet[g.AdminID] = struct{}{}
			case database.AdminTypeGroup:
				groupIDSet[g.AdminID] = struct{}{}
			}
		}
	}
	userIDs := make([]string, 0, len(userIDSet))
	for id := range userIDSet {
		userIDs = append(userIDs, id)
	}
	groupIDs := make([]string, 0, len(groupIDSet))
	for id := range groupIDSet {
		groupIDs = append(groupIDs, id)
	}
	userCards, err := database.GetUserCards(db, userIDs)
	if err != nil {
		return nil, err
	}
	groupCards, err := database.GetGroupCards(db, groupIDs)
	if err != nil {
		return nil, err
	}
	views := make([]GroupView, len(groups))
	for i := range groups {
		g := groups[i]
		v := GroupView{Group: g}
		if c, ok := userCards[g.OwnerID]; ok {
			v.OwnerUser = &c
		}
		if c, ok := userCards[g.CreatedBy]; ok {
			v.CreatedByUser = &c
		}
		if g.AdminID != "" {
			switch g.AdminType {
			case database.AdminTypeUser:
				if c, ok := userCards[g.AdminID]; ok {
					v.AdminUser = &c
				}
			case database.AdminTypeGroup:
				if c, ok := groupCards[g.AdminID]; ok {
					v.AdminGroup = &c
				}
			}
		}
		views[i] = v
	}
	return views, nil
}

// enrichGroup is the single-group convenience wrapper around enrichGroups.
func enrichGroup(db *gorm.DB, g *database.Group) (*GroupView, error) {
	views, err := enrichGroups(db, []database.Group{*g})
	if err != nil {
		return nil, err
	}
	if len(views) == 0 {
		return nil, nil
	}
	// Members live on g, which is embedded; preserve them on the view.
	views[0].Members = g.Members
	return &views[0], nil
}

type AddGroupMemberReq struct {
	UserID string `json:"userId"`
}

// UpdateGroupReq carries optional updates for PATCH /groups/:id.
//   - Name (machine identifier) may only be changed by a system admin.
//     Owners/group-admins attempting it get 403.
//   - DisplayName and Description are owner-editable.
type UpdateGroupReq struct {
	Name        *string `json:"name"`
	DisplayName *string `json:"displayName"`
	Description *string `json:"description"`
}

type UpdateGroupOwnershipReq struct {
	OwnerID   *string             `json:"ownerId"`
	AdminID   *string             `json:"adminId"`
	AdminType *database.AdminType `json:"adminType"`
}

type CreateInviteLinkReq struct {
	IsSingleUse bool   `json:"isSingleUse"`
	ExpiresIn   string `json:"expiresIn"` // Duration string, e.g. "168h", "7d"
}

type RedeemInviteLinkReq struct {
	Token string `json:"token"`
}

// UpdateUserStatusReq is for the admin-only PUT /users/:id/status endpoint.
// Status flips an account between active and inactive — purely an
// authorization concern. Display name (a human label) used to ride along
// here; it now goes through PATCH /users/:id (admin) or PATCH /me (self),
// matching the user-record contract on database.User.
type UpdateUserStatusReq struct {
	Status *database.UserStatus `json:"status"`
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

	user, userId, callerGroups, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := CheckAdmin(identity)
	isUserAdmin, _ := CheckUserAdmin(identity)

	// System admins AND user admins see every group; everyone else
	// sees the union of: groups they own/admin/are a member of in the
	// DB AND any groups the caller's login cookie asserts membership
	// of (wlcg.groups, sourced from the OIDC IdP or htpasswd bootstrap).
	// The latter are filtered to groups that actually exist in the DB
	// so non-existent names asserted by the IdP don't pollute the
	// listing. user_admin is included because the design contract
	// puts "manage non-admin users and unprivileged groups" under the
	// user_admin scope — they need to see what exists to manage it.
	var groups []database.Group
	if isAdmin || isUserAdmin {
		groups, err = database.ListGroups(database.ServerDatabase)
	} else {
		groups, err = database.ListGroupsVisibleToUser(database.ServerDatabase, userId, callerGroups)
	}
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list groups",
		})
		return
	}
	views, err := enrichGroups(database.ServerDatabase, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to resolve group ownership details",
		})
		return
	}

	ctx.JSON(http.StatusOK, views)
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

	// Restrict to callers who can see this group: system admin, owner, admin,
	// or member. Returning 404 (rather than 403) on visibility failure avoids
	// confirming the existence of groups the caller can't access.
	caller, callerID, callerGroups, err := GetUserGroups(ctx)
	if err != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: caller,
		ID:       callerID,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	})
	if !database.CanSeeGroup(database.ServerDatabase, group, callerID, isAdmin, callerGroups) {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group not found",
		})
		return
	}

	view, err := enrichGroup(database.ServerDatabase, group)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to resolve group ownership details",
		})
		return
	}
	ctx.JSON(http.StatusOK, view)
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

	caller, userId, callerGroups, err := GetUserGroups(ctx)
	if err != nil || userId == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify group creator",
		})
		return
	}
	identity := UserIdentity{
		Username: caller,
		ID:       userId,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	// System admins and user admins can create groups (the latter manages
	// non-privileged groups per the user-admin role's contract). Non-admins
	// can manage groups they own but cannot stand up new ones.
	isAdmin, _ := CheckAdmin(identity)
	isUserAdmin, _ := CheckUserAdmin(identity)
	if !isAdmin && !isUserAdmin {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to create groups",
		})
		return
	}

	authMethod, authMethodID := captureAuthMethod(ctx)
	group, err := database.CreateGroup(database.ServerDatabase, req.Name, req.DisplayName, req.Description, database.Creator{
		UserID:       userId,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
	}, req.CreatedForCollectionID)
	if err != nil {
		if errors.Is(err, database.ErrReservedGroupPrefix) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Group name cannot start with 'user-'",
			})
			return
		}
		if errors.Is(err, database.ErrInvalidIdentifier) || errors.Is(err, database.ErrInvalidDisplayName) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
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

	if err := database.UpdateGroup(database.ServerDatabase, id, req.Name, req.DisplayName, req.Description, userId, isAdmin); err != nil {
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
		} else if errors.Is(err, database.ErrInvalidIdentifier) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
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

	caller, callerID, callerGroups, err := GetUserGroups(ctx)
	if err != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: caller,
		ID:       callerID,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	})
	if !database.CanSeeGroup(database.ServerDatabase, group, callerID, isAdmin, callerGroups) {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group not found",
		})
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

// AddUserReq describes a user-create request. There are two flavors:
//
//   - Local user (username/password login): supply Username (and optionally
//     DisplayName). The user is created without a password; the admin then
//     mints a password-set invite (POST /users/:id/password-invite) and
//     hands the link to the user, who picks their own password. Admins
//     never see or set passwords directly — that's the whole point.
//   - External (OIDC) user: supply Username, Sub, and Issuer.
type AddUserReq struct {
	Username    string `json:"username"`
	Sub         string `json:"sub,omitempty"`
	Issuer      string `json:"issuer,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
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

	if req.Username == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Username is required",
		})
		return
	}

	// Capture the caller for the audit trail. Route is admin-walled so
	// callerID is always a real user; we derive auth method from the
	// request (cookie vs API token).
	_, callerID, _, idErr := GetUserGroups(ctx)
	if idErr != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	authMethod, authMethodID := captureAuthMethod(ctx)
	creator := database.Creator{
		UserID:       callerID,
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
	}

	// Local vs OIDC is decided purely by whether sub/issuer were supplied.
	// Local users are *always* created without a password — the admin then
	// mints a password-set invite separately so they never see the
	// password themselves.
	isLocal := req.Sub == "" && req.Issuer == ""

	var user *database.User
	if isLocal {
		localIssuer := param.Server_ExternalWebUrl.GetString()
		if localIssuer == "" {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Server.ExternalWebUrl is not configured; cannot create local users",
			})
			return
		}
		// Pass an empty password — the user will set their own via the
		// invite flow.
		user, err = database.CreateLocalUser(database.ServerDatabase, req.Username, req.DisplayName, localIssuer, creator)
	} else {
		if req.Sub == "" || req.Issuer == "" {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Sub and issuer are required for external (OIDC) users",
			})
			return
		}
		user, err = database.CreateUser(database.ServerDatabase, req.Username, req.Sub, req.Issuer, creator)
	}
	if err != nil {
		if errors.Is(err, database.ErrInvalidIdentifier) || errors.Is(err, database.ErrInvalidDisplayName) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to create user: %v", err),
		})
		return
	}

	// Returning the full user record (rather than just {id}) is convenient
	// for the admin UI: it can immediately follow up with a
	// POST /users/:id/password-invite call and show the resulting link.
	ctx.JSON(http.StatusCreated, user)
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
	// Per the user-record contract (see comment on database.User):
	//   - Username is the authorization handle; admin-only renames go here.
	//   - DisplayName is a human label; admins can override one as a courtesy
	//     even though users normally edit their own via PATCH /me.
	//   - Sub/Issuer are linked OIDC identities; managed via
	//     /users/:id/identities, never directly here.
	Username    *string `json:"username"`
	DisplayName *string `json:"displayName"`
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
	if req.Username == nil && req.DisplayName == nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "request must specify at least one of: username, displayName",
		})
		return
	}

	// Route-level UserAdminAuthHandler clears either admin or
	// user_admin. Per the design contract, a user-admin must NOT be
	// able to rename or relabel a system admin (otherwise they could
	// kick a system admin off their own account by renaming them out
	// of Server.UIAdminUsers). System admins keep full access.
	user, userId, groups, idErr := GetUserGroups(ctx)
	if idErr != nil || userId == "" || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isSystemAdmin, _ := CheckAdmin(identity)
	if !isSystemAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot modify system admin accounts",
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

	if req.Username != nil {
		// RenameUser keeps the local-issuer invariant intact (sub == username
		// for locally-authenticated accounts) so password login keeps
		// working after the rename. OIDC accounts have their sub left alone.
		localIssuer := param.Server_ExternalWebUrl.GetString()
		if err := database.RenameUser(database.ServerDatabase, id, *req.Username, localIssuer); err != nil {
			if errors.Is(err, database.ErrInvalidIdentifier) {
				ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    err.Error(),
				})
				return
			}
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
	identity := UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}

	// Allow system admins or user admins
	isAdmin, _ := CheckAdmin(identity)
	isUserAdmin, _ := CheckUserAdmin(identity)
	if !isAdmin && !isUserAdmin {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to delete users",
		})
		return
	}

	// User admins cannot delete system admin users
	if !isAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot delete system admin accounts",
		})
		return
	}

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

	authMethod, authMethodID := captureAuthMethod(ctx)
	link, plainToken, err := database.CreateGroupInviteLink(database.ServerDatabase, groupID, userId, expiresAt, req.IsSingleUse, isAdmin, authMethod, authMethodID)
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

	// Invite links are sensitive (their existence is itself an invitation
	// signal); only owners/admins can list them, never plain members.
	caller, callerID, callerGroups, err := GetUserGroups(ctx)
	if err != nil || callerID == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify caller",
		})
		return
	}
	isAdmin, _ := CheckAdmin(UserIdentity{
		Username: caller,
		ID:       callerID,
		Groups:   callerGroups,
		Sub:      ctx.GetString("OIDCSub"),
	})
	group, err := database.GetGroupWithMembers(database.ServerDatabase, groupID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "group not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to load group: %v", err),
		})
		return
	}
	if !database.CanManageGroup(database.ServerDatabase, group, callerID, isAdmin) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you do not have permission to view this group's invite links",
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

	// Resolve redeemed-by user IDs to lightweight cards in a single
	// batched query so the UI can render a user pill ("Display Name
	// (username)") instead of an opaque ID. Same pattern as
	// enrichGroups for owner/admin/createdBy.
	views := enrichInviteLinks(database.ServerDatabase, links)
	ctx.JSON(http.StatusOK, views)
}

// InviteLinkView wraps a GroupInviteLink with a resolved RedeemedByUser
// summary. Embedding the card avoids a follow-up GET /users/:id call
// (which most callers don't have permission for) and lets the UI render
// the same UserPill component used elsewhere.
type InviteLinkView struct {
	database.GroupInviteLink
	RedeemedByUser *database.UserCard `json:"redeemedByUser,omitempty"`
}

// enrichInviteLinks attaches a UserCard for the RedeemedBy user of each
// link in a single round-trip. Links with no redemption (RedeemedBy
// empty) carry a nil card. Errors during card lookup are non-fatal:
// the caller still gets the link rows, just without the user pill.
func enrichInviteLinks(db *gorm.DB, links []database.GroupInviteLink) []InviteLinkView {
	idSet := map[string]struct{}{}
	for _, l := range links {
		if l.RedeemedBy != "" {
			idSet[l.RedeemedBy] = struct{}{}
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	cards, _ := database.GetUserCards(db, ids)
	views := make([]InviteLinkView, len(links))
	for i, l := range links {
		v := InviteLinkView{GroupInviteLink: l}
		if l.RedeemedBy != "" {
			if c, ok := cards[l.RedeemedBy]; ok {
				v.RedeemedByUser = &c
			}
		}
		views[i] = v
	}
	return views
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
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to identify user",
		})
		return
	}

	// Extract OIDC identity from context for auto-creation
	var sub, issuer, username string
	if v, exists := ctx.Get("OIDCSub"); exists {
		sub, _ = v.(string)
	}
	if v, exists := ctx.Get("OIDCIss"); exists {
		issuer, _ = v.(string)
	}

	// Use the authenticated user's display name as the username for auto-creation
	if user, exists := ctx.Get("User"); exists {
		if userStr, ok := user.(string); ok && userStr != "" {
			username = userStr
		}
	}
	// If username is still empty, derive from sub
	if username == "" && sub != "" {
		username = sub
	}

	groupID, _, err := database.RedeemGroupInviteLink(database.ServerDatabase, req.Token, userId, sub, issuer, username)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invite link not found",
			})
		} else {
			log.Warningf("Failed to redeem invite link: %v", err)
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to redeem invite link",
			})
		}
		return
	}

	// Resolve group name for the response so the UI can deep-link without a
	// follow-up call. groupID is empty for user-onboarding invites.
	resp := gin.H{
		"status":  server_structs.RespOK,
		"message": "Successfully joined the group",
	}
	if groupID != "" {
		if grp, err := database.GetGroupWithMembers(database.ServerDatabase, groupID); err == nil {
			resp["groupId"] = grp.ID
			resp["groupName"] = grp.Name
		} else {
			resp["groupId"] = groupID
		}
	} else {
		resp["message"] = "Invite redeemed; your account is now active."
	}
	ctx.JSON(http.StatusOK, resp)
}

// handleRedeemCollectionOwnershipInvite consumes a single-use
// ownership-transfer invite link, swapping the collection's
// OwnerID / Owner fields to the authenticated caller. Single-use is
// enforced inside the DB helper; the redeem path here just maps the
// caller's identity to the redeemer and translates errors. The
// caller MUST be authenticated — anonymous redemption would let
// link-holders make ANYBODY the owner; we record the caller's
// User.ID specifically so the audit trail names a real account.
func handleRedeemCollectionOwnershipInvite(ctx *gin.Context) {
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
	collectionID, prevOwner, err := database.RedeemCollectionOwnershipInviteLink(database.ServerDatabase, req.Token, userId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invite link not found",
			})
		} else {
			log.Warningf("Failed to redeem ownership invite link: %v", err)
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to redeem invite link",
			})
		}
		return
	}
	ctx.JSON(http.StatusOK, gin.H{
		"status":          server_structs.RespOK,
		"message":         "Ownership transferred to you.",
		"collectionId":    collectionID,
		"previousOwnerId": prevOwner,
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

	// Require user admin or system admin privileges
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

	// User admins cannot modify system admin users (only system admins can)
	isSystemAdmin, _ := CheckAdmin(identity)
	if !isSystemAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot modify system admin accounts",
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

	if req.Status == nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "status is required (use PATCH /users/:id or /me to change display name)",
		})
		return
	}
	if *req.Status != database.UserStatusActive && *req.Status != database.UserStatusInactive {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "status must be 'active' or 'inactive'",
		})
		return
	}
	if err := database.UpdateUserStatus(database.ServerDatabase, id, *req.Status); err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to update user status: %v", err),
		})
		return
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

// handleClearAUPAgreement wipes a user's recorded AUP acceptance.
// Admin tooling for an operator who needs to force one user back
// through the AUP workflow (e.g. they signed under duress, or their
// account was suspected to be compromised between signing and now).
// Distinct from rotating the active AUP itself, which forces every
// user on the server to re-accept.
//
// Authorization mirrors the rest of /users/* (admin-walled at the
// route level); for parity with handleClearUserPassword we ALSO
// refuse the operation when the target is a system admin and the
// caller is only a user-admin, so a user-admin can't lock a system
// admin out of the system by repeatedly clearing their AUP.
func handleClearAUPAgreement(ctx *gin.Context) {
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
	if !isAdmin && IsSystemAdminUserID(database.ServerDatabase, id) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user administrators cannot clear a system admin's AUP acceptance",
		})
		return
	}

	if err := database.ClearAUPAgreement(database.ServerDatabase, id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "user not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to clear AUP agreement: %v", err),
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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "identity not found",
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

	authMethod, authMethodID := captureAuthMethod(ctx)
	link, plainToken, createErr := database.CreateUserOnboardingInviteLink(database.ServerDatabase, userId, expiresAt, req.IsSingleUse, authMethod, authMethodID)
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

// handleGetAUP has moved to web_ui/aup.go to consolidate AUP source
// resolution (operator file vs. embedded default) and footer rendering.
