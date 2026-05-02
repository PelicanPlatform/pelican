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

// Effective-scopes evaluation. The Check* helpers (CheckAdmin,
// CheckUserAdmin, CheckCollectionAdmin) are now thin wrappers that
// consult EffectiveScopesForIdentity for a single named scope; this
// is the unified pipeline the user/group design doc has been asking
// for since the start.
//
// EffectiveScopesForIdentity unions two sources:
//
//  1. DB-stored grants — user_scopes for the user, plus group_scopes
//     for groups they're a member of (via group_members or via the
//     cookie's wlcg.groups assertion). Lives in
//     database.EffectiveScopes; this function is just the caller.
//
//  2. Config-derived grants — the historical Server.UIAdminUsers,
//     Server.AdminGroups, Server.UserAdminUsers, ... lists. Evaluated
//     live on every request, NOT mirrored into the DB. Mirroring
//     would silently preserve a privilege after the operator removed
//     the name from the config file; we want config edits to take
//     effect immediately and unambiguously, so the source of truth
//     for config-driven grants stays the file. DB-stored grants are
//     reserved for grants made deliberately through the management
//     API; revoking a DB grant is the way to take back DB-granted
//     privileges, and editing the config file is the way to take
//     back config-granted ones.
//
// Both sources flow through token_scopes.IsUserGrantable, so a
// data-plane scope (wlcg.*, scitokens.*, lot.*, ...) accidentally
// stored or named in config is never returned.

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	pkgerrors "github.com/pkg/errors"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/api_token"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// init wires the api_token package's EffectiveScopesForUser hook so
// API-token verification can intersect a key's persisted scopes
// against the creator's *current* authority on every use. Without
// this, a user who lost server.user_admin would keep using the
// scope through any API token they had previously minted.
//
// We resolve through EffectiveScopesForIdentity rather than the
// pure DB-layer EffectiveScopes so config-derived grants
// (Server.UIAdminUsers, Server.AdminGroups, ...) flow through too —
// the same evaluation an interactive login would see.
//
// The user's external (cookie-asserted) groups aren't available
// here — API-token Verify runs on the bearer-token path, not a
// cookie path — so we pass nil. Group-derived scopes via DB
// membership still apply via database.EffectiveScopes; the only
// gap is OIDC-asserted groups, which by definition aren't part of
// an API token's audit trail.
func init() {
	api_token.EffectiveScopesForUser = func(userID string) []token_scopes.TokenScope {
		// Look up the user record so we can populate Username for
		// config-derived matching. A deleted user → no scopes,
		// which makes their tokens drop every user-grantable scope
		// (i.e. the user-grantable subset of their tokens stops
		// working) on the next call.
		//
		// The api_token.ApiKey.created_by column has historically
		// captured whichever of {user-id-slug, username} the create
		// handler had on hand — newer rows store the slug (consistent
		// with every other audit field), but older rows may hold the
		// username. Try ID first, fall back to username; the user
		// record is the same either way and the effective-scope
		// evaluation is stable across both lookups.
		if database.ServerDatabase == nil {
			return nil
		}
		user, err := database.GetUserByID(database.ServerDatabase, userID)
		if err != nil {
			user, err = database.GetUserByUsername(database.ServerDatabase, userID)
		}
		if err != nil {
			return nil
		}
		if user.Status == database.UserStatusInactive {
			return nil
		}
		identity := UserIdentity{
			Username: user.Username,
			ID:       user.ID,
			Sub:      user.Sub,
		}
		return EffectiveScopesForIdentity(identity)
	}
}

// builtinAdminUsername is the literal username used by the
// htpasswd-bootstrap admin account. CheckAdmin used to short-circuit
// on this; we preserve the behavior here as a config-derived grant.
const builtinAdminUsername = "admin"

// EffectiveScopesForIdentity returns the union of every scope the
// user holds. Combines DB-stored grants with config-derived ones so
// the historical Server.UIAdminUsers / Server.AdminGroups / ... config
// keys keep working without each operator having to migrate them
// into user_scopes rows.
//
// The set is deduplicated and filtered to user-grantable scopes
// (token_scopes.IsUserGrantable). Returns an empty slice for an
// empty/anonymous identity.
func EffectiveScopesForIdentity(identity UserIdentity) []token_scopes.TokenScope {
	seen := map[token_scopes.TokenScope]struct{}{}
	out := []token_scopes.TokenScope{}

	add := func(scope token_scopes.TokenScope) {
		if !token_scopes.IsUserGrantable(scope) {
			return
		}
		if _, ok := seen[scope]; ok {
			return
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}

	// 1. DB-stored grants. Any DB error is silently ignored — we'd
	//    rather return the config-derived subset than fail the auth
	//    decision because of a transient database hiccup.
	if database.ServerDatabase != nil {
		dbScopes, err := database.EffectiveScopes(database.ServerDatabase, identity.ID, identity.Groups)
		if err == nil {
			for _, s := range dbScopes {
				add(s)
			}
		}
	}

	// 2. Config-derived grants.
	if identity.Username == builtinAdminUsername {
		add(token_scopes.Server_Admin)
	}

	addByUsernameMatch := func(list []string, scope token_scopes.TokenScope) {
		if identity.Username == "" {
			return
		}
		for _, name := range list {
			if name == identity.Username {
				add(scope)
				return
			}
		}
	}
	addByGroupMatch := func(list []string, scope token_scopes.TokenScope) {
		if len(identity.Groups) == 0 || len(list) == 0 {
			return
		}
		for _, configured := range list {
			for _, userGroup := range identity.Groups {
				if configured == userGroup {
					add(scope)
					return
				}
			}
		}
	}

	if param.Server_UIAdminUsers.IsSet() {
		addByUsernameMatch(param.Server_UIAdminUsers.GetStringSlice(), token_scopes.Server_Admin)
	}
	if param.Server_AdminGroups.IsSet() {
		addByGroupMatch(param.Server_AdminGroups.GetStringSlice(), token_scopes.Server_Admin)
	}
	addByUsernameMatch(param.Server_UserAdminUsers.GetStringSlice(), token_scopes.Server_UserAdmin)
	addByGroupMatch(param.Server_UserAdminGroups.GetStringSlice(), token_scopes.Server_UserAdmin)
	addByUsernameMatch(param.Server_CollectionAdminUsers.GetStringSlice(), token_scopes.Server_CollectionAdmin)
	addByGroupMatch(param.Server_CollectionAdminGroups.GetStringSlice(), token_scopes.Server_CollectionAdmin)

	// 3. Implications. server.admin is the master scope; per the
	//    description in docs/scopes.yaml it implies the other two.
	//    Apply this AFTER both sources so the implication holds
	//    regardless of where Server_Admin came from.
	if _, ok := seen[token_scopes.Server_Admin]; ok {
		add(token_scopes.Server_UserAdmin)
		add(token_scopes.Server_CollectionAdmin)
	}

	return out
}

// hasScope reports whether `scope` is in the identity's effective set.
// Used by the Check* wrappers below.
func hasScope(identity UserIdentity, scope token_scopes.TokenScope) bool {
	for _, s := range EffectiveScopesForIdentity(identity) {
		if s == scope {
			return true
		}
	}
	return false
}

// =============================================================================
// HTTP handlers
// =============================================================================

// scopeCatalogEntry is the shape returned by GET /scopes — every
// user-grantable scope along with the human-readable description
// pulled (at generate time) from docs/scopes.yaml. The description
// drives the management UI's "what does this scope imply?"
// affordance on the grant picker.
type scopeCatalogEntry struct {
	Name        token_scopes.TokenScope `json:"name"`
	Description string                  `json:"description,omitempty"`
}

// handleListScopeCatalog returns the user-grantable scope set. Public
// to any authenticated caller — knowing what scopes exist isn't
// sensitive — so the UI can populate its scope-picker without each
// caller needing admin privileges first.
func handleListScopeCatalog(ctx *gin.Context) {
	out := make([]scopeCatalogEntry, 0, len(token_scopes.UserGrantableScopes))
	for _, s := range token_scopes.UserGrantableScopes {
		out = append(out, scopeCatalogEntry{
			Name:        s,
			Description: s.Describe(),
		})
	}
	ctx.JSON(http.StatusOK, out)
}

// handleGetMyScopes returns the calling user's effective scopes.
// Self-service surface — the user already knows who they are, so
// listing their own scopes leaks nothing.
func handleGetMyScopes(ctx *gin.Context) {
	id := callerID(ctx)
	if id == "" {
		return
	}
	var groups []string
	if v, ok := ctx.Get("Groups"); ok {
		if s, ok := v.([]string); ok {
			groups = s
		}
	}
	identity := UserIdentity{
		Username: ctx.GetString("User"),
		ID:       id,
		Sub:      ctx.GetString("OIDCSub"),
		Groups:   groups,
	}
	ctx.JSON(http.StatusOK, EffectiveScopesForIdentity(identity))
}

// handleListUserScopes returns the DB-stored direct grants for a
// user. Does NOT include group-derived or config-derived scopes; for
// the full effective set use EffectiveScopesForIdentity. The split
// is deliberate: this surface is for editing direct grants, where
// "what's stored vs. what's evaluated" matters.
func handleListUserScopes(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id is required",
		})
		return
	}
	rows, err := database.ListUserScopes(database.ServerDatabase, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list user scopes",
		})
		return
	}
	ctx.JSON(http.StatusOK, rows)
}

// scopeMutationReq is the body for POST /users/:id/scopes and
// POST /groups/:id/scopes.
type scopeMutationReq struct {
	Scope string `json:"scope"`
}

// handleGrantUserScope assigns a scope to a user. Admin-walled at the
// route level. The scope value must be in token_scopes.UserGrantableScopes —
// the database layer rejects anything else, so a client can't sneak in
// a data-plane scope.
func handleGrantUserScope(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id is required",
		})
		return
	}
	var req scopeMutationReq
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Scope == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "scope is required",
		})
		return
	}
	authMethod, authMethodID := captureAuthMethod(ctx)
	creator := database.Creator{
		UserID:       ctx.GetString("UserId"),
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
	}
	err := database.GrantUserScope(database.ServerDatabase, id, token_scopes.TokenScope(req.Scope), creator)
	if err != nil {
		if errors.Is(err, database.ErrUngrantableScope) || pkgerrors.Is(err, database.ErrUngrantableScope) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to grant scope: " + err.Error(),
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}

// handleRevokeUserScope removes a direct user-level scope grant.
// Has no effect on scopes the user inherits via group membership or
// config — those are revoked elsewhere (group_scopes endpoint or
// editing the corresponding param).
func handleRevokeUserScope(ctx *gin.Context) {
	id := ctx.Param("id")
	scope := ctx.Param("scope")
	if id == "" || scope == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "user id and scope are required",
		})
		return
	}
	err := database.RevokeUserScope(database.ServerDatabase, id, token_scopes.TokenScope(scope))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "scope was not directly granted to this user",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to revoke scope",
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}

// handleListGroupScopes mirrors handleListUserScopes for groups.
func handleListGroupScopes(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}
	rows, err := database.ListGroupScopes(database.ServerDatabase, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list group scopes",
		})
		return
	}
	ctx.JSON(http.StatusOK, rows)
}

// handleGrantGroupScope assigns a scope to a group. System-admin-only
// at the route level: granting Server_Admin (or any management
// scope) to a group lets every member of that group act as an admin,
// so the privilege boundary has to be tight.
func handleGrantGroupScope(ctx *gin.Context) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id is required",
		})
		return
	}
	var req scopeMutationReq
	if err := ctx.ShouldBindJSON(&req); err != nil || req.Scope == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "scope is required",
		})
		return
	}
	authMethod, authMethodID := captureAuthMethod(ctx)
	creator := database.Creator{
		UserID:       ctx.GetString("UserId"),
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
	}
	err := database.GrantGroupScope(database.ServerDatabase, id, token_scopes.TokenScope(req.Scope), creator)
	if err != nil {
		if errors.Is(err, database.ErrUngrantableScope) || pkgerrors.Is(err, database.ErrUngrantableScope) {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    err.Error(),
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to grant scope: " + err.Error(),
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}

// handleRevokeGroupScope removes a group-level scope grant.
func handleRevokeGroupScope(ctx *gin.Context) {
	id := ctx.Param("id")
	scope := ctx.Param("scope")
	if id == "" || scope == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "group id and scope are required",
		})
		return
	}
	err := database.RevokeGroupScope(database.ServerDatabase, id, token_scopes.TokenScope(scope))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "scope was not granted to this group",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to revoke scope",
		})
		return
	}
	ctx.Status(http.StatusNoContent)
}
