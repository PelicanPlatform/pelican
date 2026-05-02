package origin

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui"
)

func RegisterCollectionsAPI(group *gin.RouterGroup) {
	// Collections API
	group.GET("", web_ui.AuthHandler, handleListCollections)
	group.POST("", web_ui.AuthHandler, handleCreateCollection)
	group.PATCH("/:id", web_ui.AuthHandler, handleUpdateCollection)
	group.DELETE("/:id", web_ui.AuthHandler, handleDeleteCollection)
	group.GET("/:id", web_ui.AuthHandler, handleGetCollection)
	// TODO: More collections work in the future, the notion of members is up in the air
	// group.POST("/:id/members", web_ui.AuthHandler, handleAddCollectionMembers)
	// group.DELETE("/:id/members", web_ui.AuthHandler, handleRemoveCollectionMembers)
	// group.DELETE("/:id/members/:encoded_object_url", web_ui.AuthHandler, handleRemoveCollectionMember)
	// group.GET("/:id/members", web_ui.AuthHandler, handleListCollectionMembers)
	group.GET("/:id/metadata", web_ui.AuthHandler, handleGetCollectionMetadata)
	group.PUT("/:id/metadata/:key", web_ui.AuthHandler, handlePutCollectionMetadata)
	group.DELETE("/:id/metadata/:key", web_ui.AuthHandler, handleDeleteCollectionMetadata)
	group.GET("/:id/acl", web_ui.AuthHandler, handleGetCollectionAcls)
	group.POST("/:id/acl", web_ui.AuthHandler, handleGrantCollectionAcl)
	group.DELETE("/:id/acl", web_ui.AuthHandler, handleRevokeCollectionAcl)
	// Candidate-owners list — drives the owner-picker on the edit
	// page for callers who don't hold server.user_admin (and so
	// can't list every user). The set is the union of: current
	// owner, admin-group members, and members of every group
	// attached via an ACL row.
	group.GET("/:id/candidate-owners", web_ui.AuthHandler, handleListCollectionCandidateOwners)

	// Ownership-transfer invites: mint a single-use link that, when
	// redeemed, transfers Collection.OwnerID to the redeemer. Useful
	// for the "I'm onboarding a faculty member who'll own this
	// collection" flow without having to pre-create their User row.
	// Authorization mirrors PATCH-ownerId — the underlying DB helper
	// re-gates on owner / admin-group / collection_admin.
	group.POST("/:id/ownership-invites", web_ui.AuthHandler, handleCreateCollectionOwnershipInvite)
}

// callerIsCollectionAdmin reports whether the cookie/bearer-bound
// caller's effective scope set contains server.admin or
// server.collection_admin. Used as the authorization step on
// management endpoints (create/modify/delete/list-all): the existing
// verifyTokenWithCollectionScope merely AUTHENTICATES (since it
// accepts the bearer-only web_ui.access scope from a login cookie),
// it does not authorize. Without this check, every logged-in user
// could create or list collections.
//
// Returns false (and sets identity = nil) when the caller has no
// resolvable identity in the context — handlers should already have
// short-circuited on that earlier, but the helper stays safe.
func callerIsCollectionAdmin(ctx *gin.Context) bool {
	user, userId, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		return false
	}
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	if isAdmin, _ := web_ui.CheckAdmin(identity); isAdmin {
		return true
	}
	if isCollAdmin, _ := web_ui.CheckCollectionAdmin(identity); isCollAdmin {
		return true
	}
	return false
}

// hasExplicitBearerCollectionScope reports whether the caller presented
// a bearer (Authorization: Bearer …) token whose verified scope set
// contains the supplied collection.* scope EXPLICITLY — i.e. not via
// the web_ui.access fallback that verifyTokenWithCollectionScope also
// accepts. This is the path OA4MP / CLI clients use to drive a
// collection action without holding a management role; we keep it
// open in the management-endpoint authorization step.
func hasExplicitBearerCollectionScope(ctx *gin.Context, scope token_scopes.TokenScope) bool {
	auth := ctx.Request.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	_, ok, _ := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{scope},
	})
	return ok
}

// verifyTokenWithCollectionScope verifies a token with standard verification first,
// and falls back to manual collection scope verification if standard verification fails.
// This handles cases where OA4MP adds collection IDs to scopes (e.g., "collection.read:test_collection").
// For read operations on public collections, it also provides a fallback that doesn't require explicit scopes.
//
// Note: This accepts tokens with EITHER web_ui.access OR the specific collection scope.
// This design allows both:
//   - Web UI users (who have web_ui.access from login cookies) to access collections
//   - CLI/API clients (who have collection-specific scopes from OAuth2 device flow) to access collections
//
// AUTHENTICATION ONLY. The web_ui.access fallback means every logged-in
// caller (including unprivileged ones) clears this gate. Management
// endpoints must additionally call callerIsCollectionAdmin (or
// equivalent) before mutating collection state.
func verifyTokenWithCollectionScope(ctx *gin.Context, expectedScope token_scopes.TokenScope, collectionID string) (status int, ok bool, err error) {
	authOption := token.AuthOption{
		Sources: []token.TokenSource{token.Cookie, token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.WebUi_Access, expectedScope},
	}

	// Try standard verification first
	status, ok, err = token.Verify(ctx, authOption)
	if ok {
		return status, ok, nil
	}

	// If standard verification failed, try manual verification for collection scopes with IDs
	log.Debugf("verifyTokenWithCollectionScope: Standard verification failed, trying fallback collection scope verification. Error: %v", err)
	if verifyCollectionScope(ctx, expectedScope, collectionID) {
		log.Debugf("verifyTokenWithCollectionScope: Fallback collection scope verification succeeded")
		return http.StatusOK, true, nil
	}

	log.Debugf("verifyTokenWithCollectionScope: Both standard and fallback verification failed")
	return status, false, err
}

// verifyCollectionScope manually verifies a token has a collection scope, handling scopes with collection IDs.
// This is used as a fallback when standard token.Verify fails due to OA4MP adding collection IDs to scopes.
// For read operations, it also checks if the collection is public as a final fallback.
func verifyCollectionScope(ctx *gin.Context, expectedScope token_scopes.TokenScope, collectionID string) bool {
	// Extract token from Authorization header
	headerToken := ctx.Request.Header["Authorization"]
	if len(headerToken) == 0 {
		log.Debugf("verifyCollectionScope: No Authorization header found")
		return false
	}

	tokenStr, found := strings.CutPrefix(headerToken[0], "Bearer ")
	if !found {
		log.Debugf("verifyCollectionScope: No Bearer token found in Authorization header")
		return false
	}

	// Parse token (without verification first to check issuer)
	tok, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		log.Debugf("verifyCollectionScope: Failed to parse token (no verify): %v", err)
		return false
	}

	// Verify issuer matches local issuer
	serverURL := param.Server_ExternalWebUrl.GetString()
	tokenIssuer := tok.Issuer()
	log.Debugf("verifyCollectionScope: Comparing issuer - server: %s, token: %s", serverURL, tokenIssuer)
	if serverURL != tokenIssuer {
		log.Debugf("verifyCollectionScope: Issuer mismatch - expected %s, got %s", serverURL, tokenIssuer)
		return false
	}

	// Verify signature
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		log.Debugf("verifyCollectionScope: Failed to get issuer public JWKS: %v", err)
		return false
	}

	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(jwks))
	if err != nil {
		log.Debugf("verifyCollectionScope: Failed to parse token with signature verification: %v", err)
		return false
	}

	// Basic validation
	if err := jwt.Validate(parsed); err != nil {
		log.Debugf("verifyCollectionScope: Token validation failed: %v", err)
		return false
	}

	// Check scope claim
	scopeAny, ok := parsed.Get("scope")
	if !ok {
		log.Debugf("verifyCollectionScope: No scope claim found in token")
		// For read operations on public collections, check if collection is public as final fallback
		if expectedScope == token_scopes.Collection_Read && collectionID != "" {
			return checkPublicCollectionAccess(ctx, collectionID, parsed)
		}
		return false
	}

	scopeStr, ok := scopeAny.(string)
	if !ok {
		log.Debugf("verifyCollectionScope: Scope claim is not a string")
		return false
	}

	log.Debugf("verifyCollectionScope: Token scope string: %s, expected scope: %s", scopeStr, expectedScope.String())

	// Check each scope in the token
	scopes := strings.Split(scopeStr, " ")
	for _, scope := range scopes {
		if scope == "" {
			continue
		}
		log.Debugf("verifyCollectionScope: Checking scope '%s' against expected '%s'", scope, expectedScope.String())
		// Use CheckCollectionScope helper which handles collection IDs
		if token_scopes.CheckCollectionScope(scope, expectedScope) {
			log.Debugf("verifyCollectionScope: Scope match found! scope='%s', expected='%s'", scope, expectedScope.String())
			// Extract user identity from the token (subject claim)
			user := parsed.Subject()
			if user != "" {
				ctx.Set("User", user)
				log.Debugf("verifyCollectionScope: Set User context to: %s", user)
			}

			// Extract userId claim
			if userIdIface, ok := parsed.Get("user_id"); ok {
				if userId, ok := userIdIface.(string); ok && userId != "" {
					ctx.Set("UserId", userId)
				}
			}

			// Extract oidc_sub claim
			if oidcSubIface, ok := parsed.Get("oidc_sub"); ok {
				if oidcSub, ok := oidcSubIface.(string); ok && oidcSub != "" {
					ctx.Set("OIDCSub", oidcSub)
				}
			}

			// Extract groups if present
			groupsIface, ok := parsed.Get("wlcg.groups")
			if ok {
				if groupsTmp, ok := groupsIface.([]interface{}); ok {
					groups := make([]string, 0, len(groupsTmp))
					for _, groupObj := range groupsTmp {
						if groupStr, ok := groupObj.(string); ok {
							groups = append(groups, groupStr)
						}
					}
					ctx.Set("Groups", groups)
					log.Debugf("verifyCollectionScope: Set Groups context to: %v", groups)
				}
			}

			return true
		}
	}

	log.Debugf("verifyCollectionScope: No matching scope found. Token scopes: %v, expected: %s", scopes, expectedScope.String())

	// Final fallback: For read operations, check if collection is public
	if expectedScope == token_scopes.Collection_Read && collectionID != "" {
		return checkPublicCollectionAccess(ctx, collectionID, parsed)
	}

	return false
}

// checkPublicCollectionAccess checks if a collection is public and allows read access.
// This is used as a fallback when token doesn't have explicit collection scopes.
// It also sets user context from the token for logging purposes.
func checkPublicCollectionAccess(ctx *gin.Context, collectionID string, parsed jwt.Token) bool {
	log.Debugf("checkPublicCollectionAccess: Checking if collection %s is public", collectionID)

	// Check if collection exists and is public
	var collection database.Collection
	if err := database.ServerDatabase.Where("id = ?", collectionID).First(&collection).Error; err != nil {
		log.Debugf("checkPublicCollectionAccess: Collection %s not found: %v", collectionID, err)
		return false
	}

	if collection.Visibility != database.VisibilityPublic {
		log.Debugf("checkPublicCollectionAccess: Collection %s is not public (visibility: %s)", collectionID, collection.Visibility)
		return false
	}

	log.Infof("checkPublicCollectionAccess: Allowing read access to public collection %s", collectionID)

	// Extract and set user context from token for audit logging
	user := parsed.Subject()
	if user != "" {
		ctx.Set("User", user)
		log.Debugf("checkPublicCollectionAccess: Set User context to: %s", user)
	}

	// Extract and set groups if present
	groupsIface, ok := parsed.Get("wlcg.groups")
	if ok {
		if groupsTmp, ok := groupsIface.([]interface{}); ok {
			groups := make([]string, 0, len(groupsTmp))
			for _, groupObj := range groupsTmp {
				if groupStr, ok := groupObj.(string); ok {
					groups = append(groups, groupStr)
				}
			}
			ctx.Set("Groups", groups)
			log.Debugf("checkPublicCollectionAccess: Set Groups context to: %v", groups)
		}
	}

	return true
}

// namespaceWithinExport reports whether the supplied namespace path
// is contained within at least one of the origin's exported prefixes.
// "Within" means either an exact match OR a strict path-descendant —
// e.g. an export of `/org/foo` accepts a collection rooted at
// `/org/foo`, `/org/foo/projectA`, or `/org/foo/team/2026`, but
// rejects `/org/foobar` (the next character after the prefix MUST
// be a `/` separator). The empty namespace and any path that
// doesn't begin with `/` are rejected, matching the same path-shape
// invariant ACL enforcement uses elsewhere in this file.
//
// Pulled out of the handler so unit tests can exercise the
// boundary cases without spinning up a Gin engine.
func namespaceWithinExport(ns string, exports []server_utils.OriginExport) bool {
	if ns == "" || !strings.HasPrefix(ns, "/") {
		return false
	}
	for _, export := range exports {
		prefix := export.FederationPrefix
		if prefix == "" {
			continue
		}
		if ns == prefix {
			return true
		}
		if strings.HasPrefix(ns, prefix+"/") {
			return true
		}
	}
	return false
}

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
	// Ownership-model fields. OwnerID transfers the collection to a
	// different user (passed as a User.ID slug); AdminID assigns or
	// clears the admin group. Use the empty string to clear AdminID.
	// Only the existing owner / admin-group / collection_admin can
	// touch these — write-ACL holders cannot self-promote.
	OwnerID *string `json:"ownerId"`
	AdminID *string `json:"adminId"`
}

type MetadataValue struct {
	Value string `json:"value"`
}

// GrantAclReq accepts BOTH camelCase (groupId) and snake_case
// (group_id) so the older test/CLI clients that use group_id keep
// working alongside the frontend's groupId convention. Same for
// RevokeAclReq below. The handler resolves the effective value via
// `cmp.Or` style: groupId wins when both are set, otherwise
// group_id is used.
type GrantAclReq struct {
	GroupID         string     `json:"groupId"`
	GroupIDSnakeAlt string     `json:"group_id"`
	Role            string     `json:"role"`
	ExpiresAt       *time.Time `json:"expiresAt"`
	ExpiresAtSnake  *time.Time `json:"expires_at"`
}

// resolvedGroupID returns whichever of groupId / group_id the caller
// actually populated. The frontend uses camelCase; older tooling and
// existing tests use snake_case.
func (r *GrantAclReq) resolvedGroupID() string {
	if r.GroupID != "" {
		return r.GroupID
	}
	return r.GroupIDSnakeAlt
}

// resolvedExpiresAt mirrors resolvedGroupID for the optional expiry.
func (r *GrantAclReq) resolvedExpiresAt() *time.Time {
	if r.ExpiresAt != nil {
		return r.ExpiresAt
	}
	return r.ExpiresAtSnake
}

type RevokeAclReq struct {
	GroupID         string `json:"groupId"`
	GroupIDSnakeAlt string `json:"group_id"`
	Role            string `json:"role"`
}

func (r *RevokeAclReq) resolvedGroupID() string {
	if r.GroupID != "" {
		return r.GroupID
	}
	return r.GroupIDSnakeAlt
}

type AddCollectionMembersReq struct {
	Members []string `json:"members"`
}

type RemoveCollectionMembersReq struct {
	Members []string `json:"members"`
}

type ListCollectionRes struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Owner is the legacy username field (kept for client back-compat
	// + audit). OwnerID is the User.ID slug — the authoritative
	// ownership handle going forward. AdminID is the optional admin
	// group slug; empty means no admin group is assigned.
	Owner       string    `json:"owner"`
	OwnerID     string    `json:"ownerId"`
	AdminID     string    `json:"adminId"`
	Description string    `json:"description"`
	Visibility  string    `json:"visibility"`
	Namespace   string    `json:"namespace"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	// OwnerCard / AdminCard are the resolved {id, username,
	// displayName} / {id, name} summaries — populated server-side in
	// one batched query so the listing page can render
	// "Display Name (username)" and the admin-group label without an
	// N+1 round-trip from the client. Either may be omitted when the
	// referenced row is missing (deleted user, no admin group set).
	OwnerCard *database.UserCard  `json:"ownerCard,omitempty"`
	AdminCard *database.GroupCard `json:"adminCard,omitempty"`
	// CanEdit mirrors the PATCH gate: true iff the calling user is
	// the row's owner, a member of the row's admin group, or holds
	// server.collection_admin (admin implies it). Computed
	// server-side per row so the listing UI can hide edit affordances
	// for callers who would just 403 on save — no equivalent client-
	// side lookup is possible since membership requires a DB query.
	CanEdit bool `json:"canEdit"`
}

type GetCollectionRes struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	Owner       string                   `json:"owner"`
	OwnerID     string                   `json:"ownerId"`
	AdminID     string                   `json:"adminId"`
	Description string                   `json:"description"`
	Visibility  string                   `json:"visibility"`
	Namespace   string                   `json:"namespace"`
	Members     []string                 `json:"members"`
	ACLs        []database.CollectionACL `json:"acls"`
	Metadata    map[string]string        `json:"metadata"`
	CreatedAt   time.Time                `json:"createdAt"`
	UpdatedAt   time.Time                `json:"updatedAt"`
	// CanEdit — same contract as ListCollectionRes.CanEdit. Lets the
	// edit page disable controls (or refuse to mount) when the caller
	// can read but not modify this row.
	CanEdit bool `json:"canEdit"`
}

func handleListCollections(ctx *gin.Context) {
	// List collections doesn't target a specific collection, so pass empty string
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Read, "")
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	// Admin bypass: a system or collection admin gets global
	// visibility into every collection on the origin (matches the
	// management posture on update/delete). Non-admins keep the
	// existing public-or-ACL-granted scope.
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin := false
	if a, _ := web_ui.CheckAdmin(identity); a {
		isAdmin = true
	} else if a, _ := web_ui.CheckCollectionAdmin(identity); a {
		isAdmin = true
	}

	collections, err := database.ListCollections(database.ServerDatabase, user, userId, groups, isAdmin)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list collections: %v", err),
		})
		return
	}

	// Batch-resolve owner User.IDs → UserCard and admin Group.IDs →
	// GroupCard so the list page can render "Display Name (username)"
	// + admin-group labels without an N+1 round-trip per row.
	ownerIDs := make([]string, 0, len(collections))
	adminIDs := make([]string, 0, len(collections))
	for _, c := range collections {
		if c.OwnerID != "" {
			ownerIDs = append(ownerIDs, c.OwnerID)
		}
		if c.AdminID != "" {
			adminIDs = append(adminIDs, c.AdminID)
		}
	}
	ownerCards, err := database.GetUserCards(database.ServerDatabase, ownerIDs)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to resolve owner cards: %v", err),
		})
		return
	}
	adminCards, err := database.GetGroupCards(database.ServerDatabase, adminIDs)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to resolve admin-group cards: %v", err),
		})
		return
	}

	res := make([]ListCollectionRes, 0)
	for _, collection := range collections {
		row := ListCollectionRes{
			ID:          collection.ID,
			Name:        collection.Name,
			Owner:       collection.Owner,
			OwnerID:     collection.OwnerID,
			AdminID:     collection.AdminID,
			Description: collection.Description,
			Visibility:  string(collection.Visibility),
			Namespace:   collection.Namespace,
			CreatedAt:   collection.CreatedAt,
			UpdatedAt:   collection.UpdatedAt,
		}
		if uc, ok := ownerCards[collection.OwnerID]; ok {
			row.OwnerCard = &uc
		}
		if gc, ok := adminCards[collection.AdminID]; ok {
			row.AdminCard = &gc
		}
		// Mirror the PATCH gate (database.UpdateCollection): admin
		// scope holders pass unconditionally, otherwise the row's
		// owner / admin-group members can edit. The membership check
		// touches the DB; we eat the per-row cost rather than
		// inventing a join — a typical listing has at most dozens of
		// rows so the latency hit is negligible.
		row.CanEdit = isAdmin ||
			database.CallerIsCollectionOwnerOrAdmin(
				database.ServerDatabase,
				&collection,
				user, userId, groups,
			)
		res = append(res, row)
	}

	ctx.JSON(http.StatusOK, res)
}

func handleCreateCollection(ctx *gin.Context) {
	// Collection create doesn't have a specific collection ID yet, so pass empty string
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Create, "")
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	// AUTHORIZATION: verifyTokenWithCollectionScope only AUTHENTICATES.
	// Web UI cookies all carry web_ui.access, so without this guard every
	// logged-in user could create a collection. Per the design contract,
	// creating a collection is server.collection_admin (or
	// server.admin, which transitively grants collection_admin); the
	// bearer-API-token path with an explicit collection.create scope
	// stays open for OA4MP / device-flow clients.
	if !hasExplicitBearerCollectionScope(ctx, token_scopes.Collection_Create) &&
		!callerIsCollectionAdmin(ctx) {
		ctx.JSON(http.StatusForbidden, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "you must hold server.collection_admin (or server.admin) to create a collection",
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

	// Validate that the namespace is *within* an exported prefix.
	// Collections aren't limited to top-level exports — operators
	// regularly want a collection rooted at a sub-path of a larger
	// namespace (e.g. an export of `/org/foo` with one collection at
	// `/org/foo/projectA` and another at `/org/foo/projectB/2026`).
	// We accept the request when the requested namespace equals OR is
	// a strict path-descendant of any exported prefix; the
	// "next character is /" guard prevents `/org/foo` from matching
	// `/org/foobar`.
	exports, err := server_utils.GetOriginExports()
	if err != nil {
		log.Errorf("Failed to get origin exports: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to validate namespace",
		})
		return
	}
	if !namespaceWithinExport(req.Namespace, exports) {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Namespace '%s' is not within a prefix exported by this origin", req.Namespace),
		})
		return
	}

	user, userId, _, err := web_ui.GetUserGroups(ctx)
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

	// Pass both `user` (legacy username audit field — kept for the
	// uniqueness index and back-compat) and `userId` (User.ID slug —
	// the authoritative ownership handle going forward). userId may be
	// empty for bearer-token callers without a user record; the
	// collection then falls back to username-only ownership semantics.
	coll, err := database.CreateCollectionWithMetadata(database.ServerDatabase, req.Name, req.Description, user, userId, req.Namespace, visibility, req.Metadata)
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
	collectionID := ctx.Param("id")
	if collectionID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Collection ID is required",
		})
		return
	}

	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
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

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

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

	err = database.UpdateCollection(database.ServerDatabase, ctx.Param("id"), user, userId, groups, req.Name, req.Description, visPtr, req.OwnerID, req.AdminID, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to update collection: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

/*
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

	isAdmin, _ := web_ui.CheckAdmin(user)

	err = database.RemoveCollectionMembers(database.ServerDatabase, ctx.Param("id"), req.Members, user, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to remove collection members: %v", err),
			})
		}
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

	isAdmin, _ := web_ui.CheckAdmin(user)

	err = database.RemoveCollectionMembers(database.ServerDatabase, ctx.Param("id"), []string{objectURL}, user, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to remove collection member: %v", err),
			})
		}
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

	isAdmin, _ := web_ui.CheckAdmin(user)

	err = database.AddCollectionMembers(database.ServerDatabase, ctx.Param("id"), req.Members, user, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to add collection members: %v", err),
			})
		}
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
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to list collection members: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, members)
}
*/

func handleGetCollectionMetadata(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Read, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	metadata, err := database.GetCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, userId, groups)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get collection metadata: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, metadata)
}

func handlePutCollectionMetadata(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
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

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	err = database.UpsertCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, userId, groups, key, value, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to put collection metadata: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleDeleteCollectionMetadata(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
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

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	err = database.DeleteCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, userId, groups, key, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to delete collection metadata: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleGetCollection(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Read, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	// Same admin bypass as list/update/delete: a collection admin can
	// open any collection's page; non-admins still pass through the
	// public/ACL filter inside GetCollection.
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin := false
	if a, _ := web_ui.CheckAdmin(identity); a {
		isAdmin = true
	} else if a, _ := web_ui.CheckCollectionAdmin(identity); a {
		isAdmin = true
	}

	coll, err := database.GetCollection(database.ServerDatabase, ctx.Param("id"), user, userId, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "collection not found"})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to get collection: %v", err),
		})
		return
	}

	metadata := make(map[string]string)
	for _, meta := range coll.Metadata {
		metadata[meta.Key] = meta.Value
	}

	members := make([]string, 0)
	for _, member := range coll.Members {
		members = append(members, member.ObjectURL)
	}

	res := GetCollectionRes{
		ID:          coll.ID,
		Name:        coll.Name,
		Owner:       coll.Owner,
		OwnerID:     coll.OwnerID,
		AdminID:     coll.AdminID,
		Description: coll.Description,
		Visibility:  string(coll.Visibility),
		Namespace:   coll.Namespace,
		Members:     members,
		ACLs:        coll.ACLs,
		Metadata:    metadata,
		CreatedAt:   coll.CreatedAt,
		UpdatedAt:   coll.UpdatedAt,
		// Same predicate as the listing: admin scope OR row-level
		// owner / admin-group membership. Surfaced so the edit page
		// can render read-only when the caller can see but not modify.
		CanEdit: isAdmin ||
			database.CallerIsCollectionOwnerOrAdmin(
				database.ServerDatabase,
				coll,
				user, userId, groups,
			),
	}
	ctx.JSON(http.StatusOK, res)
}

func handleDeleteCollection(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Delete, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	// we will use this check to determine if we can bypass the collection owner check
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	err = database.DeleteCollection(database.ServerDatabase, ctx.Param("id"), user, userId, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to delete collection: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

// handleListCollectionCandidateOwners drives the owner-picker on the
// edit page when the caller doesn't hold server.user_admin (and so
// can't list every user via /users). The set of candidates is the
// union of:
//
//   - The current owner.
//   - Members of the collection's admin group.
//   - Members of every group attached via a CollectionACL row.
//
// Output rows are UserCard ({id, username, displayName}) so callers
// never see more than the public-safe projection. Callers with
// server.user_admin should prefer the regular /users endpoint, which
// returns the full list — this endpoint is the fallback for
// not-quite-admin callers (collection owners, admin-group members,
// holders of server.collection_admin) who still need to pick a new
// owner from the people already adjacent to the collection.
//
// Authorization: same gate as PATCH on the collection — owner /
// admin-group / collection_admin pass; everyone else gets the
// generic 404 to match GetCollection's leak posture.
func handleListCollectionCandidateOwners(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	if collectionID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Collection ID is required",
		})
		return
	}

	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Read, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isCollectionAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	// Reuse GetCollection's authorization (owner / admin / ACL /
	// admin-bypass / public-visibility) so the candidate list is
	// only readable by callers who can already see the collection.
	coll, err := database.GetCollection(database.ServerDatabase, collectionID, user, userId, groups, isCollectionAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to load collection: %v", err),
		})
		return
	}

	cards, err := database.CollectionCandidateOwners(database.ServerDatabase, coll)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to compute candidate owners: %v", err),
		})
		return
	}
	ctx.JSON(http.StatusOK, cards)
}

// CreateCollectionOwnershipInviteReq is the body for
// POST /collections/:id/ownership-invites. ExpiresIn is a Go
// duration string; an absent or empty value defaults to 7 days. The
// link is always single-use — there's no client-controllable
// IsSingleUse field, by design (ownership transfer is by definition
// one-shot).
type CreateCollectionOwnershipInviteReq struct {
	ExpiresIn string `json:"expiresIn,omitempty"`
}

// CreateCollectionOwnershipInviteRes is what we send back. Mirrors
// the existing group-invite shape so the frontend's existing
// "redeem-link displayer" components can consume it without a
// kind-specific adapter.
type CreateCollectionOwnershipInviteRes struct {
	ID          string    `json:"id"`
	InviteToken string    `json:"inviteToken"`
	ExpiresAt   time.Time `json:"expiresAt"`
	IsSingleUse bool      `json:"isSingleUse"`
}

// handleCreateCollectionOwnershipInvite mints a single-use link that,
// when redeemed by an authenticated user, transfers ownership of the
// collection to that user. Authorization mirrors the PATCH-ownerId
// path: existing owner / admin-group member / server.collection_admin
// or admin holders pass; everyone else gets ErrForbidden (mapped
// to 404 to match the rest of the surface's leak posture).
func handleCreateCollectionOwnershipInvite(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	if collectionID == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Collection ID is required",
		})
		return
	}
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}
	var req CreateCollectionOwnershipInviteReq
	if bindErr := ctx.ShouldBindJSON(&req); bindErr != nil && bindErr.Error() != "EOF" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", bindErr),
		})
		return
	}
	expiry := 7 * 24 * time.Hour
	if req.ExpiresIn != "" {
		d, parseErr := time.ParseDuration(req.ExpiresIn)
		if parseErr != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Invalid expiresIn (Go duration): %v", parseErr),
			})
			return
		}
		expiry = d
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
	if err != nil || user == "" {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to get user from context",
		})
		return
	}
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isCollectionAdmin := false
	if a, _ := web_ui.CheckAdmin(identity); a {
		isCollectionAdmin = true
	} else if a, _ := web_ui.CheckCollectionAdmin(identity); a {
		isCollectionAdmin = true
	}
	authMethod, authMethodID := web_ui.CaptureAuthMethod(ctx)

	link, plaintext, err := database.CreateCollectionOwnershipInviteLink(
		database.ServerDatabase, collectionID, user, userId, groups,
		time.Now().Add(expiry), isCollectionAdmin, authMethod, authMethodID,
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
			return
		}
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to mint ownership invite: %v", err),
		})
		return
	}
	ctx.JSON(http.StatusCreated, CreateCollectionOwnershipInviteRes{
		ID:          link.ID,
		InviteToken: plaintext,
		ExpiresAt:   link.ExpiresAt,
		IsSingleUse: link.IsSingleUse,
	})
}

func handleGetCollectionAcls(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Read, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	// Same admin bypass as GetCollection: a system or collection
	// admin reading the ACL list of any collection they can see goes
	// through. Without this, opening the edit page (or expanding the
	// listing row) for a collection with no Modify-scope ACL would
	// return a misleading "collection not found" 404.
	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin := false
	if a, _ := web_ui.CheckAdmin(identity); a {
		isAdmin = true
	} else if a, _ := web_ui.CheckCollectionAdmin(identity); a {
		isAdmin = true
	}

	acls, err := database.GetCollectionAcls(database.ServerDatabase, ctx.Param("id"), user, userId, groups, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to get collection acls: %v", err),
			})
		}
		return
	}

	ctx.JSON(http.StatusOK, acls)
}

func handleGrantCollectionAcl(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
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
	groupID := req.resolvedGroupID()
	expiresAt := req.resolvedExpiresAt()

	if groupID == "" || req.Role == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "groupId and role are required",
		})
		return
	}

	role := database.AclRole(req.Role)
	// Per the user/group-design rewrite, ownership is now a property
	// of the Collection row itself (Owner = user, AdminID = group);
	// the AclRoleOwner row pattern is deprecated. New ACL grants are
	// limited to read/write — owner-equivalent authority comes from
	// the Owner / AdminID fields on the collection.
	if role != database.AclRoleRead && role != database.AclRoleWrite {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid role. Must be one of 'read' or 'write'. To make a user the owner, set the collection's owner field; to give a group full management rights, set the collection's admin group.",
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	err = database.GrantCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, userId, groups, groupID, role, expiresAt, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to grant collection acl: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}

func handleRevokeCollectionAcl(ctx *gin.Context) {
	collectionID := ctx.Param("id")
	status, ok, err := verifyTokenWithCollectionScope(ctx, token_scopes.Collection_Modify, collectionID)
	if !ok {
		ctx.JSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    err.Error(),
		})
		return
	}

	var req RevokeAclReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Invalid request body: %v", err),
		})
		return
	}

	groupID := req.resolvedGroupID()
	if groupID == "" || req.Role == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "groupId and role are required",
		})
		return
	}

	role := database.AclRole(req.Role)
	// Revoke tolerates AclRoleOwner because legacy rows minted before
	// the ownership-model rewrite still carry it; an admin needs to
	// be able to clear them. Grant is what gets locked down to
	// read/write.
	if role != database.AclRoleRead && role != database.AclRoleWrite && role != database.AclRoleOwner {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid role. Must be one of 'read', 'write', or 'owner' (legacy)",
		})
		return
	}

	user, userId, groups, err := web_ui.GetUserGroups(ctx)
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

	identity := web_ui.UserIdentity{
		Username: user,
		ID:       userId,
		Groups:   groups,
		Sub:      ctx.GetString("OIDCSub"),
	}
	isAdmin, _ := web_ui.CheckCollectionAdmin(identity)

	err = database.RevokeCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, userId, groups, groupID, role, isAdmin)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, database.ErrForbidden) {
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "collection not found",
			})
		} else {
			ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    fmt.Sprintf("Failed to revoke collection acl: %v", err),
			})
		}
		return
	}

	ctx.Status(http.StatusNoContent)
}
