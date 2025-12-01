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

// verifyTokenWithCollectionScope verifies a token with standard verification first,
// and falls back to manual collection scope verification if standard verification fails.
// This handles cases where OA4MP adds collection IDs to scopes (e.g., "collection.read:test_collection").
// For read operations on public collections, it also provides a fallback that doesn't require explicit scopes.
//
// Note: This accepts tokens with EITHER web_ui.access OR the specific collection scope.
// This design allows both:
//   - Web UI users (who have web_ui.access from login cookies) to access collections
//   - CLI/API clients (who have collection-specific scopes from OAuth2 device flow) to access collections
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

type ListCollectionRes struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	OwnerID     string `json:"owner_id"`
	Description string `json:"description"`
	Visibility  string `json:"visibility"`
	Namespace   string `json:"namespace"`
}

type GetCollectionRes struct {
	ID          string                   `json:"id"`
	Name        string                   `json:"name"`
	OwnerID     string                   `json:"owner_id"`
	Description string                   `json:"description"`
	Visibility  string                   `json:"visibility"`
	Namespace   string                   `json:"namespace"`
	Members     []string                 `json:"members"`
	ACLs        []database.CollectionACL `json:"acls"`
	Metadata    map[string]string        `json:"metadata"`
	CreatedAt   time.Time                `json:"created_at"`
	UpdatedAt   time.Time                `json:"updated_at"`
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	collections, err := database.ListCollections(database.ServerDatabase, user, groups)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprintf("Failed to list collections: %v", err),
		})
		return
	}

	res := make([]ListCollectionRes, 0)
	for _, collection := range collections {
		res = append(res, ListCollectionRes{
			ID:          collection.ID,
			Name:        collection.Name,
			OwnerID:     collection.Owner,
			Description: collection.Description,
			Visibility:  string(collection.Visibility),
			Namespace:   collection.Namespace,
		})
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

	user, _, _, err := web_ui.GetUserGroups(ctx)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	err = database.UpdateCollection(database.ServerDatabase, ctx.Param("id"), user, groups, req.Name, req.Description, visPtr, isAdmin)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	err = database.UpsertCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, groups, key, value, isAdmin)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	err = database.DeleteCollectionMetadata(database.ServerDatabase, ctx.Param("id"), user, groups, key, isAdmin)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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
		OwnerID:     coll.Owner,
		Description: coll.Description,
		Visibility:  string(coll.Visibility),
		Namespace:   coll.Namespace,
		Members:     members,
		ACLs:        coll.ACLs,
		Metadata:    metadata,
		CreatedAt:   coll.CreatedAt,
		UpdatedAt:   coll.UpdatedAt,
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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
	isAdmin, _ := web_ui.CheckAdmin(user)

	err = database.DeleteCollection(database.ServerDatabase, ctx.Param("id"), user, groups, isAdmin)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	err = database.GrantCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, groups, req.GroupID, role, req.ExpiresAt, isAdmin)
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

	user, _, groups, err := web_ui.GetUserGroups(ctx)
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

	err = database.RevokeCollectionAcl(database.ServerDatabase, ctx.Param("id"), user, groups, req.GroupID, role, isAdmin)
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
