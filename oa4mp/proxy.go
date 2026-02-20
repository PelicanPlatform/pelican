/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package oa4mp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/utils"
	"github.com/pelicanplatform/pelican/web_ui"
)

var (
	// We have a custom transport object based on the common code in `config`;
	// this is because we need a custom dialer to talk to OA4MP over a socket.
	transport *http.Transport

	onceTransport sync.Once
)

func getTransport() *http.Transport {
	onceTransport.Do(func() {
		socketName := filepath.Join(param.Issuer_ScitokensServerLocation.GetString(),
			"var", "http.sock")
		transport = config.GetTransport().Clone()
		// When creating a new socket out to the remote server, ignore the actual
		// requested address and return a Unix socket instead.
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketName)
		}
	})
	return transport
}

// MergeGroups merges two slices of groups, removing duplicates.
func MergeGroups(groups1, groups2 []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(groups1)+len(groups2))

	for _, g := range groups1 {
		if _, ok := seen[g]; !ok {
			seen[g] = struct{}{}
			result = append(result, g)
		}
	}
	for _, g := range groups2 {
		if _, ok := seen[g]; !ok {
			seen[g] = struct{}{}
			result = append(result, g)
		}
	}
	return result
}

// calculateAllowedScopes determines which scopes the user is allowed based on
// the configured authorization templates.
//
// Parameters:
//   - user: The username (used for $USER substitution in prefixes and legacy user matching)
//   - userId: The internal user ID (used for matching against the 'users' list in templates)
//   - groupsList: The user's group memberships
//
// The 'users' list in authorization templates is matched against both the internal
// user ID (preferred, set by the web UI) and the username (for backwards compatibility
// with manually configured templates).
//
// Returns the allowed scopes and the groups that matched authorization rules.
func CalculateAllowedScopes(user string, userId string, groupsList []string) ([]string, []string) {
	if len(compiledAuthzRules) == 0 {
		log.Debugf("calculateAllowedScopes: compiledAuthzRules is empty")
		return []string{}, []string{}
	}

	log.Debugf("calculateAllowedScopes: user=%s, userId=%s, groupsList=%v, numRules=%d", user, userId, groupsList, len(compiledAuthzRules))
	scopeSet := make(map[string]struct{})
	groupSet := make(map[string]struct{})
	userEscaped := url.PathEscape(user)
	for idx, rule := range compiledAuthzRules {
		log.Debugf("calculateAllowedScopes: Processing rule %d: prefix=%s, actions=%v, groupLiterals=%v, groupRegexes=%d, userSet=%v",
			idx, rule.Prefix, rule.Actions, rule.GroupLiterals, len(rule.GroupRegexes), rule.UserSet)
		// First, check if the user is allowed by this rule.
		// Check both userId (internal ID, preferred) and user (username, for backwards compatibility).
		if len(rule.UserSet) > 0 {
			_, matchById := rule.UserSet[userId]
			_, matchByUsername := rule.UserSet[user]
			if !matchById && !matchByUsername {
				log.Debugf("calculateAllowedScopes: Rule %d skipped - neither userId %s nor username %s in UserSet", idx, userId, user)
				continue
			}
		}

		// Next, check if the rule has group requirements.
		hasGroupRequirements := len(rule.GroupLiterals) > 0 || len(rule.GroupRegexes) > 0
		log.Debugf("calculateAllowedScopes: Rule %d hasGroupRequirements=%v", idx, hasGroupRequirements)
		currentMatchingGroups := make([]string, 0)
		if hasGroupRequirements {
			for _, group := range groupsList {
				_, literalMatch := rule.GroupLiterals[group]
				regexMatch := false
				if !literalMatch {
					for _, rgx := range rule.GroupRegexes {
						if rgx.MatchString(group) {
							regexMatch = true
							break
						}
					}
				}
				if literalMatch || regexMatch {
					currentMatchingGroups = append(currentMatchingGroups, group)
					log.Debugf("calculateAllowedScopes: Rule %d matched group: %s", idx, group)
				}
			}
			if len(currentMatchingGroups) == 0 {
				log.Debugf("calculateAllowedScopes: Rule %d skipped - no matching groups found", idx)
				continue
			}
		}

		// This rule applies; any groups that matched are now considered "active"
		for _, group := range currentMatchingGroups {
			groupSet[group] = struct{}{}
		}

		// Finally, generate the scopes
		if strings.Contains(rule.Prefix, "$GROUP") {
			groupsToIterate := groupsList
			if hasGroupRequirements {
				groupsToIterate = currentMatchingGroups
			}
			// When a $GROUP template rule has no explicit group restrictions,
			// all user groups are used for scope expansion.  Record them in
			// groupSet so they appear in the token's wlcg.groups claim.
			for _, group := range groupsToIterate {
				groupSet[group] = struct{}{}
			}
			for _, group := range groupsToIterate {
				groupEscaped := url.PathEscape(group)
				for _, action := range rule.Actions {
					scope := ""
					switch action {
					case "read":
						scope = "storage.read"
					case "write":
						scope = "storage.modify"
					case "create":
						scope = "storage.create"
					case "modify":
						scope = "storage.modify"
					case "collection_read":
						scope = "collection.read"
					case "collection_write":
						scope = "collection.modify"
					case "collection_create":
						scope = "collection.create"
					case "collection_modify":
						scope = "collection.modify"
					case "collection_delete":
						scope = "collection.delete"
					default:
						scope = action
					}
					prefix := strings.ReplaceAll(rule.Prefix, "$GROUP", groupEscaped)
					prefix = strings.ReplaceAll(prefix, "$USER", userEscaped)
					s := scope + ":" + prefix
					scopeSet[s] = struct{}{}
				}
			}
		} else {
			for _, action := range rule.Actions {
				scope := ""
				switch action {
				case "read":
					scope = "storage.read"
				case "write":
					scope = "storage.modify"
				case "create":
					scope = "storage.create"
				case "modify":
					scope = "storage.modify"
				case "collection_read":
					scope = "collection.read"
				case "collection_write":
					scope = "collection.modify"
				case "collection_create":
					scope = "collection.create"
				case "collection_modify":
					scope = "collection.modify"
				case "collection_delete":
					scope = "collection.delete"
				default:
					scope = action
				}
				prefix := strings.ReplaceAll(rule.Prefix, "$USER", userEscaped)
				s := scope + ":" + prefix
				scopeSet[s] = struct{}{}
			}
		}
	}

	allowedScopes := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		allowedScopes = append(allowedScopes, scope)
	}

	matchedGroups := make([]string, 0, len(groupSet))
	for group := range groupSet {
		matchedGroups = append(matchedGroups, group)
	}

	log.Debugf("calculateAllowedScopes: Final - allowedScopes=%v, matchedGroups=%v, groupSet=%v", allowedScopes, matchedGroups, groupSet)
	return allowedScopes, matchedGroups
}

// getUserCollectionScopes returns collection scopes and matched groups for a user.
// The matched groups are groups that have ACLs on collections, which should be
// included in the token's wlcg.groups claim for collection ACL checking.
// GetUserCollectionScopes returns collection scopes and matched groups for a user.
func GetUserCollectionScopes(db *gorm.DB, user string, groupsList []string) (scopes []string, matchedGroups []string, err error) {
	scopes = make([]string, 0)
	matchedGroupSet := make(map[string]struct{})

	// Any authenticated user can create new collections - they become the owner.
	// This is a capability scope, not tied to an existing resource.
	scopes = append(scopes, token_scopes.Collection_Create.String()+":/")

	// Any authenticated user can list/read collections - the actual access control
	// is handled at the database level based on ACLs and visibility.
	scopes = append(scopes, token_scopes.Collection_Read.String()+":/")

	userGroup := "user-" + user
	if !slices.Contains(groupsList, userGroup) {
		groupsList = append(groupsList, userGroup)
	}

	var acls []database.CollectionACL
	if result := db.
		Joins("JOIN collections ON collections.id = collection_acls.collection_id").
		Where("collection_acls.group_id IN ?", groupsList).
		Find(&acls); result.Error != nil {
		return nil, nil, result.Error
	}

	collectionPerms := make(map[string]database.AclRole)
	for _, acl := range acls {
		if acl.ExpiresAt != nil && acl.ExpiresAt.Before(time.Now()) {
			continue
		}

		// Track which groups have ACLs (for wlcg.groups claim)
		matchedGroupSet[acl.GroupID] = struct{}{}

		existingRole, ok := collectionPerms[acl.CollectionID]
		if !ok {
			collectionPerms[acl.CollectionID] = acl.Role
		} else {
			// Owner > Write > Read
			if acl.Role == database.AclRoleOwner {
				collectionPerms[acl.CollectionID] = database.AclRoleOwner
			} else if acl.Role == database.AclRoleWrite && (existingRole != database.AclRoleOwner && existingRole != database.AclRoleWrite) {
				collectionPerms[acl.CollectionID] = database.AclRoleWrite
			}
		}
	}

	for collectionID, role := range collectionPerms {
		switch role {
		case database.AclRoleOwner:
			scopes = append(scopes, token_scopes.Collection_Read.String()+":"+collectionID)
			scopes = append(scopes, token_scopes.Collection_Modify.String()+":"+collectionID)
			scopes = append(scopes, token_scopes.Collection_Delete.String()+":"+collectionID)
		case database.AclRoleWrite:
			scopes = append(scopes, token_scopes.Collection_Read.String()+":"+collectionID)
			scopes = append(scopes, token_scopes.Collection_Modify.String()+":"+collectionID)
		case database.AclRoleRead:
			scopes = append(scopes, token_scopes.Collection_Read.String()+":"+collectionID)
		}
	}

	// Convert matched group set to slice
	matchedGroups = make([]string, 0, len(matchedGroupSet))
	for group := range matchedGroupSet {
		matchedGroups = append(matchedGroups, group)
	}

	return scopes, matchedGroups, nil
}

// Proxy a HTTP request from the Pelican server to the OA4MP server
//
// Maps a request to /api/v1.0/issuer/foo to /scitokens-server/foo.  Most
// headers are forwarded as well.  The `X-Pelican-User` header is added
// to the request, using data from the Pelican login session, allowing
// the OA4MP server to base its logic on the Pelican authentication.
func oa4mpProxy(ctx *gin.Context) {
	var userEncoded string
	var user string
	var userId string
	var groupsList []string
	var allMatchedGroups []string
	if ctx.Request.URL.Path == "/api/v1.0/issuer/device" || ctx.Request.URL.Path == "/api/v1.0/issuer/authorize" {
		web_ui.RequireAuthMiddleware(ctx)
		if ctx.IsAborted() {
			return
		}
		user = ctx.GetString("User")
		if user == "" {
			// Should be impossible; proxy ought to be called via a middleware which always
			// sets this variable
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "User authentication not set",
			})
			return
		}
		userId = ctx.GetString("UserId")
		if userId == "" {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "User ID not set in authentication context",
			})
			return
		}
		groupsList = ctx.GetStringSlice("Groups")
		if groupsList == nil {
			groupsList = make([]string, 0)
		}
		// WORKAROUND: OA4MP 5.4.x does not provide a mechanism to pass data through headers (the
		// existing mechanism only works with the authorization code grant, not the device authorization
		// grant).  Therefore, all the data we want passed we stuff into the username (which *is* copied
		// through); a small JSON struct is created and base64-encoded.  The policy files on the other
		// side will appropriately unwrap this information.
		userInfo := make(map[string]interface{})
		userInfo["u"] = user
		allowedScopes, authzMatchedGroups := CalculateAllowedScopes(user, userId, groupsList)
		userCollectionScopes, collectionMatchedGroups, err := GetUserCollectionScopes(database.ServerDatabase, user, groupsList)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Unable to get user collection scopes",
			})
			return
		}

		allowedScopes = append(allowedScopes, userCollectionScopes...)

		// Merge groups from authorization templates and collection ACLs.
		// Authorization templates may match different groups than collection ACLs,
		// so we need both sets in wlcg.groups for proper access control.
		allMatchedGroups = MergeGroups(authzMatchedGroups, collectionMatchedGroups)
		userInfo["g"] = allMatchedGroups
		userInfo["s"] = allowedScopes
		log.Debugf("Before proxying to OA4MP: allowedScopes=%v, userCollectionScopes=%v, authzMatchedGroups=%v, collectionMatchedGroups=%v for user=%s", allowedScopes, userCollectionScopes, authzMatchedGroups, collectionMatchedGroups, user)
		userBytes, err := json.Marshal(userInfo)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Unable to serialize user authentication",
			})
			return
		}
		userEncoded = base64.StdEncoding.EncodeToString(userBytes)
	}

	origPath := ctx.Request.URL.Path
	origPath = strings.TrimPrefix(origPath, "/api/v1.0/issuer")
	ctx.Request.URL.Path = "/scitokens-server" + origPath
	ctx.Request.URL.Scheme = "http"
	ctx.Request.URL.Host = "localhost"
	if userEncoded == "" {
		ctx.Request.Header.Del("X-Pelican-User")
	} else {
		ctx.Request.Header.Set("X-Pelican-User", userEncoded)
	}

	if user != "" {
		log.Debugf("Will proxy request to URL %s with user '%s' and groups '%s'", ctx.Request.URL.String(), user, strings.Join(allMatchedGroups, ","))
	} else {
		log.Debugln("Will proxy request to URL", ctx.Request.URL.String())
	}
	transport = getTransport()
	resp, err := transport.RoundTrip(ctx.Request)
	if err != nil {
		log.Infoln("Failed to talk to OA4MP service:", err)
		ctx.JSON(http.StatusServiceUnavailable, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Unable to contact token issuer",
		})
		return
	}
	defer resp.Body.Close()

	utils.CopyHeader(ctx.Writer.Header(), resp.Header)
	ctx.Writer.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(ctx.Writer, resp.Body); err != nil {
		log.Warningln("Failed to copy response body from OA4MP to client:", err)
	}
}

// CORs middleware to allow cross-origin requests to the OA4MP proxy
// Echos the origin header back as the Access-Control-Allow-Origin header if present in Issuer.RedirectUris
func addCORSHeadersMiddleware(ctx *gin.Context) {

	// Convert Issuer.RedirectUris into a map of hostnames
	allowedHostsMap := make(map[string]bool)
	for _, uri := range param.Issuer_RedirectUris.GetStringSlice() {
		parsedUrl, err := url.Parse(uri)
		if err != nil {
			log.Printf("Failed to parse URI %s: %v", uri, err)
			continue
		}
		allowedHostsMap[parsedUrl.Scheme+"://"+parsedUrl.Host] = true
	}

	// Check if the request's host exists in the map
	host := ctx.Request.Header.Get("Origin")
	if allowedHostsMap[host] {
		ctx.Header("Access-Control-Allow-Origin", host)
	} else {
		ctx.Header("Access-Control-Allow-Origin", "")
	}

	// Print out a debug log of all the relevant values to help me see what state is present here
	log.Debugf("CORS middleware: Issuer.RedirectUris: %v", param.Issuer_RedirectUris.GetStringSlice())
	log.Debugf("CORS middleware: Allowed hosts map: %v", allowedHostsMap)
	log.Debugf("CORS middleware: Request Origin: %s", host)

	ctx.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	ctx.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")
}

// Middleware to reject requests with unregistered CORS origins
func rejectUnregisteredRedirects(ctx *gin.Context) {

	// If this request is not to register a dynamic client skip the check ( POST to /oidc-cm )
	if !(strings.HasSuffix(ctx.Request.URL.Path, "oidc-cm") && ctx.Request.Method == http.MethodPost) {
		ctx.Next()
		return
	}

	// Parse the JSON body
	bodyBytes, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to read request body"})
		return
	}

	// Restore the body for subsequent handlers
	ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var requestBody struct {
		RedirectUris []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(bodyBytes, &requestBody); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "Invalid JSON body",
		})
		return
	}

	// Convert Issuer.RedirectUris into a map for quick lookup
	allowedUris := make(map[string]bool)
	for _, uri := range param.Issuer_RedirectUris.GetStringSlice() {
		allowedUris[uri] = true
	}

	// Check if any redirect_uri is not in the allowed list
	for _, uri := range requestBody.RedirectUris {
		if !allowedUris[uri] {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Unregistered redirect_uri, make sure you have registered this uri in your Origins configuration under Issuer.RedirectUris: " + uri,
			})
			return
		}
	}

	// If all redirect_uris are valid, proceed to the next handler
	ctx.Next()
}
func ConfigureOA4MPProxy(router *gin.Engine) error {
	if router == nil {
		return errors.New("Origin configuration passed a nil pointer")
	}

	// Add a middleware to handle CORS headers
	router.Use(addCORSHeadersMiddleware)

	router.Any("/api/v1.0/issuer", oa4mpProxy)
	router.Any("/api/v1.0/issuer/*path", rejectUnregisteredRedirects, oa4mpProxy)

	return nil
}
