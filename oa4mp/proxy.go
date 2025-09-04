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
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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
		var copyTransport http.Transport = *config.GetTransport()
		transport = &copyTransport
		// When creating a new socket out to the remote server, ignore the actual
		// requested address and return a Unix socket instead.
		transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", socketName)
		}
	})
	return transport
}

func calculateAllowedScopes(user string, groupsList []string) ([]string, []string) {
	if len(compiledAuthzRules) == 0 {
		return []string{}, []string{}
	}

	scopeSet := make(map[string]struct{})
	groupSet := make(map[string]struct{})
	userEscaped := url.PathEscape(user)
	for _, rule := range compiledAuthzRules {
		// First, check if the user is allowed by this rule
		if len(rule.UserSet) > 0 {
			if _, ok := rule.UserSet[user]; !ok {
				continue
			}
		}

		// Next, check if the rule has group requirements.
		hasGroupRequirements := len(rule.GroupLiterals) > 0 || len(rule.GroupRegexes) > 0
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
				}
			}
			if len(currentMatchingGroups) == 0 {
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

	return allowedScopes, matchedGroups
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
	var groupsList []string
	var matchedGroups []string
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
		allowedScopes, matchedGroups := calculateAllowedScopes(user, groupsList)
		userInfo["g"] = matchedGroups
		userInfo["s"] = allowedScopes
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
		log.Debugf("Will proxy request to URL %s with user '%s' and groups '%s'", ctx.Request.URL.String(), user, strings.Join(matchedGroups, ","))
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
