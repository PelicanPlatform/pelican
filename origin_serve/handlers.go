/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package origin_serve

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/afero"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	webdavHandlers map[string]*webdav.Handler
)

// extractToken extracts the bearer token from the request
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	
	return parts[1]
}

// getActionFromMethod determines the token scope action from HTTP method
func getActionFromMethod(method string) token_scopes.TokenScope {
	switch method {
	case http.MethodGet, http.MethodHead:
		return token_scopes.Wlcg_Storage_Read
	case http.MethodPut, http.MethodPost:
		return token_scopes.Wlcg_Storage_Create
	case http.MethodDelete:
		return token_scopes.Wlcg_Storage_Modify
	case "PROPFIND":
		return token_scopes.Wlcg_Storage_Read
	default:
		return token_scopes.Wlcg_Storage_Read
	}
}

// authMiddleware handles token-based authorization
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractToken(c.Request)
		action := getActionFromMethod(c.Request.Method)
		resource := c.Request.URL.Path
		
		ac := GetAuthConfig()
		if ac == nil {
			log.Error("Auth config not initialized")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		
		// Check for public reads first
		exports := ac.exports.Load()
		if exports != nil && action == token_scopes.Wlcg_Storage_Read {
			for _, export := range *exports {
				if export.Capabilities.PublicReads && strings.HasPrefix(resource, export.FederationPrefix) {
					// Allow public reads without token
					userInfo := &UserInfo{
						User:   "nobody",
						Groups: []string{},
					}
					ctx := SetUserInfo(c.Request.Context(), userInfo)
					c.Request = c.Request.WithContext(ctx)
					c.Next()
					return
				}
			}
		}
		
		// If not public read, check authorization
		if token == "" {
			log.Debugf("No token provided for %s %s", c.Request.Method, resource)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		
		if !ac.authorize(action, resource, token) {
			log.Debugf("Authorization failed for %s %s", c.Request.Method, resource)
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		
		// TODO: Extract user and group information from the token and add to context
		// For now, we'll use a placeholder
		userInfo := &UserInfo{
			User:   "nobody",
			Groups: []string{},
		}
		
		// Add user info to the request context
		ctx := SetUserInfo(c.Request.Context(), userInfo)
		c.Request = c.Request.WithContext(ctx)
		
		c.Next()
	}
}

// InitializeHandlers initializes the WebDAV handlers for each export
func InitializeHandlers(exports []server_utils.OriginExport) error {
	webdavHandlers = make(map[string]*webdav.Handler)
	
	for _, export := range exports {
		// Create a filesystem for this export
		fs := afero.NewBasePathFs(afero.NewOsFs(), export.StoragePrefix)
		afs := newAferoFileSystem(fs, "")
		
		// Create a WebDAV handler
		handler := &webdav.Handler{
			FileSystem: afs,
			LockSystem: webdav.NewMemLS(),
			Logger: func(r *http.Request, err error) {
				if err != nil {
					log.Debugf("WebDAV error for %s %s: %v", r.Method, r.URL.Path, err)
				}
			},
		}
		
		webdavHandlers[export.FederationPrefix] = handler
		log.Infof("Initialized WebDAV handler for %s -> %s", export.FederationPrefix, export.StoragePrefix)
	}
	
	return nil
}

// RegisterHandlers registers the HTTP handlers with the Gin engine
func RegisterHandlers(engine *gin.Engine) error {
	// Register handlers for each export
	for prefix, handler := range webdavHandlers {
		// Create a route group for this prefix
		group := engine.Group(prefix)
		group.Use(authMiddleware())
		
		// Register the WebDAV handler for all HTTP methods
		group.Any("/*path", func(c *gin.Context) {
			handler.ServeHTTP(c.Writer, c.Request)
		})
		
		log.Infof("Registered HTTP handlers for prefix: %s", prefix)
	}
	
	return nil
}
