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
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/spf13/afero"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	webdavHandlers  map[string]*webdav.Handler
	exportPrefixMap map[string]string // Maps federation prefix to storage prefix
)

// extractTokens extracts bearer tokens from the request
// Tokens can come from:
// 1. Authorization header (may have multiple comma-separated tokens)
// 2. Query parameter "access_token" (standard)
// 3. Query parameter "authz" (non-standard)
func extractTokens(r *http.Request) []string {
	tokens := make([]string, 0)
	
	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Split by comma to handle multiple tokens
		for _, part := range strings.Split(authHeader, ",") {
			part = strings.TrimSpace(part)
			// Case-insensitive bearer token extraction
			if len(part) > 7 && strings.ToLower(part[:7]) == "bearer " {
				token := strings.TrimSpace(part[7:])
				if token != "" {
					tokens = append(tokens, token)
				}
			}
		}
	}
	
	// Check query parameters
	query := r.URL.Query()
	if accessToken := query.Get("access_token"); accessToken != "" {
		tokens = append(tokens, accessToken)
	}
	if authzToken := query.Get("authz"); authzToken != "" {
		tokens = append(tokens, authzToken)
	}
	
	return tokens
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
		// Log the request
		log.Infof("Request: %s %s from %s", c.Request.Method, c.Request.URL.Path, c.ClientIP())
		
		tokens := extractTokens(c.Request)
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
		
		// If not public read, check authorization with each token
		if len(tokens) == 0 {
			log.Debugf("No token provided for %s %s", c.Request.Method, resource)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		
		// Try each token until one authorizes the request
		for _, token := range tokens {
			ctx, authorized := ac.authorizeWithContext(c.Request.Context(), action, resource, token)
			if authorized {
				c.Request = c.Request.WithContext(ctx)
				c.Next()
				return
			}
		}
		
		log.Debugf("Authorization failed for %s %s", c.Request.Method, resource)
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// InitializeHandlers initializes the WebDAV handlers for each export
func InitializeHandlers(exports []server_utils.OriginExport) error {
	webdavHandlers = make(map[string]*webdav.Handler)
	exportPrefixMap = make(map[string]string) // Initialize the global map
	
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
		exportPrefixMap[export.FederationPrefix] = export.StoragePrefix
		log.Infof("Initialized WebDAV handler for %s -> %s", export.FederationPrefix, export.StoragePrefix)
	}
	
	return nil
}

// RegisterHandlers registers the HTTP handlers with the Gin engine
func RegisterHandlers(engine *gin.Engine) error {
	// Initialize checksummer
	InitializeChecksummer()
	
	// Register handlers for each export
	for prefix, handler := range webdavHandlers {
		// Get the storage prefix for this federation prefix
		storagePrefix := exportPrefixMap[prefix]
		
		// Create a route group for this prefix
		group := engine.Group(prefix)
		group.Use(authMiddleware())
		
		// Custom HEAD handler to add checksums
		group.HEAD("/*path", func(c *gin.Context) {
			handleHeadWithChecksum(c, handler, storagePrefix)
		})
		
		// Register the WebDAV handler for all other HTTP methods
		group.Any("/*path", func(c *gin.Context) {
			// Skip if it's a HEAD request (already handled above)
			if c.Request.Method == http.MethodHead {
				c.Next()
				return
			}
			handler.ServeHTTP(c.Writer, c.Request)
		})
		
		log.Infof("Registered HTTP handlers for prefix: %s", prefix)
	}
	
	return nil
}

// handleHeadWithChecksum handles HEAD requests and adds checksum headers
func handleHeadWithChecksum(c *gin.Context, handler *webdav.Handler, storagePrefix string) {
	// First, let the WebDAV handler process the HEAD request normally
	handler.ServeHTTP(c.Writer, c.Request)
	
	// If successful, add checksum headers
	if c.Writer.Status() == http.StatusOK {
		// Get the relative path from the request
		relativePath := c.Param("path")
		
		// Construct the full filesystem path
		fullPath := path.Join(storagePrefix, relativePath)
		
		checksummer := GetChecksummer()
		
		// Add MD5 checksum header
		if md5sum, err := checksummer.GetChecksum(fullPath, ChecksumTypeMD5); err == nil {
			c.Header("Digest", "md5="+md5sum)
		}
		
		// Add SHA1 checksum header (alternative)
		if sha1sum, err := checksummer.GetChecksum(fullPath, ChecksumTypeSHA1); err == nil {
			c.Header("X-Checksum-Sha1", sha1sum)
		}
		
		// Add CRC32 checksum header
		if crc32sum, err := checksummer.GetChecksum(fullPath, ChecksumTypeCRC32); err == nil {
			c.Header("X-Checksum-Crc32", crc32sum)
		}
	}
}
