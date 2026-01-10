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
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	webdavHandlers     map[string]*webdav.Handler
	exportPrefixMap    map[string]string // Maps federation prefix to storage prefix
	handlersRegistered bool              // Tracks whether handlers have been registered
)

func init() {
	// Register the reset callback with server_utils
	server_utils.RegisterPOSIXv2Reset(ResetHandlers)
}

// ResetHandlers resets the handler state (for testing)
func ResetHandlers() {
	webdavHandlers = nil
	exportPrefixMap = nil
	handlersRegistered = false
	globalChecksummer = nil
}

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
		// Strip the /api/v1.0/origin/data prefix if present
		// This happens when the director is co-located with the origin
		// Token scopes are always for the federation prefix (e.g., /test/...),
		// not the HTTP route prefix
		const apiPrefix = "/api/v1.0/origin/data"
		if strings.HasPrefix(resource, apiPrefix) {
			resource = strings.TrimPrefix(resource, apiPrefix)
		}
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
					ui := &userInfo{
						User:   "nobody",
						Groups: []string{},
					}
					ctx := setUserInfo(c.Request.Context(), ui)
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

		log.Warningf("Authorization failed for %s %s - tried %d token(s)", c.Request.Method, resource, len(tokens))
		c.AbortWithStatus(http.StatusForbidden)
	}
}

// InitializeHandlers initializes the WebDAV handlers for each export
func InitializeHandlers(exports []server_utils.OriginExport) error {
	webdavHandlers = make(map[string]*webdav.Handler)
	exportPrefixMap = make(map[string]string) // Initialize the global map

	for _, export := range exports {
		// Create a filesystem for this export with auto-directory creation
		baseFs := afero.NewBasePathFs(afero.NewOsFs(), export.StoragePrefix)
		fs := newAutoCreateDirFs(baseFs)

		// Create logger function
		logger := func(r *http.Request, err error) {
			if err != nil {
				log.Debugf("WebDAV error for %s %s: %v", r.Method, r.URL.Path, err)
			}
		}

		afs := newAferoFileSystem(fs, "", logger)

		// Create a WebDAV handler
		handler := &webdav.Handler{
			FileSystem: afs,
			LockSystem: webdav.NewMemLS(),
			Logger:     logger,
		}

		webdavHandlers[export.FederationPrefix] = handler
		exportPrefixMap[export.FederationPrefix] = export.StoragePrefix
		log.Infof("Initialized WebDAV handler for %s -> %s", export.FederationPrefix, export.StoragePrefix)
	}

	return nil
}

// RegisterHandlers registers the HTTP handlers with the Gin engine.
// When the director is also running in the same server, handlers are registered
// under /api/v1.0/origin/<prefix> so the director can distinguish between its routing
// and the origin's file serving. Otherwise, handlers are registered directly at the
// federation prefix for standalone origins.
func RegisterHandlers(engine *gin.Engine, directorEnabled bool) error {
	// Prevent double registration when both director and POSIXv2 origin are running
	if handlersRegistered {
		log.Debug("POSIXv2 handlers already registered, skipping")
		return nil
	}

	// Initialize checksummer
	InitializeChecksummer()

	// Register handlers for each export
	for prefix, handler := range webdavHandlers {
		// Get the storage prefix for this federation prefix
		storagePrefix := exportPrefixMap[prefix]

		// When director is enabled, register under /api/v1.0/origin/data/<prefix>
		// This allows the director to distinguish between routing requests and origin file serving
		var routePrefix string
		if directorEnabled {
			routePrefix = "/api/v1.0/origin/data" + prefix
		} else {
			routePrefix = prefix
		}

		// Create a route group for this prefix
		group := engine.Group(routePrefix)
		group.Use(authMiddleware())

		// Create a handler function for all requests
		handleRequest := func(c *gin.Context) {
			// Get the path relative to the export (strip the federation prefix)
			wildcardPath := c.Param("path")

			// The wildcardPath is relative to the federation prefix (e.g., /test)
			// Pass only the wildcardPath to WebDAV so it writes relative to storage root
			newPath := wildcardPath

			// Create a shallow copy of the request and modify its URL
			modifiedReq := c.Request.Clone(c.Request.Context())
			modifiedURL := *c.Request.URL
			modifiedURL.Path = newPath
			modifiedReq.URL = &modifiedURL

			if c.Request.Method == http.MethodHead {
				// Pass the modified request and file path info to handleHeadWithChecksum
				handleHeadWithChecksum(c, handler, modifiedReq, wildcardPath, storagePrefix)
			} else {
				handler.ServeHTTP(c.Writer, modifiedReq)
			}
		}

		// Register handler for standard HTTP methods
		group.Any("/*path", handleRequest)

		// Register handler for WebDAV methods (not covered by Any())
		group.Handle("PROPFIND", "/*path", handleRequest)
		group.Handle("PROPPATCH", "/*path", handleRequest)
		group.Handle("MKCOL", "/*path", handleRequest)
		group.Handle("COPY", "/*path", handleRequest)
		group.Handle("MOVE", "/*path", handleRequest)
		group.Handle("LOCK", "/*path", handleRequest)
		group.Handle("UNLOCK", "/*path", handleRequest)

		log.Infof("Registered HTTP handlers for prefix: %s (route: %s)", prefix, routePrefix)
	}

	handlersRegistered = true
	return nil
}

// handleHeadWithChecksum handles HEAD requests and adds checksum headers per RFC 3230
func handleHeadWithChecksum(c *gin.Context, handler *webdav.Handler, modifiedReq *http.Request, relativePath string, storagePrefix string) {
	// Compute checksums BEFORE processing the HEAD request so we can add headers
	fullPath := filepath.Join(storagePrefix, relativePath)

	// Check if client requested checksums via Want-Digest header
	wantDigest := c.GetHeader("Want-Digest")
	if wantDigest == "" {
		// Default to MD5 if not specified
		wantDigest = "md5"
	}

	checksummer := GetChecksummer()
	digestValues := []string{}

	// Parse Want-Digest header and compute requested checksums
	for _, alg := range strings.Split(wantDigest, ",") {
		alg = strings.TrimSpace(strings.ToLower(alg))

		var checksumType ChecksumType
		switch alg {
		case "md5":
			checksumType = ChecksumTypeMD5
		case "sha", "sha-1", "sha1":
			checksumType = ChecksumTypeSHA1
		case "crc32":
			checksumType = ChecksumTypeCRC32
		case "crc32c":
			checksumType = ChecksumTypeCRC32C
		default:
			continue
		}

		if xc, ok := checksummer.(*XattrChecksummer); ok {
			if digest, err := xc.GetChecksumRFC3230(fullPath, checksumType); err == nil {
				digestValues = append(digestValues, digest)
			}
		}
	}

	// Set Digest header BEFORE calling WebDAV handler
	if len(digestValues) > 0 {
		c.Header("Digest", strings.Join(digestValues, ","))
	}

	// Now let the WebDAV handler process the HEAD request
	handler.ServeHTTP(c.Writer, modifiedReq)
}
