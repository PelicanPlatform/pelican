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

package origin_serve

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	webdavHandlers     map[string]*webdav.Handler
	exportPrefixMap    map[string]string // Maps federation prefix to storage prefix
	handlersRegistered bool              // Tracks whether handlers have been registered
)

// metricsResponseWriter wraps gin.ResponseWriter to track bytes written
type metricsResponseWriter struct {
	gin.ResponseWriter
	bytesWritten int64
}

func (mrw *metricsResponseWriter) Write(data []byte) (int, error) {
	n, err := mrw.ResponseWriter.Write(data)
	mrw.bytesWritten += int64(n)
	return n, err
}

func (mrw *metricsResponseWriter) WriteString(s string) (int, error) {
	n, err := mrw.ResponseWriter.WriteString(s)
	mrw.bytesWritten += int64(n)
	return n, err
}

// metricsRequestReader wraps http.Request.Body to track bytes read
type metricsRequestReader struct {
	reader    io.ReadCloser
	bytesRead int64
}

func (mrr *metricsRequestReader) Read(p []byte) (int, error) {
	n, err := mrr.reader.Read(p)
	mrr.bytesRead += int64(n)
	return n, err
}

func (mrr *metricsRequestReader) Close() error {
	return mrr.reader.Close()
}

// etagResponseWriter wraps http.ResponseWriter to ensure ETag, Last-Modified,
// and Cache-Control headers are set before response headers are flushed.
// The Cache-Control value is driven by the Origin.CacheControl configuration
// parameter.  When empty (the default), no Cache-Control header is set,
// matching the behaviour of a plain XRootD origin.
type etagResponseWriter struct {
	http.ResponseWriter
	etag         string
	lastModified string
	cacheControl string
	wroteHeader  bool
}

func (w *etagResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		if w.etag != "" {
			w.Header().Set("ETag", w.etag)
		}
		if w.lastModified != "" {
			w.Header().Set("Last-Modified", w.lastModified)
		}
		// Set Cache-Control for successful responses (2xx) and 304,
		// but only when the operator has configured a policy.
		if w.cacheControl != "" && ((code >= 200 && code < 300) || code == http.StatusNotModified) {
			w.Header().Set("Cache-Control", w.cacheControl)
		}
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *etagResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

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

	// Check query parameters (may be multi-valued)
	query := r.URL.Query()
	// Handle multi-valued access_token parameters
	for _, accessToken := range query["access_token"] {
		if accessToken != "" {
			tokens = append(tokens, accessToken)
		}
	}
	// Handle multi-valued authz parameters
	for _, authzToken := range query["authz"] {
		if authzToken != "" {
			tokens = append(tokens, authzToken)
		}
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
		resource = strings.TrimPrefix(resource, apiPrefix)
		ac := GetAuthConfig()
		if ac == nil {
			log.Error("Auth config not initialized")
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		// Check for public reads first
		isPublicRead := false
		exports := ac.exports.Load()
		if exports != nil && action == token_scopes.Wlcg_Storage_Read {
			for _, export := range *exports {
				if export.Capabilities.PublicReads && hasPathPrefix(resource, export.FederationPrefix) {
					isPublicRead = true
					break
				}
			}
		}

		disableDirectClients := param.Origin_DisableDirectClients.GetBool()

		// If DisableDirectClients is enabled, validate federation token presence
		var fedIssuers map[string]bool
		if disableDirectClients {
			fedInfo, err := config.GetFederation(c.Request.Context())
			if err != nil {
				log.Errorf("DisableDirectClients enabled but failed to get federation info: %v", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			fedIssuers = make(map[string]bool)
			if fedInfo.DiscoveryEndpoint != "" {
				fedIssuers[fedInfo.DiscoveryEndpoint] = true
			}
			// Also accept DirectorEndpoint because the director may create
			// federation tokens before the canonical discovery URL has been
			// established.  This is safe because the origin's own issuer URL
			// is now a distinct sub-path when co-located with the director.
			if fedInfo.DirectorEndpoint != "" {
				fedIssuers[fedInfo.DirectorEndpoint] = true
			}
			if len(fedIssuers) == 0 {
				log.Error("DisableDirectClients enabled but no federation issuer URLs configured")
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}

		// Try each token and collect authorization results.
		// When DisableDirectClients is enabled, we need both a user token
		// (authorizedContext) and a federation token (federationCtx).  The
		// federation token's issuer matches a known federation URL; any
		// other valid token is treated as the user token.
		var authorizedContext context.Context
		var federationCtx context.Context

		for _, tok := range tokens {
			ctx, authorized := ac.authorizeWithContext(c.Request.Context(), action, resource, tok)
			if authorized {
				isFedToken := false
				if disableDirectClients && len(fedIssuers) > 0 {
					issuer, ok := ctx.Value(issuerContextKey{}).(string)
					if ok && fedIssuers[issuer] {
						federationCtx = ctx
						isFedToken = true
					}
				}
				if !isFedToken {
					authorizedContext = ctx
				}
				if authorizedContext != nil && (!disableDirectClients || federationCtx != nil) {
					break // No need to check more tokens
				}
			}
		}

		// If DisableDirectClients is enabled, validate federation token requirements
		if disableDirectClients && federationCtx == nil {
			log.Debugf("DisableDirectClients requires federation token for %s %s", c.Request.Method, resource)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		// For non-public reads, require an authorized context
		// For public reads, the authorizedContext may be nil
		if !isPublicRead && authorizedContext == nil {
			log.Warningf("Authorization failed for %s %s - tried %d token(s)", c.Request.Method, resource, len(tokens))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		} else if authorizedContext != nil {
			c.Request = c.Request.WithContext(authorizedContext)
		}
		c.Next()
	}
}

// httpMetricsMiddleware tracks HTTP-level metrics for WebDAV requests
func httpMetricsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		method := c.Request.Method
		serverTypeOrigin := strings.ToLower(server_structs.OriginType.String())

		// Track active requests
		metrics.HttpActiveRequests.WithLabelValues(serverTypeOrigin, method).Inc()
		defer metrics.HttpActiveRequests.WithLabelValues(serverTypeOrigin, method).Dec()

		// Wrap request body to track bytes read
		mrr := &metricsRequestReader{reader: c.Request.Body}
		c.Request.Body = mrr

		// Wrap response writer to track bytes out
		mrw := &metricsResponseWriter{ResponseWriter: c.Writer}
		c.Writer = mrw

		// Process request
		c.Next()

		// Calculate duration
		duration := time.Since(start).Seconds()
		status := c.Writer.Status()
		statusStr := fmt.Sprintf("%d", status)

		// Track request completion
		metrics.HttpRequestsTotal.WithLabelValues(serverTypeOrigin, method, statusStr).Inc()
		metrics.HttpRequestDuration.WithLabelValues(serverTypeOrigin, method, statusStr).Observe(duration)

		// Track bytes in (actual bytes read from request body)
		if mrr.bytesRead > 0 {
			metrics.HttpBytesTotal.WithLabelValues(serverTypeOrigin, metrics.DirectionIn, method).Add(float64(mrr.bytesRead))
		}

		// Track bytes out
		if mrw.bytesWritten > 0 {
			metrics.HttpBytesTotal.WithLabelValues(serverTypeOrigin, metrics.DirectionOut, method).Add(float64(mrw.bytesWritten))
		}

		// Track large transfers (>100MB)
		if mrr.bytesRead >= metrics.LargeTransferThreshold {
			metrics.HttpLargeTransfersTotal.WithLabelValues(serverTypeOrigin, method).Inc()
			metrics.HttpLargeTransferBytes.WithLabelValues(serverTypeOrigin, metrics.DirectionIn, method).Add(float64(mrr.bytesRead))
		}
		if mrw.bytesWritten >= metrics.LargeTransferThreshold {
			metrics.HttpLargeTransfersTotal.WithLabelValues(serverTypeOrigin, method).Inc()
			metrics.HttpLargeTransferBytes.WithLabelValues(serverTypeOrigin, metrics.DirectionOut, method).Add(float64(mrw.bytesWritten))
		}

		// Track errors (5xx status codes)
		if status >= 500 && status < 600 {
			metrics.HttpErrorsTotal.WithLabelValues(serverTypeOrigin, method, statusStr).Inc()
		}
	}
}

// InitializeHandlers initializes the WebDAV handlers for each export
func InitializeHandlers(exports []server_utils.OriginExport) error {
	// Validate that if DisableDirectClients is enabled, no exports have DirectReads
	if param.Origin_DisableDirectClients.GetBool() {
		for _, export := range exports {
			if export.Capabilities.DirectReads {
				return fmt.Errorf("cannot enable DisableDirectClients with exports that have DirectReads capability (export: %s)", export.FederationPrefix)
			}
		}
	}

	webdavHandlers = make(map[string]*webdav.Handler)
	exportPrefixMap = make(map[string]string) // Initialize the global map

	// Get optional rate limit for testing
	readRateLimit := param.Origin_TransferRateLimit.GetByteRate()
	if readRateLimit > 0 {
		log.Infof("Applying read rate limit: %s", readRateLimit.String())
	}

	for _, export := range exports {
		// Create a filesystem for this export with auto-directory creation
		// Use OsRootFs to prevent symlink traversal attacks
		// OsRootFs is already rooted at StoragePrefix, so we don't need BasePathFs
		osRootFs, err := NewOsRootFs(export.StoragePrefix)
		if err != nil {
			return fmt.Errorf("failed to create OsRootFs for %s: %w", export.StoragePrefix, err)
		}

		// Apply rate limiting if configured (for testing)
		var fs afero.Fs = osRootFs
		if readRateLimit > 0 {
			fs = newRateLimitedFs(fs, readRateLimit)
		}

		fs = newAutoCreateDirFs(fs)

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
		group.Use(httpMetricsMiddleware())
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
			} else if c.Request.Method == http.MethodGet {
				// For GET requests, add ETag header based on file metadata
				handleGetWithETag(c, handler, modifiedReq, wildcardPath, storagePrefix)
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
	// Check if client requested checksums via Want-Digest header
	wantDigest := c.GetHeader("Want-Digest")
	if wantDigest == "" {
		// Default to MD5 if not specified
		wantDigest = "md5"
	}

	checksummer := GetChecksummer()
	digestValues := []string{}

	// Parse Want-Digest header into types and compute in bulk
	var types []ChecksumType
	for _, alg := range strings.Split(wantDigest, ",") {
		alg = strings.TrimSpace(strings.ToLower(alg))

		switch alg {
		case "md5":
			types = append(types, ChecksumTypeMD5)
		case "sha", "sha-1", "sha1":
			types = append(types, ChecksumTypeSHA1)
		case "crc32":
			types = append(types, ChecksumTypeCRC32)
		case "crc32c":
			types = append(types, ChecksumTypeCRC32C)
		default:
			continue
		}
	}

	// Use os.Root to prevent symlink attacks when accessing checksums
	// Open the storage root directory
	root, err := os.OpenRoot(storagePrefix)
	if err != nil {
		log.Debugf("Failed to open storage root for checksum: %v", err)
	} else {
		defer root.Close()

		if xc, ok := checksummer.(*XattrChecksummer); ok {
			// Normalize the path for os.Root (remove leading slash)
			normalizedPath := relativePath
			if len(normalizedPath) > 0 && normalizedPath[0] == '/' {
				normalizedPath = normalizedPath[1:]
			}

			if digests, err := xc.GetChecksumsRFC3230(root, normalizedPath, types); err == nil {
				digestValues = append(digestValues, digests...)
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

// computeETag generates an ETag string based on file metadata (mtime and size).
// This matches the default ETag format used by golang.org/x/net/webdav.
func computeETag(modTime int64, size int64) string {
	return fmt.Sprintf(`"%x%x"`, modTime, size)
}

// normalizeETag strips the weak validator prefix (W/) from an ETag for comparison.
// Per RFC 7232: For If-None-Match, weak comparison is used (ignores W/ prefix).
func normalizeETag(etag string) string {
	if strings.HasPrefix(etag, "W/") {
		return etag[2:]
	}
	return etag
}

// etagsMatch compares two ETags using weak comparison (suitable for If-None-Match).
// Per RFC 7232 Section 2.3.2: Two ETags are weakly equivalent if their opaque-tags
// match character-by-character, regardless of the weak indicator.
func etagsMatch(a, b string) bool {
	return normalizeETag(a) == normalizeETag(b)
}

// checkIfModifiedSince returns true if the resource has been modified since
// the time specified in the If-Modified-Since header.
// Returns false (304 should be sent) if the resource hasn't been modified.
func checkIfModifiedSince(r *http.Request, modTime time.Time) bool {
	ims := r.Header.Get("If-Modified-Since")
	if ims == "" {
		return true // No conditional, treat as modified
	}

	// Per HTTP spec, must use RFC 1123 date format
	t, err := http.ParseTime(ims)
	if err != nil {
		return true // Invalid date, treat as modified
	}

	// Compare at second precision (HTTP Date header precision)
	// Return false (not modified) if modTime <= ims
	return modTime.Truncate(time.Second).After(t.Truncate(time.Second))
}

// handleGetWithETag handles GET requests and adds ETag header for HTTP caching.
// It also handles conditional requests (If-None-Match, If-Modified-Since) returning 304 Not Modified.
// Per RFC 7232:
// - If-None-Match takes precedence over If-Modified-Since when both are present
// - If-None-Match compares ETags (strong or weak comparison depending on method)
// - If-Modified-Since compares modification times (only for GET/HEAD)
func handleGetWithETag(c *gin.Context, handler *webdav.Handler, modifiedReq *http.Request, relativePath string, storagePrefix string) {
	// Use os.Root to prevent symlink attacks
	root, err := os.OpenRoot(storagePrefix)
	if err != nil {
		log.Debugf("Failed to open storage root for ETag: %v", err)
		handler.ServeHTTP(c.Writer, modifiedReq)
		return
	}
	defer root.Close()

	// Normalize the path for os.Root (remove leading slash)
	normalizedPath := relativePath
	if len(normalizedPath) > 0 && normalizedPath[0] == '/' {
		normalizedPath = normalizedPath[1:]
	}

	// Stat the file to get mtime and size for ETag
	info, err := root.Stat(normalizedPath)
	if err != nil {
		// File doesn't exist or can't be accessed, let WebDAV handle the error
		handler.ServeHTTP(c.Writer, modifiedReq)
		return
	}

	// Don't set ETag for directories
	if info.IsDir() {
		handler.ServeHTTP(c.Writer, modifiedReq)
		return
	}

	modTime := info.ModTime()
	// Compute ETag based on mtime and size (same as WebDAV default)
	etag := computeETag(modTime.UnixNano(), info.Size())
	lastModifiedStr := modTime.UTC().Format(http.TimeFormat)

	// Check for conditional request (If-None-Match) - takes precedence per RFC 7232
	ifNoneMatch := modifiedReq.Header.Get("If-None-Match")
	if ifNoneMatch != "" {
		// Parse If-None-Match header (may contain multiple ETags)
		for _, match := range strings.Split(ifNoneMatch, ",") {
			match = strings.TrimSpace(match)
			// Handle weak ETag comparison (W/"..." prefix)
			// For GET/HEAD, weak comparison is used - strip W/ prefix for comparison
			compareETag := etag
			compareMatch := match
			if strings.HasPrefix(match, "W/") {
				compareMatch = match[2:]
			}
			if strings.HasPrefix(etag, "W/") {
				compareETag = etag[2:]
			}
			if match == "*" || compareMatch == compareETag {
				// ETag matches, return 304 Not Modified
				c.Header("ETag", etag)
				c.Header("Last-Modified", lastModifiedStr)
				if cc := param.Origin_CacheControl.GetString(); cc != "" {
					c.Header("Cache-Control", cc)
				}
				c.Writer.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	// Check for If-Modified-Since (only if If-None-Match not present or didn't match)
	// Per RFC 7232, If-Modified-Since is only evaluated if If-None-Match is absent
	ifModifiedSince := modifiedReq.Header.Get("If-Modified-Since")
	if ifNoneMatch == "" && ifModifiedSince != "" {
		// Parse the If-Modified-Since header (HTTP date format)
		ifModifiedTime, err := http.ParseTime(ifModifiedSince)
		if err == nil {
			// Truncate to seconds for comparison (HTTP dates have second precision)
			// Per RFC 7232: resource is considered not modified if the Last-Modified
			// time is less than or equal to the If-Modified-Since time
			if !modTime.Truncate(time.Second).After(ifModifiedTime.Truncate(time.Second)) {
				// Resource has not been modified
				c.Header("ETag", etag)
				c.Header("Last-Modified", lastModifiedStr)
				if cc := param.Origin_CacheControl.GetString(); cc != "" {
					c.Header("Cache-Control", cc)
				}
				c.Writer.WriteHeader(http.StatusNotModified)
				return
			}
		}
		// If parsing fails, ignore the header and serve content normally
	}

	// Use a wrapper to ensure ETag and Last-Modified headers are set before response
	// This is needed because the WebDAV handler may write headers before we can
	wrapper := &etagResponseWriter{
		ResponseWriter: c.Writer,
		etag:           etag,
		lastModified:   lastModifiedStr,
		cacheControl:   param.Origin_CacheControl.GetString(),
	}

	// Let WebDAV handler serve the content with our wrapped writer
	handler.ServeHTTP(wrapper, modifiedReq)
}
