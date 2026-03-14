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
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/afero"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/ssh_posixv2"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	backends           map[string]server_utils.OriginBackend
	webdavHandlers     map[string]*webdav.Handler
	exportPrefixMap    map[string]string // Maps federation prefix to storage prefix
	handlersRegistered bool              // Tracks whether handlers have been registered

	// globusBackends stores Globus v2 backends for token refresh management.
	globusBackends map[string]*globusBackend
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

func init() {
	// Register the reset callback with server_utils
	server_utils.RegisterPOSIXv2Reset(ResetHandlers)
}

// ResetHandlers resets the handler state (for testing)
func ResetHandlers() {
	backends = nil
	webdavHandlers = nil
	exportPrefixMap = nil
	handlersRegistered = false
	globusBackends = nil
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
		// Log the incoming request
		log.WithFields(log.Fields{
			"component": "origin",
			"method":    c.Request.Method,
			"resource":  c.Request.URL.Path,
			"client":    c.ClientIP(),
		}).Debug("Received Request")

		tokens := extractTokens(c.Request)
		action := getActionFromMethod(c.Request.Method)
		// Clean the request path to prevent path-traversal attacks
		// via URL-encoded dot segments (e.g., %2e%2e). Gin and Go's
		// net/http do NOT normalize these before reaching handlers.
		resource := path.Clean(c.Request.URL.Path)
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
		var fedDiscoveryURL string

		// If DisableDirectClients is enabled, validate federation token presence
		if disableDirectClients {
			fedInfo, err := config.GetFederation(c.Request.Context())
			if err != nil {
				log.Errorf("DisableDirectClients enabled but failed to get federation info: %v", err)
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
			fedDiscoveryURL = fedInfo.DiscoveryEndpoint
			if fedDiscoveryURL == "" {
				log.Error("DisableDirectClients enabled but federation discovery URL not configured")
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}
		}

		// Try each token and collect authorization results
		var authorizedContext context.Context
		var federationCtx context.Context

		for _, tok := range tokens {
			ctx, authorized := ac.authorizeWithContext(c.Request.Context(), action, resource, tok)
			if authorized {
				// Check if this token is from the federation issuer (for DisableDirectClients tracking)
				if disableDirectClients && fedDiscoveryURL != "" {
					issuer, ok := ctx.Value(issuerContextKey{}).(string)
					if ok && issuer == fedDiscoveryURL {
						federationCtx = ctx
					}
				} else {
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

		// For HTTPS passthrough backends, stash the client token in context
		// so the backend filesystem can forward it to the upstream server.
		if len(tokens) > 0 {
			ctx := WithClientToken(c.Request.Context(), tokens[0])
			c.Request = c.Request.WithContext(ctx)
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

	backends = make(map[string]server_utils.OriginBackend)
	webdavHandlers = make(map[string]*webdav.Handler)
	exportPrefixMap = make(map[string]string) // Initialize the global map
	globusBackends = make(map[string]*globusBackend)

	// Get optional rate limit for testing
	readRateLimit := param.Origin_TransferRateLimit.GetByteRate()
	if readRateLimit > 0 {
		log.Infof("Applying read rate limit: %s", readRateLimit.String())
	}

	// Determine storage type for filesystem creation
	storageType := server_structs.OriginStorageType(param.Origin_StorageType.GetString())

	for _, export := range exports {
		var backend server_utils.OriginBackend

		// Create logger function
		logger := func(r *http.Request, err error) {
			if err != nil {
				log.Debugf("WebDAV error for %s %s: %v", r.Method, r.URL.Path, err)
			}
		}

		switch storageType {
		case server_structs.OriginStorageSSH:
			// Use SSH filesystem that proxies to the remote helper
			sshBackend, err := ssh_posixv2.GetSSHBackend(export.FederationPrefix, export.StoragePrefix)
			if err != nil {
				return fmt.Errorf("failed to create SSH backend for %s: %w", export.FederationPrefix, err)
			}
			backend = sshBackend

		case server_structs.OriginStorageS3v2:
			// Native blob backend (S3, GCS, Azure) via gocloud.dev/blob
			blobURL := param.Origin_ObjectProviderURL.GetString()

			var blobOpts BlobBackendOptions
			if blobURL != "" {
				blobOpts = BlobBackendOptions{
					BlobURL:       blobURL,
					StoragePrefix: export.StoragePrefix,
				}
			} else {
				accessKey, secretKey, err := loadS3Credentials(export.S3AccessKeyfile, export.S3SecretKeyfile)
				if err != nil {
					return fmt.Errorf("failed to load S3 credentials for %s: %w", export.FederationPrefix, err)
				}
				s3ServiceURL := param.Origin_S3ServiceUrl.GetString()
				s3Region := param.Origin_S3Region.GetString()
				s3UrlStyle := param.Origin_S3UrlStyle.GetString()
				if s3UrlStyle == "" {
					s3UrlStyle = "path"
				}
				blobOpts = BlobBackendOptions{
					ServiceURL:    s3ServiceURL,
					Region:        s3Region,
					Bucket:        export.S3Bucket,
					AccessKey:     accessKey,
					SecretKey:     secretKey,
					URLStyle:      s3UrlStyle,
					StoragePrefix: export.StoragePrefix,
				}
			}
			blobBe, blobErr := newBlobBackend(blobOpts)
			if blobErr != nil {
				return fmt.Errorf("failed to create blob backend for %s: %w", export.FederationPrefix, blobErr)
			}
			backend = blobBe
			if blobURL != "" {
				log.Infof("Initialized blob backend for %s (url: %s)", export.FederationPrefix, blobURL)
			} else {
				log.Infof("Initialized native S3 backend for %s (bucket: %s, region: %s)", export.FederationPrefix, export.S3Bucket, param.Origin_S3Region.GetString())
			}

		case server_structs.OriginStorageHTTPSv2:
			// Native HTTPS/WebDAV backend (no XRootD)
			httpServiceURL := param.Origin_HttpServiceUrl.GetString()
			tokenMode := HTTPSTokenNone
			staticTokenFile := ""
			var oauth2Cfg *oauth2.Config
			var oauth2Tok *oauth2.Token

			// Determine token mode
			if param.Origin_HttpAuthTokenPassthrough.GetBool() {
				tokenMode = HTTPSTokenPassthrough
			} else if param.Origin_HttpAuthOAuth2ClientID.GetString() != "" {
				tokenMode = HTTPSTokenOAuth2

				secretFile := param.Origin_HttpAuthOAuth2ClientSecretFile.GetString()
				if secretFile == "" {
					return fmt.Errorf("Origin.HttpAuthOAuth2ClientSecretFile must be set when Origin.HttpAuthOAuth2ClientID is configured")
				}
				secretBytes, rErr := os.ReadFile(secretFile)
				if rErr != nil {
					return fmt.Errorf("failed to read OAuth2 client secret file %s: %w", secretFile, rErr)
				}

				issuerUrl := param.Origin_HttpAuthOAuth2Issuer.GetString()
				if issuerUrl == "" {
					return fmt.Errorf("Origin.HttpAuthOAuth2Issuer must be set when Origin.HttpAuthOAuth2ClientID is configured")
				}
				issuerMeta, dErr := config.GetIssuerMetadata(issuerUrl)
				if dErr != nil {
					return fmt.Errorf("failed to discover OAuth2 metadata from issuer %s: %w", issuerUrl, dErr)
				}
				if issuerMeta.TokenURL == "" {
					return fmt.Errorf("OAuth2 issuer %s did not advertise a token_endpoint", issuerUrl)
				}

				oauth2Cfg = &oauth2.Config{
					ClientID:     param.Origin_HttpAuthOAuth2ClientID.GetString(),
					ClientSecret: strings.TrimSpace(string(secretBytes)),
					Endpoint: oauth2.Endpoint{
						TokenURL: issuerMeta.TokenURL,
					},
				}
				// For client_credentials flow, create an initial token that will be refreshed
				oauth2Tok = &oauth2.Token{}
			} else if param.Origin_HttpAuthTokenFile.GetString() != "" {
				tokenMode = HTTPSTokenStatic
				staticTokenFile = param.Origin_HttpAuthTokenFile.GetString()
			}

			backend = newHTTPSBackend(HTTPSBackendOptions{
				ServiceURL:      httpServiceURL,
				StoragePrefix:   export.StoragePrefix,
				TokenMode:       tokenMode,
				StaticTokenFile: staticTokenFile,
				OAuth2Config:    oauth2Cfg,
				OAuth2Token:     oauth2Tok,
				EnableAutoMkdir: true,
			})
			log.Infof("Initialized native HTTPS backend for %s (upstream: %s, token mode: %d)", export.FederationPrefix, httpServiceURL, tokenMode)

		case server_structs.OriginStorageGlobusv2:
			// Native Globus backend (no XRootD)
			// The Globus backend is initialized in two phases:
			// 1. Here we create the backend structure
			// 2. In OriginServe, Globus tokens are loaded and the backend is activated
			gb := NewGlobusBackend(GlobusBackendConfig{
				CollectionID:  export.GlobusCollectionID,
				StoragePrefix: export.StoragePrefix,
			})
			backend = gb
			globusBackends[export.GlobusCollectionID] = gb
			log.Infof("Initialized native Globus backend for %s (collection: %s)", export.FederationPrefix, export.GlobusCollectionID)

		default:
			// Use local filesystem (POSIXv2)
			// Create a filesystem for this export with auto-directory creation
			// Use OsRootFs to prevent symlink traversal attacks
			// OsRootFs is already rooted at StoragePrefix, so we don't need BasePathFs
			osRootFs, err := server_utils.NewOsRootFs(export.StoragePrefix)
			if err != nil {
				return fmt.Errorf("failed to create OsRootFs for %s: %w", export.StoragePrefix, err)
			}

			// Apply rate limiting if configured (for testing)
			var localFs afero.Fs = osRootFs
			if readRateLimit > 0 {
				localFs = newRateLimitedFs(localFs, readRateLimit)
			}

			autoFs := newAutoCreateDirFs(localFs)
			fs := newAferoFileSystem(autoFs, "", logger)
			backend = newLocalBackend(fs, export.StoragePrefix)
		}

		// Create a WebDAV handler
		handler := &webdav.Handler{
			FileSystem: backend.FileSystem(),
			LockSystem: webdav.NewMemLS(),
			Logger:     logger,
		}

		backends[export.FederationPrefix] = backend
		webdavHandlers[export.FederationPrefix] = handler
		exportPrefixMap[export.FederationPrefix] = export.StoragePrefix
		log.Infof("Initialized WebDAV handler for %s -> %s (storage: %s)", export.FederationPrefix, export.StoragePrefix, storageType)
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

	// Register handlers for each export
	for prefix, handler := range webdavHandlers {
		backend := backends[prefix]

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
			// Ask the backend whether it can serve requests right now.
			if err := backend.CheckAvailability(); err != nil {
				statusCode := http.StatusServiceUnavailable
				if sc, ok := err.(server_utils.HTTPStatusCoder); ok {
					statusCode = sc.HTTPStatusCode()
				}
				c.AbortWithStatusJSON(statusCode, gin.H{"error": err.Error()})
				return
			}

			// Get the path relative to the export (strip the federation prefix)
			wildcardPath := c.Param("path")

			// Clean the path to prevent traversal attacks via
			// URL-encoded dot-dot sequences (%2e%2e). Without
			// this, a request like /prefix/%2e%2e/secret reaches
			// the backend with ".." intact, potentially escaping
			// the storage root.
			newPath := path.Clean(wildcardPath)

			// Create a shallow copy of the request and modify its URL
			modifiedReq := c.Request.Clone(c.Request.Context())
			modifiedURL := *c.Request.URL
			modifiedURL.Path = newPath
			modifiedReq.URL = &modifiedURL

			// Stash client tracing headers (X-Pelican-JobId,
			// X-Pelican-Timeout) in the request context so backends
			// that forward requests can propagate them.
			modifiedReq = server_utils.StashPelicanHeaders(modifiedReq)

			// For PUT requests, pass the Content-Length as a size hint
			// so the blob backend can optimize upload part sizes.
			if c.Request.Method == http.MethodPut && c.Request.ContentLength > 0 {
				ctx := ContextWithContentLength(modifiedReq.Context(), c.Request.ContentLength)
				modifiedReq = modifiedReq.WithContext(ctx)
			}

			if c.Request.Method == http.MethodHead {
				handleHeadWithChecksum(c, handler, modifiedReq, wildcardPath, backend)
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
func handleHeadWithChecksum(c *gin.Context, handler *webdav.Handler, modifiedReq *http.Request, relativePath string, backend server_utils.OriginBackend) {
	// Check if client requested checksums via Want-Digest header
	wantDigest := c.GetHeader("Want-Digest")
	if wantDigest == "" {
		// Default to MD5 if not specified
		wantDigest = "md5"
	}

	// Ask the backend for digest values.  Backends that do not support
	// checksums (e.g. SSH) return a nil Checksummer.
	if cs := backend.Checksummer(); cs != nil {
		digests, err := cs.GetDigests(relativePath, wantDigest)
		if err != nil {
			log.Debugf("Failed to compute checksums for %s: %v", relativePath, err)
		} else if len(digests) > 0 {
			c.Header("Digest", strings.Join(digests, ","))
		}
	}

	// Now let the WebDAV handler process the HEAD request
	handler.ServeHTTP(c.Writer, modifiedReq)
}
