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

package local_cache

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/error_codes"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// isConnectionError checks if an error is a connection error (reset, refused, etc.)
// that should be treated as a gateway timeout
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for common connection error patterns
	return strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "i/o timeout")
}

// trailerWriter wraps http.ResponseWriter to track write errors for trailer support.
// When sendTrailer is true, it suppresses the Content-Length header that
// http.ServeContent sets.  Without Content-Length, Go's HTTP server uses
// chunked transfer-encoding, which is required for HTTP/1.1 trailers.
type trailerWriter struct {
	http.ResponseWriter
	writeErr    *error
	sendTrailer bool
}

func (tw *trailerWriter) Header() http.Header {
	return tw.ResponseWriter.Header()
}

func (tw *trailerWriter) WriteHeader(code int) {
	if tw.sendTrailer {
		// Remove Content-Length to force chunked transfer-encoding,
		// which is required for HTTP/1.1 trailers.
		tw.ResponseWriter.Header().Del("Content-Length")
	}
	tw.ResponseWriter.WriteHeader(code)
}

func (tw *trailerWriter) Write(p []byte) (int, error) {
	n, err := tw.ResponseWriter.Write(p)
	if err != nil && *tw.writeErr == nil {
		*tw.writeErr = err
	}
	return n, err
}

// Unwrap exposes the underlying ResponseWriter so that Go's HTTP server can
// discover optional interfaces (http.Flusher, http.Hijacker, etc.) even
// when the writer is wrapped.
func (tw *trailerWriter) Unwrap() http.ResponseWriter {
	return tw.ResponseWriter
}

// errorTrackingReader wraps an io.ReadSeeker and records the first read error.
// This is needed because http.ServeContent uses io.CopyN internally and
// discards the return value, so read-side errors (e.g. AES-GCM authentication
// failures from corrupted data) are silently lost.  By wrapping the reader we
// can surface these errors in the X-Transfer-Status trailer.
type errorTrackingReader struct {
	io.ReadSeeker
	readErr *error
}

func (etr *errorTrackingReader) Read(p []byte) (int, error) {
	n, err := etr.ReadSeeker.Read(p)
	if err != nil && err != io.EOF && *etr.readErr == nil {
		*etr.readErr = err
	}
	return n, err
}

// handleError writes an appropriate HTTP error response based on the error type
func handleError(w http.ResponseWriter, getErr error, sendTrailer bool) {
	if errors.Is(getErr, authorizationDenied) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Authorization Denied")); err != nil {
			log.Errorln("Failed to write authorization denied to client")
		}
		return
	} else if errors.Is(getErr, context.DeadlineExceeded) {
		w.WriteHeader(http.StatusGatewayTimeout)
		if _, err := w.Write([]byte("Upstream response timeout")); err != nil {
			log.Errorln("Failed to write gateway timeout to client")
		}
		return
	}

	log.Errorln("Failed to get file from cache:", getErr)
	var sce *client.StatusCodeError
	var pe *error_codes.PelicanError
	var netErr net.Error
	if errors.As(getErr, &sce) {
		w.WriteHeader(int(*sce))
	} else if errors.As(getErr, &pe) {
		// Map Pelican error codes to HTTP status codes
		switch pe.Code() {
		case 5011: // FileNotFound
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else if errors.As(getErr, &netErr) && netErr.Timeout() {
		// Network timeout errors should return 504 Gateway Timeout
		w.WriteHeader(http.StatusGatewayTimeout)
		if _, err := w.Write([]byte("Upstream timeout")); err != nil {
			log.Errorln("Failed to write gateway timeout message to client")
		}
	} else if isConnectionError(getErr) {
		// Connection errors (reset, refused) should also return 504
		w.WriteHeader(http.StatusGatewayTimeout)
		if _, err := w.Write([]byte("Upstream connection error")); err != nil {
			log.Errorln("Failed to write gateway timeout message to client")
		}
	} else {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte("Unexpected internal error")); err != nil {
			log.Errorln("Failed to write internal error message to client")
		}
	}
}

// requestOnlyIfCached returns true when the client indicates it only wants a
// stored (cached) response.  This is signalled by the standard
// Cache-Control: only-if-cached directive (RFC 7234 §5.2.1.7) or by the
// legacy X-Pelican-NoDownload: true header.
func requestOnlyIfCached(r *http.Request) bool {
	if r.Header.Get("X-Pelican-NoDownload") == "true" {
		return true
	}
	for _, v := range r.Header.Values("Cache-Control") {
		for _, dir := range strings.Split(v, ",") {
			if strings.TrimSpace(dir) == "only-if-cached" {
				return true
			}
		}
	}
	return false
}

// serveObject is the shared request handler for both the Unix-socket listener
// and the Gin-based cache endpoint.  It handles GET, HEAD, and PROPFIND
// requests for cached objects including:
//   - Authorization checking
//   - X-Transfer-Status trailer support
//   - X-Pelican-Timeout request timeout
//   - HEAD: stat-only (never downloads); with Cache-Control: only-if-cached returns 504 on miss
//   - If-None-Match / ETag conditional responses (304)
//   - Cache-Control / Age response headers from stored metadata
//   - No-store streaming (io.Copy) for non-seekable responses
//   - Range requests via http.ServeContent for seekable responses
func (pc *PersistentCache) serveObject(w http.ResponseWriter, r *http.Request) {
	authzHeader := r.Header.Get("Authorization")
	bearerToken := ""
	if strings.HasPrefix(authzHeader, "Bearer ") {
		bearerToken = authzHeader[7:] // len("Bearer ") == 7
	}
	objectPath := path.Clean(r.URL.Path)

	// Handle PROPFIND requests (directory listings) - proxy to origin
	if r.Method == "PROPFIND" {
		pc.proxyPropfind(w, r, objectPath, bearerToken)
		return
	}

	// Handle write-through requests (PUT, DELETE) - proxy to origin
	if r.Method == "PUT" || r.Method == "DELETE" {
		pc.proxyWrite(w, r, objectPath, bearerToken)
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	transferStatusStr := r.Header.Get("X-Transfer-Status")
	sendTrailer := false
	if transferStatusStr == "true" {
		// HTTP/2 natively supports trailers; HTTP/1.1 requires TE: trailers.
		if r.ProtoMajor >= 2 {
			sendTrailer = true
			w.Header().Set("Trailer", "X-Transfer-Status")
		} else {
			for _, encoding := range r.Header.Values("TE") {
				if encoding == "trailers" {
					sendTrailer = true
					w.Header().Set("Trailer", "X-Transfer-Status")
					break
				}
			}
		}
	}

	var headerTimeout time.Duration
	timeoutStr := r.Header.Get("X-Pelican-Timeout")
	if timeoutStr != "" {
		if ht, parseErr := time.ParseDuration(timeoutStr); parseErr != nil {
			log.Debugln("Invalid X-Pelican-Timeout value:", timeoutStr)
		} else {
			headerTimeout = ht
		}
	}
	log.Debugln("Setting header timeout:", timeoutStr)

	// Handle HEAD requests: never trigger a download.
	// With only-if-cached: return 504 on cache miss (RFC 7234 §5.2.1.7).
	// Without: query the origin for size if not cached.
	if r.Method == "HEAD" {
		if requestOnlyIfCached(r) {
			size, statErr := pc.StatCachedOnly(objectPath, bearerToken)
			if errors.Is(statErr, ErrNotCached) {
				w.WriteHeader(http.StatusGatewayTimeout)
				return
			} else if errors.Is(statErr, authorizationDenied) {
				w.WriteHeader(http.StatusForbidden)
				if _, err := w.Write([]byte("Authorization Denied")); err != nil {
					log.Errorln("Failed to write authorization denied to client")
				}
				return
			} else if statErr != nil {
				handleError(w, statErr, sendTrailer)
				return
			}
			w.Header().Set("Content-Length", strconv.FormatUint(size, 10))
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusOK)
			return
		}

		// Plain HEAD — stat only, no download.
		result, headErr := pc.HeadObject(objectPath, bearerToken)
		if errors.Is(headErr, authorizationDenied) {
			w.WriteHeader(http.StatusForbidden)
			return
		} else if headErr != nil {
			handleError(w, headErr, sendTrailer)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(result.ContentLength, 10))
		w.Header().Set("Accept-Ranges", "bytes")
		if result.Meta != nil {
			if result.Meta.ETag != "" {
				w.Header().Set("ETag", result.Meta.ETag)
			}
			w.Header().Set("Cache-Control", result.Meta.ResponseCacheControl())
			if !result.Meta.Completed.IsZero() {
				age := int(time.Since(result.Meta.Completed).Seconds())
				if age >= 0 {
					w.Header().Set("Age", strconv.Itoa(age))
				}
			}
		} else {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	// Handle Cache-Control: only-if-cached for GET requests (RFC 7234 §5.2.1.7).
	// Return the cached object if present, or 504 Gateway Timeout if not.
	if requestOnlyIfCached(r) {
		size, statErr := pc.StatCachedOnly(objectPath, bearerToken)
		if errors.Is(statErr, ErrNotCached) {
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		} else if errors.Is(statErr, authorizationDenied) {
			w.WriteHeader(http.StatusForbidden)
			return
		} else if statErr != nil {
			handleError(w, statErr, sendTrailer)
			return
		}
		// Object is cached — fall through to the normal GET path which will
		// serve it from cache without contacting the origin.
		_ = size
	}

	// Create request context with optional timeout (GET only from here)
	reqCtx := context.Background()
	if headerTimeout > 0 {
		var cancelReqFunc context.CancelFunc
		reqCtx, cancelReqFunc = context.WithTimeout(reqCtx, headerTimeout)
		defer cancelReqFunc()
	}

	// Get seekable reader for the object (handles on-demand fetching).
	// When the client sent a Range header, tell the cache so that on a
	// miss it can use a lightweight HEAD + on-demand block fetch instead
	// of a full sequential download from the origin.
	reader, meta, getErr := pc.GetSeekableReader(reqCtx, objectPath, bearerToken, r.Header.Get("Range") != "")
	if getErr != nil {
		handleError(w, getErr, sendTrailer)
		return
	}
	defer reader.Close()

	// Set cache-related headers from metadata
	if meta != nil {
		// Set Age header (time since object was cached)
		if !meta.Completed.IsZero() {
			age := int(time.Since(meta.Completed).Seconds())
			if age >= 0 {
				w.Header().Set("Age", strconv.Itoa(age))
			}
		}

		// Set ETag header if available
		if meta.ETag != "" {
			w.Header().Set("ETag", meta.ETag)
		}

		// Handle If-None-Match conditional request (http.ServeContent doesn't handle this)
		if meta.ETag != "" {
			ifNoneMatch := r.Header.Get("If-None-Match")
			if ifNoneMatch != "" {
				// Parse If-None-Match header (may contain multiple ETags)
				for _, match := range strings.Split(ifNoneMatch, ",") {
					match = strings.TrimSpace(match)
					if match == "*" || match == meta.ETag {
						// ETag matches, return 304 Not Modified
						w.Header().Set("Cache-Control", meta.ResponseCacheControl())
						w.WriteHeader(http.StatusNotModified)
						return
					}
				}
			}
		}
	}

	// Set Cache-Control header from stored metadata or use sensible default.
	// This must be set before http.ServeContent since it may return 304 for If-Modified-Since.
	if meta != nil {
		w.Header().Set("Cache-Control", meta.ResponseCacheControl())
	} else {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	}

	// For no-store streaming responses the reader is not seekable, so we
	// cannot use http.ServeContent (which calls Seek).  Stream directly
	// with io.Copy and set the response headers manually.
	if reader.IsNoStore() {
		contentLen := reader.ContentLength()
		if contentLen > 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(contentLen, 10))
		}
		w.Header().Set("Accept-Ranges", "none")
		w.WriteHeader(http.StatusOK)

		var writeErr error
		if _, err := io.Copy(w, reader); err != nil {
			writeErr = err
		}
		if sendTrailer {
			trailerVal := "200: OK"
			if writeErr != nil {
				trailerVal = fmt.Sprintf("%d: %s", 500, writeErr)
			}
			w.Header().Set("X-Transfer-Status", trailerVal)
		}
		return
	}

	// Use http.ServeContent which handles:
	// - Range requests (bytes=start-end)
	// - If-Modified-Since conditional requests
	// - Content-Length, Content-Type detection
	// - Proper status codes (200, 206, 304, 416)
	// Note: It does NOT handle If-None-Match (ETag-based), which we handle above
	var modTime time.Time
	if meta != nil && !meta.LastModified.IsZero() {
		modTime = meta.LastModified
	}

	// Create wrappers that track errors for trailer support.
	// - trailerWriter captures write-side errors (e.g. client disconnect)
	//   and suppresses Content-Length when sendTrailer is true so that
	//   Go uses chunked transfer-encoding (required for HTTP/1.1 trailers).
	// - errorTrackingReader captures read-side errors (e.g. AES-GCM
	//   authentication failure from corrupted data) that http.ServeContent
	//   would otherwise silently discard.
	var writeErr, readErr error
	wrappedWriter := &trailerWriter{
		ResponseWriter: w,
		writeErr:       &writeErr,
		sendTrailer:    sendTrailer,
	}
	wrappedReader := &errorTrackingReader{
		ReadSeeker: reader,
		readErr:    &readErr,
	}

	http.ServeContent(wrappedWriter, r, objectPath, modTime, wrappedReader)

	if sendTrailer {
		trailerVal := "200: OK"
		if writeErr != nil {
			trailerVal = fmt.Sprintf("%d: %s", 500, writeErr)
		} else if readErr != nil {
			trailerVal = fmt.Sprintf("%d: %s", 500, readErr)
		}
		w.Header().Set("X-Transfer-Status", trailerVal)
	}
}

// proxyPropfind forwards a PROPFIND request to the origin server.
// Directory listings are NOT cached; they always go to the origin.
func (pc *PersistentCache) proxyPropfind(w http.ResponseWriter, r *http.Request, objectPath string, bearerToken string) {
	// Check authorization
	if !pc.ac.authorize("storage.read", objectPath, bearerToken) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Authorization Denied")); err != nil {
			log.Errorln("Failed to write authorization denied to client")
		}
		return
	}

	// Build origin URL from director URL
	if pc.directorURL == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte("Cache not configured")); err != nil {
			log.Errorln("Failed to write service unavailable to client")
		}
		return
	}

	// Route through the director's origin endpoint so it redirects to the
	// origin without requiring the DirectReads capability.
	originURL := *pc.directorURL
	originURL.Path = path.Join("/api/v1.0/director/origin", objectPath)
	originURL.Scheme = "https"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyReq, err := http.NewRequestWithContext(ctx, "PROPFIND", originURL.String(), r.Body)
	if err != nil {
		log.Errorln("Failed to create PROPFIND request:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send the user's token to the director via Authorization header.
	// The federation token is added to the redirect URL (not the
	// director request) in CheckRedirect below.
	if bearerToken != "" {
		proxyReq.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	fedToken := pc.getFedToken()
	if depth := r.Header.Get("Depth"); depth != "" {
		proxyReq.Header.Set("Depth", depth)
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		proxyReq.Header.Set("Content-Type", contentType)
	}

	// Make the request.  The director 307-redirects to the origin (a
	// different host), so Go's default redirect policy strips the
	// Authorization header.  Use a custom CheckRedirect that preserves it
	// and adds the federation token as access_token on the origin URL.
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if auth := via[0].Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
			if fedToken != "" {
				q := req.URL.Query()
				q.Set("access_token", fedToken)
				req.URL.RawQuery = q.Encode()
			}
			return nil
		},
	}

	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Errorln("Failed to proxy PROPFIND request:", err)
		if isConnectionError(err) || errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(http.StatusGatewayTimeout)
		} else {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Debugln("Error copying PROPFIND response body:", err)
	}
}

// proxyWrite forwards a PUT or DELETE request to the origin server (write-through).
// On success, any locally-cached copy of the object is invalidated so that
// subsequent GETs retrieve the new version from the origin.
func (pc *PersistentCache) proxyWrite(w http.ResponseWriter, r *http.Request, objectPath string, bearerToken string) {
	// Check authorization — PUT requires storage.create, DELETE requires storage.modify
	var requiredScope token_scopes.TokenScope
	if r.Method == "DELETE" {
		requiredScope = token_scopes.Wlcg_Storage_Modify
	} else {
		requiredScope = token_scopes.Wlcg_Storage_Create
	}
	if !pc.ac.authorize(requiredScope, objectPath, bearerToken) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte("Authorization Denied")); err != nil {
			log.Errorln("Failed to write authorization denied to client")
		}
		return
	}

	if pc.directorURL == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte("Cache not configured")); err != nil {
			log.Errorln("Failed to write service unavailable to client")
		}
		return
	}

	// Route through the director's origin endpoint so it redirects to the
	// origin without requiring the DirectReads capability.
	originURL := *pc.directorURL
	originURL.Path = path.Join("/api/v1.0/director/origin", objectPath)
	originURL.Scheme = "https"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Buffer the request body so that Go's http.Client can re-send it across
	// 307/308 redirects (the default redirect policy only re-sends bodies for
	// types that implement io.Seeker or have GetBody set, which r.Body does not).
	var bodyReader io.Reader
	if r.Body != nil && r.Body != http.NoBody {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			log.Errorln("Failed to read write-through request body:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		bodyReader = bytes.NewReader(bodyBytes)
	}

	proxyReq, err := http.NewRequestWithContext(ctx, r.Method, originURL.String(), bodyReader)
	if err != nil {
		log.Errorln("Failed to create write-through request:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send the user's token to the director via Authorization header.
	// The federation token is added to the redirect URL (not the
	// director request) in CheckRedirect below.
	if bearerToken != "" {
		proxyReq.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	fedToken := pc.getFedToken()
	if ct := r.Header.Get("Content-Type"); ct != "" {
		proxyReq.Header.Set("Content-Type", ct)
	}
	if cl := r.Header.Get("Content-Length"); cl != "" {
		proxyReq.Header.Set("Content-Length", cl)
	}
	// Forward checksum headers
	for _, hdr := range []string{"Digest", "Want-Digest", "Content-MD5"} {
		if v := r.Header.Get(hdr); v != "" {
			proxyReq.Header.Set(hdr, v)
		}
	}

	// The director 307-redirects to the origin (a different host), so Go's
	// default redirect policy strips the Authorization header.  Use a
	// custom CheckRedirect that preserves it and adds the federation
	// token as access_token on the origin URL.
	httpClient := &http.Client{
		Transport: config.GetTransport(),
		Timeout:   5 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if auth := via[0].Header.Get("Authorization"); auth != "" {
				req.Header.Set("Authorization", auth)
			}
			if fedToken != "" {
				q := req.URL.Query()
				q.Set("access_token", fedToken)
				req.URL.RawQuery = q.Encode()
			}
			return nil
		},
	}

	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		log.Errorln("Failed to proxy write-through request:", err)
		if isConnectionError(err) || errors.Is(err, context.DeadlineExceeded) {
			w.WriteHeader(http.StatusGatewayTimeout)
		} else {
			w.WriteHeader(http.StatusBadGateway)
		}
		return
	}
	defer resp.Body.Close()

	// On successful write, invalidate any cached version of this object.
	// This ensures subsequent GETs fetch the new version from the origin.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		pc.invalidateCachedObject(objectPath)
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Debugln("Error copying write-through response body:", err)
	}
}

// invalidateCachedObject removes any locally-cached version of the given
// object path.  Called after a successful write-through PUT or DELETE so
// that subsequent GETs retrieve the new version from the origin.
func (pc *PersistentCache) invalidateCachedObject(objectPath string) {
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// If there's an active download for this object, wait for it to finish
	// so that the ETag and metadata are committed before we try to delete.
	pc.activeDownloadsMu.RLock()
	dl, downloading := pc.activeDownloads[objectHash]
	pc.activeDownloadsMu.RUnlock()
	if downloading {
		log.Debugf("Waiting for active download of %s to complete before invalidation", objectPath)
		<-dl.completionDone
	}

	// Look up the latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil || etag == "" {
		// Not in cache — nothing to invalidate
		return
	}

	instanceHash := ComputeInstanceHash(etag, objectHash)

	if err := pc.storage.Delete(instanceHash); err != nil {
		log.Warnf("Failed to invalidate cached object %s: %v", objectPath, err)
	} else {
		log.Debugf("Invalidated cached object %s after write-through", objectPath)
	}
}

// LaunchListener launches the unix socket listener for the persistent cache
func (pc *PersistentCache) LaunchListener(ctx context.Context, egrp *errgroup.Group) (err error) {
	socketName := param.LocalCache_Socket.GetString()
	socketDir := filepath.Dir(socketName)

	if err = os.MkdirAll(socketDir, fs.FileMode(0755)); err != nil {
		err = errors.Wrap(err, "failed to create socket directory")
		return
	}

	var startupDir string
	// Create a temporary directory for the socket; once we are listening on the socket, we rename
	// the temporary directory to the final socket name. This allows us to avoid outages if multiple
	// processes are trying to create the socket at the same time (or if the socket already exists
	// from a previous startup that didn't clean up properly).
	//
	// Note: Linux has relatively short limits on the name length of a Unix socket.
	// We use the terse "pc-*" prefix to avoid exceeding the limit.
	if startupDir, err = os.MkdirTemp(socketDir, "pc-*"); err != nil {
		err = errors.Wrap(err, "failed to create temporary directory for launching persistent cache socket")
		return
	}
	// Allow other users to access the socket
	if err = os.Chmod(startupDir, 0755); err != nil {
		err = errors.Wrap(err, "failed to set permissions on temporary directory for persistent cache socket")
		return
	}
	defer func() {
		var matches []string
		matches, err2 := filepath.Glob(filepath.Join(socketDir, "pc-*"))
		if err2 != nil {
			err2 = errors.Wrap(err2, "failed to list temporary directories for cleaning up persistent cache socket")
			if err == nil {
				err = err2
			}
			return
		}
		for _, dir := range matches {
			if err2 := os.RemoveAll(dir); err2 != nil {
				log.Warningf("Failed to remove temporary directory %s: %v", dir, err2)
			}
		}
	}()

	startupSockName := filepath.Join(startupDir, filepath.Base(socketName))
	var listener *net.UnixListener
	if listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: startupSockName, Net: "unix"}); err != nil {
		err = errors.Wrap(err, "failed to create unix socket for persistent cache")
		log.Warningf("Failed to create socket %s: %v", startupSockName, err)
		return err
	}

	// Allow other users to write to the socket
	if err = os.Chmod(startupSockName, 0777); err != nil {
		err = errors.Wrap(err, "failed to set permissions on persistent cache socket")
		if err2 := listener.Close(); err2 != nil {
			log.Errorf("Failed to close socket listener: %v", err2)
		}
		return err
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		pc.serveObject(w, r)
	}

	srv := http.Server{
		Handler: http.HandlerFunc(handler),
	}
	egrp.Go(func() error {
		return srv.Serve(listener)
	})
	egrp.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	})

	if err = os.Rename(startupSockName, socketName); err != nil {
		err = errors.Wrap(err, "failed to rename temporary socket to final socket name for persistent cache")
	}
	return
}

// Register registers the control & monitoring routines with Gin
func (pc *PersistentCache) Register(ctx context.Context, router *gin.RouterGroup) {
	router.POST("/api/v1.0/localcache/purge", func(ginCtx *gin.Context) { pc.purgeCmd(ginCtx) })
	router.POST("/api/v1.0/localcache/purge_first", func(ginCtx *gin.Context) { pc.purgeFirstCmd(ginCtx) })
	router.GET("/api/v1.0/localcache/stats", func(ginCtx *gin.Context) { pc.statsCmd(ginCtx) })
}

// decodeDiscoveryHost decodes a URL-encoded discovery host:port from a URL path
func decodeDiscoveryHost(encoded string) (string, error) {
	return url.PathUnescape(encoded)
}

// purgeCmd handles the purge API command
func (pc *PersistentCache) purgeCmd(ginCtx *gin.Context) {
	status, verified, err := token.Verify(ginCtx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer, token.APITokenIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Localcache_Purge},
	})
	if err != nil {
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		ginCtx.AbortWithStatusJSON(
			status,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	} else if !verified {
		ginCtx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Unknown verification error"})
		return
	}

	err = pc.Purge()
	if err != nil {
		ginCtx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Failed to successfully run purge"})
		return
	}
	ginCtx.JSON(
		http.StatusOK,
		server_structs.SimpleApiResp{Status: server_structs.RespOK})
}

// purgeFirstCmd handles the purge_first API command
func (pc *PersistentCache) purgeFirstCmd(ginCtx *gin.Context) {
	log.Infoln("Received request to mark object for priority purge")
	status, verified, err := token.Verify(ginCtx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.LocalIssuer},
		Scopes:  []token_scopes.TokenScope{token_scopes.Localcache_Purge},
	})
	if err != nil {
		if status == http.StatusOK {
			status = http.StatusInternalServerError
		}
		ginCtx.AbortWithStatusJSON(
			status,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: err.Error()})
		return
	} else if !verified {
		ginCtx.AbortWithStatusJSON(
			http.StatusInternalServerError,
			server_structs.SimpleApiResp{Status: server_structs.RespFailed, Msg: "Unknown verification error"})
		return
	}

	var req struct {
		Path string `json:"path"`
	}

	if err = ginCtx.ShouldBindJSON(&req); err != nil {
		log.Warningln("Received invalid JSON request")
		ginCtx.AbortWithStatusJSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: "Invalid request format"})
		return
	}

	log.Debugf("Request received to mark object for priority purge (path: %s)", req.Path)
	err = pc.MarkPurgeFirst(req.Path)
	if err != nil {
		log.Warningf("Failed to mark object for priority purge (path: %s, error: %v)", req.Path, err)
		ginCtx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed, Msg: err.Error()})
		return
	}

	log.Infof("Successfully marked object for priority purge (path: %s)", req.Path)
	ginCtx.JSON(http.StatusOK, server_structs.SimpleApiResp{Status: server_structs.RespOK})
}

// statsCmd returns cache statistics
func (pc *PersistentCache) statsCmd(ginCtx *gin.Context) {
	stats := pc.GetStats()
	ginCtx.JSON(http.StatusOK, stats)
}

// Purge triggers the eviction manager to purge old entries
func (pc *PersistentCache) Purge() error {
	return pc.eviction.ForcePurge()
}

// MarkPurgeFirst marks an object to be purged first during next eviction
func (pc *PersistentCache) MarkPurgeFirst(objectPath string) error {
	// Compute object hash from URL
	pelicanURL := pc.normalizePath(objectPath)
	objectHash := ComputeObjectHash(pelicanURL)

	// Look up latest ETag for this object
	etag, err := pc.db.GetLatestETag(objectHash)
	if err != nil {
		return errors.Wrap(err, "failed to look up ETag")
	}

	// Compute file hash
	instanceHash := ComputeInstanceHash(etag, objectHash)

	// Mark in eviction manager
	return pc.eviction.MarkPurgeFirst(instanceHash)
}

// RegisterCacheHandlers registers HTTP handlers for the persistent cache on the Gin engine.
// This is used for the XRootD-free cache implementation where the cache serves content
// directly via the web server instead of using XRootD.
//
// Unlike LaunchListener (which creates a Unix socket), this registers handlers on the
// existing Gin web server, allowing it to serve cache requests on the standard HTTP/HTTPS ports.
//
// When the director is enabled (directorEnabled=true), handlers are registered under
// /api/v1.0/cache/data/*path so the director can distinguish between its routing and the
// cache's file serving. The director will redirect clients to this API endpoint.
// When running standalone (directorEnabled=false), handlers are registered at the root path.
func (pc *PersistentCache) RegisterCacheHandlers(engine *gin.Engine, directorEnabled bool) error {
	log.Info("Registering persistent cache HTTP handlers")

	// Create a handler function for all cache requests
	handleCacheRequest := func(c *gin.Context) {
		pc.serveObject(c.Writer, c.Request)
	}

	// Register the handler based on whether director is enabled
	if directorEnabled {
		// When director is enabled, register under /api/v1.0/cache/data/:discovery/*path
		// The :discovery parameter is a URL-encoded federation discovery host:port
		// This allows the cache to serve multiple federations

		// Helper to extract discovery host and set up context
		setupDiscoveryContext := func(c *gin.Context) bool {
			encodedDiscovery := c.Param("discovery")
			discoveryHost, err := decodeDiscoveryHost(encodedDiscovery)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid discovery host encoding"})
				return false
			}
			// Store discovery host in context for use by handlers
			c.Set("discoveryHost", discoveryHost)
			// Set the object path (strip the discovery prefix)
			c.Request.URL.Path = c.Param("path")
			return true
		}

		group := engine.Group("/api/v1.0/cache/data")
		group.GET("/:discovery/*path", func(c *gin.Context) {
			if setupDiscoveryContext(c) {
				handleCacheRequest(c)
			}
		})
		group.HEAD("/:discovery/*path", func(c *gin.Context) {
			if setupDiscoveryContext(c) {
				handleCacheRequest(c)
			}
		})
		// Register PROPFIND for directory listings (passthrough to origin)
		group.Handle("PROPFIND", "/:discovery/*path", func(c *gin.Context) {
			if setupDiscoveryContext(c) {
				handleCacheRequest(c)
			}
		})
		// Register PUT for write-through caching (proxy to origin)
		group.PUT("/:discovery/*path", func(c *gin.Context) {
			if setupDiscoveryContext(c) {
				handleCacheRequest(c)
			}
		})
		// Register DELETE for write-through deletion (proxy to origin)
		group.DELETE("/:discovery/*path", func(c *gin.Context) {
			if setupDiscoveryContext(c) {
				handleCacheRequest(c)
			}
		})
		log.Info("Persistent cache HTTP handlers registered at /api/v1.0/cache/data/:discovery/*path")
	} else {
		// When running standalone, use NoRoute to catch all requests
		engine.NoRoute(handleCacheRequest)
		log.Info("Persistent cache HTTP handlers registered at root path")
	}

	// Register the management/monitoring API endpoints for the cache server.
	// These are normally registered by pc.Register() for the local cache module,
	// but the cache server module needs them too. Use NoRoute-safe individual
	// registrations to avoid conflicts if the local cache module also registers them.
	engine.GET("/api/v1.0/cache/stats", func(c *gin.Context) { pc.statsCmd(c) })

	return nil
}
