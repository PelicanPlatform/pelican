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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	gowebdav "github.com/studio-b12/gowebdav"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_utils"
)

// ---------------------------------------------------------------------------
// HTTPSTokenMode controls how the backend authenticates to the upstream server.
// ---------------------------------------------------------------------------

type HTTPSTokenMode int

const (
	// HTTPSTokenNone — no token is sent to the backend.
	HTTPSTokenNone HTTPSTokenMode = iota
	// HTTPSTokenStatic — a static bearer token read from a file is sent.
	HTTPSTokenStatic
	// HTTPSTokenPassthrough — the client-supplied token is forwarded.
	HTTPSTokenPassthrough
	// HTTPSTokenOAuth2 — an OAuth2 access token is acquired and refreshed automatically.
	HTTPSTokenOAuth2
)

// ---------------------------------------------------------------------------
// BackendMode — whether the upstream speaks WebDAV or plain HTTP.
// Determined by an OPTIONS probe at startup.
// ---------------------------------------------------------------------------

type BackendMode int

const (
	BackendModeUnknown BackendMode = iota
	BackendModeWebDAV
	BackendModeHTTP
)

// ---------------------------------------------------------------------------
// httpsBackend — OriginBackend for HTTPS/WebDAV upstream storage
// ---------------------------------------------------------------------------

type httpsBackend struct {
	fs *httpsFileSystem
}

// HTTPSBackendOptions groups the parameters needed to construct an HTTPS backend.
type HTTPSBackendOptions struct {
	ServiceURL    string
	StoragePrefix string
	TokenMode     HTTPSTokenMode
	// For static tokens:
	StaticTokenFile string
	// For OAuth2 tokens:
	OAuth2Config *oauth2.Config
	OAuth2Token  *oauth2.Token // initial token (with refresh_token)
	// EnableAutoMkdir, when true, causes PUT operations to automatically
	// create missing parent directories via WebDAV MKCOL before retrying.
	EnableAutoMkdir bool
}

// ErrNotSupported is returned when an operation is not supported by the
// backend (e.g. Mkdir on a plain HTTP server).  Callers can test for this
// with errors.Is(err, ErrNotSupported).
var ErrNotSupported = errors.New("operation not supported by backend")

func newHTTPSBackend(opts HTTPSBackendOptions) *httpsBackend {
	fs := &httpsFileSystem{
		serviceURL:      strings.TrimSuffix(opts.ServiceURL, "/"),
		storagePrefix:   opts.StoragePrefix,
		tokenMode:       opts.TokenMode,
		staticTokenFile: opts.StaticTokenFile,
		httpClient:      &http.Client{Transport: config.GetTransport()},
		enableAutoMkdir: opts.EnableAutoMkdir,
	}
	if opts.OAuth2Config != nil && opts.OAuth2Token != nil {
		fs.oauth2Cfg = opts.OAuth2Config
		fs.oauth2Tok = opts.OAuth2Token
	}
	return &httpsBackend{fs: fs}
}

// CheckAvailability probes the upstream to determine whether it speaks WebDAV or
// plain HTTP by issuing an OPTIONS request and inspecting the Allow / DAV headers.
func (b *httpsBackend) CheckAvailability() error {
	return b.fs.probeBackendMode()
}

func (b *httpsBackend) FileSystem() webdav.FileSystem { return b.fs }
func (b *httpsBackend) Checksummer() server_utils.OriginChecksummer {
	return nil // Remote HTTPS backends don't support local checksums
}

// SetOAuth2Token allows external callers (e.g. Globus init) to update the
// managed OAuth2 token at runtime.
func (b *httpsBackend) SetOAuth2Token(tok *oauth2.Token) {
	if b.fs != nil {
		b.fs.oauthMu.Lock()
		defer b.fs.oauthMu.Unlock()
		b.fs.oauth2Tok = tok
	}
}

// SetServiceURL updates the upstream service URL at runtime.
// This is used by the Globus backend which discovers the collection
// HTTPS endpoint after initial construction.
func (b *httpsBackend) SetServiceURL(u string) {
	if b.fs != nil {
		b.fs.serviceURL = strings.TrimSuffix(u, "/")
		// Reset detected mode so it will be re-probed on next request
		b.fs.backendMode = BackendModeUnknown
	}
}

// BackendMode returns the detected mode (WebDAV or HTTP).
func (b *httpsBackend) BackendMode() BackendMode {
	return b.fs.backendMode
}

// ---------------------------------------------------------------------------
// httpsFileSystem — implements webdav.FileSystem backed by an upstream HTTPS server.
// When the backend supports WebDAV, directory operations use the gowebdav library.
// When it is plain HTTP, we fall back to simple verbs (GET, PUT, DELETE, HEAD).
// ---------------------------------------------------------------------------

type httpsFileSystem struct {
	serviceURL      string
	storagePrefix   string
	tokenMode       HTTPSTokenMode
	staticTokenFile string
	backendMode     BackendMode

	// OAuth2 token management
	oauth2Cfg *oauth2.Config
	oauth2Tok *oauth2.Token
	oauthMu   sync.Mutex // protects oauth2Tok

	httpClient *http.Client

	// enableAutoMkdir, when true, causes PUT operations to automatically
	// create missing parent directories on the upstream server.
	enableAutoMkdir bool
}

// probeBackendMode issues an OPTIONS request against the upstream root and
// inspects the Allow and DAV headers to decide between WebDAV and plain HTTP.
func (fs *httpsFileSystem) probeBackendMode() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := fs.doRequest(ctx, "OPTIONS", fs.serviceURL+"/", nil, nil)
	if err != nil {
		// If OPTIONS fails outright, assume plain HTTP.
		fs.backendMode = BackendModeHTTP
		log.Infof("HTTPS backend at %s: OPTIONS probe failed (%v); assuming plain HTTP", fs.serviceURL, err)
		return nil
	}
	defer resp.Body.Close()

	allow := resp.Header.Get("Allow")
	dav := resp.Header.Get("DAV")

	if strings.Contains(allow, "PROPFIND") || dav != "" {
		fs.backendMode = BackendModeWebDAV
		log.Infof("HTTPS backend at %s detected as WebDAV (Allow=%q, DAV=%q)", fs.serviceURL, allow, dav)
	} else {
		fs.backendMode = BackendModeHTTP
		log.Infof("HTTPS backend at %s detected as plain HTTP (Allow=%q)", fs.serviceURL, allow)
	}
	return nil
}

// davPath constructs the path that the gowebdav client expects (relative to the
// service URL root). It prepends the configured storagePrefix.
func (fs *httpsFileSystem) davPath(name string) string {
	// Clean the path as defense-in-depth against traversal attacks.
	name = path.Clean("/" + name)
	name = strings.TrimPrefix(name, "/")
	prefix := strings.TrimPrefix(fs.storagePrefix, "/")
	if prefix != "" {
		return "/" + prefix + "/" + name
	}
	return "/" + name
}

// getDavClient returns a gowebdav.Client configured with the appropriate bearer
// token for the current request context.  The simpleBearerAuth captures a
// reference to the httpsFileSystem so that every HTTP request made through
// this client calls getToken() afresh — this ensures tokens that expire
// mid-transfer are transparently renewed for long-lived clients.
func (fs *httpsFileSystem) getDavClient(ctx context.Context) *gowebdav.Client {
	auth := &simpleBearerAuth{tokenFunc: func() string { return fs.getToken(ctx) }}
	client := gowebdav.NewAuthClient(fs.serviceURL, auth)
	if fs.httpClient.Transport != nil {
		client.SetTransport(fs.httpClient.Transport)
	}
	return client
}

// upstreamURL returns the full URL for the given path on the upstream server.
func (fs *httpsFileSystem) upstreamURL(name string) string {
	// Clean the path as defense-in-depth against traversal attacks.
	name = path.Clean("/" + name)
	name = strings.TrimPrefix(name, "/")
	prefix := strings.TrimPrefix(fs.storagePrefix, "/")
	if prefix != "" {
		return fs.serviceURL + "/" + prefix + "/" + name
	}
	return fs.serviceURL + "/" + name
}

// getToken returns the bearer token to use for the upstream request.
func (fs *httpsFileSystem) getToken(ctx context.Context) string {
	switch fs.tokenMode {
	case HTTPSTokenStatic:
		return fs.readStaticToken()
	case HTTPSTokenPassthrough:
		return tokenFromContext(ctx)
	case HTTPSTokenOAuth2:
		return fs.getOAuth2Token(ctx)
	default:
		return ""
	}
}

func (fs *httpsFileSystem) readStaticToken() string {
	if fs.staticTokenFile == "" {
		return ""
	}
	data, err := os.ReadFile(fs.staticTokenFile)
	if err != nil {
		log.Debugf("Failed to read HTTPS auth token file %s: %v", fs.staticTokenFile, err)
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (fs *httpsFileSystem) getOAuth2Token(ctx context.Context) string {
	fs.oauthMu.Lock()
	defer fs.oauthMu.Unlock()

	if fs.oauth2Cfg == nil || fs.oauth2Tok == nil {
		return ""
	}

	ts := fs.oauth2Cfg.TokenSource(ctx, fs.oauth2Tok)
	tok, err := ts.Token()
	if err != nil {
		log.Warningf("Failed to refresh OAuth2 token for HTTPS backend: %v", err)
		return fs.oauth2Tok.AccessToken
	}
	fs.oauth2Tok = tok
	return tok.AccessToken
}

// doRequest creates and executes an HTTP request to the upstream server.
func (fs *httpsFileSystem) doRequest(ctx context.Context, method, urlStr string, body io.Reader, extraHeaders map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
	if err != nil {
		return nil, err
	}
	if token := fs.getToken(ctx); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if ph := server_utils.PelicanHeadersFromContext(ctx); ph != nil {
		if ph.JobId != "" {
			req.Header.Set("X-Pelican-JobId", ph.JobId)
		}
		if ph.Timeout != "" {
			req.Header.Set("X-Pelican-Timeout", ph.Timeout)
		}
	}
	return fs.httpClient.Do(req)
}

// ---------------------------------------------------------------------------
// webdav.FileSystem method implementations
// ---------------------------------------------------------------------------

// Mkdir implements webdav.FileSystem.
func (fs *httpsFileSystem) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	if fs.backendMode == BackendModeWebDAV {
		client := fs.getDavClient(ctx)
		return client.Mkdir(fs.davPath(name), perm)
	}
	return fmt.Errorf("mkdir: %w", ErrNotSupported)
}

// ensureParentDirs recursively creates parent directories for the given file
// path.  It walks up from the deepest parent toward the root until it finds an
// existing directory, then creates the missing directories back down the path.
//
// This mirrors the approach used by the xrootd-s3-http Globus plugin: probe
// from deepest parent upward (via Stat) until we find one that exists, then
// mkdir each missing component going back down.  EEXIST is tolerated to
// handle concurrent writers that may create the same directory between our
// Stat and Mkdir calls.
func (fs *httpsFileSystem) ensureParentDirs(ctx context.Context, name string) error {
	if fs.backendMode != BackendModeWebDAV {
		return fmt.Errorf("auto-mkdir requires WebDAV backend")
	}

	// Build all parent prefixes.  For "/a/b/c/file.txt" we get ["/a", "/a/b", "/a/b/c"].
	dir := path.Dir(name)
	if dir == "." || dir == "/" || dir == "" {
		return nil // no parent directories to create
	}

	var prefixes []string
	for cur := dir; cur != "." && cur != "/" && cur != ""; cur = path.Dir(cur) {
		prefixes = append(prefixes, cur)
	}
	if len(prefixes) == 0 {
		return nil
	}

	// prefixes is deepest-first: ["/a/b/c", "/a/b", "/a"].
	// Walk from deepest toward root to find the first existing directory.
	firstMissingIdx := 0
	for i := 0; i < len(prefixes); i++ {
		_, err := fs.Stat(ctx, prefixes[i])
		if err == nil {
			// This prefix exists; everything deeper needs to be created.
			firstMissingIdx = i
			break
		}
		if i == len(prefixes)-1 {
			// Even the shallowest prefix doesn't exist; create everything.
			firstMissingIdx = len(prefixes)
		}
	}

	// Create from shallowest missing toward deepest.
	for i := firstMissingIdx - 1; i >= 0; i-- {
		var lastErr error
		for attempt := 0; attempt < 5; attempt++ {
			lastErr = fs.Mkdir(ctx, prefixes[i], 0755)
			if lastErr == nil {
				break
			}
			// Tolerate "already exists" (405 Method Not Allowed in WebDAV) in
			// case a concurrent writer created the directory between our Stat
			// and Mkdir calls.
			if gowebdav.IsErrCode(lastErr, http.StatusMethodNotAllowed) {
				lastErr = nil
				break
			}
			// A 423 Locked response means a concurrent MKCOL is in progress
			// on the same resource.  Retry after a short backoff; the lock
			// will be released once the other writer finishes.
			if gowebdav.IsErrCode(lastErr, http.StatusLocked) {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(100 * time.Millisecond * time.Duration(attempt+1)):
				}
				continue
			}
			// Any other error is fatal.
			return fmt.Errorf("failed to create directory %q: %w", prefixes[i], lastErr)
		}
		if lastErr != nil {
			return fmt.Errorf("failed to create directory %q after retries: %w", prefixes[i], lastErr)
		}
	}

	return nil
}

// OpenFile implements webdav.FileSystem.
func (fs *httpsFileSystem) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	// For write operations, return a writer that PUTs on Close.
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		return newHTTPSWriteFile(ctx, fs, name), nil
	}

	// In WebDAV mode, check whether the path is a directory first.
	if fs.backendMode == BackendModeWebDAV {
		client := fs.getDavClient(ctx)
		davP := fs.davPath(name)
		info, err := client.Stat(davP)
		if err == nil && info.IsDir() {
			children, dirErr := client.ReadDir(davP)
			if dirErr != nil {
				return nil, dirErr
			}
			return &httpsReadDirFile{name: name, entries: children}, nil
		}
		if err != nil && gowebdav.IsErrNotFound(err) {
			return nil, os.ErrNotExist
		}
		// Regular file — we already have size & mod-time from the Stat above,
		// so skip the HEAD request and return a lazy-read file directly.
		if err == nil {
			var etag string
			if gf, ok := info.(interface{ ETag() string }); ok {
				etag = gf.ETag()
			}
			return &httpsReadFile{
				name:          name,
				fs:            fs,
				ctx:           ctx,
				contentLength: info.Size(),
				lastModified:  info.ModTime(),
				etag:          etag,
			}, nil
		}
		// Stat failed for a non-404 reason — fall through to HEAD.
	}

	urlStr := fs.upstreamURL(name)

	// Use HEAD to discover the file's size and last-modified time without
	// downloading the body.  The actual bytes are fetched lazily (possibly
	// with a Range header) on the first Read call.
	resp, err := fs.doRequest(ctx, http.MethodHead, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("https head failed with status %d", resp.StatusCode)
	}

	return &httpsReadFile{
		name:          name,
		fs:            fs,
		ctx:           ctx,
		contentLength: resp.ContentLength,
		lastModified:  parseHTTPDate(resp.Header.Get("Last-Modified")),
		etag:          resp.Header.Get("ETag"),
	}, nil
}

// RemoveAll implements webdav.FileSystem.
func (fs *httpsFileSystem) RemoveAll(ctx context.Context, name string) error {
	if fs.backendMode == BackendModeWebDAV {
		client := fs.getDavClient(ctx)
		return client.RemoveAll(fs.davPath(name))
	}
	// HTTP-only: plain DELETE.
	urlStr := fs.upstreamURL(name)
	resp, err := fs.doRequest(ctx, http.MethodDelete, urlStr, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("https delete failed with status %d", resp.StatusCode)
}

// Rename implements webdav.FileSystem.
func (fs *httpsFileSystem) Rename(ctx context.Context, oldName, newName string) error {
	if fs.backendMode == BackendModeWebDAV {
		client := fs.getDavClient(ctx)
		return client.Rename(fs.davPath(oldName), fs.davPath(newName), true)
	}
	return fmt.Errorf("rename: %w", ErrNotSupported)
}

// Stat implements webdav.FileSystem.
func (fs *httpsFileSystem) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if fs.backendMode == BackendModeWebDAV {
		client := fs.getDavClient(ctx)
		info, err := client.Stat(fs.davPath(name))
		if err != nil {
			if gowebdav.IsErrNotFound(err) {
				return nil, os.ErrNotExist
			}
			return nil, err
		}
		return info, nil
	}

	// HTTP-only: use HEAD.
	urlStr := fs.upstreamURL(name)
	resp, err := fs.doRequest(ctx, http.MethodHead, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("https head failed with status %d", resp.StatusCode)
	}

	return &httpsFileInfo{
		name:    path.Base(name),
		size:    resp.ContentLength,
		modTime: parseHTTPDate(resp.Header.Get("Last-Modified")),
		isDir:   false,
		etag:    resp.Header.Get("ETag"),
	}, nil
}

// ---------------------------------------------------------------------------
// Token passthrough context key
// ---------------------------------------------------------------------------

type clientTokenKey struct{}

// WithClientToken stores the client's bearer token in the context
// so that the HTTPS backend can forward it to the upstream server.
func WithClientToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, clientTokenKey{}, token)
}

func tokenFromContext(ctx context.Context) string {
	if tok, ok := ctx.Value(clientTokenKey{}).(string); ok {
		return tok
	}
	return ""
}

// ---------------------------------------------------------------------------
// simpleBearerAuth — implements gowebdav.Authorizer using a token-getter
// function.  The function is called for every HTTP request so that expired
// tokens are transparently refreshed without recreating the gowebdav.Client.
// ---------------------------------------------------------------------------

type simpleBearerAuth struct {
	tokenFunc func() string
}

type simpleBearerAuthenticator struct {
	tokenFunc func() string
}

func (a *simpleBearerAuth) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &simpleBearerAuthenticator{tokenFunc: a.tokenFunc}, body
}

func (a *simpleBearerAuth) AddAuthenticator(_ string, _ gowebdav.AuthFactory) {}

func (auth *simpleBearerAuthenticator) Authorize(_ *http.Client, rq *http.Request, _ string) error {
	if tok := auth.tokenFunc(); tok != "" {
		rq.Header.Set("Authorization", "Bearer "+tok)
	}
	return nil
}

func (auth *simpleBearerAuthenticator) Verify(_ *http.Client, _ *http.Response, _ string) (bool, error) {
	return false, nil
}

func (auth *simpleBearerAuthenticator) Close() error { return nil }

func (auth *simpleBearerAuthenticator) Clone() gowebdav.Authenticator {
	return &simpleBearerAuthenticator{tokenFunc: auth.tokenFunc}
}

// ---------------------------------------------------------------------------
// httpsFileInfo — implements os.FileInfo (used only in HTTP-only mode).
// In WebDAV mode the gowebdav library returns its own FileInfo.
// ---------------------------------------------------------------------------

// HTTPSFileSysInfo carries optional metadata (e.g. ETag) from an upstream
// HTTPS/WebDAV server.  Returned by httpsFileInfo.Sys() when populated.
type HTTPSFileSysInfo struct {
	ETag string
}

type httpsFileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
	etag    string
}

func (fi *httpsFileInfo) Name() string      { return fi.name }
func (fi *httpsFileInfo) Size() int64       { return fi.size }
func (fi *httpsFileInfo) Mode() os.FileMode { return 0444 }
func (fi *httpsFileInfo) ModTime() time.Time {
	if fi.modTime.IsZero() {
		return time.Now()
	}
	return fi.modTime
}
func (fi *httpsFileInfo) IsDir() bool { return fi.isDir }
func (fi *httpsFileInfo) Sys() interface{} {
	if fi.etag != "" {
		return &HTTPSFileSysInfo{ETag: fi.etag}
	}
	return nil
}

// ETag implements the webdav.ETager interface so that the webdav handler
// can set the ETag response header from the upstream server's value.
func (fi *httpsFileInfo) ETag(_ context.Context) (string, error) {
	if fi.etag != "" {
		return fi.etag, nil
	}
	// Return ErrNotImplemented so the webdav handler falls back to its
	// default ETag computation (modtime + size).
	return "", webdav.ErrNotImplemented
}

// ---------------------------------------------------------------------------
// httpsReadFile — read-only file backed by an HTTPS upstream.
// Seek is real: it records the desired offset and lazily opens a Range GET
// on the next Read call.  This means only the requested byte range is fetched
// from the upstream server, which is critical for multi-gigabyte files.
// ---------------------------------------------------------------------------

type httpsReadFile struct {
	name          string
	fs            *httpsFileSystem
	ctx           context.Context
	contentLength int64
	lastModified  time.Time
	etag          string

	offset int64         // logical cursor position
	body   io.ReadCloser // current upstream body (nil until first Read after Seek)
}

func (f *httpsReadFile) Read(p []byte) (int, error) {
	if f.body == nil {
		// Open a GET with a Range header starting at the current offset.
		urlStr := f.fs.upstreamURL(f.name)
		headers := map[string]string{
			"Range": fmt.Sprintf("bytes=%d-", f.offset),
		}
		resp, err := f.fs.doRequest(f.ctx, http.MethodGet, urlStr, nil, headers)
		if err != nil {
			return 0, err
		}
		// Accept both 200 (server ignores Range) and 206 (partial content).
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
			resp.Body.Close()
			return 0, fmt.Errorf("https range get failed with status %d", resp.StatusCode)
		}
		f.body = resp.Body
	}
	n, err := f.body.Read(p)
	f.offset += int64(n)
	return n, err
}

func (f *httpsReadFile) Seek(offset int64, whence int) (int64, error) {
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = f.offset + offset
	case io.SeekEnd:
		newOff = f.contentLength + offset
	default:
		return 0, fmt.Errorf("httpsReadFile.Seek: invalid whence %d", whence)
	}
	if newOff < 0 {
		return 0, fmt.Errorf("httpsReadFile.Seek: negative position %d", newOff)
	}
	// If the position changed, discard the existing body so the next Read
	// opens a fresh Range GET at the new offset.
	if newOff != f.offset || f.body == nil {
		if f.body != nil {
			f.body.Close()
			f.body = nil
		}
	}
	f.offset = newOff
	return newOff, nil
}

func (f *httpsReadFile) Close() error {
	if f.body != nil {
		return f.body.Close()
	}
	return nil
}

func (f *httpsReadFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on read file")
}

func (f *httpsReadFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on file")
}

func (f *httpsReadFile) Stat() (os.FileInfo, error) {
	return &httpsFileInfo{
		name:    path.Base(f.name),
		size:    f.contentLength,
		modTime: f.lastModified,
		isDir:   false,
		etag:    f.etag,
	}, nil
}

// ---------------------------------------------------------------------------
// httpsWriteFile — write file that streams PUTs to the upstream server.
//
// Bytes flow Write -> io.Pipe -> http.Request.Body -> upstream. We do NOT
// buffer the whole upload in memory anymore; multi-GB writes therefore
// no longer balloon RSS in proportion to the body size.
//
// Lifecycle:
//   - newHTTPSWriteFile only records intent; nothing happens on the wire.
//   - The first Write (or Close, for an empty PUT) triggers ensureStarted,
//     which optionally pre-flights MKCOL for missing parents and then kicks
//     off a goroutine that runs the upstream PUT with the pipe reader as
//     its body. Subsequent Writes feed the pipe.
//   - Close shuts the pipe writer (signaling EOF to the body) and waits
//     for the PUT goroutine to return its status.
//
// Auto-mkdir trade-off: the old code retried on 409/404, but with a
// streamed body the request body is already consumed by the time we'd
// know we need to retry. So when auto-mkdir is on for a WebDAV upstream
// we Stat/MKCOL the parents up front and skip the retry path. For
// plain-HTTP upstreams (or auto-mkdir disabled) we just PUT and surface
// whatever status the server returns.
// ---------------------------------------------------------------------------

type httpsWriteFile struct {
	ctx  context.Context
	fs   *httpsFileSystem
	name string

	// startOnce gates the lazy spawn of the PUT goroutine. Subsequent
	// Writes / a single Close all funnel through it.
	startOnce sync.Once
	startErr  error // non-nil if pre-flight (e.g. ensureParentDirs) failed

	// pipeW is the local end the WebDAV handler's bytes are written into;
	// the goroutine consumes the matching reader as the request body.
	pipeW *io.PipeWriter
	// putErrCh receives exactly one value: the PUT goroutine's terminal
	// error (or nil on success). Buffered so the goroutine never blocks.
	putErrCh chan error

	// mu guards offset; serializes Stat/Seek against Write.
	mu     sync.Mutex
	offset int64
	closed bool
}

func newHTTPSWriteFile(ctx context.Context, fs *httpsFileSystem, name string) *httpsWriteFile {
	return &httpsWriteFile{ctx: ctx, fs: fs, name: name}
}

// ensureStarted lazily kicks off the upstream PUT. It is safe to call
// repeatedly; only the first call does work. If the pre-flight mkdir
// fails, the cached startErr is returned to every caller.
func (f *httpsWriteFile) ensureStarted() error {
	f.startOnce.Do(func() {
		// When auto-mkdir is on with a WebDAV upstream we cannot rely on
		// the old retry-on-409/404 path -- the streamed body is already
		// consumed by the time we know we need a retry. Pay the Stat
		// cost up front instead. For the common case the parent already
		// exists and Stat short-circuits cheaply.
		if f.fs.enableAutoMkdir && f.fs.backendMode == BackendModeWebDAV {
			if err := f.fs.ensureParentDirs(f.ctx, f.name); err != nil {
				f.startErr = fmt.Errorf("auto-mkdir before HTTPS PUT failed: %w", err)
				return
			}
		}

		pipeR, pipeW := io.Pipe()
		f.pipeW = pipeW
		f.putErrCh = make(chan error, 1)

		urlStr := f.fs.upstreamURL(f.name)
		req, err := http.NewRequestWithContext(f.ctx, http.MethodPut, urlStr, pipeR)
		if err != nil {
			_ = pipeR.CloseWithError(err)
			f.startErr = err
			return
		}
		if token := f.fs.getToken(f.ctx); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if ph := server_utils.PelicanHeadersFromContext(f.ctx); ph != nil {
			if ph.JobId != "" {
				req.Header.Set("X-Pelican-JobId", ph.JobId)
			}
			if ph.Timeout != "" {
				req.Header.Set("X-Pelican-Timeout", ph.Timeout)
			}
		}
		// Honor a Content-Length hint from the request context so the wire
		// stays non-chunked when the size is known up front. With no hint
		// we leave ContentLength == -1 and the transport will use chunked
		// transfer-encoding.
		if hint := contentLengthFromCtx(f.ctx); hint >= 0 {
			req.ContentLength = hint
		}

		go func() {
			resp, err := f.fs.httpClient.Do(req)
			if err != nil {
				// Wake any blocked Write with the same error so the caller
				// learns about the failure synchronously.
				_ = pipeR.CloseWithError(err)
				f.putErrCh <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			switch resp.StatusCode {
			case http.StatusOK, http.StatusCreated, http.StatusNoContent:
				f.putErrCh <- nil
				return
			}
			log.Debugf("HTTPS PUT to %s response (%d): %s", urlStr, resp.StatusCode, string(body))
			putErr := fmt.Errorf("https put failed with status %d", resp.StatusCode)
			_ = pipeR.CloseWithError(putErr)
			f.putErrCh <- putErr
		}()
	})
	return f.startErr
}

func (f *httpsWriteFile) Write(p []byte) (int, error) {
	if err := f.ensureStarted(); err != nil {
		return 0, err
	}
	n, err := f.pipeW.Write(p)
	if n > 0 {
		f.mu.Lock()
		f.offset += int64(n)
		f.mu.Unlock()
	}
	return n, err
}

func (f *httpsWriteFile) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	f.mu.Unlock()

	// Even an empty PUT (no Write calls) must hit the wire so the upstream
	// observes a zero-byte file. ensureStarted is idempotent.
	if err := f.ensureStarted(); err != nil {
		return err
	}
	// Signal EOF to the request body and wait for the PUT goroutine to
	// surface the upstream's status.
	if err := f.pipeW.Close(); err != nil {
		return err
	}
	return <-f.putErrCh
}

func (f *httpsWriteFile) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read not supported on write file")
}

// Seek supports only no-op seeks (seeking to the current offset).
// This satisfies callers like the WebDAV handler that seek to the
// current position to determine the write offset.
func (f *httpsWriteFile) Seek(offset int64, whence int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = f.offset + offset
	case io.SeekEnd:
		// For a write file, "end" is the current write position.
		target = f.offset + offset
	default:
		return 0, fmt.Errorf("httpsWriteFile.Seek: invalid whence %d", whence)
	}
	if target != f.offset {
		return 0, fmt.Errorf("httpsWriteFile.Seek: non-sequential seek not supported")
	}
	return f.offset, nil
}

func (f *httpsWriteFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on write file")
}

func (f *httpsWriteFile) Stat() (os.FileInfo, error) {
	f.mu.Lock()
	n := f.offset
	f.mu.Unlock()
	return &httpsFileInfo{
		name:  path.Base(f.name),
		size:  n,
		isDir: false,
	}, nil
}

// ---------------------------------------------------------------------------
// httpsReadDirFile — directory listing returned from OpenFile for collections.
// ---------------------------------------------------------------------------

type httpsReadDirFile struct {
	name    string
	entries []os.FileInfo
}

func (f *httpsReadDirFile) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read not supported on directory")
}

func (f *httpsReadDirFile) Seek(_ int64, _ int) (int64, error) {
	return 0, fmt.Errorf("seek not supported on directory")
}

func (f *httpsReadDirFile) Close() error { return nil }

func (f *httpsReadDirFile) Write(_ []byte) (int, error) {
	return 0, fmt.Errorf("write not supported on directory")
}

func (f *httpsReadDirFile) Readdir(count int) ([]os.FileInfo, error) {
	if count <= 0 || count > len(f.entries) {
		result := f.entries
		f.entries = nil
		return result, nil
	}
	result := f.entries[:count]
	f.entries = f.entries[count:]
	return result, nil
}

func (f *httpsReadDirFile) Stat() (os.FileInfo, error) {
	return &httpsFileInfo{
		name:  path.Base(f.name),
		isDir: true,
	}, nil
}
