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
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	gowebdav "github.com/studio-b12/gowebdav"
	"golang.org/x/net/webdav"
	"golang.org/x/oauth2"

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
}

func newHTTPSBackend(opts HTTPSBackendOptions) *httpsBackend {
	fs := &httpsFileSystem{
		serviceURL:      strings.TrimSuffix(opts.ServiceURL, "/"),
		storagePrefix:   opts.StoragePrefix,
		tokenMode:       opts.TokenMode,
		staticTokenFile: opts.StaticTokenFile,
		httpClient:      &http.Client{Timeout: 60 * time.Second},
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

	// OAuth2 token management (in-memory only — no disk persistence)
	oauth2Cfg *oauth2.Config
	oauth2Tok *oauth2.Token
	oauthMu   sync.Mutex // protects oauth2Tok

	httpClient *http.Client
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
	name = strings.TrimPrefix(name, "/")
	prefix := strings.TrimPrefix(fs.storagePrefix, "/")
	if prefix != "" {
		return "/" + prefix + "/" + name
	}
	return "/" + name
}

// getDavClient returns a gowebdav.Client configured with the appropriate bearer
// token for the current request context.  A fresh client is created per call so
// that the passthrough token is always correct even under concurrent requests.
func (fs *httpsFileSystem) getDavClient(ctx context.Context) *gowebdav.Client {
	token := fs.getToken(ctx)
	var client *gowebdav.Client
	if token != "" {
		auth := &simpleBearerAuth{token: token}
		client = gowebdav.NewAuthClient(fs.serviceURL, auth)
	} else {
		client = gowebdav.NewClient(fs.serviceURL, "", "")
	}
	if fs.httpClient.Transport != nil {
		client.SetTransport(fs.httpClient.Transport)
	}
	return client
}

// upstreamURL returns the full URL for the given path on the upstream server.
func (fs *httpsFileSystem) upstreamURL(name string) string {
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
	return fmt.Errorf("mkdir not supported on HTTP-only backend")
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
		// Either it's a regular file or Stat failed for a non-404 reason — fall
		// through to GET.
	}

	urlStr := fs.upstreamURL(name)
	resp, err := fs.doRequest(ctx, http.MethodGet, urlStr, nil, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("https get failed with status %d", resp.StatusCode)
	}

	return &httpsReadFile{
		name:          name,
		body:          resp.Body,
		contentLength: resp.ContentLength,
		lastModified:  parseHTTPDate(resp.Header.Get("Last-Modified")),
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
	return fmt.Errorf("rename not supported on HTTP-only backend")
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
// simpleBearerAuth — implements gowebdav.Authorizer for a fixed bearer token.
// A fresh instance is created per request via getDavClient.
// ---------------------------------------------------------------------------

type simpleBearerAuth struct {
	token string
}

type simpleBearerAuthenticator struct {
	token string
}

func (a *simpleBearerAuth) NewAuthenticator(body io.Reader) (gowebdav.Authenticator, io.Reader) {
	return &simpleBearerAuthenticator{token: a.token}, body
}

func (a *simpleBearerAuth) AddAuthenticator(_ string, _ gowebdav.AuthFactory) {}

func (auth *simpleBearerAuthenticator) Authorize(_ *http.Client, rq *http.Request, _ string) error {
	if auth.token != "" {
		rq.Header.Set("Authorization", "Bearer "+auth.token)
	}
	return nil
}

func (auth *simpleBearerAuthenticator) Verify(_ *http.Client, _ *http.Response, _ string) (bool, error) {
	return false, nil
}

func (auth *simpleBearerAuthenticator) Close() error { return nil }

func (auth *simpleBearerAuthenticator) Clone() gowebdav.Authenticator {
	return &simpleBearerAuthenticator{token: auth.token}
}

// ---------------------------------------------------------------------------
// httpsFileInfo — implements os.FileInfo (used only in HTTP-only mode).
// In WebDAV mode the gowebdav library returns its own FileInfo.
// ---------------------------------------------------------------------------

type httpsFileInfo struct {
	name    string
	size    int64
	modTime time.Time
	isDir   bool
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
func (fi *httpsFileInfo) IsDir() bool      { return fi.isDir }
func (fi *httpsFileInfo) Sys() interface{} { return nil }

// ---------------------------------------------------------------------------
// httpsReadFile — read-only file backed by an HTTPS GET response.
// Uses atomic offset for concurrent safety.
// ---------------------------------------------------------------------------

type httpsReadFile struct {
	name          string
	body          io.ReadCloser
	contentLength int64
	lastModified  time.Time
	offset        atomic.Int64
}

func (f *httpsReadFile) Read(p []byte) (int, error) {
	n, err := f.body.Read(p)
	f.offset.Add(int64(n))
	return n, err
}

func (f *httpsReadFile) Seek(offset int64, whence int) (int64, error) {
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = f.offset.Load() + offset
	case io.SeekEnd:
		newOff = f.contentLength + offset
	}
	f.offset.Store(newOff)
	return newOff, nil
}

func (f *httpsReadFile) Close() error { return f.body.Close() }

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
	}, nil
}

// ---------------------------------------------------------------------------
// httpsWriteFile — write file that PUTs to the upstream server on Close.
// Uses a mutex to protect concurrent appends to the buffer.
// ---------------------------------------------------------------------------

type httpsWriteFile struct {
	ctx  context.Context
	fs   *httpsFileSystem
	name string
	mu   sync.Mutex
	buf  []byte
}

func newHTTPSWriteFile(ctx context.Context, fs *httpsFileSystem, name string) *httpsWriteFile {
	return &httpsWriteFile{ctx: ctx, fs: fs, name: name}
}

func (f *httpsWriteFile) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.buf = append(f.buf, p...)
	return len(p), nil
}

func (f *httpsWriteFile) Close() error {
	f.mu.Lock()
	data := make([]byte, len(f.buf))
	copy(data, f.buf)
	f.mu.Unlock()

	urlStr := f.fs.upstreamURL(f.name)
	body := strings.NewReader(string(data))

	resp, err := f.fs.doRequest(f.ctx, http.MethodPut, urlStr, body, map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(data)),
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	log.Debugf("HTTPS PUT response (%d): %s", resp.StatusCode, string(respBody))
	return fmt.Errorf("https put failed with status %d", resp.StatusCode)
}

func (f *httpsWriteFile) Read(_ []byte) (int, error) {
	return 0, fmt.Errorf("read not supported on write file")
}

func (f *httpsWriteFile) Seek(_ int64, _ int) (int64, error) {
	return 0, fmt.Errorf("seek not supported on write file")
}

func (f *httpsWriteFile) Readdir(_ int) ([]os.FileInfo, error) {
	return nil, fmt.Errorf("readdir not supported on write file")
}

func (f *httpsWriteFile) Stat() (os.FileInfo, error) {
	f.mu.Lock()
	n := len(f.buf)
	f.mu.Unlock()
	return &httpsFileInfo{
		name:  path.Base(f.name),
		size:  int64(n),
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
