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
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

// spyFileSystem records the paths passed to webdav.FileSystem methods so tests
// can verify which path actually reaches the storage backend.
type spyFileSystem struct {
	mu       sync.Mutex
	lastPath string
}

func (s *spyFileSystem) OpenFile(_ context.Context, name string, _ int, _ os.FileMode) (webdav.File, error) {
	s.mu.Lock()
	s.lastPath = name
	s.mu.Unlock()
	return nil, os.ErrNotExist
}

func (s *spyFileSystem) Stat(_ context.Context, name string) (os.FileInfo, error) {
	s.mu.Lock()
	s.lastPath = name
	s.mu.Unlock()
	return nil, os.ErrNotExist
}

func (s *spyFileSystem) Mkdir(context.Context, string, os.FileMode) error  { return os.ErrPermission }
func (s *spyFileSystem) RemoveAll(context.Context, string) error           { return os.ErrPermission }
func (s *spyFileSystem) Rename(context.Context, string, string) error      { return os.ErrPermission }

// spyBackend implements server_utils.OriginBackend backed by a spyFileSystem.
type spyBackend struct {
	fs *spyFileSystem
}

func (b *spyBackend) CheckAvailability() error                    { return nil }
func (b *spyBackend) FileSystem() webdav.FileSystem               { return b.fs }
func (b *spyBackend) Checksummer() server_utils.OriginChecksummer { return nil }

// TestPathTraversal_HasPathPrefix verifies that hasPathPrefix is robust
// against attempts to escape an authorized prefix using ".." sequences.
func TestPathTraversal_HasPathPrefix(t *testing.T) {
	tests := []struct {
		name             string
		requestPath      string
		authorizedPrefix string
		expected         bool
	}{
		// Baseline: normal access within the prefix
		{
			name:             "NormalSubpath",
			requestPath:      "/data/project/file.txt",
			authorizedPrefix: "/data/project",
			expected:         true,
		},
		// Dot-dot that escapes the prefix entirely
		{
			name:             "DotDotEscapesPrefix",
			requestPath:      "/data/project/../../etc/passwd",
			authorizedPrefix: "/data/project",
			expected:         false,
		},
		// Dot-dot that escapes one level above prefix
		{
			name:             "DotDotToSibling",
			requestPath:      "/data/project/../other/secret",
			authorizedPrefix: "/data/project",
			expected:         false,
		},
		// Dot-dot that stays within (normalizes back into) the prefix
		{
			name:             "DotDotStaysWithin",
			requestPath:      "/data/project/sub/../file.txt",
			authorizedPrefix: "/data/project",
			expected:         true,
		},
		// Many dot-dots that would traverse past the root
		{
			name:             "ManyDotDotsPastRoot",
			requestPath:      "/data/project/../../../../../etc/shadow",
			authorizedPrefix: "/data/project",
			expected:         false,
		},
		// Single dot (current dir) should normalize cleanly
		{
			name:             "DotCurrent",
			requestPath:      "/data/project/./file.txt",
			authorizedPrefix: "/data/project",
			expected:         true,
		},
		// Double slashes should normalize
		{
			name:             "DoubleSlash",
			requestPath:      "/data/project//file.txt",
			authorizedPrefix: "/data/project",
			expected:         true,
		},
		// Trailing slash normalization
		{
			name:             "TrailingSlash",
			requestPath:      "/data/project/sub/",
			authorizedPrefix: "/data/project",
			expected:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasPathPrefix(tt.requestPath, tt.authorizedPrefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPathTraversal_DavPath verifies that the HTTPS backend's davPath
// function normalizes path traversal sequences.
func TestPathTraversal_DavPath(t *testing.T) {
	tests := []struct {
		name          string
		storagePrefix string
		inputPath     string
		expected      string
	}{
		{
			name:          "Normal",
			storagePrefix: "/store",
			inputPath:     "/file.txt",
			expected:      "/store/file.txt",
		},
		{
			name:          "DotDotEscapesStorage",
			storagePrefix: "/store",
			inputPath:     "/../../etc/passwd",
			expected:      "/store/etc/passwd",
		},
		{
			name:          "DotDotPartial",
			storagePrefix: "/store",
			inputPath:     "/sub/../other",
			expected:      "/store/other",
		},
		{
			name:          "DotDotWithoutPrefix",
			storagePrefix: "",
			inputPath:     "/foo/../bar",
			expected:      "/bar",
		},
		{
			name:          "DotDotMultiple",
			storagePrefix: "/store",
			inputPath:     "/a/b/../../c",
			expected:      "/store/c",
		},
		{
			name:          "DotOnly",
			storagePrefix: "/store",
			inputPath:     "/./file.txt",
			expected:      "/store/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &httpsFileSystem{
				serviceURL:    "https://example.com",
				storagePrefix: tt.storagePrefix,
			}
			result := fs.davPath(tt.inputPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPathTraversal_UpstreamURL verifies that the HTTPS backend's
// upstreamURL function normalizes path traversal.
func TestPathTraversal_UpstreamURL(t *testing.T) {
	tests := []struct {
		name          string
		storagePrefix string
		inputPath     string
		expected      string
	}{
		{
			name:          "Normal",
			storagePrefix: "/store",
			inputPath:     "/file.txt",
			expected:      "https://example.com/store/file.txt",
		},
		{
			name:          "DotDotEscape",
			storagePrefix: "/store",
			inputPath:     "/../../etc/passwd",
			expected:      "https://example.com/store/etc/passwd",
		},
		{
			name:          "NoPrefix_DotDot",
			storagePrefix: "",
			inputPath:     "/foo/../bar",
			expected:      "https://example.com/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := &httpsFileSystem{
				serviceURL:    "https://example.com",
				storagePrefix: tt.storagePrefix,
			}
			result := fs.upstreamURL(tt.inputPath)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPathTraversal_BlobKey verifies that the blob backend's blobKey
// function normalizes path traversal sequences.
func TestPathTraversal_BlobKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal",
			input:    "/foo/bar",
			expected: "foo/bar",
		},
		{
			name:     "DotDotEscape",
			input:    "/foo/../../etc/passwd",
			expected: "etc/passwd",
		},
		{
			name:     "DotDotPartial",
			input:    "/foo/bar/../baz",
			expected: "foo/baz",
		},
		{
			name:     "Root",
			input:    "/",
			expected: "",
		},
		{
			name:     "DotOnly",
			input:    "/./foo",
			expected: "foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := blobKey(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPathTraversal_HandleRequest exercises the real RegisterHandlers /
// handleRequest code path to verify that path.Clean is applied before the
// request reaches the storage backend.  If the path.Clean call in
// handleRequest were removed, the spy filesystem would receive uncleaned
// ".." sequences and the assertions would fail.
func TestPathTraversal_HandleRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// --- set up spy backend ------------------------------------------------
	spy := &spyFileSystem{}
	be := &spyBackend{fs: spy}

	// --- wire package-level state ------------------------------------------
	ResetHandlers()
	t.Cleanup(func() {
		ResetHandlers()
		globalAuthConfig = nil
	})

	backends = map[string]server_utils.OriginBackend{
		"/test": be,
	}
	webdavHandlers = map[string]*webdav.Handler{
		"/test": {
			FileSystem: spy,
			LockSystem: webdav.NewMemLS(),
		},
	}
	exportPrefixMap = map[string]string{
		"/test": "/storage",
	}

	// --- minimal auth config with PublicReads so no token is required ------
	exports := []server_utils.OriginExport{{
		FederationPrefix: "/test",
		StoragePrefix:    "/storage",
		Capabilities:     server_structs.Capabilities{PublicReads: true},
	}}
	ac := &authConfig{}
	ac.exports.Store(&exports)
	globalAuthConfig = ac

	// --- register the real handlers ----------------------------------------
	engine := gin.New()
	require.NoError(t, RegisterHandlers(engine, false))

	// --- test cases --------------------------------------------------------
	tests := []struct {
		name           string
		requestPath    string // sent to the router
		expectedFSPath string // what the spy filesystem should see ("" = not called)
		expectAuthz401 bool   // true if auth middleware should block the request
	}{
		{
			name:           "NormalPath",
			requestPath:    "/test/sub/file.txt",
			expectedFSPath: "/sub/file.txt",
		},
		{
			name:           "DotDotPartial",
			requestPath:    "/test/sub/../other",
			expectedFSPath: "/other",
		},
		{
			name:           "DotDotDeep",
			requestPath:    "/test/a/b/../../c",
			expectedFSPath: "/c",
		},
		{
			// When .. escapes the export prefix entirely, the auth
			// middleware (which also path.Clean's) correctly blocks
			// the request because the resolved path is outside /test.
			name:           "DotDotEscapesExport_blocked",
			requestPath:    "/test/sub/../../etc/passwd",
			expectAuthz401: true,
		},
		{
			name:           "DotOnly",
			requestPath:    "/test/./sub/file.txt",
			expectedFSPath: "/sub/file.txt",
		},
		{
			name:           "DoubleSlash",
			requestPath:    "/test/sub//file.txt",
			expectedFSPath: "/sub/file.txt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spy.mu.Lock()
			spy.lastPath = ""
			spy.mu.Unlock()

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.requestPath, nil)
			engine.ServeHTTP(w, req)

			spy.mu.Lock()
			got := spy.lastPath
			spy.mu.Unlock()

			if tt.expectAuthz401 {
				assert.Equal(t, http.StatusUnauthorized, w.Code,
					"auth middleware should block paths that escape the export")
				assert.Empty(t, got, "filesystem should NOT be called for blocked requests")
			} else {
				assert.NotEmpty(t, got, "filesystem should have been called")
				assert.Equal(t, tt.expectedFSPath, got,
					"filesystem should receive the path.Clean'd path")
			}
		})
	}
}
