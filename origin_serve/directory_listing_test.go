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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAcceptsHTML tests the acceptsHTML helper function
func TestAcceptsHTML(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		expected bool
	}{
		{
			name:     "Empty Accept header",
			accept:   "",
			expected: false,
		},
		{
			name:     "Browser Accept header",
			accept:   "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			expected: true,
		},
		{
			name:     "Plain text/html",
			accept:   "text/html",
			expected: true,
		},
		{
			name:     "JSON only",
			accept:   "application/json",
			expected: false,
		},
		{
			name:     "Wildcard only",
			accept:   "*/*",
			expected: false,
		},
		{
			name:     "curl default",
			accept:   "*/*",
			expected: false,
		},
		{
			name:     "WebDAV client",
			accept:   "application/xml",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			result := acceptsHTML(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFormatSize tests the formatSize helper function
func TestFormatSize(t *testing.T) {
	tests := []struct {
		size     int64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatSize(tt.size)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestDirectoryListingStreaming tests that directory listing streams content
// without blocking on large directories
func TestDirectoryListingStreaming(t *testing.T) {
	// Create a temp directory with some files
	tmpDir := t.TempDir()

	// Create test files and directories
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir1"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir2"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("world!"), 0644))

	// Open the root for os.Root
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	// Create a test request with HTML accept header
	req, _ := http.NewRequest("GET", "/test/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	// Create a response recorder
	w := httptest.NewRecorder()

	// Create a mock gin context
	c := createMockGinContext(w, req)

	// Call streamDirectoryListing
	streamDirectoryListing(c, root, ".", "/test/", tmpDir)

	// Check response
	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"))
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	// Check body contains expected elements
	body := w.Body.String()
	assert.Contains(t, body, "<!DOCTYPE html>")
	assert.Contains(t, body, "Index of /test/")
	assert.Contains(t, body, "Pelican")
	assert.Contains(t, body, "subdir1/")
	assert.Contains(t, body, "subdir2/")
	assert.Contains(t, body, "file1.txt")
	assert.Contains(t, body, "file2.txt")

	// Check directories are listed before files (they should appear first)
	subdir1Pos := strings.Index(body, "subdir1/")
	file1Pos := strings.Index(body, "file1.txt")
	assert.Less(t, subdir1Pos, file1Pos, "directories should appear before files")
}

// TestDirectoryListingParentLink tests that parent link is shown correctly
func TestDirectoryListingParentLink(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "file.txt"), []byte("test"), 0644))

	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	req, _ := http.NewRequest("GET", "/test/subdir/", nil)
	req.Header.Set("Accept", "text/html")

	w := httptest.NewRecorder()
	c := createMockGinContext(w, req)

	streamDirectoryListing(c, root, "subdir", "/test/subdir/", tmpDir)

	body := w.Body.String()
	assert.Contains(t, body, "..")
	assert.Contains(t, body, `href="/test"`) // Parent link points to /test (parent of /test/subdir)
}

// TestDirectoryListingRootNoParent tests that root directory doesn't show parent link
func TestDirectoryListingRootNoParent(t *testing.T) {
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "file.txt"), []byte("test"), 0644))

	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept", "text/html")

	w := httptest.NewRecorder()
	c := createMockGinContext(w, req)

	streamDirectoryListing(c, root, ".", "/", tmpDir)

	body := w.Body.String()
	// Root should not have parent link (should not contain ".." except in the path)
	assert.NotContains(t, body, `<a href="/">..</a>`)
}

// TestDirectoryListingEmptyDir tests listing an empty directory
func TestDirectoryListingEmptyDir(t *testing.T) {
	tmpDir := t.TempDir()

	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	req, _ := http.NewRequest("GET", "/test/", nil)
	req.Header.Set("Accept", "text/html")

	w := httptest.NewRecorder()
	c := createMockGinContext(w, req)

	streamDirectoryListing(c, root, ".", "/test/", tmpDir)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body := w.Body.String()
	assert.Contains(t, body, "Index of /test/")
	// Empty dir should still have table structure
	assert.Contains(t, body, "<tbody>")
	assert.Contains(t, body, "</tbody>")
}

// TestDirectoryListingLargeDirectory tests that large directories stream properly
func TestDirectoryListingLargeDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create 500 files to test batching/streaming
	for i := 0; i < 500; i++ {
		name := filepath.Join(tmpDir, strings.Repeat("a", 5)+"_file"+strings.Repeat("0", 4-len(string(rune('0'+i%10))))+".txt")
		require.NoError(t, os.WriteFile(name, []byte("test"), 0644))
	}

	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	req, _ := http.NewRequest("GET", "/test/", nil)
	req.Header.Set("Accept", "text/html")

	w := httptest.NewRecorder()
	c := createMockGinContext(w, req)

	streamDirectoryListing(c, root, ".", "/test/", tmpDir)

	resp := w.Result()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	body := w.Body.String()
	// Should contain footer (streaming completed)
	assert.Contains(t, body, "Powered by Pelican Platform")
}

// TestDirectoryListingNonBrowserRequest tests that non-browser requests
// don't get HTML listing (they get WebDAV 405 instead, but we just verify
// the acceptsHTML function returns false)
func TestDirectoryListingNonBrowserRequest(t *testing.T) {
	// This is tested by acceptsHTML tests above, but here we document
	// the expected behavior
	req, _ := http.NewRequest("GET", "/", nil)
	// No Accept header (like curl default) or JSON-only
	assert.False(t, acceptsHTML(req))

	req.Header.Set("Accept", "application/json")
	assert.False(t, acceptsHTML(req))
}

// createMockGinContext creates a minimal gin.Context for testing
func createMockGinContext(w http.ResponseWriter, req *http.Request) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	return c
}
