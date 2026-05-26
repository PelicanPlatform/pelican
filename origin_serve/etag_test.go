//go:build !windows

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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/webdav"
)

// statHelper stats a file directly (not through os.Root) so that the resulting
// FileInfo.Sys() carries a *syscall.Stat_t (FileInode succeeds on unix).
func statHelper(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info
}

// TestComputeETag_Format checks the opaque, fixed-width layout: a quoted
// 16-char lowercase hex string (the first 8 bytes of a SHA-256 digest).
func TestComputeETag_Format(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o644))

	etag := computeETag(statHelper(t, path))

	require.True(t, strings.HasPrefix(etag, `"`), "ETag should be quoted")
	require.True(t, strings.HasSuffix(etag, `"`), "ETag should be quoted")
	inner := strings.Trim(etag, `"`)
	require.Equal(t, 16, len(inner),
		"opaque ETag should be 16 hex chars (8 bytes of SHA-256); got %q", etag)
	for _, r := range inner {
		require.True(t,
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'),
			"ETag body must be lowercase hex: %q", etag)
	}
}

// TestComputeETag_DistinguishesFilesWithSameSizeAndMTime is the bug the
// developer reported: two files with the same size and mtime previously
// collapsed to identical ETags. Including the inode fixes that.
func TestComputeETag_DistinguishesFilesWithSameSizeAndMTime(t *testing.T) {
	tmpDir := t.TempDir()
	a := filepath.Join(tmpDir, "a.txt")
	b := filepath.Join(tmpDir, "b.txt")

	// Same byte length, deliberately different content.
	require.NoError(t, os.WriteFile(a, []byte("AAAAA"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("BBBBB"), 0o644))

	// Force identical modification timestamps so size+mtime alone cannot
	// distinguish them. We pick a wall-clock time in the past so that we know
	// the value persists exactly across both files.
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(a, fixed, fixed))
	require.NoError(t, os.Chtimes(b, fixed, fixed))

	infoA := statHelper(t, a)
	infoB := statHelper(t, b)
	require.Equal(t, infoA.Size(), infoB.Size(), "test setup: sizes must match")
	require.Equal(t, infoA.ModTime().UnixNano(), infoB.ModTime().UnixNano(),
		"test setup: mtimes must match")

	etagA := computeETag(infoA)
	etagB := computeETag(infoB)
	assert.NotEqual(t, etagA, etagB,
		"two files with the same size+mtime must still have distinct ETags (got %q for both)", etagA)
}

// TestComputeETag_ChangesOnRewrite verifies that rewriting an existing file
// (which preserves the inode but updates mtime) produces a new ETag.
func TestComputeETag_ChangesOnRewrite(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o644))
	etag1 := computeETag(statHelper(t, path))

	// Wait long enough that even coarsely-tracked filesystems update mtime.
	time.Sleep(15 * time.Millisecond)
	require.NoError(t, os.WriteFile(path, []byte("v22"), 0o644))
	etag2 := computeETag(statHelper(t, path))

	assert.NotEqual(t, etag1, etag2,
		"rewriting a file should change its ETag (mtime/size differ)")
}

// TestComputeETag_StableForSameFile verifies that two stats of the same file
// produce identical ETags (no entropy / time-of-call dependency).
func TestComputeETag_StableForSameFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("payload"), 0o644))

	first := computeETag(statHelper(t, path))
	time.Sleep(5 * time.Millisecond)
	second := computeETag(statHelper(t, path))
	assert.Equal(t, first, second, "ETag for an unmodified file must be stable")
}

// TestComputeETag_FallbackWhenNoInode covers the Windows / synthesized-FileInfo
// path by passing an afero in-memory FileInfo, whose Sys() does not return a
// *syscall.Stat_t. The output shape is still a quoted 16-char opaque tag --
// the inode simply isn't mixed into the hash.
func TestComputeETag_FallbackWhenNoInode(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/x.txt", []byte("data"), 0o644))
	info, err := fs.Stat("/x.txt")
	require.NoError(t, err)

	etag := computeETag(info)
	require.True(t, strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`),
		"ETag should be quoted: %q", etag)
	inner := strings.Trim(etag, `"`)
	assert.Equal(t, 16, len(inner),
		"opaque ETag should be 16 hex chars even without an inode: %q", etag)
}

// --- End-to-end checks through the GET/PUT handlers -------------------------

// newTestGetServer wires up a minimal handler chain that mimics how RegisterHandlers
// dispatches GET requests, without bringing up a full federation. The Gin router
// strips the /test prefix; the WebDAV handler serves files from storageDir.
func newTestGetServer(t *testing.T, storageDir string) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	wd := &webdav.Handler{
		FileSystem: webdav.Dir(storageDir),
		LockSystem: webdav.NewMemLS(),
		Prefix:     "/test",
	}
	r.GET("/test/*path", func(c *gin.Context) {
		handleGetWithETag(c, wd, c.Request, c.Param("path"), storageDir)
	})
	return httptest.NewServer(r)
}

func doGet(t *testing.T, url string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

// TestGetETag_DistinctForSameSizeAndMTime is the HTTP-level analogue of
// TestComputeETag_DistinguishesFilesWithSameSizeAndMTime.
func TestGetETag_DistinctForSameSizeAndMTime(t *testing.T) {
	storage := t.TempDir()
	a := filepath.Join(storage, "a.bin")
	b := filepath.Join(storage, "b.bin")
	require.NoError(t, os.WriteFile(a, []byte("AAAAA"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("BBBBB"), 0o644))

	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(a, fixed, fixed))
	require.NoError(t, os.Chtimes(b, fixed, fixed))

	srv := newTestGetServer(t, storage)
	defer srv.Close()

	respA, _ := doGet(t, srv.URL+"/test/a.bin", nil)
	require.Equal(t, http.StatusOK, respA.StatusCode)
	etagA := respA.Header.Get("ETag")
	require.NotEmpty(t, etagA, "GET should expose ETag")

	respB, _ := doGet(t, srv.URL+"/test/b.bin", nil)
	require.Equal(t, http.StatusOK, respB.StatusCode)
	etagB := respB.Header.Get("ETag")
	require.NotEmpty(t, etagB)

	assert.NotEqual(t, etagA, etagB,
		"two files with the same size+mtime served over HTTP must have distinct ETags")
}

// TestGetIfNoneMatch_NewFormat verifies the conditional-request path still
// produces a 304 after the format change.
func TestGetIfNoneMatch_NewFormat(t *testing.T) {
	storage := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(storage, "f.txt"), []byte("hi"), 0o644))

	srv := newTestGetServer(t, storage)
	defer srv.Close()

	resp, _ := doGet(t, srv.URL+"/test/f.txt", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag)

	resp2, body := doGet(t, srv.URL+"/test/f.txt", map[string]string{"If-None-Match": etag})
	assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
		"matching If-None-Match should return 304 (body=%q, etag=%q)", string(body), etag)
}

// TestGetETag_ChangesAfterRewrite is the HTTP-level analogue of
// TestComputeETag_ChangesOnRewrite.
func TestGetETag_ChangesAfterRewrite(t *testing.T) {
	storage := t.TempDir()
	path := filepath.Join(storage, "f.txt")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o644))

	srv := newTestGetServer(t, storage)
	defer srv.Close()

	resp, _ := doGet(t, srv.URL+"/test/f.txt", nil)
	etag1 := resp.Header.Get("ETag")
	require.NotEmpty(t, etag1)

	time.Sleep(15 * time.Millisecond)
	require.NoError(t, os.WriteFile(path, []byte("v2 longer"), 0o644))

	resp2, _ := doGet(t, srv.URL+"/test/f.txt", nil)
	etag2 := resp2.Header.Get("ETag")
	require.NotEmpty(t, etag2)

	assert.NotEqual(t, etag1, etag2)
	// And the previously-issued ETag should no longer satisfy If-None-Match.
	resp3, _ := doGet(t, srv.URL+"/test/f.txt", map[string]string{"If-None-Match": etag1})
	assert.Equal(t, http.StatusOK, resp3.StatusCode,
		"stale ETag must not yield 304 after rewrite")
}
