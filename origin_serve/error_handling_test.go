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
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FailingFS implements afero.Fs interface that can inject failures
type FailingFS struct {
	afero.Fs
	failureMode string
	failPath    string
	callCount   int
}

// NewFailingFS creates a new failing filesystem with injected failures
func NewFailingFS(baseFS afero.Fs, failureMode, failPath string) *FailingFS {
	return &FailingFS{
		Fs:          baseFS,
		failureMode: failureMode,
		failPath:    failPath,
		callCount:   0,
	}
}

// shouldFail determines if this operation should fail
func (f *FailingFS) shouldFail(path string) bool {
	if f.failPath == "" {
		return true
	}
	return path == f.failPath || contains(path, f.failPath)
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0)
}

// Open implements afero.Fs.Open with possible failures
func (f *FailingFS) Open(name string) (afero.File, error) {
	if f.shouldFail(name) {
		switch f.failureMode {
		case "permission_denied":
			return nil, fmt.Errorf("permission denied: %s", name)
		case "not_found":
			return nil, fmt.Errorf("no such file or directory: %s", name)
		case "io_error":
			return nil, fmt.Errorf("io error: read failed: %s", name)
		case "bad_fd":
			return nil, fmt.Errorf("bad file descriptor: %s", name)
		}
	}
	return f.Fs.Open(name)
}

// Create implements afero.Fs.Create with possible failures
func (f *FailingFS) Create(name string) (afero.File, error) {
	if f.shouldFail(name) {
		switch f.failureMode {
		case "permission_denied":
			return nil, fmt.Errorf("permission denied: %s", name)
		case "no_space":
			return nil, fmt.Errorf("disk quota exceeded: %s", name)
		case "read_only":
			return nil, fmt.Errorf("read only file system: %s", name)
		}
	}
	return f.Fs.Create(name)
}

// Stat implements afero.Fs.Stat with possible failures
func (f *FailingFS) Stat(name string) (os.FileInfo, error) {
	if f.shouldFail(name) {
		switch f.failureMode {
		case "permission_denied":
			return nil, fmt.Errorf("permission denied: %s", name)
		case "not_found":
			return nil, fmt.Errorf("no such file or directory: %s", name)
		}
	}
	return f.Fs.Stat(name)
}

// RemoveAll implements afero.Fs.RemoveAll with possible failures
func (f *FailingFS) RemoveAll(path string) error {
	if f.shouldFail(path) {
		switch f.failureMode {
		case "permission_denied":
			return fmt.Errorf("permission denied: %s", path)
		case "not_found":
			return fmt.Errorf("no such file or directory: %s", path)
		}
	}
	return f.Fs.RemoveAll(path)
}

// TestErrorHandlerMapping tests filesystem error to HTTP status mapping
func TestErrorHandlerMapping(t *testing.T) {
	handler := NewErrorHandler()

	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{"PermissionDenied", fmt.Errorf("permission denied: /path"), http.StatusForbidden},
		{"NotFound", fmt.Errorf("no such file or directory"), http.StatusNotFound},
		{"FileExists", fmt.Errorf("file exists"), http.StatusConflict},
		{"IsDirectory", fmt.Errorf("is a directory"), http.StatusBadRequest},
		{"IOError", fmt.Errorf("io error: read failed"), http.StatusInternalServerError},
		{"BadFD", fmt.Errorf("bad file descriptor"), http.StatusInternalServerError},
		{"ConnRefused", fmt.Errorf("connection refused"), http.StatusServiceUnavailable},
		{"QuotaExceeded", fmt.Errorf("disk quota exceeded"), http.StatusInsufficientStorage},
		{"TooManyFiles", fmt.Errorf("too many open files"), http.StatusServiceUnavailable},
		{"Unauthorized", fmt.Errorf("unauthorized"), http.StatusUnauthorized},
		{"Forbidden", fmt.Errorf("forbidden"), http.StatusForbidden},
		{"TokenExpired", fmt.Errorf("token expired"), http.StatusUnauthorized},
		{"NilError", nil, http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := handler.MapToHTTPStatus(tt.err)
			assert.Equal(t, tt.expected, status)
		})
	}
}

// TestFailingFSPermissionDenied tests filesystem permission denied failures
func TestFailingFSPermissionDenied(t *testing.T) {
	memFS := afero.NewMemMapFs()
	_, err := memFS.Create("/test/file.txt")
	require.NoError(t, err)

	failingFS := NewFailingFS(memFS, "permission_denied", "/test/file.txt")

	_, err = failingFS.Open("/test/file.txt")
	assert.Error(t, err, "Should fail with permission denied")
	assert.Contains(t, err.Error(), "permission denied")

	// Other paths should still work
	err = afero.WriteFile(failingFS, "/other/file.txt", []byte("data"), 0644)
	assert.NoError(t, err, "Operations on other paths should succeed")
}

// TestFailingFSNotFound tests filesystem not found failures
func TestFailingFSNotFound(t *testing.T) {
	memFS := afero.NewMemMapFs()
	failingFS := NewFailingFS(memFS, "not_found", "/missing/file.txt")

	_, err := failingFS.Open("/missing/file.txt")
	assert.Error(t, err, "Should fail with not found")
	assert.Contains(t, err.Error(), "no such file or directory")

	_, err = failingFS.Stat("/missing/file.txt")
	assert.Error(t, err, "Stat should also fail")
}

// TestFailingFSNoSpace tests disk quota failures
func TestFailingFSNoSpace(t *testing.T) {
	memFS := afero.NewMemMapFs()
	failingFS := NewFailingFS(memFS, "no_space", "/large_file")

	_, err := failingFS.Create("/large_file")
	assert.Error(t, err, "Should fail with no space")
	assert.Contains(t, err.Error(), "disk quota exceeded")

	// Other paths should work
	file, err := failingFS.Create("/small_file")
	assert.NoError(t, err)
	if file != nil {
		file.Close()
	}
}

// TestFailingFSReadOnly tests read-only filesystem failures
func TestFailingFSReadOnly(t *testing.T) {
	memFS := afero.NewMemMapFs()
	failingFS := NewFailingFS(memFS, "read_only", "/protected")

	_, err := failingFS.Create("/protected")
	assert.Error(t, err, "Should fail with read-only")
	assert.Contains(t, err.Error(), "read only file system")
}

// TestFailingFSSelectivePath tests that failures only affect specific paths
func TestFailingFSSelectivePath(t *testing.T) {
	memFS := afero.NewMemMapFs()
	err := afero.WriteFile(memFS, "/allowed/file.txt", []byte("data"), 0644)
	require.NoError(t, err)
	err = afero.WriteFile(memFS, "/denied/secret.txt", []byte("secret"), 0644)
	require.NoError(t, err)

	failingFS := NewFailingFS(memFS, "permission_denied", "/denied/secret.txt")

	data, err := afero.ReadFile(failingFS, "/allowed/file.txt")
	assert.NoError(t, err)
	assert.Equal(t, []byte("data"), data)

	_, err = failingFS.Open("/denied/secret.txt")
	assert.Error(t, err)
}

// BenchmarkErrorHandlerMapping benchmarks error mapping
func BenchmarkErrorHandlerMapping(b *testing.B) {
	handler := NewErrorHandler()
	err := fmt.Errorf("permission denied: /path/to/file")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.MapToHTTPStatus(err)
	}
}
