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

package origin

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestCalculateDiskUsagePOSIX(t *testing.T) {
	// Create a temporary directory with test files
	tmpDir := t.TempDir()

	// Create test files with known sizes
	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	subdir := filepath.Join(tmpDir, "subdir")
	file3 := filepath.Join(subdir, "file3.txt")

	// Create files
	require.NoError(t, os.WriteFile(file1, []byte("12345"), 0644))
	require.NoError(t, os.WriteFile(file2, []byte("1234567890"), 0644))
	require.NoError(t, os.MkdirAll(subdir, 0755))
	require.NoError(t, os.WriteFile(file3, []byte("123"), 0644))

	ctx := context.Background()
	limiter := rate.NewLimiter(rate.Limit(1000), 2000)

	bytes, count, err := calculateDiskUsagePOSIX(ctx, tmpDir, limiter)
	require.NoError(t, err)

	// We should have 3 files totaling 18 bytes
	assert.Equal(t, uint64(18), bytes, "Expected total bytes to match")
	assert.Equal(t, uint64(3), count, "Expected file count to match")
}

func TestCalculateDiskUsageForExport(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Set storage type to POSIX
	require.NoError(t, param.Set(param.Origin_StorageType.GetName(), "posix"))

	// Create a temporary directory with test files
	tmpDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test1.txt"), []byte("hello"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tmpDir, "test2.txt"), []byte("world"), 0644))

	export := server_utils.OriginExport{
		StoragePrefix:    tmpDir,
		FederationPrefix: "/test",
		Capabilities:     server_structs.Capabilities{},
	}

	ctx := context.Background()
	limiter := rate.NewLimiter(rate.Limit(1000), 2000)

	result, err := calculateDiskUsageForExport(ctx, export, limiter, "", false)
	require.NoError(t, err)

	assert.Equal(t, "/test", result.prefix)
	assert.Equal(t, uint64(10), result.bytes) // "hello" + "world" = 10 bytes
	assert.Equal(t, uint64(2), result.count)
}

// Verify the Prometheus error counter increases when we
// force an error during disk usage calculation (here, by
// setting an invalid discovery URL).
func TestCalculateDiskUsageErrors(t *testing.T) {
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Set a dummy discovery URL (invalid) to verify we try to use it
	require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), "https://example.com"))

	export := server_utils.OriginExport{
		FederationPrefix: "/test",
		Capabilities:     server_structs.Capabilities{},
	}

	limiter := rate.NewLimiter(rate.Limit(1000), 2000)
	ctx := context.Background()

	// Force PelicanFS-based disk usage calculation.
	_, err := calculateDiskUsageForExport(ctx, export, limiter, "", true)

	// Since we suppress errors in the walker to allow continuation, the function itself returns nil error
	require.NoError(t, err)

	// However, we should have recorded an error in the metrics
	// The label is the federation prefix
	metric := PelicanOriginDiskUsageCrawlErrors.WithLabelValues("/test")
	val := testutil.ToFloat64(metric)
	assert.GreaterOrEqual(t, val, float64(1.0), "Expected at least one error recorded in metrics due to invalid URL")
}

func TestCalculateDiskUsageContextCancellation(t *testing.T) {
	// Create a directory with many files to test cancellation
	tmpDir := t.TempDir()
	for i := 0; i < 100; i++ {
		filename := filepath.Join(tmpDir, "file_"+string(rune('a'+i%26))+".txt")
		require.NoError(t, os.WriteFile(filename, []byte("test"), 0644))
	}

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	limiter := rate.NewLimiter(rate.Limit(1000), 2000)

	_, _, err := calculateDiskUsagePOSIX(ctx, tmpDir, limiter)
	assert.Error(t, err, "Expected error due to cancelled context")
	assert.Equal(t, context.Canceled, err, "Expected context.Canceled error")
}

func TestCalculateDiskUsageRateLimiting(t *testing.T) {
	// Create a directory with some files
	tmpDir := t.TempDir()
	for i := 0; i < 20; i++ {
		filename := filepath.Join(tmpDir, "file_"+string(rune('a'+(i%26)))+string(rune('0'+(i/26)))+".txt")
		require.NoError(t, os.WriteFile(filename, []byte("test"), 0644))
	}

	ctx := context.Background()
	// Set a rate limit - the main goal is to verify rate limiting doesn't break the calculation
	limiter := rate.NewLimiter(rate.Limit(100), 200)

	bytes, count, err := calculateDiskUsagePOSIX(ctx, tmpDir, limiter)

	require.NoError(t, err)
	assert.Equal(t, uint64(80), bytes) // 20 files * 4 bytes each
	assert.Equal(t, uint64(20), count)
}

func TestCalculateDiskUsageEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	ctx := context.Background()
	limiter := rate.NewLimiter(rate.Limit(1000), 2000)

	bytes, count, err := calculateDiskUsagePOSIX(ctx, tmpDir, limiter)
	require.NoError(t, err)

	assert.Equal(t, uint64(0), bytes, "Empty directory should have 0 bytes")
	assert.Equal(t, uint64(0), count, "Empty directory should have 0 files")
}

func TestCalculateDiskUsageNonExistentDirectory(t *testing.T) {
	ctx := context.Background()
	limiter := rate.NewLimiter(rate.Limit(1000), 2000)

	// filepath.WalkDir doesn't return an error for non-existent paths, it just calls the walkFunc with an error
	// So we don't expect an error from calculateDiskUsagePOSIX
	bytes, count, err := calculateDiskUsagePOSIX(ctx, "/nonexistent/path/that/does/not/exist", limiter)

	// The function logs errors but doesn't fail on individual file errors
	// It should complete with zero bytes/count
	require.NoError(t, err)
	assert.Equal(t, uint64(0), bytes)
	assert.Equal(t, uint64(0), count)
}
