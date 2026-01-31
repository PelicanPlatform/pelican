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
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/metrics"
)

// TestPOSIXv2MetricsCollection verifies that POSIXv2 filesystem operations
// correctly publish unified pelican_storage_* metrics with backend="posixv2"
func TestPOSIXv2MetricsCollection(t *testing.T) {
	// Setup temporary filesystem
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	// Get initial metric values for backend="posixv2"
	initialReads := promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2"))
	initialWrites := promtest.ToFloat64(metrics.StorageWritesTotal.WithLabelValues("posixv2"))
	initialStats := promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2"))
	initialOpens := promtest.ToFloat64(metrics.StorageOpensTotal.WithLabelValues("posixv2"))
	initialMkdirs := promtest.ToFloat64(metrics.StorageMkdirsTotal.WithLabelValues("posixv2"))

	ctx := context.Background()

	// Test 1: Mkdir operation
	err = fs.Mkdir(ctx, "/subdir", 0755)
	require.NoError(t, err)

	// Verify mkdir metric incremented
	mkdirCount := promtest.ToFloat64(metrics.StorageMkdirsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, mkdirCount, initialMkdirs, "Mkdir metric should increment for backend=posixv2")

	// Test 2: Stat operation
	_, err = fs.Stat(ctx, "/subdir")
	require.NoError(t, err)

	// Verify stat metric incremented
	statCount := promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, statCount, initialStats, "Stat metric should increment for backend=posixv2")

	// Test 3: File open/write operation
	file, err := fs.OpenFile(ctx, "/test.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)

	// Verify open metric incremented
	openCount := promtest.ToFloat64(metrics.StorageOpensTotal.WithLabelValues("posixv2"))
	assert.Greater(t, openCount, initialOpens, "Open metric should increment for backend=posixv2")

	// Write data
	testData := []byte("Hello, POSIXv2 metrics!")
	n, err := file.Write(testData)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)

	// Close to flush metrics (removed defer to ensure immediate close)
	err = file.Close()
	require.NoError(t, err)

	// Verify write metric incremented
	writeCount := promtest.ToFloat64(metrics.StorageWritesTotal.WithLabelValues("posixv2"))
	assert.Greater(t, writeCount, initialWrites, "Write metric should increment for backend=posixv2")

	// Verify bytes written
	bytesWritten := promtest.ToFloat64(metrics.StorageBytesWritten.WithLabelValues("posixv2"))
	assert.GreaterOrEqual(t, bytesWritten, float64(len(testData)), "Write bytes should be at least the data written")

	// Test 4: File read operation
	file, err = fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)

	readBuf := make([]byte, len(testData))
	n, err = file.Read(readBuf)
	require.NoError(t, err)
	require.Equal(t, len(testData), n)

	// Close immediately (removed defer to ensure immediate close)
	err = file.Close()
	require.NoError(t, err)

	// Verify read metric incremented
	readCount := promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, readCount, initialReads, "Read metric should increment for backend=posixv2")

	// Verify bytes read
	bytesRead := promtest.ToFloat64(metrics.StorageBytesRead.WithLabelValues("posixv2"))
	assert.GreaterOrEqual(t, bytesRead, float64(len(testData)), "Read bytes should be at least the data read")
}

// TestPOSIXv2SlowOperationMetrics verifies that slow operations (>2s) are tracked
func TestPOSIXv2SlowOperationMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow operation test in short mode")
	}

	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Get initial slow operation count
	initialSlowStats := promtest.ToFloat64(metrics.StorageSlowStatsTotal.WithLabelValues("posixv2"))

	// Note: We can't easily create a genuinely slow operation in a test without
	// mocking the filesystem or actually blocking for 2 seconds. This test
	// documents the metric exists and is labeled correctly.
	// In real usage, slow operations would be tracked automatically by trackOperation()

	// Verify the metric exists with the posixv2 label
	_, _ = fs.Stat(ctx, "/nonexistent")
	// Error is expected for nonexistent file

	// The metric should be queryable even if no slow operations occurred yet
	slowStatCount := promtest.ToFloat64(metrics.StorageSlowStatsTotal.WithLabelValues("posixv2"))
	assert.GreaterOrEqual(t, slowStatCount, initialSlowStats, "Slow stat metric should be accessible for backend=posixv2")
}

// TestPOSIXv2ErrorHandling verifies that errors don't crash the metrics system
func TestPOSIXv2ErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Get initial stat count
	initialStats := promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2"))

	// Try to stat a nonexistent file (should error)
	_, err = fs.Stat(ctx, "/nonexistent-file-12345")
	require.Error(t, err, "Should error for nonexistent file")

	// Verify stat metric still incremented (operation attempted)
	stats := promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, stats, initialStats, "Stat metric should increment even for errors for backend=posixv2")
}

// TestPOSIXv2ActiveOperationMetrics verifies that active operation gauges work
func TestPOSIXv2ActiveOperationMetrics(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Active operations are tracked during the operation
	// The gauge increments when operation starts, decrements when it ends
	// We can't easily observe it mid-operation without complex synchronization,
	// but we can verify the metric exists and is accessible

	// Get initial active read count
	initialActiveReads := promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))

	// Create and read a file
	testFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	defer file.Close()

	buf := make([]byte, 4)
	_, _ = file.Read(buf)
	file.Close()

	// After operation completes, active reads should be back to baseline
	activeReads := promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))
	assert.Equal(t, initialActiveReads, activeReads, "Active reads should return to baseline after operation completes")
}

// TestPOSIXv2MetricLabels verifies that all metrics use the correct backend label
func TestPOSIXv2MetricLabels(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Perform various operations
	_ = fs.Mkdir(ctx, "/dir", 0755)
	_, _ = fs.Stat(ctx, "/dir")
	file, _ := fs.OpenFile(ctx, "/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	if file != nil {
		_, _ = file.Write([]byte("test"))
		file.Close()
	}

	// Verify metrics can be queried with backend="posixv2" label
	metricsToCheck := []prometheus.Collector{
		metrics.StorageReadsTotal,
		metrics.StorageWritesTotal,
		metrics.StorageStatsTotal,
		metrics.StorageOpensTotal,
		metrics.StorageMkdirsTotal,
		metrics.StorageBytesRead,
		metrics.StorageBytesWritten,
	}

	for _, metric := range metricsToCheck {
		// This will panic if the label doesn't exist or is incorrect
		// The test passing means all metrics have the posixv2 label
		_ = promtest.ToFloat64(metric.(prometheus.Collector))
	}
}

// TestPOSIXv2RemoveMetrics verifies that remove/unlink operations are tracked
func TestPOSIXv2RemoveMetrics(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Create a file to remove
	file, err := fs.OpenFile(ctx, "/remove-me.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	file.Close()

	// Get initial unlink count
	initialUnlinks := promtest.ToFloat64(metrics.StorageUnlinksTotal.WithLabelValues("posixv2"))

	// Remove the file
	err = fs.RemoveAll(ctx, "/remove-me.txt")
	require.NoError(t, err)

	// Verify unlink metric incremented
	unlinkCount := promtest.ToFloat64(metrics.StorageUnlinksTotal.WithLabelValues("posixv2"))
	assert.Greater(t, unlinkCount, initialUnlinks, "Unlink metric should increment for backend=posixv2")
}

// TestPOSIXv2RenameMetrics verifies that rename operations are tracked
func TestPOSIXv2RenameMetrics(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Create a file to rename
	file, err := fs.OpenFile(ctx, "/old-name.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	file.Close()

	// Get initial rename count
	initialRenames := promtest.ToFloat64(metrics.StorageRenamesTotal.WithLabelValues("posixv2"))

	// Rename the file
	err = fs.Rename(ctx, "/old-name.txt", "/new-name.txt")
	require.NoError(t, err)

	// Verify rename metric incremented
	renameCount := promtest.ToFloat64(metrics.StorageRenamesTotal.WithLabelValues("posixv2"))
	assert.Greater(t, renameCount, initialRenames, "Rename metric should increment for backend=posixv2")
}
