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
	"os"
	"path/filepath"
	"testing"
	"time"

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

	// Create underlying filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)

	// Wrap with slowFs that delays Stat operations by 2.5 seconds
	slowRootFs := &slowFs{
		Fs:        osRootFs,
		statDelay: 2500 * time.Millisecond,
	}
	fs := newAferoFileSystem(slowRootFs, "", nil)

	ctx := context.Background()

	// Create a file to stat
	testFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	// Get initial slow operation count
	initialSlowStats := promtest.ToFloat64(metrics.StorageSlowStatsTotal.WithLabelValues("posixv2"))

	// Perform a slow Stat operation (2.5s delay)
	_, err = fs.Stat(ctx, "/test.txt")
	require.NoError(t, err)

	// Verify slow stat metric incremented
	slowStatCount := promtest.ToFloat64(metrics.StorageSlowStatsTotal.WithLabelValues("posixv2"))
	assert.Greater(t, slowStatCount, initialSlowStats, "Slow stat metric should increment for operations >2s with backend=posixv2")
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

	// Create underlying filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)

	// Create a channel to control when Read proceeds
	readReady := make(chan struct{})

	// Wrap with slowFs that blocks Read operations until signaled
	slowRootFs := &slowFs{
		Fs:        osRootFs,
		readReady: readReady,
	}
	fs := newAferoFileSystem(slowRootFs, "", nil)

	ctx := context.Background()

	// Create a test file
	testFile := filepath.Join(tmpDir, "test.txt")
	err = os.WriteFile(testFile, []byte("test data for active metrics"), 0644)
	require.NoError(t, err)

	// Get initial active read count
	initialActiveReads := promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))

	// Start a read operation in a goroutine
	// The flow will be: file.Read() -> metricsFile.metricsOnlyRead() -> Inc gauge -> mf.File.Read(p) -> slowFile.Read(p) -> block on channel
	readComplete := make(chan error, 1)
	go func() {
		file, err := fs.OpenFile(ctx, "/test.txt", os.O_RDONLY, 0)
		if err != nil {
			readComplete <- err
			return
		}
		defer file.Close()

		buf := make([]byte, 100)
		_, err = file.Read(buf) // This will Inc gauge, then block in slowFile.Read waiting for channel
		readComplete <- err
	}()

	// Give the Read call time to:
	// 1. Enter metricsFile.metricsOnlyRead
	// 2. Inc the StorageActiveReads gauge
	// 3. Call mf.File.Read(p) which calls slowFile.Read
	// 4. Block on the readReady channel
	time.Sleep(50 * time.Millisecond)

	// Verify active reads incremented while operation is in progress
	activeReads := promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))
	assert.Greater(t, activeReads, initialActiveReads, "Active reads should increment while read operation is in progress for backend=posixv2")

	// Signal the Read to proceed
	close(readReady)

	// Wait for operation to complete
	err = <-readComplete
	require.NoError(t, err)

	// Give metrics time to decrement
	time.Sleep(10 * time.Millisecond)

	// After operation completes, active reads should be back to baseline
	activeReadsAfter := promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))
	assert.Equal(t, initialActiveReads, activeReadsAfter, "Active reads should return to baseline after operation completes for backend=posixv2")
}

// TestPOSIXv2MetricLabels verifies that all metrics use the correct backend label
func TestPOSIXv2MetricLabels(t *testing.T) {
	tmpDir := t.TempDir()

	// Create filesystem
	osRootFs, err := NewOsRootFs(tmpDir)
	require.NoError(t, err)
	fs := newAferoFileSystem(osRootFs, "", nil)

	ctx := context.Background()

	// Get initial metric values to establish baseline
	initialReads := promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2"))
	initialWrites := promtest.ToFloat64(metrics.StorageWritesTotal.WithLabelValues("posixv2"))
	initialStats := promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2"))
	initialOpens := promtest.ToFloat64(metrics.StorageOpensTotal.WithLabelValues("posixv2"))
	initialMkdirs := promtest.ToFloat64(metrics.StorageMkdirsTotal.WithLabelValues("posixv2"))
	initialUnlinks := promtest.ToFloat64(metrics.StorageUnlinksTotal.WithLabelValues("posixv2"))
	initialRenames := promtest.ToFloat64(metrics.StorageRenamesTotal.WithLabelValues("posixv2"))

	// Perform various operations
	err = fs.Mkdir(ctx, "/dir", 0755)
	require.NoError(t, err)

	_, err = fs.Stat(ctx, "/dir")
	require.NoError(t, err)

	file, err := fs.OpenFile(ctx, "/file.txt", os.O_CREATE|os.O_WRONLY, 0644)
	require.NoError(t, err)
	_, err = file.Write([]byte("test"))
	require.NoError(t, err)
	file.Close()

	// Read the file back
	file, err = fs.OpenFile(ctx, "/file.txt", os.O_RDONLY, 0)
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = file.Read(buf)
	require.NoError(t, err)
	file.Close()

	// Rename the file
	err = fs.Rename(ctx, "/file.txt", "/renamed.txt")
	require.NoError(t, err)

	// Remove the file
	err = fs.RemoveAll(ctx, "/renamed.txt")
	require.NoError(t, err)

	// Verify all metrics incremented with the correct backend="posixv2" label
	assert.Greater(t, promtest.ToFloat64(metrics.StorageReadsTotal.WithLabelValues("posixv2")), initialReads,
		"StorageReadsTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageWritesTotal.WithLabelValues("posixv2")), initialWrites,
		"StorageWritesTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageStatsTotal.WithLabelValues("posixv2")), initialStats,
		"StorageStatsTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageOpensTotal.WithLabelValues("posixv2")), initialOpens,
		"StorageOpensTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageMkdirsTotal.WithLabelValues("posixv2")), initialMkdirs,
		"StorageMkdirsTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageUnlinksTotal.WithLabelValues("posixv2")), initialUnlinks,
		"StorageUnlinksTotal should increment for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageRenamesTotal.WithLabelValues("posixv2")), initialRenames,
		"StorageRenamesTotal should increment for backend=posixv2")

	// Verify byte counters also work
	assert.Greater(t, promtest.ToFloat64(metrics.StorageBytesRead.WithLabelValues("posixv2")), 0.0,
		"StorageBytesRead should be >0 for backend=posixv2")
	assert.Greater(t, promtest.ToFloat64(metrics.StorageBytesWritten.WithLabelValues("posixv2")), 0.0,
		"StorageBytesWritten should be >0 for backend=posixv2")

	// Verify gauge metrics exist and can be queried (they may be 0 at this point)
	_ = promtest.ToFloat64(metrics.StorageActiveReads.WithLabelValues("posixv2"))
	_ = promtest.ToFloat64(metrics.StorageActiveWrites.WithLabelValues("posixv2"))

	t.Log("All metrics verified with correct backend=posixv2 label")
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
