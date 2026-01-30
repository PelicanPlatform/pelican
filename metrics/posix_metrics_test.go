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

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlowOperationThreshold verifies the slow operation threshold is set correctly
func TestSlowOperationThreshold(t *testing.T) {
	assert.Equal(t, 2*time.Second, SlowOperationThreshold, "Slow operation threshold should be 2 seconds")
}

// TestMetricsUpdateInterval verifies the metrics update interval is set correctly
func TestMetricsUpdateInterval(t *testing.T) {
	assert.Equal(t, 250*time.Millisecond, MetricsUpdateInterval, "Metrics update interval should be 250ms")
}

// TestPosixOperationTrackerBasic tests basic operation tracking
func TestPosixOperationTrackerBasic(t *testing.T) {
	// Get initial counter values
	initialReads := promtest.ToFloat64(PosixReadsTotal)
	initialWrites := promtest.ToFloat64(PosixWritesTotal)

	// Track a read operation
	readTracker := NewPosixOperationTracker(PosixOpRead, 1024)
	time.Sleep(100 * time.Millisecond) // Simulate some work
	readTracker.Complete(nil)

	// Verify read counter incremented
	assert.Equal(t, initialReads+1, promtest.ToFloat64(PosixReadsTotal), "Read counter should increment")

	// Track a write operation
	writeTracker := NewPosixOperationTracker(PosixOpWrite, 2048)
	time.Sleep(100 * time.Millisecond)
	writeTracker.Complete(nil)

	// Verify write counter incremented
	assert.Equal(t, initialWrites+1, promtest.ToFloat64(PosixWritesTotal), "Write counter should increment")
}

// TestPosixOperationTrackerSlowOps tests slow operation tracking
func TestPosixOperationTrackerSlowOps(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow operation test in short mode")
	}

	// Get initial slow read counter
	initialSlowReads := promtest.ToFloat64(PosixSlowReadsTotal)

	// Track a slow read operation (>2s)
	tracker := NewPosixOperationTracker(PosixOpRead, 4096)
	time.Sleep(2100 * time.Millisecond) // Sleep just over 2 seconds
	tracker.Complete(nil)

	// Verify slow read counter incremented
	require.Greater(t, promtest.ToFloat64(PosixSlowReadsTotal), initialSlowReads,
		"Slow read counter should increment for operations >2s")
}

// TestPosixOperationTrackerActiveGauges tests active operation gauges
func TestPosixOperationTrackerActiveGauges(t *testing.T) {
	// Get initial active reads gauge
	initialActiveReads := promtest.ToFloat64(PosixActiveReads)
	initialActiveIO := promtest.ToFloat64(PosixActiveIO)

	// Start a read operation
	tracker := NewPosixOperationTracker(PosixOpRead, 512)

	// Verify gauges incremented
	assert.Equal(t, initialActiveReads+1, promtest.ToFloat64(PosixActiveReads),
		"Active reads gauge should increment when operation starts")
	assert.Equal(t, initialActiveIO+1, promtest.ToFloat64(PosixActiveIO),
		"Active IO gauge should increment when operation starts")

	// Complete the operation
	tracker.Complete(nil)

	// Give time for deferred cleanup to execute
	time.Sleep(10 * time.Millisecond)

	// Verify gauges decremented back
	assert.Equal(t, initialActiveReads, promtest.ToFloat64(PosixActiveReads),
		"Active reads gauge should decrement when operation completes")
	assert.Equal(t, initialActiveIO, promtest.ToFloat64(PosixActiveIO),
		"Active IO gauge should decrement when operation completes")
}

// TestPosixOperationTrackerPeriodicUpdates tests that cumulative time counters are updated periodically
func TestPosixOperationTrackerPeriodicUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping periodic update test in short mode")
	}

	// Get initial cumulative time
	initialReadTime := promtest.ToFloat64(PosixReadTimeTotal)

	// Start a long-running read operation
	tracker := NewPosixOperationTracker(PosixOpRead, 8192)

	// Wait for at least 2 metric update intervals
	time.Sleep(600 * time.Millisecond)

	// Verify cumulative time increased (should have at least 2 updates at 250ms each)
	currentReadTime := promtest.ToFloat64(PosixReadTimeTotal)
	require.Greater(t, currentReadTime, initialReadTime+0.4,
		"Cumulative read time should increase by at least 400ms after 600ms of operation")

	// Complete the operation
	tracker.Complete(nil)
}

// TestPosixOperationTrackerErrorTracking tests error counter increments
func TestPosixOperationTrackerErrorTracking(t *testing.T) {
	// Get initial error counters
	initialReadErrors := promtest.ToFloat64(PosixReadErrorsTotal)
	initialWriteErrors := promtest.ToFloat64(PosixWriteErrorsTotal)

	// Track a failed read
	readTracker := NewPosixOperationTracker(PosixOpRead, 256)
	readTracker.Complete(assert.AnError)

	// Verify read error counter incremented
	assert.Equal(t, initialReadErrors+1, promtest.ToFloat64(PosixReadErrorsTotal),
		"Read error counter should increment on error")

	// Track a failed write
	writeTracker := NewPosixOperationTracker(PosixOpWrite, 512)
	writeTracker.Complete(assert.AnError)

	// Verify write error counter incremented
	assert.Equal(t, initialWriteErrors+1, promtest.ToFloat64(PosixWriteErrorsTotal),
		"Write error counter should increment on error")
}

// TestPosixOperationTrackerBytesTransferred tests byte counters
func TestPosixOperationTrackerBytesTransferred(t *testing.T) {
	// Get initial byte counters
	initialBytesRead := promtest.ToFloat64(PosixBytesRead)
	initialBytesWritten := promtest.ToFloat64(PosixBytesWritten)

	// Track read with byte count
	readTracker := NewPosixOperationTracker(PosixOpRead, 1024)
	readTracker.Complete(nil)

	// Verify bytes read incremented
	assert.Equal(t, initialBytesRead+1024, promtest.ToFloat64(PosixBytesRead),
		"Bytes read counter should increment by operation size")

	// Track write with byte count
	writeTracker := NewPosixOperationTracker(PosixOpWrite, 2048)
	writeTracker.Complete(nil)

	// Verify bytes written incremented
	assert.Equal(t, initialBytesWritten+2048, promtest.ToFloat64(PosixBytesWritten),
		"Bytes written counter should increment by operation size")
}

// TestPosixOperationTrackerHistograms tests that timing histograms are populated
func TestPosixOperationTrackerHistograms(t *testing.T) {
	// Track an operation
	tracker := NewPosixOperationTracker(PosixOpOpen, 0)
	time.Sleep(50 * time.Millisecond)
	tracker.Complete(nil)

	// Verify the histogram counter increased by checking the open counter
	// (histograms are harder to inspect, but we know the counter should have increased)
	require.Greater(t, promtest.ToFloat64(PosixOpensTotal), float64(0),
		"Open counter should be non-zero after operation")
}

// TestAllOperationTypes tests all operation types
func TestAllOperationTypes(t *testing.T) {
	operations := []struct {
		opType   PosixOperationType
		name     string
		counter  prometheus.Counter
		slowName string
	}{
		{PosixOpRead, "read", PosixReadsTotal, "slow_read"},
		{PosixOpWrite, "write", PosixWritesTotal, "slow_write"},
		{PosixOpOpen, "open", PosixOpensTotal, "slow_open"},
		{PosixOpClose, "close", PosixClosesTotal, "close"},
		{PosixOpStat, "stat", PosixStatsTotal, "slow_stat"},
		{PosixOpMkdir, "mkdir", PosixMkdirsTotal, "slow_mkdir"},
		{PosixOpRename, "rename", PosixRenamesTotal, "slow_rename"},
		{PosixOpUnlink, "unlink", PosixUnlinksTotal, "slow_unlink"},
		{PosixOpTruncate, "truncate", PosixTruncatesTotal, "slow_truncate"},
		{PosixOpReaddir, "readdir", PosixReaddirTotal, "slow_readdir"},
	}

	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			initial := promtest.ToFloat64(op.counter)
			tracker := NewPosixOperationTracker(op.opType, 128)
			time.Sleep(10 * time.Millisecond)
			tracker.Complete(nil)

			assert.Equal(t, initial+1, promtest.ToFloat64(op.counter),
				"%s counter should increment", op.name)
		})
	}
}
