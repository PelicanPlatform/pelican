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
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// POSIXv2 filesystem metrics - analogous to XRootD OSS metrics
// These track operations on the underlying POSIX filesystem layer

var (
	// Operation counters
	PosixReadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_reads_total",
		Help: "The total number of read operations on the POSIX filesystem",
	})

	PosixWritesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_writes_total",
		Help: "The total number of write operations on the POSIX filesystem",
	})

	PosixOpensTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_opens_total",
		Help: "The total number of open operations on the POSIX filesystem",
	})

	PosixClosesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_closes_total",
		Help: "The total number of close operations on the POSIX filesystem",
	})

	PosixStatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_stats_total",
		Help: "The total number of stat operations on the POSIX filesystem",
	})

	PosixMkdirsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_mkdirs_total",
		Help: "The total number of mkdir operations on the POSIX filesystem",
	})

	PosixRenamesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_renames_total",
		Help: "The total number of rename operations on the POSIX filesystem",
	})

	PosixUnlinksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_unlinks_total",
		Help: "The total number of unlink operations on the POSIX filesystem",
	})

	PosixTruncatesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_truncates_total",
		Help: "The total number of truncate operations on the POSIX filesystem",
	})

	PosixReaddirTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_readdir_total",
		Help: "The total number of readdir operations on the POSIX filesystem",
	})

	// Byte counters
	PosixBytesRead = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_bytes_read_total",
		Help: "Total bytes read from the POSIX filesystem",
	})

	PosixBytesWritten = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_bytes_written_total",
		Help: "Total bytes written to the POSIX filesystem",
	})

	// Active operation gauges
	PosixActiveReads = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "posixv2_active_reads",
		Help: "Number of currently active read operations",
	})

	PosixActiveWrites = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "posixv2_active_writes",
		Help: "Number of currently active write operations",
	})

	PosixActiveIO = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "posixv2_active_io",
		Help: "Total number of currently active I/O operations",
	})

	// Timing histograms (in seconds)
	PosixTimeHistogramBuckets = prometheus.ExponentialBuckets(0.00001, 2, 20) // 10µs to ~10s

	PosixReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_read_time_seconds",
		Help:    "Time taken for read operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_write_time_seconds",
		Help:    "Time taken for write operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixOpenTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_open_time_seconds",
		Help:    "Time taken for open operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixCloseTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_close_time_seconds",
		Help:    "Time taken for close operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixStatTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_stat_time_seconds",
		Help:    "Time taken for stat operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixMkdirTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_mkdir_time_seconds",
		Help:    "Time taken for mkdir operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixRenameTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_rename_time_seconds",
		Help:    "Time taken for rename operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixUnlinkTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_unlink_time_seconds",
		Help:    "Time taken for unlink operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixTruncateTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_truncate_time_seconds",
		Help:    "Time taken for truncate operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	PosixReaddirTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_readdir_time_seconds",
		Help:    "Time taken for readdir operations on the POSIX filesystem",
		Buckets: PosixTimeHistogramBuckets,
	})

	// Cumulative time counters (analogous to ServerIOWaitTimeTotal)
	PosixReadTimeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_read_time_seconds_total",
		Help: "Cumulative time spent in read operations on the POSIX filesystem",
	})

	PosixWriteTimeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_write_time_seconds_total",
		Help: "Cumulative time spent in write operations on the POSIX filesystem",
	})

	PosixIOTimeTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_io_time_seconds_total",
		Help: "Cumulative time spent in all I/O operations on the POSIX filesystem",
	})

	// Error counters
	PosixReadErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_read_errors_total",
		Help: "Total number of failed read operations",
	})

	PosixWriteErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_write_errors_total",
		Help: "Total number of failed write operations",
	})

	PosixOpenErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_open_errors_total",
		Help: "Total number of failed open operations",
	})

	// Rate limiter metrics
	PosixRateLimitWaitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_rate_limit_waits_total",
		Help: "Total number of times operations had to wait for rate limiter tokens",
	})

	PosixRateLimitWaitTime = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_rate_limit_wait_seconds_total",
		Help: "Cumulative time spent waiting for rate limiter tokens",
	})

	// File size metrics
	PosixReadSizes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_read_bytes",
		Help:    "Distribution of read operation sizes in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 12), // 1KB to ~16MB
	})

	PosixWriteSizes = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_write_bytes",
		Help:    "Distribution of write operation sizes in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 12), // 1KB to ~16MB
	})

	// Slow operation counters (operations taking > SlowOperationThreshold = 2.0s)
	PosixSlowReadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_reads_total",
		Help: "Total number of slow read operations (>2s) on the POSIX filesystem",
	})

	PosixSlowWritesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_writes_total",
		Help: "Total number of slow write operations (>2s) on the POSIX filesystem",
	})

	PosixSlowOpensTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_opens_total",
		Help: "Total number of slow open operations (>2s) on the POSIX filesystem",
	})

	PosixSlowStatsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_stats_total",
		Help: "Total number of slow stat operations (>2s) on the POSIX filesystem",
	})

	PosixSlowMkdirsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_mkdirs_total",
		Help: "Total number of slow mkdir operations (>2s) on the POSIX filesystem",
	})

	PosixSlowRenamesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_renames_total",
		Help: "Total number of slow rename operations (>2s) on the POSIX filesystem",
	})

	PosixSlowUnlinksTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_unlinks_total",
		Help: "Total number of slow unlink operations (>2s) on the POSIX filesystem",
	})

	PosixSlowTruncatesTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_truncates_total",
		Help: "Total number of slow truncate operations (>2s) on the POSIX filesystem",
	})

	PosixSlowReaddirTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "posixv2_slow_readdir_total",
		Help: "Total number of slow readdir operations (>2s) on the POSIX filesystem",
	})

	// Slow operation timing histograms (in seconds, for operations > 2s)
	PosixSlowReadTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_read_time_seconds",
		Help:    "Time taken for slow read operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15), // 2s to ~32768s
	})

	PosixSlowWriteTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_write_time_seconds",
		Help:    "Time taken for slow write operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowOpenTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_open_time_seconds",
		Help:    "Time taken for slow open operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowStatTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_stat_time_seconds",
		Help:    "Time taken for slow stat operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowMkdirTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_mkdir_time_seconds",
		Help:    "Time taken for slow mkdir operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowRenameTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_rename_time_seconds",
		Help:    "Time taken for slow rename operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowUnlinkTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_unlink_time_seconds",
		Help:    "Time taken for slow unlink operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowTruncateTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_truncate_time_seconds",
		Help:    "Time taken for slow truncate operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})

	PosixSlowReaddirTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "posixv2_slow_readdir_time_seconds",
		Help:    "Time taken for slow readdir operations (>2s) on the POSIX filesystem",
		Buckets: prometheus.ExponentialBuckets(2.0, 2, 15),
	})
)

const (
	// SlowOperationThreshold defines the duration above which an operation is considered "slow"
	// This matches the XRootD default of 2.0 seconds
	SlowOperationThreshold = 2 * time.Second

	// MetricsUpdateInterval is how often cumulative time counters are updated during long-running operations
	MetricsUpdateInterval = 250 * time.Millisecond
)

// PosixOperationType represents the type of POSIX operation being tracked
type PosixOperationType int

const (
	PosixOpRead PosixOperationType = iota
	PosixOpWrite
	PosixOpOpen
	PosixOpClose
	PosixOpStat
	PosixOpMkdir
	PosixOpRename
	PosixOpUnlink
	PosixOpTruncate
	PosixOpReaddir
)

// PosixOperationTracker tracks a single POSIX operation for metrics
type PosixOperationTracker struct {
	opType     PosixOperationType
	startTime  time.Time
	size       int // For read/write operations
	stopUpdate chan struct{}
	doneChan   chan struct{}
}

// NewPosixOperationTracker creates a new operation tracker and starts metrics collection
func NewPosixOperationTracker(opType PosixOperationType, size int) *PosixOperationTracker {
	tracker := &PosixOperationTracker{
		opType:     opType,
		startTime:  time.Now(),
		size:       size,
		stopUpdate: make(chan struct{}),
		doneChan:   make(chan struct{}),
	}

	// Increment active operation gauges (both old and new metrics)
	switch opType {
	case PosixOpRead:
		PosixActiveReads.Inc()
		PosixActiveIO.Inc()
		StorageActiveReads.WithLabelValues(BackendPOSIXv2).Inc()
		StorageActiveIO.WithLabelValues(BackendPOSIXv2).Inc()
	case PosixOpWrite:
		PosixActiveWrites.Inc()
		PosixActiveIO.Inc()
		StorageActiveWrites.WithLabelValues(BackendPOSIXv2).Inc()
		StorageActiveIO.WithLabelValues(BackendPOSIXv2).Inc()
	}

	// Start periodic updates for cumulative time counters
	go tracker.periodicUpdate()

	return tracker
}

// periodicUpdate runs in a goroutine to update cumulative time counters every 250ms
func (t *PosixOperationTracker) periodicUpdate() {
	ticker := time.NewTicker(MetricsUpdateInterval)
	defer ticker.Stop()
	defer close(t.doneChan)

	lastUpdate := t.startTime

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(lastUpdate).Seconds()
			lastUpdate = now

			// Update cumulative time counters (both old and new metrics)
			switch t.opType {
			case PosixOpRead:
				PosixReadTimeTotal.Add(elapsed)
				PosixIOTimeTotal.Add(elapsed)
				StorageReadTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
				StorageIOTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
			case PosixOpWrite:
				PosixWriteTimeTotal.Add(elapsed)
				PosixIOTimeTotal.Add(elapsed)
				StorageWriteTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
				StorageIOTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
			}

		case <-t.stopUpdate:
			// Final update before stopping
			now := time.Now()
			elapsed := now.Sub(lastUpdate).Seconds()
			if elapsed > 0 {
				switch t.opType {
				case PosixOpRead:
					PosixReadTimeTotal.Add(elapsed)
					PosixIOTimeTotal.Add(elapsed)
					StorageReadTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
					StorageIOTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
				case PosixOpWrite:
					PosixWriteTimeTotal.Add(elapsed)
					PosixIOTimeTotal.Add(elapsed)
					StorageWriteTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
					StorageIOTimeTotal.WithLabelValues(BackendPOSIXv2).Add(elapsed)
				}
			}
			return
		}
	}
}

// Complete finalizes the operation tracking and updates all metrics
func (t *PosixOperationTracker) Complete(err error) {
	// Stop the periodic updater and wait for it to complete
	close(t.stopUpdate)
	<-t.doneChan

	duration := time.Since(t.startTime)
	durationSec := duration.Seconds()
	isSlow := duration >= SlowOperationThreshold

	// Update operation-specific metrics (both old POSIXv2 and new unified metrics)
	switch t.opType {
	case PosixOpRead:
		// Old metrics (for compatibility)
		PosixReadsTotal.Inc()
		PosixReadTime.Observe(durationSec)
		// New unified metrics
		StorageReadsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageReadTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if t.size > 0 {
			PosixBytesRead.Add(float64(t.size))
			PosixReadSizes.Observe(float64(t.size))
			StorageBytesRead.WithLabelValues(BackendPOSIXv2).Add(float64(t.size))
			StorageReadSizes.WithLabelValues(BackendPOSIXv2).Observe(float64(t.size))
		}
		if isSlow {
			PosixSlowReadsTotal.Inc()
			PosixSlowReadTime.Observe(durationSec)
			StorageSlowReadsTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowReadTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}
		if err != nil {
			PosixReadErrorsTotal.Inc()
			StorageReadErrorsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		}
		PosixActiveReads.Dec()
		PosixActiveIO.Dec()
		StorageActiveReads.WithLabelValues(BackendPOSIXv2).Dec()
		StorageActiveIO.WithLabelValues(BackendPOSIXv2).Dec()

	case PosixOpWrite:
		PosixWritesTotal.Inc()
		PosixWriteTime.Observe(durationSec)
		StorageWritesTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageWriteTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if t.size > 0 {
			PosixBytesWritten.Add(float64(t.size))
			PosixWriteSizes.Observe(float64(t.size))
			StorageBytesWritten.WithLabelValues(BackendPOSIXv2).Add(float64(t.size))
			StorageWriteSizes.WithLabelValues(BackendPOSIXv2).Observe(float64(t.size))
		}
		if isSlow {
			PosixSlowWritesTotal.Inc()
			PosixSlowWriteTime.Observe(durationSec)
			StorageSlowWritesTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowWriteTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}
		if err != nil {
			PosixWriteErrorsTotal.Inc()
			StorageWriteErrorsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		}
		PosixActiveWrites.Dec()
		PosixActiveIO.Dec()
		StorageActiveWrites.WithLabelValues(BackendPOSIXv2).Dec()
		StorageActiveIO.WithLabelValues(BackendPOSIXv2).Dec()

	case PosixOpOpen:
		PosixOpensTotal.Inc()
		PosixOpenTime.Observe(durationSec)
		StorageOpensTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageOpenTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowOpensTotal.Inc()
			PosixSlowOpenTime.Observe(durationSec)
			StorageSlowOpensTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowOpenTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}
		if err != nil {
			PosixOpenErrorsTotal.Inc()
			StorageOpenErrorsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		}

	case PosixOpClose:
		PosixClosesTotal.Inc()
		PosixCloseTime.Observe(durationSec)
		StorageClosesTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageCloseTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

	case PosixOpStat:
		PosixStatsTotal.Inc()
		PosixStatTime.Observe(durationSec)
		StorageStatsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageStatTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowStatsTotal.Inc()
			PosixSlowStatTime.Observe(durationSec)
			StorageSlowStatsTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowStatTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}

	case PosixOpMkdir:
		PosixMkdirsTotal.Inc()
		PosixMkdirTime.Observe(durationSec)
		StorageMkdirsTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageMkdirTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowMkdirsTotal.Inc()
			PosixSlowMkdirTime.Observe(durationSec)
			StorageSlowMkdirsTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowMkdirTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}

	case PosixOpRename:
		PosixRenamesTotal.Inc()
		PosixRenameTime.Observe(durationSec)
		StorageRenamesTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageRenameTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowRenamesTotal.Inc()
			PosixSlowRenameTime.Observe(durationSec)
			StorageSlowRenamesTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowRenameTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}

	case PosixOpUnlink:
		PosixUnlinksTotal.Inc()
		PosixUnlinkTime.Observe(durationSec)
		StorageUnlinksTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageUnlinkTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowUnlinksTotal.Inc()
			PosixSlowUnlinkTime.Observe(durationSec)
			StorageSlowUnlinksTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowUnlinkTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}

	case PosixOpTruncate:
		PosixTruncatesTotal.Inc()
		PosixTruncateTime.Observe(durationSec)
		StorageTruncatesTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageTruncateTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowTruncatesTotal.Inc()
			PosixSlowTruncateTime.Observe(durationSec)
			StorageSlowTruncatesTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowTruncateTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}

	case PosixOpReaddir:
		PosixReaddirTotal.Inc()
		PosixReaddirTime.Observe(durationSec)
		StorageReaddirTotal.WithLabelValues(BackendPOSIXv2).Inc()
		StorageReaddirTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)

		if isSlow {
			PosixSlowReaddirTotal.Inc()
			PosixSlowReaddirTime.Observe(durationSec)
			StorageSlowReaddirTotal.WithLabelValues(BackendPOSIXv2).Inc()
			StorageSlowReaddirTime.WithLabelValues(BackendPOSIXv2).Observe(durationSec)
		}
	}
}
