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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Unified storage metrics for both XRootD OSS and POSIXv2 backends
// These metrics use a "backend" label to differentiate between storage implementations
// backend="xrootd" for XRootD OSS layer
// backend="posixv2" for POSIXv2 native implementation

var (
	// Operation counters with backend label
	StorageReadsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_reads_total",
		Help: "Total number of read operations on the storage layer",
	}, []string{"backend"})

	StorageWritesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_writes_total",
		Help: "Total number of write operations on the storage layer",
	}, []string{"backend"})

	StorageStatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_stats_total",
		Help: "Total number of stat operations on the storage layer",
	}, []string{"backend"})

	StorageMkdirsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_mkdirs_total",
		Help: "Total number of mkdir operations on the storage layer",
	}, []string{"backend"})

	StorageRenamesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_renames_total",
		Help: "Total number of rename operations on the storage layer",
	}, []string{"backend"})

	StorageUnlinksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_unlinks_total",
		Help: "Total number of unlink operations on the storage layer",
	}, []string{"backend"})

	StorageTruncatesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_truncates_total",
		Help: "Total number of truncate operations on the storage layer",
	}, []string{"backend"})

	StorageOpensTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_opens_total",
		Help: "Total number of open operations on the storage layer",
	}, []string{"backend"})

	StorageClosesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_closes_total",
		Help: "Total number of close operations on the storage layer",
	}, []string{"backend"})

	StorageReaddirTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_readdir_total",
		Help: "Total number of readdir operations on the storage layer",
	}, []string{"backend"})

	StorageChmodsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_chmods_total",
		Help: "Total number of chmod operations on the storage layer",
	}, []string{"backend"})

	// Slow operation counters (>2s)
	StorageSlowReadsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_reads_total",
		Help: "Total number of slow read operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowWritesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_writes_total",
		Help: "Total number of slow write operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowStatsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_stats_total",
		Help: "Total number of slow stat operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowMkdirsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_mkdirs_total",
		Help: "Total number of slow mkdir operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowRenamesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_renames_total",
		Help: "Total number of slow rename operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowUnlinksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_unlinks_total",
		Help: "Total number of slow unlink operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowTruncatesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_truncates_total",
		Help: "Total number of slow truncate operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowOpensTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_opens_total",
		Help: "Total number of slow open operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowReaddirTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_readdir_total",
		Help: "Total number of slow readdir operations (>2s) on the storage layer",
	}, []string{"backend"})

	StorageSlowChmodsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_slow_chmods_total",
		Help: "Total number of slow chmod operations (>2s) on the storage layer",
	}, []string{"backend"})

	// Timing histograms
	StorageHistogramBuckets = prometheus.ExponentialBuckets(0.00001, 2, 20) // 10µs to ~10s

	StorageReadTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_read_time_seconds",
		Help:    "Time taken for read operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageWriteTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_write_time_seconds",
		Help:    "Time taken for write operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageStatTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_stat_time_seconds",
		Help:    "Time taken for stat operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageMkdirTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_mkdir_time_seconds",
		Help:    "Time taken for mkdir operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageRenameTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_rename_time_seconds",
		Help:    "Time taken for rename operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageUnlinkTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_unlink_time_seconds",
		Help:    "Time taken for unlink operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageTruncateTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_truncate_time_seconds",
		Help:    "Time taken for truncate operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageOpenTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_open_time_seconds",
		Help:    "Time taken for open operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageCloseTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_close_time_seconds",
		Help:    "Time taken for close operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageReaddirTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_readdir_time_seconds",
		Help:    "Time taken for readdir operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	StorageChmodTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_chmod_time_seconds",
		Help:    "Time taken for chmod operations on the storage layer",
		Buckets: StorageHistogramBuckets,
	}, []string{"backend"})

	// Slow operation timing histograms (>2s)
	StorageSlowHistogramBuckets = prometheus.ExponentialBuckets(2.0, 2, 15) // 2s to ~32768s

	StorageSlowReadTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_read_time_seconds",
		Help:    "Time taken for slow read operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowWriteTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_write_time_seconds",
		Help:    "Time taken for slow write operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowStatTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_stat_time_seconds",
		Help:    "Time taken for slow stat operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowMkdirTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_mkdir_time_seconds",
		Help:    "Time taken for slow mkdir operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowRenameTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_rename_time_seconds",
		Help:    "Time taken for slow rename operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowUnlinkTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_unlink_time_seconds",
		Help:    "Time taken for slow unlink operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowTruncateTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_truncate_time_seconds",
		Help:    "Time taken for slow truncate operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowOpenTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_open_time_seconds",
		Help:    "Time taken for slow open operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowReaddirTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_readdir_time_seconds",
		Help:    "Time taken for slow readdir operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	StorageSlowChmodTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_slow_chmod_time_seconds",
		Help:    "Time taken for slow chmod operations (>2s) on the storage layer",
		Buckets: StorageSlowHistogramBuckets,
	}, []string{"backend"})

	// Byte counters
	StorageBytesRead = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_bytes_read_total",
		Help: "Total bytes read from the storage layer",
	}, []string{"backend"})

	StorageBytesWritten = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_bytes_written_total",
		Help: "Total bytes written to the storage layer",
	}, []string{"backend"})

	// Active operation gauges
	StorageActiveReads = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_storage_active_reads",
		Help: "Number of currently active read operations",
	}, []string{"backend"})

	StorageActiveWrites = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_storage_active_writes",
		Help: "Number of currently active write operations",
	}, []string{"backend"})

	StorageActiveIO = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pelican_storage_active_io",
		Help: "Total number of currently active I/O operations",
	}, []string{"backend"})

	// Cumulative time counters
	StorageReadTimeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_read_time_seconds_total",
		Help: "Cumulative time spent in read operations on the storage layer",
	}, []string{"backend"})

	StorageWriteTimeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_write_time_seconds_total",
		Help: "Cumulative time spent in write operations on the storage layer",
	}, []string{"backend"})

	StorageIOTimeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_io_time_seconds_total",
		Help: "Cumulative time spent in all I/O operations on the storage layer",
	}, []string{"backend"})

	// Error counters
	StorageReadErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_read_errors_total",
		Help: "Total number of failed read operations",
	}, []string{"backend"})

	StorageWriteErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_write_errors_total",
		Help: "Total number of failed write operations",
	}, []string{"backend"})

	StorageOpenErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_open_errors_total",
		Help: "Total number of failed open operations",
	}, []string{"backend"})

	// Size histograms
	StorageReadSizes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_read_bytes",
		Help:    "Distribution of read operation sizes in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 12), // 1KB to ~16MB
	}, []string{"backend"})

	StorageWriteSizes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pelican_storage_write_bytes",
		Help:    "Distribution of write operation sizes in bytes",
		Buckets: prometheus.ExponentialBuckets(1024, 4, 12), // 1KB to ~16MB
	}, []string{"backend"})

	// Rate limiter metrics (POSIXv2 only, but using same structure for consistency)
	StorageRateLimitWaitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_rate_limit_waits_total",
		Help: "Total number of times operations had to wait for rate limiter tokens",
	}, []string{"backend"})

	StorageRateLimitWaitTime = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "pelican_storage_rate_limit_wait_seconds_total",
		Help: "Cumulative time spent waiting for rate limiter tokens",
	}, []string{"backend"})
)

// Backend label values
const (
	BackendXRootD  = "xrootd"
	BackendPOSIXv2 = "posixv2"
)
