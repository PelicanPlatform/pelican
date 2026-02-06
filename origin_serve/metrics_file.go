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
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/afero"

	"github.com/pelicanplatform/pelican/htb"
	"github.com/pelicanplatform/pelican/metrics"
)

// metricsFile wraps an afero.File to track Prometheus metrics for all operations.
// When a rate limiter is available, it reuses the rate limiter's timing infrastructure.
type metricsFile struct {
	afero.File
	rateLimiter *htb.HTB
	userID      string
	ctx         context.Context
	startTime   time.Time
}

// newMetricsFile wraps a file to track metrics
func newMetricsFile(file afero.File, rateLimiter *htb.HTB, userID string, ctx context.Context) *metricsFile {
	return &metricsFile{
		File:        file,
		rateLimiter: rateLimiter,
		userID:      userID,
		ctx:         ctx,
		startTime:   time.Now(),
	}
}

// Read implements io.Reader with metrics tracking
func (mf *metricsFile) Read(p []byte) (n int, err error) {
	// Handle rate limiting with metrics if rate limiter is available
	if mf.rateLimiter != nil {
		return mf.rateLimitedRead(p)
	}

	// No rate limiting - just track metrics
	return mf.metricsOnlyRead(p)
}

// Write implements io.Writer with metrics tracking
func (mf *metricsFile) Write(p []byte) (n int, err error) {
	// Handle rate limiting with metrics if rate limiter is available
	if mf.rateLimiter != nil {
		return mf.rateLimitedWrite(p)
	}

	// No rate limiting - just track metrics
	return mf.metricsOnlyWrite(p)
}

// metricsOnlyRead performs a read without rate limiting, just tracking metrics
func (mf *metricsFile) metricsOnlyRead(p []byte) (n int, err error) {
	start := time.Now()
	metrics.StorageActiveReads.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageReadsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		metrics.StorageActiveReads.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.StorageReadTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		metrics.StorageReadTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)
		metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.StorageSlowReadsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
			metrics.StorageSlowReadTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		}

		if err != nil && err != io.EOF {
			metrics.StorageReadErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		}
	}()

	n, err = mf.File.Read(p)
	if n > 0 {
		metrics.StorageBytesRead.WithLabelValues(metrics.BackendPOSIXv2).Add(float64(n))
		metrics.StorageReadSizes.WithLabelValues(metrics.BackendPOSIXv2).Observe(float64(n))
	}
	return n, err
}

// metricsOnlyWrite performs a write without rate limiting, just tracking metrics
func (mf *metricsFile) metricsOnlyWrite(p []byte) (n int, err error) {
	start := time.Now()
	metrics.StorageActiveWrites.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageWritesTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		metrics.StorageActiveWrites.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.StorageWriteTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		metrics.StorageWriteTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)
		metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.StorageSlowWritesTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
			metrics.StorageSlowWriteTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		}

		if err != nil {
			metrics.StorageWriteErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		}
	}()

	n, err = mf.File.Write(p)
	if n > 0 {
		metrics.StorageBytesWritten.WithLabelValues(metrics.BackendPOSIXv2).Add(float64(n))
		metrics.StorageWriteSizes.WithLabelValues(metrics.BackendPOSIXv2).Observe(float64(n))
	}
	return n, err
}

// ioMetrics defines the metrics to track for an I/O operation
type ioMetrics struct {
	activeCounter     *prometheus.GaugeVec
	totalCounter      *prometheus.CounterVec
	errorCounter      *prometheus.CounterVec
	bytesCounter      *prometheus.CounterVec
	sizeHistogram     *prometheus.HistogramVec
	timeHistogram     *prometheus.HistogramVec
	timeTotalCounter  *prometheus.CounterVec
	slowCounter       *prometheus.CounterVec
	slowTimeHistogram *prometheus.HistogramVec
	ignoreEOF         bool
}

// rateLimitedIO performs rate-limited I/O with metrics tracking
func (mf *metricsFile) rateLimitedIO(p []byte, ioFunc func([]byte) (int, error), m *ioMetrics) (n int, err error) {
	const (
		initialWaitNs = 50 * 1000 * 1000  // 50ms
		chunkWaitNs   = 100 * 1000 * 1000 // 100ms
	)

	// Track that we're waiting for rate limiter
	waitStart := time.Now()
	tokens, err := mf.rateLimiter.Wait(mf.ctx, mf.userID, initialWaitNs)
	if err != nil {
		m.errorCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		return 0, err
	}
	waitTime := time.Since(waitStart).Seconds()
	if waitTime > 0.0 {
		metrics.StorageRateLimitWaitsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		metrics.StorageRateLimitWaitTime.WithLabelValues(metrics.BackendPOSIXv2).Add(waitTime)
	}

	// Start tracking the operation
	opStart := time.Now()
	tickerStart := opStart

	m.activeCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	m.totalCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		m.activeCounter.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		now := time.Now()
		tickerElapsed := now.Sub(tickerStart)
		tickerElapsedSec := tickerElapsed.Seconds()

		elapsedNs := tickerElapsed.Nanoseconds()
		if tokens != nil {
			tokens.Use(elapsedNs)
			mf.rateLimiter.Return(tokens)
		}

		opElapsed := now.Sub(opStart)
		opElapsedSec := opElapsed.Seconds()
		m.timeHistogram.WithLabelValues(metrics.BackendPOSIXv2).Observe(opElapsedSec)
		m.timeTotalCounter.WithLabelValues(metrics.BackendPOSIXv2).Add(tickerElapsedSec)
		metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(tickerElapsedSec)

		// Track slow operations (>2s)
		if opElapsed >= metrics.SlowOperationThreshold {
			m.slowCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
			m.slowTimeHistogram.WithLabelValues(metrics.BackendPOSIXv2).Observe(opElapsedSec)
		}

		if err != nil && !(m.ignoreEOF && err == io.EOF) {
			m.errorCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		}
	}()

	// Launch I/O in goroutine
	type ioResult struct {
		n   int
		err error
	}
	resultCh := make(chan ioResult, 1)

	go func() {
		n, err := ioFunc(p)
		resultCh <- ioResult{n, err}
	}()

	// Timer for requesting more tokens
	tokenTimer := time.NewTimer(time.Duration(initialWaitNs) * time.Nanosecond)
	defer tokenTimer.Stop()

	for {
		select {
		case <-mf.ctx.Done():
			return 0, mf.ctx.Err()

		case result := <-resultCh:
			if result.n > 0 {
				m.bytesCounter.WithLabelValues(metrics.BackendPOSIXv2).Add(float64(result.n))
				m.sizeHistogram.WithLabelValues(metrics.BackendPOSIXv2).Observe(float64(result.n))
			}
			return result.n, result.err

		case <-tokenTimer.C:
			// Operation is still running - we need more tokens immediately
			// Use ForceWait because the I/O is already consuming time
			now := time.Now()
			elapsed := now.Sub(tickerStart)
			tickerStart = now
			elapsedNs := elapsed.Nanoseconds()
			elapsedSec := elapsed.Seconds()

			m.timeTotalCounter.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)
			metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsedSec)

			if tokens != nil {
				// If elapsed is nonzero, it means more time elapsed than tokens
				// we have.  We'll have to "bill" them later.
				elapsedNs = tokens.Use(elapsedNs)
				mf.rateLimiter.Return(tokens)
			}
			// Get new tokens with force allocation (operation already started)
			tokens, err = mf.rateLimiter.ForceWait(mf.ctx, mf.userID, chunkWaitNs+elapsedNs)
			if err != nil {
				m.errorCounter.WithLabelValues(metrics.BackendPOSIXv2).Inc()
				tokens = nil
				return 0, err
			}
			tokenTimer.Reset(time.Duration(chunkWaitNs) * time.Nanosecond)
		}
	}
}

// rateLimitedRead performs rate-limited read with metrics tracking
func (mf *metricsFile) rateLimitedRead(p []byte) (n int, err error) {
	m := &ioMetrics{
		activeCounter:     metrics.StorageActiveReads,
		totalCounter:      metrics.StorageReadsTotal,
		errorCounter:      metrics.StorageReadErrorsTotal,
		bytesCounter:      metrics.StorageBytesRead,
		sizeHistogram:     metrics.StorageReadSizes,
		timeHistogram:     metrics.StorageReadTime,
		timeTotalCounter:  metrics.StorageReadTimeTotal,
		slowCounter:       metrics.StorageSlowReadsTotal,
		slowTimeHistogram: metrics.StorageSlowReadTime,
		ignoreEOF:         true,
	}
	return mf.rateLimitedIO(p, mf.File.Read, m)
}

// rateLimitedWrite performs rate-limited write with metrics tracking
func (mf *metricsFile) rateLimitedWrite(p []byte) (n int, err error) {
	m := &ioMetrics{
		activeCounter:     metrics.StorageActiveWrites,
		totalCounter:      metrics.StorageWritesTotal,
		errorCounter:      metrics.StorageWriteErrorsTotal,
		bytesCounter:      metrics.StorageBytesWritten,
		sizeHistogram:     metrics.StorageWriteSizes,
		timeHistogram:     metrics.StorageWriteTime,
		timeTotalCounter:  metrics.StorageWriteTimeTotal,
		slowCounter:       metrics.StorageSlowWritesTotal,
		slowTimeHistogram: metrics.StorageSlowWriteTime,
		ignoreEOF:         false,
	}
	return mf.rateLimitedIO(p, mf.File.Write, m)
}

// Close implements afero.File.Close with metrics
func (mf *metricsFile) Close() error {
	start := time.Now()
	metrics.StorageClosesTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		elapsed := time.Since(start).Seconds()
		metrics.StorageCloseTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsed)
	}()

	return mf.File.Close()
}

// Stat implements afero.File.Stat with metrics
func (mf *metricsFile) Stat() (os.FileInfo, error) {
	start := time.Now()
	metrics.StorageStatsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.StorageStatTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.StorageSlowStatsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
			metrics.StorageSlowStatTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		}
	}()

	return mf.File.Stat()
}

// Readdir implements afero.File.Readdir with metrics
func (mf *metricsFile) Readdir(count int) ([]os.FileInfo, error) {
	start := time.Now()
	metrics.StorageReaddirTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.StorageReaddirTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.StorageSlowReaddirTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
			metrics.StorageSlowReaddirTime.WithLabelValues(metrics.BackendPOSIXv2).Observe(elapsedSec)
		}
	}()

	return mf.File.Readdir(count)
}
