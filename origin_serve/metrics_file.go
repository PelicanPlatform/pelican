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

// rateLimitedRead performs rate-limited read with metrics tracking
func (mf *metricsFile) rateLimitedRead(p []byte) (n int, err error) {
	const (
		initialWaitNs = 50 * 1000 * 1000       // 50ms
		chunkWaitNs   = 100 * 1000 * 1000      // 100ms
		tickInterval  = 250 * time.Millisecond // Update metrics every 250ms
	)

	// Track that we're waiting for rate limiter
	waitStart := time.Now()
	tokens, err := mf.rateLimiter.Wait(mf.ctx, mf.userID, initialWaitNs)
	if err != nil {
		metrics.StorageReadErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		return 0, err
	}
	waitTime := time.Since(waitStart).Seconds()
	if waitTime > 0.001 { // Only count if we actually waited >1ms
		metrics.StorageRateLimitWaitsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		metrics.StorageRateLimitWaitTime.WithLabelValues(metrics.BackendPOSIXv2).Add(waitTime)
	}

	allTokens := []*htb.Tokens{tokens}
	defer func() {
		for _, t := range allTokens {
			mf.rateLimiter.Return(t)
		}
	}()

	// Start tracking the operation
	opStart := time.Now()
	metrics.StorageActiveReads.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageReadsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		metrics.StorageActiveReads.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		elapsed := time.Since(opStart)
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

	// Launch read in goroutine
	type ioResult struct {
		n   int
		err error
	}
	resultCh := make(chan ioResult, 1)

	go func() {
		n, err := mf.File.Read(p)
		resultCh <- ioResult{n, err}
	}()

	// Create ticker for periodic metric updates
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	// Timer for requesting more tokens
	tokenTimer := time.NewTimer(time.Duration(initialWaitNs) * time.Nanosecond)
	defer tokenTimer.Stop()

	for {
		select {
		case <-mf.ctx.Done():
			elapsed := time.Since(opStart).Nanoseconds()
			tokens.Use(elapsed)
			return 0, mf.ctx.Err()

		case result := <-resultCh:
			elapsed := time.Since(opStart).Nanoseconds()
			tokens.Use(elapsed)
			if result.n > 0 {
				metrics.StorageBytesRead.WithLabelValues(metrics.BackendPOSIXv2).Add(float64(result.n))
				metrics.StorageReadSizes.WithLabelValues(metrics.BackendPOSIXv2).Observe(float64(result.n))
			}
			return result.n, result.err

		case <-ticker.C:
			// Periodically update cumulative time counter while operation is running
			elapsed := time.Since(opStart).Seconds()
			metrics.StorageReadTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsed)
			metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsed)
			// Reset the start time for next tick
			opStart = time.Now()

		case <-tokenTimer.C:
			// Request more tokens
			moreTokens, err := mf.rateLimiter.Wait(mf.ctx, mf.userID, chunkWaitNs)
			if err != nil {
				elapsed := time.Since(opStart).Nanoseconds()
				tokens.Use(elapsed)
				metrics.StorageReadErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
				return 0, err
			}
			allTokens = append(allTokens, moreTokens)
			tokenTimer.Reset(time.Duration(chunkWaitNs) * time.Nanosecond)
		}
	}
}

// rateLimitedWrite performs rate-limited write with metrics tracking
func (mf *metricsFile) rateLimitedWrite(p []byte) (n int, err error) {
	const (
		initialWaitNs = 50 * 1000 * 1000  // 50ms
		chunkWaitNs   = 100 * 1000 * 1000 // 100ms
		tickInterval  = 250 * time.Millisecond
	)

	// Track rate limiter wait
	waitStart := time.Now()
	tokens, err := mf.rateLimiter.Wait(mf.ctx, mf.userID, initialWaitNs)
	if err != nil {
		metrics.StorageWriteErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		return 0, err
	}
	waitTime := time.Since(waitStart).Seconds()
	if waitTime > 0.001 {
		metrics.StorageRateLimitWaitsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
		metrics.StorageRateLimitWaitTime.WithLabelValues(metrics.BackendPOSIXv2).Add(waitTime)
	}

	allTokens := []*htb.Tokens{tokens}
	defer func() {
		for _, t := range allTokens {
			mf.rateLimiter.Return(t)
		}
	}()

	opStart := time.Now()
	metrics.StorageActiveWrites.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	metrics.StorageWritesTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
	defer func() {
		metrics.StorageActiveWrites.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		metrics.StorageActiveIO.WithLabelValues(metrics.BackendPOSIXv2).Dec()
		elapsed := time.Since(opStart)
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

	// Launch write in goroutine
	type ioResult struct {
		n   int
		err error
	}
	resultCh := make(chan ioResult, 1)

	go func() {
		n, err := mf.File.Write(p)
		resultCh <- ioResult{n, err}
	}()

	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	tokenTimer := time.NewTimer(time.Duration(initialWaitNs) * time.Nanosecond)
	defer tokenTimer.Stop()

	for {
		select {
		case <-mf.ctx.Done():
			elapsed := time.Since(opStart).Nanoseconds()
			tokens.Use(elapsed)
			return 0, mf.ctx.Err()

		case result := <-resultCh:
			elapsed := time.Since(opStart).Nanoseconds()
			tokens.Use(elapsed)
			if result.n > 0 {
				metrics.StorageBytesWritten.WithLabelValues(metrics.BackendPOSIXv2).Add(float64(result.n))
				metrics.StorageWriteSizes.WithLabelValues(metrics.BackendPOSIXv2).Observe(float64(result.n))
			}
			return result.n, result.err

		case <-ticker.C:
			// Periodic metric update
			elapsed := time.Since(opStart).Seconds()
			metrics.StorageWriteTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsed)
			metrics.StorageIOTimeTotal.WithLabelValues(metrics.BackendPOSIXv2).Add(elapsed)
			opStart = time.Now()

		case <-tokenTimer.C:
			moreTokens, err := mf.rateLimiter.Wait(mf.ctx, mf.userID, chunkWaitNs)
			if err != nil {
				elapsed := time.Since(opStart).Nanoseconds()
				tokens.Use(elapsed)
				metrics.StorageWriteErrorsTotal.WithLabelValues(metrics.BackendPOSIXv2).Inc()
				return 0, err
			}
			allTokens = append(allTokens, moreTokens)
			tokenTimer.Reset(time.Duration(chunkWaitNs) * time.Nanosecond)
		}
	}
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
	metrics.PosixStatsTotal.Inc()
	defer func() {
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.PosixStatTime.Observe(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.PosixSlowStatsTotal.Inc()
			metrics.PosixSlowStatTime.Observe(elapsedSec)
		}
	}()

	return mf.File.Stat()
}

// Readdir implements afero.File.Readdir with metrics
func (mf *metricsFile) Readdir(count int) ([]os.FileInfo, error) {
	start := time.Now()
	metrics.PosixReaddirTotal.Inc()
	defer func() {
		elapsed := time.Since(start)
		elapsedSec := elapsed.Seconds()
		metrics.PosixReaddirTime.Observe(elapsedSec)

		// Track slow operations (>2s)
		if elapsed >= metrics.SlowOperationThreshold {
			metrics.PosixSlowReaddirTotal.Inc()
			metrics.PosixSlowReaddirTime.Observe(elapsedSec)
		}
	}()

	return mf.File.Readdir(count)
}
