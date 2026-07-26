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

package logging

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
)

// TestFlushLogsToFileAndSyncMode exercises the real wiring: FlushLogs(true)
// installs the async writer as the logrus output, log lines reach the file once
// drained, and EnterSyncMode flushes + flips to synchronous mode so that a
// line emitted afterward is written directly and still lands in the file.
func TestFlushLogsToFileAndSyncMode(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "pelican.log")

	// Snapshot/restore the global logging state touched by this test.
	t.Cleanup(func() {
		CloseLogger()
		ResetLogFlush()
	})

	require.NoError(t, param.Logging_LogLocation.Set(logPath))
	require.NoError(t, param.Logging_Rotation_Frequency.Set("daily"))
	require.NoError(t, param.Logging_Rotation_DisableCompress.Set(true))
	require.NoError(t, param.Logging_Rotation_FlushInterval.Set(5*time.Millisecond))

	ResetLogFlush()
	SetupLogBuffering()

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	SetErrgroup(egrpCtx, egrp)

	log.SetLevel(log.InfoLevel)
	log.Info("before-flush buffered line")

	FlushLogs(true)

	log.Info("after-flush async line")

	// Shutdown handler: drain + flip to synchronous mode.
	EnterSyncMode()

	// A line emitted after EnterSyncMode is written directly by this goroutine.
	log.Info("post-shutdown direct line")

	// The errgroup-managed writer goroutine should have exited cleanly.
	require.NoError(t, egrp.Wait())

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	got := string(content)
	assert.Contains(t, got, "before-flush buffered line", "buffered pre-flush lines should reach the file")
	assert.Contains(t, got, "after-flush async line", "async lines should reach the file")
	assert.Contains(t, got, "post-shutdown direct line", "post-shutdown lines should be written directly to the file")
}

// TestBuildRotateConfigRejectsBadSize verifies a malformed MaxSize is reported
// as an error (so the caller can fail loudly at startup) rather than being
// silently ignored.
func TestBuildRotateConfigRejectsBadSize(t *testing.T) {
	t.Cleanup(func() { _ = param.Reset() })

	require.NoError(t, param.Logging_Rotation_MaxSize.Set("100 bananas"))
	_, err := buildRotateConfig()
	require.Error(t, err, "an unparsable MaxSize must surface an error, not be silently dropped")
	assert.Contains(t, err.Error(), param.Logging_Rotation_MaxSize.GetName())

	// A value that exceeds int64 (but still fits uint64) must error, not wrap to
	// a negative size. 1e10 GB ~= 1.07e19 bytes, above MaxInt64 (~9.2e18).
	require.NoError(t, param.Logging_Rotation_MaxSize.Set("10000000000GB"))
	_, err = buildRotateConfig()
	require.Error(t, err, "an out-of-range MaxSize must surface an error")
	assert.Contains(t, err.Error(), "too large")

	// A negative size must be rejected rather than turning rotation off: the
	// unsigned parse it would otherwise reach yields 0, which reads as
	// "no size limit".
	require.NoError(t, param.Logging_Rotation_MaxSize.Set("-1GB"))
	_, err = buildRotateConfig()
	require.Error(t, err, "a negative MaxSize must surface an error, not silently disable rotation")
	assert.Contains(t, err.Error(), "negative")

	// A valid size parses cleanly.
	require.NoError(t, param.Logging_Rotation_MaxSize.Set("250MB"))
	cfg, err := buildRotateConfig()
	require.NoError(t, err)
	assert.Equal(t, int64(250*1024*1024), cfg.maxSize)
}

// TestBuildRotateConfigRejectsUnknownFrequency verifies an unrecognized
// Frequency is reported rather than quietly treated as daily: an administrator
// who asked for "weekly" must learn that no such cadence exists instead of
// discovering months later that logs rotated every night.
func TestBuildRotateConfigRejectsUnknownFrequency(t *testing.T) {
	t.Cleanup(func() { _ = param.Reset() })

	require.NoError(t, param.Logging_Rotation_Frequency.Set("weekly"))
	_, err := buildRotateConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), param.Logging_Rotation_Frequency.GetName())

	for _, valid := range []string{"daily", "hourly", "none", "DAILY", ""} {
		require.NoError(t, param.Logging_Rotation_Frequency.Set(valid))
		_, err := buildRotateConfig()
		assert.NoError(t, err, "%q must be accepted", valid)
	}
}
