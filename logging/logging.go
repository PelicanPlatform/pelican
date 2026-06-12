/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/go-kit/log/term"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
)

// BufferedLogHook buffers log entries until they are flushed
type BufferedLogHook struct {
	entries []*log.Entry
	flushed atomic.Bool
}

// Global hook instance
var (
	bufferedHook atomic.Pointer[BufferedLogHook]
	flushOnce    sync.Once
	logFHandle   *os.File

	// asyncMu guards asyncW, loggingCtx, and loggingEgrp.
	asyncMu     sync.Mutex
	asyncW      *asyncWriter
	loggingCtx  context.Context = context.Background()
	loggingEgrp *errgroup.Group
)

// SetErrgroup registers the process-wide errgroup (and its context) used to run
// the asynchronous log-writer goroutine: the goroutine runs under the errgroup
// so a fatal write error propagates, and stops when the context is cancelled at
// shutdown. Call this once, early (e.g. from cmd.Execute), before file logging
// is initialized.
func SetErrgroup(ctx context.Context, egrp *errgroup.Group) {
	asyncMu.Lock()
	defer asyncMu.Unlock()
	loggingCtx = ctx
	loggingEgrp = egrp
}

// buildRotateConfig reads the Logging.Rotation.* parameters into the parsed form
// used by the async writer. It returns an error on a malformed value (e.g. an
// unparsable size) so the caller can fail loudly at startup rather than
// silently disabling a misconfigured knob.
func buildRotateConfig() (rotateConfig, error) {
	// The admin-facing knobs are phrased as "Disable..." so their zero value is
	// the desired default (rotation on, compression on); invert them here so the
	// writer's internal logic stays positive.
	cfg := rotateConfig{
		enable:             !param.Logging_Rotation_Disable.GetBool(),
		frequency:          parseRotationFrequency(param.Logging_Rotation_Frequency.GetString()),
		maxRetentionPeriod: param.Logging_Rotation_MaxRetentionPeriod.GetDuration(),
		compress:           !param.Logging_Rotation_DisableCompress.GetBool(),
	}
	// Parse the byte-size knobs, failing loudly on a malformed value rather than
	// silently disabling it: a typo'd value must not be ignored until a disk
	// fills at 3am.
	sizeKnobs := []struct {
		name string
		val  string
		dst  *int64
	}{
		{param.Logging_Rotation_MaxSize.GetName(), param.Logging_Rotation_MaxSize.GetString(), &cfg.maxSize},
		{param.Logging_Rotation_MaxRetentionSize.GetName(), param.Logging_Rotation_MaxRetentionSize.GetString(), &cfg.maxRetentionSize},
	}
	for _, k := range sizeKnobs {
		if k.val == "" {
			continue
		}
		size, err := utils.ParseBytes(k.val)
		if err != nil {
			return cfg, fmt.Errorf("invalid %s value %q: %w", k.name, k.val, err)
		}
		if size > math.MaxInt64 {
			return cfg, fmt.Errorf("%s value %q is too large", k.name, k.val)
		}
		*k.dst = int64(size)
	}
	return cfg, nil
}

// EnterSyncMode is the logging shutdown handler. It drains and flushes the
// asynchronous log writer, then flips it to synchronous mode so that any
// late-arriving log line (e.g. emitted during signal handling or a panic) is
// written directly to the log file by its calling goroutine. Safe to call
// multiple times; a no-op when file logging is not active.
func EnterSyncMode() {
	asyncMu.Lock()
	w := asyncW
	asyncMu.Unlock()
	if w != nil {
		w.enterSyncMode()
	}
}

// Reset function intended for unit tests to be able to
// reset log flush state.
func ResetLogFlush() {
	asyncMu.Lock()
	if asyncW != nil {
		asyncW.close()
		asyncW = nil
	}
	// Also drop any registered errgroup/context so a later FlushLogs in a
	// different test does not reuse a stale (already-finished) errgroup.
	loggingCtx = context.Background()
	loggingEgrp = nil
	asyncMu.Unlock()
	if logFHandle != nil {
		_ = logFHandle.Close()
		logFHandle = nil
	}
	testMode := isTestProcess()
	bufferedHook.Store(nil)
	flushOnce = sync.Once{}
	removeBufferedHook()
	if testMode {
		log.SetOutput(io.Discard)
		return
	}
	log.SetOutput(os.Stderr)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:          true,
		ForceColors:            term.IsTerminal(log.StandardLogger().Out),
		DisableColors:          false,
		DisableLevelTruncation: true,
	})
}

func NewBufferedLogHook() *BufferedLogHook {
	return &BufferedLogHook{
		entries: make([]*log.Entry, 0),
	}
}

// Fire is called on every log entry
func (hook *BufferedLogHook) Fire(entry *log.Entry) error {
	if hook.flushed.Load() {
		// Do not write to logger output
		return nil
	}

	// Buffer log messages
	hook.entries = append(hook.entries, entry)
	return nil
}

// Levels defines which log levels this hook applies to
func (hook *BufferedLogHook) Levels() []log.Level {
	return log.AllLevels
}

// removeBufferedHook removes the buffered hook while preserving other hooks (e.g., test hooks).
func removeBufferedHook() {
	// Use ReplaceHooks to safely get and replace hooks with internal locking
	oldHooks := log.StandardLogger().ReplaceHooks(log.LevelHooks{})
	filtered := make(log.LevelHooks)
	for lvl, hooks := range oldHooks {
		for _, h := range hooks {
			if _, ok := h.(*BufferedLogHook); ok {
				continue
			}
			filtered[lvl] = append(filtered[lvl], h)
		}
	}
	log.StandardLogger().ReplaceHooks(filtered)
}

// FlushLogs flushes buffered logs and switches to direct logging
func FlushLogs(pushToFile bool) {
	flushOnce.Do(func() {
		hook := bufferedHook.Load()
		if hook == nil {
			return
		}

		if hook.flushed.Load() {
			return
		}

		hook.flushed.Store(true)

		logLocation := param.Logging_LogLocation.GetString()
		if pushToFile && logLocation != "" {
			// The asynchronous writer opens (creating/appending) the log file,
			// decouples logging call sites from disk I/O, and -- for regular
			// files -- manages rotation/compression/retention.
			rotCfg, err := buildRotateConfig()
			if err != nil {
				cobra.CheckErr(err)
			}
			w, err := newAsyncWriter(logLocation, rotCfg, param.Logging_Rotation_FlushInterval.GetDuration())
			if err != nil {
				cobra.CheckErr(err)
			}

			asyncMu.Lock()
			asyncW = w
			ctx, egrp := loggingCtx, loggingEgrp
			asyncMu.Unlock()
			if egrp != nil {
				w.start(ctx, egrp)
			} else {
				w.start(ctx, nil)
			}

			fmt.Fprintf(os.Stderr, "%s is set to %s. All logs are redirected to the log file.\n", param.Logging_LogLocation.GetName(), logLocation)
			log.SetOutput(w)

			// Disable colors for log files
			log.SetFormatter(&log.TextFormatter{
				FullTimestamp:          true,
				DisableColors:          true,
				DisableLevelTruncation: true,
			})
		} else {
			// In tests, avoid re-enabling stderr output to prevent duplicate log lines (test hook already captures logs)
			if isTestProcess() {
				log.SetOutput(io.Discard)
			} else {
				log.SetOutput(os.Stderr)
				log.SetFormatter(&log.TextFormatter{
					FullTimestamp:          true,
					ForceColors:            term.IsTerminal(log.StandardLogger().Out),
					DisableColors:          false,
					DisableLevelTruncation: true,
				})
			}
		}

		// Flush buffered logs
		if len(hook.entries) > 0 {
			for _, entry := range hook.entries {
				formatted, err := entry.String()
				if err == nil {
					_, _ = log.StandardLogger().Out.Write([]byte(formatted))
				}
			}

			hook.entries = nil // Clear buffer after flush
		}

		removeBufferedHook()

		if out, ok := log.StandardLogger().Out.(*os.File); ok {
			_ = out.Sync()
		}
	})
}

// For unit tests, guarantees the filehandle is closed so tests can clean up
// after themselves. Generally not needed in production code because the OS
// should clean up the file handle when the process exits. Invoking this outside
// a test will prevent the log file from being written to!!
func CloseLogger() {
	asyncMu.Lock()
	w := asyncW
	asyncW = nil
	asyncMu.Unlock()
	if w != nil {
		// Stop the writer goroutine, flush, and close the file handle.
		w.close()
		// Reset log output to prevent writing to the closed writer.
		if isTestProcess() {
			log.SetOutput(io.Discard)
		} else {
			log.SetOutput(os.Stderr)
		}
	}
	if logFHandle != nil {
		_ = logFHandle.Close()
		logFHandle = nil
		// Reset log output to prevent writing to closed file
		if isTestProcess() {
			log.SetOutput(io.Discard)
		} else {
			log.SetOutput(os.Stderr)
		}
	}
}

// isTestProcess detects whether the current binary is a `go test` binary.
func isTestProcess() bool {
	return strings.HasSuffix(filepath.Base(os.Args[0]), ".test")
}

func SetupLogBuffering() {
	log.SetOutput(io.Discard) // Start by discarding logs until flush

	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})

	hook := NewBufferedLogHook()
	if bufferedHook.CompareAndSwap(nil, hook) {
		log.AddHook(hook)
	}
}
