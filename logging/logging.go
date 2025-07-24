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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/go-kit/log/term"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/param"
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
)

// Reset function intended for unit tests to be able to
// reset log flush state.
func ResetLogFlush() {
	flushOnce = sync.Once{}
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

// removeBufferedHook removes the buffered hook (used after flushing)
func removeBufferedHook() {
	log.StandardLogger().ReplaceHooks(make(log.LevelHooks))
}

// FlushLogs flushes buffered logs and switches to direct logging
func FlushLogs(pushToFile bool) {
	flushOnce.Do(func() {
		hook := bufferedHook.Load()
		if hook == nil {
			fmt.Fprintln(os.Stderr, "FlushLogs called but no bufferedHook exists")
			return
		}

		if hook.flushed.Load() {
			return
		}

		hook.flushed.Store(true)

		logLocation := param.Logging_LogLocation.GetString()
		if pushToFile && logLocation != "" {
			dir := filepath.Dir(logLocation)
			if dir != "" {
				if err := os.MkdirAll(dir, 0750); err != nil {
					cobra.CheckErr(fmt.Errorf("failed to access/create specified directory: %w", err))
				}
			}

			f, err := os.OpenFile(logLocation, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0640)
			if err != nil {
				cobra.CheckErr(fmt.Errorf("failed to access specified log file: %w", err))
			}
			logFHandle = f
			fmt.Fprintf(os.Stderr, "Logging.LogLocation is set to %s. All logs are redirected to the log file.\n", logLocation)
			log.SetOutput(f)

			// Disable colors for log files
			log.SetFormatter(&log.TextFormatter{
				FullTimestamp:          true,
				DisableColors:          true,
				DisableLevelTruncation: true,
			})
		} else {
			log.SetOutput(os.Stderr)

			// Restore colorized output when logging to stderr
			log.SetFormatter(&log.TextFormatter{
				FullTimestamp:          true,
				ForceColors:            term.IsTerminal(log.StandardLogger().Out),
				DisableColors:          false,
				DisableLevelTruncation: true,
			})
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
	if logFHandle != nil {
		_ = logFHandle.Close()
	}
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
