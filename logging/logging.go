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
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"

	logs "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/pelicanplatform/pelican/param"
)

// BufferedLogHook buffers log entries until they are flushed
type BufferedLogHook struct {
	entries []*logs.Entry
	flushed atomic.Bool
}

// Global hook instance
var (
	bufferedHook atomic.Pointer[BufferedLogHook]
	flushOnce    sync.Once
)

func NewBufferedLogHook() *BufferedLogHook {
	return &BufferedLogHook{
		entries: make([]*logs.Entry, 0),
	}
}

// Fire is called on every log entry
func (hook *BufferedLogHook) Fire(entry *logs.Entry) error {
	if hook.flushed.Load() {
		// Do not write to logger output
		return nil
	}

	// Buffer log messages
	hook.entries = append(hook.entries, entry)
	return nil
}

// Levels defines which log levels this hook applies to
func (hook *BufferedLogHook) Levels() []logs.Level {
	return logs.AllLevels
}

// removeBufferedHook removes the buffered hook (used after flushing)
func removeBufferedHook() {
	logs.StandardLogger().ReplaceHooks(make(logs.LevelHooks))
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
			fmt.Fprintf(os.Stderr, "Logging.LogLocation is set to %s. All logs are redirected to the log file.\n", logLocation)
			logs.SetOutput(f)

			// Disable colors for log files
			logs.SetFormatter(&logs.TextFormatter{
				FullTimestamp: true,
				DisableColors: true,
			})
		} else {
			logs.SetOutput(os.Stdout)

			// Restore colorized output when logging to stdout
			logs.SetFormatter(&logs.TextFormatter{
				FullTimestamp: true,
				ForceColors:   true,
				DisableColors: false,
			})
		}

		// Flush buffered logs
		if len(hook.entries) > 0 {
			fmt.Println("\n[Buffered Logs]: Flushing logs...")

			for _, entry := range hook.entries {
				formatted, err := entry.String()
				if err == nil {
					_, _ = logs.StandardLogger().Out.Write([]byte(formatted))
				}
			}

			hook.entries = nil // Clear buffer after flush
		}

		removeBufferedHook()

		os.Stdout.Sync()
	})
}

// Auto-flush logs when the program exits
func setupAutoFlush() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

	go func() {
		sig := <-c
		fmt.Println("\nReceived signal:", sig, "- Flushing logs before exiting...")

		FlushLogs(false)

		os.Stdout.Sync()

		// Determine correct exit code based on signal
		exitCode := 0
		if sig == syscall.SIGINT {
			exitCode = 130
		} else if sig == syscall.SIGTERM {
			exitCode = 143
		}

		os.Exit(exitCode)
	}()

	logs.RegisterExitHandler(func() {
		fmt.Println("\nExit handler triggered - Flushing logs...")
		FlushLogs(false)
	})
}

func init() {
	logs.SetOutput(io.Discard) // Start by discarding logs until flush

	logs.SetFormatter(&logs.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})

	hook := NewBufferedLogHook()
	if bufferedHook.CompareAndSwap(nil, hook) {
		logs.AddHook(hook)
	}

	setupAutoFlush()
}
