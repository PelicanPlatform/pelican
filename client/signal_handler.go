//go:build !windows

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

package client

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
)

var setupSignalHandlersOnce sync.Once

// SetupSignalHandlers sets up signal handlers for SIGTERM to ensure logs are flushed
// before the process exits. If debug mode is enabled, it will also send SIGQUIT to dump
// stack traces before exiting.
func SetupSignalHandlers() {
	setupSignalHandlersOnce.Do(func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM)

		go func() {
			sig := <-sigChan
			log.Warnf("Received signal: %v. Flushing logs before exit...", sig)

			// Flush all buffered logs
			logging.FlushLogs(param.Logging_LogLocation.GetString() != "")

			// Sync stdout and stderr to ensure all output is written
			if err := os.Stdout.Sync(); err != nil {
				log.Debugf("Error syncing stdout: %v", err)
			}
			if err := os.Stderr.Sync(); err != nil {
				log.Debugf("Error syncing stderr: %v", err)
			}

			// If debug mode is enabled, send SIGQUIT to dump stack traces; the Go
			// runtime's default SIGQUIT behavior prints all goroutine stacks and exits.
			// Note logrus's global level is pinned to Trace when filter-based logging
			// is active, so consult the effective level instead of log.GetLevel().
			if effLevel := config.GetEffectiveLogLevel(); effLevel == log.DebugLevel || effLevel == log.TraceLevel {
				log.Warnln("Debug mode enabled. Sending SIGQUIT to dump stack traces...")
				_ = syscall.Kill(os.Getpid(), syscall.SIGQUIT)
			} else {
				// Re-raise SIGTERM with the default disposition restored so the process
				// reports a killed-by-SIGTERM wait status (e.g. to HTCondor) rather than
				// an ordinary exit code.
				log.Warnln("Exiting after signal handling...")
				signal.Reset(syscall.SIGTERM)
				_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}

			// Signal delivery is asynchronous; block until the pending signal
			// terminates the process.
			select {}
		}()
	})
}
