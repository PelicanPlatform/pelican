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
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
)

// SetupSignalHandlers sets up signal handlers for SIGTERM to ensure logs are flushed
// before the process exits. If debug mode is enabled, it will also send SIGQUIT to dump
// stack traces before exiting.
func SetupSignalHandlers() {
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

		// If debug mode is enabled, send SIGQUIT to dump stack traces
		if log.GetLevel() == log.DebugLevel || log.GetLevel() == log.TraceLevel {
			log.Warnln("Debug mode enabled. Sending SIGQUIT to dump stack traces...")
			_ = syscall.Kill(os.Getpid(), syscall.SIGQUIT)
			// Give a moment for the stack trace to be written
			// Note: SIGQUIT will cause the process to exit with a core dump
			// so we don't need to explicitly exit here
			return
		}

		log.Warnln("Exiting after signal handling...")
		os.Exit(1)
	}()
}
