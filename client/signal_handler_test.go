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
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
)

// TestSignalHandlerSetup verifies that SetupSignalHandlers can be called without errors
// and is idempotent
func TestSignalHandlerSetup(t *testing.T) {
	// This test simply verifies that SetupSignalHandlers doesn't panic, even when
	// invoked repeatedly. The actual signal handling is tested in TestSignalHandlerIntegration
	SetupSignalHandlers()
	SetupSignalHandlers()
	// Give the goroutine a moment to start
	time.Sleep(10 * time.Millisecond)
}

// signalHandlerSubprocess is the body run inside the re-executed test binary for the
// integration tests below. It installs the signal handler at the given log level,
// writes a readiness marker to stderr, then waits to be killed by the parent.
func signalHandlerSubprocess(level log.Level) {
	// Pin the effective log level so the handler deterministically picks between
	// the re-raise-SIGTERM path and the SIGQUIT stack-dump path (the test harness
	// otherwise leaves the hook-based log level reading as Trace).
	config.SetLogging(level)
	SetupSignalHandlers()
	// Signal readiness to the parent; also serves as output that should be flushed
	os.Stderr.WriteString("TEST_LOG_MESSAGE\n")
	// Wait for the signal
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

// spawnSignalHandlerSubprocess re-executes the test binary as a subprocess, waits for
// its readiness marker on stderr, sends it a SIGTERM, and returns the wait error along
// with everything the subprocess wrote to stderr.
func spawnSignalHandlerSubprocess(t *testing.T, mode string) (waitErr error, stderr string) {
	cmd := exec.Command(os.Args[0], "-test.run=TestSignalHandlerIntegration")
	cmd.Env = append(os.Environ(), "TEST_SIGNAL_HANDLER="+mode)
	stderrPipe, err := cmd.StderrPipe()
	require.NoError(t, err, "should be able to create stderr pipe")

	require.NoError(t, cmd.Start(), "subprocess should start successfully")

	// Wait for the readiness marker so we know the signal handler is installed
	// before sending SIGTERM
	reader := bufio.NewReader(stderrPipe)
	var sb strings.Builder
	for {
		line, err := reader.ReadString('\n')
		sb.WriteString(line)
		if strings.Contains(line, "TEST_LOG_MESSAGE") {
			break
		}
		require.NoError(t, err, "subprocess exited before signaling readiness; stderr: %s", sb.String())
	}

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM), "should be able to send SIGTERM")

	// Drain the remaining output, then reap the subprocess
	rest, _ := io.ReadAll(reader)
	sb.Write(rest)
	return cmd.Wait(), sb.String()
}

// TestSignalHandlerIntegration is an integration test that spawns a subprocess
// and sends it a SIGTERM to verify proper log flushing behavior
func TestSignalHandlerIntegration(t *testing.T) {
	switch os.Getenv("TEST_SIGNAL_HANDLER") {
	case "1":
		signalHandlerSubprocess(log.ErrorLevel)
		return
	case "debug":
		signalHandlerSubprocess(log.DebugLevel)
		return
	}

	t.Run("Default", func(t *testing.T) {
		waitErr, stderr := spawnSignalHandlerSubprocess(t, "1")

		// The handler re-raises SIGTERM after flushing, so the subprocess should
		// report a killed-by-SIGTERM wait status rather than exiting cleanly
		require.Error(t, waitErr, "subprocess should not exit cleanly after SIGTERM")
		var exitErr *exec.ExitError
		require.ErrorAs(t, waitErr, &exitErr, "subprocess should exit abnormally after SIGTERM")
		waitStatus, ok := exitErr.Sys().(syscall.WaitStatus)
		require.True(t, ok, "wait status should be available")
		assert.True(t, waitStatus.Signaled(), "subprocess should have been killed by a signal; stderr: %s", stderr)
		assert.Equal(t, syscall.SIGTERM, waitStatus.Signal(), "subprocess should have died from SIGTERM")
	})

	t.Run("Debug", func(t *testing.T) {
		waitErr, stderr := spawnSignalHandlerSubprocess(t, "debug")

		// In debug mode the handler sends itself SIGQUIT; the Go runtime dumps all
		// goroutine stacks and exits with status 2
		require.Error(t, waitErr, "subprocess should not exit cleanly after SIGTERM")
		var exitErr *exec.ExitError
		require.ErrorAs(t, waitErr, &exitErr, "subprocess should exit abnormally after SIGTERM")
		assert.Equal(t, 2, exitErr.ExitCode(), "subprocess should exit with the Go runtime's SIGQUIT status")
		assert.Contains(t, stderr, "SIGQUIT: quit", "subprocess should have dumped stacks via SIGQUIT")
	})
}
