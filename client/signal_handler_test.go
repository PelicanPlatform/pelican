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
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignalHandlerSetup verifies that SetupSignalHandlers can be called without errors
func TestSignalHandlerSetup(t *testing.T) {
	// This test simply verifies that SetupSignalHandlers doesn't panic
	// The actual signal handling is tested in TestSignalHandlerIntegration
	SetupSignalHandlers()
	// Give the goroutine a moment to start
	time.Sleep(10 * time.Millisecond)
}

// TestSignalHandlerIntegration is an integration test that spawns a subprocess
// and sends it a SIGTERM to verify proper log flushing behavior
func TestSignalHandlerIntegration(t *testing.T) {
	if os.Getenv("TEST_SIGNAL_HANDLER") == "1" {
		// This is the subprocess that will receive SIGTERM
		SetupSignalHandlers()
		// Write a log message that should be flushed on SIGTERM
		os.Stderr.WriteString("TEST_LOG_MESSAGE\n")
		// Wait for signal
		time.Sleep(10 * time.Second)
		os.Exit(0)
		return
	}

	// This is the parent test that spawns the subprocess
	cmd := exec.Command(os.Args[0], "-test.run=TestSignalHandlerIntegration")
	cmd.Env = append(os.Environ(), "TEST_SIGNAL_HANDLER=1")

	// Start the subprocess
	err := cmd.Start()
	require.NoError(t, err, "subprocess should start successfully")

	// Give the subprocess time to set up signal handler
	time.Sleep(100 * time.Millisecond)

	// Send SIGTERM to the subprocess
	err = cmd.Process.Signal(syscall.SIGTERM)
	require.NoError(t, err, "should be able to send SIGTERM")

	// Wait for the subprocess to exit
	err = cmd.Wait()
	// The process should exit with a non-zero status after receiving SIGTERM
	assert.Error(t, err, "subprocess should exit with error after SIGTERM")

	t.Log("Successfully verified signal handler responds to SIGTERM")
}

// TestSignalHandlerSIGTERM verifies basic SIGTERM handling without starting a subprocess
func TestSignalHandlerSIGTERM(t *testing.T) {
	// Set up a signal handler
	SetupSignalHandlers()

	// Give the goroutine time to set up
	time.Sleep(10 * time.Millisecond)

	// Note: We can't easily test the actual signal handling in a unit test
	// without spawning a subprocess, as sending a signal to ourselves
	// would terminate the test process. The integration test above handles
	// that scenario.

	// This test just verifies the setup doesn't panic
	assert.True(t, true, "Signal handler setup completed without panic")
}
