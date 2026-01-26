//go:build unix

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

package client_agent_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestDaemonStartAndLock tests that the daemon:
// 1. Can be started
// 2. Holds the lock file
// 3. Can be connected to
// 4. Auto-shuts down after idle timeout
func TestDaemonStartAndLock(t *testing.T) {
	server_utils.ResetTestState()

	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test-daemon.sock")
	pidFile := filepath.Join(tempDir, "test-daemon.pid")
	logFile := filepath.Join(tempDir, "test-daemon.log")

	// Start daemon with short idle timeout for testing
	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: logFile,
		MaxJobs:     2,
		DbLocation:  "",
		IdleTimeout: 5 * time.Second, // Short timeout for testing
	}

	pid, err := client_agent.StartDaemon(config)
	require.NoError(t, err, "Failed to start daemon")
	require.Greater(t, pid, 0, "Invalid PID returned")

	t.Logf("Daemon started with PID %d", pid)

	// Wait for the daemon to be ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Daemon should be running after startup")

	// Print log file for debugging
	if logData, err := os.ReadFile(logFile); err == nil {
		t.Logf("Daemon log:\n%s", string(logData))
	}

	// Verify PID file exists and contains correct PID
	holderPID, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to read PID from lock")
	require.Equal(t, pid, holderPID, "PID in lock file should match daemon PID")
	t.Logf("PID file locked by PID: %d", holderPID)

	// Verify the PID file is locked (another daemon can't start)
	_, err = client_agent.StartDaemon(config)
	assert.Error(t, err, "Should not be able to start second daemon")
	assert.Contains(t, err.Error(), "already running", "Error should indicate daemon is already running")

	// Wait for idle timeout plus some buffer
	t.Log("Waiting for idle timeout...")
	time.Sleep(config.IdleTimeout + 2*time.Second)

	// Daemon should have shut down
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	running := apiClient.IsServerRunning(ctx2)
	assert.False(t, running, "Daemon should have auto-shut down after idle timeout")

	t.Log("Daemon successfully shut down after idle timeout")
}

// TestDaemonWithActivity tests that the daemon doesn't shut down while there's activity
func TestDaemonWithActivity(t *testing.T) {
	server_utils.ResetTestState()

	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test-daemon-activity.sock")
	pidFile := filepath.Join(tempDir, "test-daemon-activity.pid")
	logFile := filepath.Join(tempDir, "test-daemon-activity.log")

	// Start daemon with short idle timeout
	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: logFile,
		MaxJobs:     2,
		DbLocation:  "",
		IdleTimeout: 3 * time.Second,
	}

	pid, err := client_agent.StartDaemon(config)
	require.NoError(t, err, "Failed to start daemon")
	t.Logf("Daemon started with PID %d", pid)

	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	// Wait for daemon to be ready
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 5*time.Second, 500*time.Millisecond, "Daemon should start within 5 seconds")

	ctx := context.Background()

	// Send periodic requests to keep the daemon alive
	for i := 0; i < 3; i++ {
		time.Sleep(2 * time.Second)

		// Make a request to reset the idle timer
		_, err := apiClient.ListJobs(ctx, "", 10, 0)
		if err != nil {
			t.Logf("List jobs request failed (daemon may have shut down): %v", err)
			break
		}
		t.Logf("Request %d sent, daemon should still be alive", i+1)
	}

	// Daemon should still be running because we've been sending requests
	running := apiClient.IsServerRunning(ctx)
	assert.True(t, running, "Daemon should still be running due to activity")

	// Now wait for idle timeout without activity
	time.Sleep(config.IdleTimeout + 2*time.Second)

	// Now it should have shut down
	running = apiClient.IsServerRunning(ctx)
	assert.False(t, running, "Daemon should have shut down after idle period")
}
