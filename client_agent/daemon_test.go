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

// getTempDir returns a temp directory, preferring t.TempDir() but falling back to /tmp
// if the socket path would exceed 80 characters (to avoid Mac's 104 char limit)
func getTempDir(t *testing.T) string {
	tempDir := t.TempDir()
	// Check if socket path would be too long (leave room for socket filename)
	testSocketPath := filepath.Join(tempDir, "daemon.sock")
	if len(testSocketPath) <= 80 {
		// Path is fine, use t.TempDir() which auto-cleans up
		return tempDir
	}

	t.Logf("TempDir socket path too long (%d chars), using /tmp instead", len(testSocketPath))

	// Path too long, use /tmp instead
	shortDir, err := os.MkdirTemp("/tmp", "pelican-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(shortDir); err != nil {
			t.Logf("Warning: failed to remove temp directory %s: %v", shortDir, err)
		}
	})
	return shortDir
}

// TestDaemonStartAndLock tests that the daemon:
// 1. Can be started
// 2. Holds the lock file
// 3. Can be connected to
// 4. Auto-shuts down after idle timeout
func TestDaemonStartAndLock(t *testing.T) {
	server_utils.ResetTestState()

	tempDir := getTempDir(t)
	socketPath := filepath.Join(tempDir, "test-daemon.sock")
	pidFile := filepath.Join(tempDir, "test-daemon.pid")
	logFile := filepath.Join(tempDir, "test-daemon.log")
	dbFile := filepath.Join(tempDir, "test-daemon.db")

	// Log path information for debugging (especially useful on macOS with 104-char socket limit)
	t.Logf("Socket path: %s (length: %d)", socketPath, len(socketPath))
	t.Logf("Temp dir: %s", tempDir)

	// Build pelican binary for testing
	pelicanBin := buildPelicanBinary(t)

	// Start daemon with short idle timeout for testing
	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: logFile,
		MaxJobs:     2,
		DbLocation:  dbFile,
		IdleTimeout: 5 * time.Second,
		ExecPath:    pelicanBin, // Use built binary instead of test binary
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
	time.Sleep(5*time.Second + 2*time.Second)

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

	tempDir := getTempDir(t)
	socketPath := filepath.Join(tempDir, "test-daemon-activity.sock")
	pidFile := filepath.Join(tempDir, "test-daemon-activity.pid")
	logFile := filepath.Join(tempDir, "test-daemon-activity.log")
	dbFile := filepath.Join(tempDir, "test-daemon-activity.db")

	// Log path information for debugging (especially useful on macOS with 104-char socket limit)
	t.Logf("Socket path: %s (length: %d)", socketPath, len(socketPath))
	t.Logf("Temp dir: %s", tempDir)

	// Build pelican binary for testing
	pelicanBin := buildPelicanBinary(t)

	// Start daemon with short idle timeout
	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: logFile,
		MaxJobs:     2,
		DbLocation:  dbFile,
		IdleTimeout: 3 * time.Second,
		ExecPath:    pelicanBin, // Use built binary instead of test binary
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
		isRunning := apiClient.IsServerRunning(ctx)
		if !isRunning {
			// Check if socket file exists
			if _, err := os.Stat(socketPath); err != nil {
				t.Logf("Socket file does not exist: %v", err)
			} else {
				t.Logf("Socket file exists but connection failed")
			}
			// Check if log file has any errors
			if logData, err := os.ReadFile(logFile); err == nil && len(logData) > 0 {
				t.Logf("Daemon log:\n%s", string(logData))
			}
		}
		return isRunning
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
	time.Sleep(3*time.Second + 2*time.Second)

	// Now it should have shut down
	running = apiClient.IsServerRunning(ctx)
	assert.False(t, running, "Daemon should have shut down after idle period")
}
