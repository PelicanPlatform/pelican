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

package main

import (
	"context"
	"os"
	"os/exec"
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
	testSocketPath := filepath.Join(tempDir, "agent.sock")
	if len(testSocketPath) <= 80 {
		// Path is fine, use t.TempDir() which auto-cleans up
		return tempDir
	}

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

// TestClientAgentCLI tests the client-agent CLI commands: start, status, stop
func TestClientAgentCLI(t *testing.T) {
	server_utils.ResetTestState()

	// Get the pelican binary (built once via sync.Once)
	binaryPath := getPelicanBinary(t)

	// Set up test paths
	tempDir := getTempDir(t)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")
	logFile := filepath.Join(tempDir, "agent.log")

	// Helper to print logs on failure
	defer func() {
		if t.Failed() {
			if logData, err := os.ReadFile(logFile); err == nil {
				t.Logf("Daemon log:\n%s", string(logData))
			}
		}
	}()

	// Test 1: Start the server
	t.Log("Starting client-agent server...")
	startCmd := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
		"--log", logFile)

	startOutput, err := startCmd.CombinedOutput()
	require.NoError(t, err, "Failed to start server: %s", string(startOutput))
	assert.Contains(t, string(startOutput), "Client agent server started as daemon")
	assert.Contains(t, string(startOutput), "Socket:")

	// Wait for the daemon to be ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Daemon should be running after startup")

	// Test 2: Check status
	t.Log("Checking server status...")
	statusCmd := exec.Command(binaryPath, "client-agent", "status",
		"--socket", socketPath,
		"--pid-file", pidFile)
	statusOutput, err := statusCmd.CombinedOutput()
	require.NoError(t, err, "Failed to check status: %s", string(statusOutput))
	assert.Contains(t, string(statusOutput), "Client agent server is running")
	assert.Contains(t, string(statusOutput), "PID:")

	// Test 3: Verify PID file
	pid, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to get server PID")
	require.Greater(t, pid, 0, "PID should be positive")
	t.Logf("Server running with PID: %d", pid)

	// Test 4: Try to start again (should fail)
	t.Log("Attempting to start server again (should fail)...")
	startAgainCmd := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile)
	startAgainOutput, err := startAgainCmd.CombinedOutput()
	assert.Error(t, err, "Should not be able to start server again")
	assert.Contains(t, string(startAgainOutput), "already running")

	// Test 5: Stop the server
	t.Log("Stopping server...")
	stopCmd := exec.Command(binaryPath, "client-agent", "stop",
		"--socket", socketPath,
		"--pid-file", pidFile)
	stopOutput, err := stopCmd.CombinedOutput()
	require.NoError(t, err, "Failed to stop server: %s", string(stopOutput))
	assert.Contains(t, string(stopOutput), "Sent shutdown signal to server")

	// Test 6: Wait for shutdown and verify server is stopped
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return !apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should shut down")

	// Test 7: Check status after stop
	t.Log("Checking status after stop...")
	statusCmd2 := exec.Command(binaryPath, "client-agent", "status",
		"--socket", socketPath,
		"--pid-file", pidFile)
	statusOutput2, err := statusCmd2.CombinedOutput()
	require.NoError(t, err, "Status command should succeed")
	assert.Contains(t, string(statusOutput2), "Client agent server is not running")

	// Test 8: Try to stop again (should be idempotent)
	t.Log("Attempting to stop server again...")
	stopCmd2 := exec.Command(binaryPath, "client-agent", "stop",
		"--socket", socketPath,
		"--pid-file", pidFile)
	stopOutput2, err := stopCmd2.CombinedOutput()
	require.NoError(t, err, "Stop command should be idempotent")
	assert.Contains(t, string(stopOutput2), "Server is not running")
}

// TestClientAgentForeground tests the --foreground flag
func TestClientAgentForeground(t *testing.T) {
	server_utils.ResetTestState()

	// Get the pelican binary (built once via sync.Once)
	binaryPath := getPelicanBinary(t)

	// Set up test paths
	tempDir := getTempDir(t)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")

	// Start the server in foreground mode
	t.Log("Starting client-agent in foreground mode...")
	startCmd := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
		"--foreground")

	// Start in background but keep the process
	require.NoError(t, startCmd.Start(), "Failed to start foreground server")
	defer func() {
		if startCmd.Process != nil {
			_ = startCmd.Process.Kill()
			_ = startCmd.Wait()
		}
	}()

	// Wait for server to be ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should be running in foreground")

	// Verify it's running
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	running := apiClient.IsServerRunning(ctx)
	cancel()
	assert.True(t, running, "Server should be running")

	// Kill the foreground process
	require.NoError(t, startCmd.Process.Kill(), "Failed to kill foreground server")
	_ = startCmd.Wait()

	// Verify server stopped
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return !apiClient.IsServerRunning(ctx)
	}, 5*time.Second, 500*time.Millisecond, "Server should stop after process killed")
}

// TestClientAgentRestart tests that the server can be restarted
func TestClientAgentRestart(t *testing.T) {
	server_utils.ResetTestState()

	// Get the pelican binary (built once via sync.Once)
	binaryPath := getPelicanBinary(t)

	// Set up test paths
	tempDir := getTempDir(t)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")
	logFile := filepath.Join(tempDir, "agent.log")

	// Helper to print logs on failure
	defer func() {
		if t.Failed() {
			if logData, err := os.ReadFile(logFile); err == nil {
				t.Logf("Daemon log:\n%s", string(logData))
			} else {
				t.Logf("Could not read log file %s: %v", logFile, err)
			}
		}
	}()

	// Start server
	startCmd := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
		"--log", logFile)
	output, err := startCmd.CombinedOutput()
	if err != nil {
		t.Logf("Start command output: %s", string(output))
	}
	require.NoError(t, err, "Failed to start server first time")

	// Wait for ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should start")

	// Get first PID
	pid1, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to get first PID")
	require.Greater(t, pid1, 0, "First PID should be positive")

	// Stop server
	stopCmd := exec.Command(binaryPath, "client-agent", "stop",
		"--socket", socketPath,
		"--pid-file", pidFile)
	_, err = stopCmd.CombinedOutput()
	require.NoError(t, err, "Failed to stop server")

	// Wait for shutdown
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return !apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should stop")

	// Start again
	startCmd2 := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
		"--log", logFile)
	startOutput2, err := startCmd2.CombinedOutput()
	if err != nil {
		t.Logf("Restart command output: %s", string(startOutput2))
	}
	require.NoError(t, err, "Failed to restart server: %s", string(startOutput2))

	// Wait for ready again
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should restart")

	// Get second PID
	pid2, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to get second PID")
	require.Greater(t, pid2, 0, "Second PID should be positive")
	assert.NotEqual(t, pid1, pid2, "PIDs should be different after restart")

	// Cleanup
	stopCmd2 := exec.Command(binaryPath, "client-agent", "stop",
		"--socket", socketPath,
		"--pid-file", pidFile)
	_ = stopCmd2.Run()
}

// TestClientAgentAutoSpawn tests that pelican object get --async will auto-spawn the server
func TestClientAgentAutoSpawn(t *testing.T) {
	server_utils.ResetTestState()

	// Get the pelican binary (built once via sync.Once)
	binaryPath := getPelicanBinary(t)

	// Set up test paths
	tempDir := getTempDir(t)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")
	logFile := filepath.Join(tempDir, "agent.log")

	// Helper to print logs on failure
	defer func() {
		if t.Failed() {
			if logData, err := os.ReadFile(logFile); err == nil {
				t.Logf("Daemon log:\n%s", string(logData))
			}
		}
	}()

	testEnv := append(os.Environ(),
		"PELICAN_CLIENTAGENT_SOCKET="+socketPath,
		"PELICAN_CLIENTAGENT_PIDFILE="+pidFile,
		"PELICAN_LOGGING_LOGLOCATION="+logFile,
	)

	// Clean up any leftover server at the end
	defer func() {
		stopCmd := exec.Command(binaryPath, "client-agent", "stop",
			"--socket", socketPath,
			"--pid-file", pidFile)
		_ = stopCmd.Run()
	}()

	// Run pelican object get --async with a fake URL (it will fail, but should still spawn the server)
	// We use a fake URL because we don't want to set up a full federation just to test auto-spawn
	t.Log("Running pelican object get --async to trigger auto-spawn...")
	getCmd := exec.Command(binaryPath, "object", "get", "--async",
		"pelican://nonexistent.example.com/test", filepath.Join(tempDir, "output"))
	getCmd.Env = testEnv
	getOutput, _ := getCmd.CombinedOutput() // We expect this to fail, so ignore error
	t.Logf("Get command output: %s", string(getOutput))

	// The command should have output a job ID, indicating the server was spawned
	assert.Contains(t, string(getOutput), "Job created:", "Should have created a job")

	// Give the server a moment to fully initialize
	time.Sleep(1 * time.Second)

	// Verify server is now running
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should have auto-spawned")

	t.Log("Server successfully auto-spawned!")

	// Verify we can get the PID
	pid, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to get server PID")
	require.Greater(t, pid, 0, "PID should be positive")
	t.Logf("Auto-spawned server running with PID: %d", pid)

	// Stop the server
	stopCmd := exec.Command(binaryPath, "client-agent", "stop")
	stopCmd.Env = testEnv
	_, err = stopCmd.CombinedOutput()
	require.NoError(t, err, "Failed to stop server")

	// Wait for shutdown
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return !apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should shut down")
}

// TestClientAgentIdleShutdown tests that the server automatically shuts down after idle timeout
func TestClientAgentIdleShutdown(t *testing.T) {
	server_utils.ResetTestState()

	// Get the pelican binary (built once via sync.Once)
	binaryPath := getPelicanBinary(t)

	// Set up test paths
	tempDir := getTempDir(t)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")
	logFile := filepath.Join(tempDir, "agent.log")

	// Helper to print logs on failure
	defer func() {
		if t.Failed() {
			if logData, err := os.ReadFile(logFile); err == nil {
				t.Logf("Daemon log:\n%s", string(logData))
			}
		}
	}()

	// Set a short idle timeout for testing (3 seconds) using environment variable
	testEnv := append(os.Environ(), "PELICAN_CLIENTAGENT_IDLETIMEOUT=3s")

	// Clean up any leftover server at the end
	defer func() {
		stopCmd := exec.Command(binaryPath, "client-agent", "stop",
			"--socket", socketPath,
			"--pid-file", pidFile)
		_ = stopCmd.Run()
	}()

	// Start the server with short idle timeout using explicit paths
	t.Log("Starting client-agent server with 3s idle timeout...")
	startCmd := exec.Command(binaryPath, "client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
		"--log", logFile)
	startCmd.Env = testEnv

	startOutput, err := startCmd.CombinedOutput()
	require.NoError(t, err, "Failed to start server: %s", string(startOutput))

	// Wait for server to be ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should start")

	t.Log("Server started successfully")

	// Verify server is running
	pid, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Failed to get server PID")
	require.Greater(t, pid, 0, "PID should be positive")
	t.Logf("Server running with PID: %d", pid)

	// Wait for idle timeout (5 seconds) plus buffer for shutdown
	t.Log("Waiting for idle timeout (5s + buffer)...")

	// Check for shutdown - start checking after 6 seconds
	time.Sleep(6 * time.Second)

	// Verify server has automatically shut down
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return !apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Server should auto-shutdown after idle timeout")

	t.Log("Server successfully shut down after idle timeout!")

	// Read and display log file for debugging
	if logData, err := os.ReadFile(logFile); err == nil {
		t.Logf("Server log output:\n%s", string(logData))
	} else {
		t.Logf("Could not read log file: %v", err)
	}

	// Verify status shows not running
	statusCmd := exec.Command(binaryPath, "client-agent", "status",
		"--socket", socketPath,
		"--pid-file", pidFile)
	statusOutput, err := statusCmd.CombinedOutput()
	require.NoError(t, err, "Status command should succeed")
	assert.Contains(t, string(statusOutput), "not running", "Status should show server not running")
}
