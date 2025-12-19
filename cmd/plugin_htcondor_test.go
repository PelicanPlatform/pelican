//go:build integration && !windows

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

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestHTCondorPlugin tests the Pelican plugin integration with HTCondor
// This test starts a mini HTCondor instance, configures it to use the Pelican
// file transfer plugin, starts a data federation, and verifies that jobs can
// successfully transfer files using the plugin.
func TestHTCondorPlugin(t *testing.T) {
	// Skip if condor_master is not available
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not found in PATH, skipping integration test")
	}

	// Reset test state
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create temporary directory for mini HTCondor
	tempDir, err := os.MkdirTemp("", "htcondor-pelican-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create secure socket directory in /tmp to avoid path length issues
	socketDir, err := os.MkdirTemp("/tmp", "htc_sock_*")
	require.NoError(t, err)
	defer os.RemoveAll(socketDir)

	t.Logf("Using temporary directory: %s", tempDir)
	t.Logf("Using socket directory: %s", socketDir)

	// Generate signing key for HTCondor authentication
	passwordsDir := filepath.Join(tempDir, "passwords.d")
	require.NoError(t, os.MkdirAll(passwordsDir, 0700))
	signingKeyPath := filepath.Join(passwordsDir, "POOL")
	// Generate a simple signing key for testing
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	require.NoError(t, os.WriteFile(signingKeyPath, key, 0600))

	// Start a Pelican data federation
	t.Log("Starting Pelican data federation...")
	fed := fed_test_utils.NewFedTest(t, `
Origin:
  StorageType: posix
  EnablePublicReads: true
  EnableWrites: true
`)

	// Wait for federation to be ready
	time.Sleep(2 * time.Second)

	// Get federation URL components
	federationHost := param.Server_Hostname.GetString()
	federationPort := param.Server_WebPort.GetInt()
	federationURL := fmt.Sprintf("pelican://%s:%d", federationHost, federationPort)
	t.Logf("Federation URL: %s", federationURL)

	// Build the pelican binary to use as the plugin
	t.Log("Building pelican binary for plugin...")
	pelicanBinary := filepath.Join(tempDir, "pelican")
	
	// Find the repository root
	repoRoot, err := findRepoRoot()
	require.NoError(t, err, "Failed to find git repository root")
	
	buildCmd := exec.Command("go", "build", "-o", pelicanBinary, ".")
	buildCmd.Dir = repoRoot
	output, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output: %s", string(output))
	}
	require.NoError(t, err, "Failed to build pelican binary")
	require.FileExists(t, pelicanBinary)

	// Create HTCondor configuration
	configFile := filepath.Join(tempDir, "condor_config")
	require.NoError(t, writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, pelicanBinary))

	// Set CONDOR_CONFIG environment variable
	t.Setenv("CONDOR_CONFIG", configFile)

	// Start condor_master
	t.Log("Starting condor_master...")
	ctx, cancel := context.WithCancel(fed.Ctx)
	defer cancel()

	condorMaster, err := startCondorMaster(ctx, configFile, tempDir)
	require.NoError(t, err, "Failed to start condor_master")
	defer stopCondorMaster(condorMaster, t)

	// Wait for condor to be ready
	t.Log("Waiting for HTCondor to be ready...")
	require.NoError(t, waitForCondor(tempDir, 60*time.Second, t))
	t.Log("HTCondor is ready!")

	// Create test input file in the origin
	testFilename := "test-input.txt"
	testContent := "Hello from Pelican via HTCondor!\nThis is test data.\n"
	testPath := filepath.Join(fed.Exports[0].StoragePrefix, testFilename)
	require.NoError(t, os.WriteFile(testPath, []byte(testContent), 0644))

	// Create a job submit directory
	jobDir := filepath.Join(tempDir, "job")
	require.NoError(t, os.MkdirAll(jobDir, 0755))

	// Create an executable script for the job
	scriptPath := filepath.Join(jobDir, "test-script.sh")
	scriptContent := fmt.Sprintf(`#!/bin/bash
echo "Job is running"
echo "Current directory: $(pwd)"
echo "Files in current directory:"
ls -la
echo "Content of input file:"
cat %s || echo "Failed to read input file"
echo "Creating output file..."
echo "Output from HTCondor job" > test-output.txt
echo "Listing directory again:"
ls -la
echo "Job completed"
`, testFilename)
	require.NoError(t, os.WriteFile(scriptPath, []byte(scriptContent), 0755))

	// Create HTCondor submit file
	submitFile := filepath.Join(jobDir, "test.sub")
	outputFile := filepath.Join(jobDir, "test-output.txt")
	submitContent := fmt.Sprintf(`executable = %s
log = %s/test.log
output = %s/test.out
error = %s/test.err

# Transfer the input file from the federation
transfer_input_files = %s/test/%s

# Transfer the output file back
transfer_output_files = test-output.txt
transfer_output_remaps = "test-output.txt=%s"

should_transfer_files = YES
when_to_transfer_output = ON_EXIT

queue
`, scriptPath, jobDir, jobDir, jobDir, federationURL, testFilename, outputFile)

	require.NoError(t, os.WriteFile(submitFile, []byte(submitContent), 0644))
	t.Logf("Submit file created: %s", submitFile)
	t.Logf("Submit file content:\n%s", submitContent)

	// Submit the job
	t.Log("Submitting job to HTCondor...")
	submitCmd := exec.Command("condor_submit", submitFile)
	submitCmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	submitOutput, err := submitCmd.CombinedOutput()
	t.Logf("Submit output: %s", string(submitOutput))
	require.NoError(t, err, "Failed to submit job")

	// Extract cluster ID from submit output
	clusterID := extractClusterID(string(submitOutput))
	require.NotEmpty(t, clusterID, "Failed to extract cluster ID")
	t.Logf("Job submitted with cluster ID: %s", clusterID)

	// Wait for job to complete
	t.Log("Waiting for job to complete...")
	require.NoError(t, waitForJobCompletion(tempDir, clusterID, 120*time.Second, t))
	t.Log("Job completed successfully!")

	// Verify output file was transferred back
	require.FileExists(t, outputFile, "Output file should exist after job completion")

	// Read and verify output content
	outputContent, err := os.ReadFile(outputFile)
	require.NoError(t, err, "Should be able to read output file")
	t.Logf("Output file content: %s", string(outputContent))
	assert.Contains(t, string(outputContent), "Output from HTCondor job", "Output should contain expected text")

	// Check the job log for any errors
	logFile := filepath.Join(jobDir, "test.log")
	if logContent, err := os.ReadFile(logFile); err == nil {
		t.Logf("Job log content:\n%s", string(logContent))
	}

	// Check stderr for any errors
	errFile := filepath.Join(jobDir, "test.err")
	if errContent, err := os.ReadFile(errFile); err == nil && len(errContent) > 0 {
		t.Logf("Job stderr content:\n%s", string(errContent))
	}

	// Check stdout
	outFile := filepath.Join(jobDir, "test.out")
	if outContent, err := os.ReadFile(outFile); err == nil {
		t.Logf("Job stdout content:\n%s", string(outContent))
		assert.Contains(t, string(outContent), "Job is running", "Job should have run")
		assert.Contains(t, string(outContent), testContent, "Job should have read input file")
	}
}

// findRepoRoot finds the root of the git repository
func findRepoRoot() (string, error) {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// writeMiniCondorConfig writes a minimal HTCondor configuration for testing
func writeMiniCondorConfig(configFile, tempDir, socketDir, passwordsDir, pelicanBinary string) error {
	// Use dynamic ports to allow parallel test execution
	collectorPort := findFreePort()
	sharedPort := findFreePort()

	config := fmt.Sprintf(`# Mini HTCondor configuration for Pelican plugin testing
LOCAL_DIR = %s
LOG = $(LOCAL_DIR)/log
SPOOL = $(LOCAL_DIR)/spool
EXECUTE = $(LOCAL_DIR)/execute
LOCK = $(LOCAL_DIR)/lock
RUN = $(LOCAL_DIR)/run

# Use secure socket directory
SEC_PASSWORD_DIRECTORY = %s
SEC_TOKEN_DIRECTORY = $(LOCAL_DIR)/tokens.d

# Network configuration - use dynamic ports
COLLECTOR_HOST = $(CONDOR_HOST):$(COLLECTOR_PORT)
COLLECTOR_PORT = %d
SHARED_PORT = %d
USE_SHARED_PORT = True
SHARED_PORT_PORT = $(SHARED_PORT)
DAEMON_LIST = MASTER, COLLECTOR, NEGOTIATOR, SCHEDD, SHARED_PORT

# Allow local access
ALLOW_WRITE = *
ALLOW_READ = *
ALLOW_NEGOTIATOR = *
ALLOW_ADMINISTRATOR = *

# Security settings for testing
SEC_DEFAULT_AUTHENTICATION = OPTIONAL
SEC_DEFAULT_AUTHENTICATION_METHODS = FS, PASSWORD
SEC_PASSWORD_FILE = $(SEC_PASSWORD_DIRECTORY)/POOL

# File transfer plugin configuration
FILETRANSFER_PLUGINS = $(LIBEXEC)/pelican_plugin

# Create wrapper script for pelican plugin
LIBEXEC = %s/libexec

# Schedd configuration
SCHEDD_INTERVAL = 5
NEGOTIATOR_INTERVAL = 10

# Startd configuration (for local universe)
START = True
SUSPEND = False
CONTINUE = True
PREEMPT = False
KILL = False
WANT_SUSPEND = False
WANT_VACATE = False

# Enable file transfer
ENABLE_FILE_TRANSFER = TRUE
`, tempDir, passwordsDir, collectorPort, sharedPort, tempDir)

	if err := os.WriteFile(configFile, []byte(config), 0644); err != nil {
		return err
	}

	// Create libexec directory and wrapper script
	libexecDir := filepath.Join(tempDir, "libexec")
	if err := os.MkdirAll(libexecDir, 0755); err != nil {
		return err
	}

	// Create wrapper script that calls pelican plugin transfer
	wrapperScript := filepath.Join(libexecDir, "pelican_plugin")
	wrapperContent := fmt.Sprintf(`#!/bin/bash
exec %s plugin transfer "$@"
`, pelicanBinary)

	if err := os.WriteFile(wrapperScript, []byte(wrapperContent), 0755); err != nil {
		return err
	}

	return nil
}

// findFreePort finds an available port by asking the OS to allocate one
// Note: There is a small race condition where another process could claim
// the port between when we close the listener and when it's used. However,
// this is acceptable for tests as the probability is low and tests will
// fail cleanly if it happens.
func findFreePort() int {
	// Let the OS allocate a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		// Fallback to a high random port if we can't bind
		return 19000 + (os.Getpid() % 10000)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// startCondorMaster starts the condor_master daemon
func startCondorMaster(ctx context.Context, configFile, logDir string) (*exec.Cmd, error) {
	// Ensure log directory exists
	logPath := filepath.Join(logDir, "log")
	if err := os.MkdirAll(logPath, 0755); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, "condor_master", "-f")
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd, nil
}

// stopCondorMaster stops the condor_master daemon
func stopCondorMaster(cmd *exec.Cmd, t *testing.T) {
	if cmd != nil && cmd.Process != nil {
		// Try graceful shutdown first
		offCmd := exec.Command("condor_off", "-daemon", "master")
		if err := offCmd.Run(); err != nil {
			t.Logf("Warning: condor_off failed: %v", err)
		}

		// Wait a bit for graceful shutdown
		time.Sleep(2 * time.Second)

		// Force kill if still running
		if err := cmd.Process.Kill(); err != nil {
			t.Logf("Warning: failed to kill condor_master: %v", err)
		}
		cmd.Wait()
	}
}

// waitForCondor waits for HTCondor to be ready
func waitForCondor(tempDir string, timeout time.Duration, t *testing.T) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Try condor_q to check if schedd is responsive
		cmd := exec.Command("condor_q")
		cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+filepath.Join(tempDir, "condor_config"))
		if err := cmd.Run(); err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("HTCondor did not become ready within %v", timeout)
}

// extractClusterID extracts the cluster ID from condor_submit output
func extractClusterID(output string) string {
	// Look for "submitted to cluster XXX"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "submitted to cluster") {
			parts := strings.Fields(line)
			for i, part := range parts {
				if part == "cluster" && i+1 < len(parts) {
					// Remove any trailing period
					clusterID := strings.TrimSuffix(parts[i+1], ".")
					return clusterID
				}
			}
		}
	}
	return ""
}

// waitForJobCompletion waits for a job to complete
func waitForJobCompletion(tempDir, clusterID string, timeout time.Duration, t *testing.T) error {
	deadline := time.Now().Add(timeout)
	configFile := filepath.Join(tempDir, "condor_config")

	for time.Now().Before(deadline) {
		// Check job status with condor_q
		cmd := exec.Command("condor_q", clusterID, "-format", "%d", "JobStatus")
		cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
		output, err := cmd.Output()

		if err != nil || len(output) == 0 {
			// Job is no longer in queue, assume it completed
			// Verify with condor_history
			histCmd := exec.Command("condor_history", clusterID, "-limit", "1", "-format", "%d", "JobStatus")
			histCmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
			histOutput, histErr := histCmd.Output()
			if histErr == nil && len(histOutput) > 0 {
				status := string(histOutput)
				if status == "4" { // 4 = Completed
					t.Logf("Job %s completed successfully", clusterID)
					return nil
				}
				t.Logf("Job %s finished with status: %s", clusterID, status)
				return nil
			}
			// If not in history yet, continue waiting
		} else {
			status := string(output)
			t.Logf("Job %s status: %s", clusterID, status)
			// Status codes: 1=Idle, 2=Running, 3=Removed, 4=Completed, 5=Held, 6=Transferring Output
			if status == "5" {
				// Job is held, get the hold reason
				reasonCmd := exec.Command("condor_q", clusterID, "-format", "%s", "HoldReason")
				reasonCmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
				reason, _ := reasonCmd.Output()
				return fmt.Errorf("job %s is held: %s", clusterID, string(reason))
			}
		}

		time.Sleep(2 * time.Second)
	}

	// Timeout reached, get more info
	cmd := exec.Command("condor_q", "-long", clusterID)
	cmd.Env = append(os.Environ(), "CONDOR_CONFIG="+configFile)
	output, _ := cmd.Output()
	t.Logf("Job status at timeout:\n%s", string(output))

	return fmt.Errorf("job %s did not complete within %v", clusterID, timeout)
}
