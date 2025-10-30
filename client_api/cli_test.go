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

package client_api_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_api"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// buildPelicanBinary builds the pelican binary for testing
func buildPelicanBinary(t *testing.T) string {
	tmpDir := t.TempDir()
	binaryPath := filepath.Join(tmpDir, "pelican")

	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build pelican binary: %s", output)

	return binaryPath
}

// TestCLIAsyncGet tests the pelican object get --async command
func TestCLIAsyncGet(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)

	// Create temporary directory
	tempDir := t.TempDir()

	// Create token
	viper.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-cli-async"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	readScope, err := token_scopes.Wlcg_Storage_Read.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, readScope)
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	tokenFile := filepath.Join(tempDir, "token")
	err = os.WriteFile(tokenFile, []byte(tkn), 0644)
	require.NoError(t, err)

	// Set up client API server
	socketPath := filepath.Join(tempDir, "client-api.sock")
	pidFile := filepath.Join(tempDir, "client-api.pid")

	serverConfig := client_api.ServerConfig{
		SocketPath:        socketPath,
		PidFile:           pidFile,
		MaxConcurrentJobs: 5,
	}

	server, err := client_api.NewServer(serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	})

	// Build pelican binary
	pelicanBin := buildPelicanBinary(t)

	// Create test file and upload it first
	testContent := []byte("Test file for async get\n")
	uploadFile := filepath.Join(tempDir, "upload.txt")
	err = os.WriteFile(uploadFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/async-get-test.txt", discoveryUrl, federationPrefix)

	// Upload synchronously first
	uploadCmd := exec.Command(pelicanBin, "object", "put", uploadFile, uploadURL, "--token", tokenFile)
	uploadCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))
	output, err := uploadCmd.CombinedOutput()
	require.NoError(t, err, "Failed to upload file: %s", output)

	// Test async get without --wait
	t.Run("AsyncGetWithoutWait", func(t *testing.T) {
		downloadFile := filepath.Join(tempDir, "downloaded-async.txt")

		cmd := exec.Command(pelicanBin, "object", "get", "--async", uploadURL, downloadFile, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async get: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain job ID
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Check status with: pelican job status")

		// Extract job ID from output
		re := regexp.MustCompile(`Job created: ([a-f0-9-]+)`)
		matches := re.FindStringSubmatch(outputStr)
		require.Len(t, matches, 2, "Could not extract job ID from output")
		jobID := matches[1]
		t.Logf("Created job ID: %s", jobID)

		// File should not exist yet (job is async)
		_, err = os.Stat(downloadFile)
		if err == nil {
			// File might exist if job completed very quickly, that's okay
			t.Logf("Note: File already exists (job completed quickly)")
		}
	})

	// Test async get with --wait
	t.Run("AsyncGetWithWait", func(t *testing.T) {
		downloadFile := filepath.Join(tempDir, "downloaded-wait.txt")

		cmd := exec.Command(pelicanBin, "object", "get", "--async", "--wait", uploadURL, downloadFile, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async get with wait: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain job creation and completion messages
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Waiting for job to complete")
		assert.Contains(t, outputStr, "Job completed successfully")

		// File should exist
		downloadedContent, err := os.ReadFile(downloadFile)
		require.NoError(t, err, "Downloaded file should exist")
		assert.Equal(t, testContent, downloadedContent, "Content should match")
	})
}

// TestCLIAsyncPut tests the pelican object put --async command
func TestCLIAsyncPut(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)

	// Create temporary directory
	tempDir := t.TempDir()

	// Create token
	viper.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-cli-async-put"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	tokenFile := filepath.Join(tempDir, "token")
	err = os.WriteFile(tokenFile, []byte(tkn), 0644)
	require.NoError(t, err)

	// Set up client API server
	socketPath := filepath.Join(tempDir, "client-api.sock")
	pidFile := filepath.Join(tempDir, "client-api.pid")

	serverConfig := client_api.ServerConfig{
		SocketPath:        socketPath,
		PidFile:           pidFile,
		MaxConcurrentJobs: 5,
	}

	server, err := client_api.NewServer(serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	})

	// Build pelican binary
	pelicanBin := buildPelicanBinary(t)

	// Create test file
	testContent := []byte("Test file for async put\n")
	uploadFile := filepath.Join(tempDir, "put-test.txt")
	err = os.WriteFile(uploadFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/async-put-test.txt", discoveryUrl, federationPrefix)

	// Test async put without --wait
	t.Run("AsyncPutWithoutWait", func(t *testing.T) {
		cmd := exec.Command(pelicanBin, "object", "put", "--async", uploadFile, uploadURL, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async put: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain job ID
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Check status with: pelican job status")
	})

	// Test async put with --wait
	t.Run("AsyncPutWithWait", func(t *testing.T) {
		uploadURL2 := fmt.Sprintf("pelican://%s%s/async-put-wait-test.txt", discoveryUrl, federationPrefix)

		cmd := exec.Command(pelicanBin, "object", "put", "--async", "--wait", uploadFile, uploadURL2, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async put with wait: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain completion message
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Waiting for job to complete")
		assert.Contains(t, outputStr, "Job completed successfully")
	})
}

// TestCLIJobCommands tests the pelican job subcommands
func TestCLIJobCommands(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)

	// Create temporary directory
	tempDir := t.TempDir()

	// Create token
	viper.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-cli-job"
	tokenConfig.AddAudienceAny()

	scopes := []token_scopes.TokenScope{}
	modScope, err := token_scopes.Wlcg_Storage_Modify.Path("/")
	require.NoError(t, err)
	scopes = append(scopes, modScope)
	tokenConfig.AddScopes(scopes...)

	tkn, err := tokenConfig.CreateToken()
	require.NoError(t, err)

	tokenFile := filepath.Join(tempDir, "token")
	err = os.WriteFile(tokenFile, []byte(tkn), 0644)
	require.NoError(t, err)

	// Set up client API server
	socketPath := filepath.Join(tempDir, "client-api.sock")
	pidFile := filepath.Join(tempDir, "client-api.pid")

	serverConfig := client_api.ServerConfig{
		SocketPath:        socketPath,
		PidFile:           pidFile,
		MaxConcurrentJobs: 5,
	}

	server, err := client_api.NewServer(serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	})

	// Build pelican binary
	pelicanBin := buildPelicanBinary(t)

	// Create test file and create a job
	testContent := []byte("Test file for job commands\n")
	uploadFile := filepath.Join(tempDir, "job-test.txt")
	err = os.WriteFile(uploadFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/job-cmd-test.txt", discoveryUrl, federationPrefix)

	// Create an async job
	cmd := exec.Command(pelicanBin, "object", "put", "--async", uploadFile, uploadURL, "--token", tokenFile)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create job: %s", output)

	// Extract job ID
	re := regexp.MustCompile(`Job created: ([a-f0-9-]+)`)
	matches := re.FindStringSubmatch(string(output))
	require.Len(t, matches, 2, "Could not extract job ID from output")
	jobID := matches[1]
	t.Logf("Created job ID: %s", jobID)

	// Test job status command
	t.Run("JobStatus", func(t *testing.T) {
		cmd := exec.Command(pelicanBin, "job", "status", jobID)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to get job status: %s", output)

		outputStr := string(output)
		t.Logf("Job status output:\n%s", outputStr)

		// Should contain job information
		assert.Contains(t, outputStr, "Job ID:")
		assert.Contains(t, outputStr, "Status:")
		assert.Contains(t, outputStr, jobID)
	})

	// Test job list command
	t.Run("JobList", func(t *testing.T) {
		cmd := exec.Command(pelicanBin, "job", "list")
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to list jobs: %s", output)

		outputStr := string(output)
		t.Logf("Job list output:\n%s", outputStr)

		// Should contain our job ID
		assert.Contains(t, outputStr, jobID)
	})

	// Test job list with status filter
	t.Run("JobListWithFilter", func(t *testing.T) {
		// Wait for job to complete
		time.Sleep(2 * time.Second)

		cmd := exec.Command(pelicanBin, "job", "list", "--status", "completed")
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to list completed jobs: %s", output)

		outputStr := string(output)
		t.Logf("Completed jobs output:\n%s", outputStr)

		// Output should indicate completed jobs or be empty
		// (Don't assert job ID is present as it might not be completed yet)
	})

	// Test job cancel command (create a new job to cancel)
	t.Run("JobCancel", func(t *testing.T) {
		// Create a large file to ensure transfer takes time
		largeFile := filepath.Join(tempDir, "large-cancel-test.txt")
		largeContent := bytes.Repeat([]byte("x"), 10*1024*1024) // 10MB
		err := os.WriteFile(largeFile, largeContent, 0644)
		require.NoError(t, err)

		cancelURL := fmt.Sprintf("pelican://%s%s/cancel-test.txt", discoveryUrl, federationPrefix)

		// Create async job
		createCmd := exec.Command(pelicanBin, "object", "put", "--async", largeFile, cancelURL, "--token", tokenFile)
		createCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err := createCmd.CombinedOutput()
		require.NoError(t, err, "Failed to create job for cancellation: %s", output)

		// Extract job ID
		matches := re.FindStringSubmatch(string(output))
		require.Len(t, matches, 2, "Could not extract job ID from output")
		cancelJobID := matches[1]

		// Give it a moment to start
		time.Sleep(200 * time.Millisecond)

		// Cancel the job
		cancelCmd := exec.Command(pelicanBin, "job", "cancel", cancelJobID)
		cancelCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

		output, err = cancelCmd.CombinedOutput()
		require.NoError(t, err, "Failed to cancel job: %s", output)

		outputStr := string(output)
		t.Logf("Cancel output: %s", outputStr)

		assert.Contains(t, outputStr, "cancelled")
	})
}

// TestCLIAsyncServerNotRunning tests behavior when server is not running
func TestCLIAsyncServerNotRunning(t *testing.T) {
	tempDir := t.TempDir()

	// Build pelican binary
	pelicanBin := buildPelicanBinary(t)

	// Try to use async without server running
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0644)
	require.NoError(t, err)

	socketPath := filepath.Join(tempDir, "nonexistent.sock")

	cmd := exec.Command(pelicanBin, "object", "put", "--async", testFile, "pelican://example.com/test", "--token", "fake-token")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENT_API_SOCKET=%s", socketPath))

	output, err := cmd.CombinedOutput()
	require.Error(t, err, "Should fail when server is not running")

	outputStr := string(output)
	t.Logf("Error output: %s", outputStr)

	// Should contain helpful error message
	lowerOutput := strings.ToLower(outputStr)
	assert.True(t,
		strings.Contains(lowerOutput, "not running") ||
			strings.Contains(lowerOutput, "failed to create") ||
			strings.Contains(lowerOutput, "connection refused"),
		"Error should indicate server is not running")
}
