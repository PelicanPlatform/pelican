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

package client_agent_test

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

var (
	buildOnce      sync.Once
	pelicanBinPath string
	binaryTempDir  string
)

// TestMain sets up fixtures that persist across all tests
func TestMain(m *testing.M) {
	// Run all tests
	code := m.Run()

	// Cleanup binary temp directory if it was created
	if binaryTempDir != "" {
		os.RemoveAll(binaryTempDir)
	}
	os.Exit(code)
}

// buildPelicanBinary builds the pelican binary on first call and returns its path
func buildPelicanBinary(t *testing.T) string {
	buildOnce.Do(func() {
		var err error
		binaryTempDir, err = os.MkdirTemp("", "pelican-cli-test-*")
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}

		pelicanBinPath = filepath.Join(binaryTempDir, "pelican")
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", pelicanBinPath, "../cmd")
		output, err := cmd.CombinedOutput()
		if err != nil {
			os.RemoveAll(binaryTempDir)
			t.Fatalf("Failed to build pelican binary: %s", output)
		}
	})

	return pelicanBinPath
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
	err := param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	require.NoError(t, err)
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

	// Set up client API server with proper temp directory handling
	serverConfig, _ := client_agent.CreateTestServerConfig(t)

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	server, err := client_agent.NewServer(ctx, serverConfig)
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
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	uploadURL := fmt.Sprintf("pelican://%s%s/async-get-test.txt", discoveryUrl.Host, federationPrefix)

	// Upload with async + wait to ensure file is present before testing downloads
	uploadCmd := exec.Command(pelicanBin, "object", "put", "--async", "--wait", uploadFile, uploadURL, "--token", tokenFile)
	uploadCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))
	output, err := uploadCmd.CombinedOutput()
	require.NoError(t, err, "Failed to upload file: %s", output)

	// Test async get without --wait
	t.Run("AsyncGetWithoutWait", func(t *testing.T) {
		downloadFile := filepath.Join(tempDir, "downloaded-async.txt")

		cmd := exec.Command(pelicanBin, "object", "get", "--async", uploadURL, downloadFile, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

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
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

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
	startTime := time.Now()
	t.Logf("TestCLIAsyncPut started at %s", startTime)

	// Reset test state
	server_utils.ResetTestState()
	t.Logf("Reset test state took %s", time.Since(startTime))

	// Create test federation
	fedStart := time.Now()
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)
	t.Logf("Federation setup took %s", time.Since(fedStart))

	// Create temporary directory
	tempDir := t.TempDir()

	// Create token
	tokenStart := time.Now()
	err := param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	require.NoError(t, err)
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
	t.Logf("Token creation took %s", time.Since(tokenStart))

	// Set up client API server
	serverStart := time.Now()
	serverConfig, _ := client_agent.CreateTestServerConfig(t)

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	server, err := client_agent.NewServer(ctx, serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	})
	t.Logf("Server setup took %s", time.Since(serverStart))

	// Build pelican binary
	buildStart := time.Now()
	pelicanBin := buildPelicanBinary(t)
	t.Logf("Binary build took %s", time.Since(buildStart))

	// Create test file
	testContent := []byte("Test file for async put\n")
	uploadFile := filepath.Join(tempDir, "put-test.txt")
	err = os.WriteFile(uploadFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	uploadURL := fmt.Sprintf("pelican://%s%s/async-put-test.txt", discoveryUrl.Host, federationPrefix)

	t.Logf("Setup complete, total time so far: %s", time.Since(startTime))

	// Test async put without --wait
	t.Run("AsyncPutWithoutWait", func(t *testing.T) {
		subtestStart := time.Now()
		t.Logf("AsyncPutWithoutWait subtest started")
		cmd := exec.Command(pelicanBin, "object", "put", "--async", uploadFile, uploadURL, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async put: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain job ID
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Check status with: pelican job status")
		t.Logf("AsyncPutWithoutWait subtest took %s", time.Since(subtestStart))
	})

	// Test async put with --wait
	t.Run("AsyncPutWithWait", func(t *testing.T) {
		subtestStart := time.Now()
		t.Logf("AsyncPutWithWait subtest started")
		uploadURL2 := fmt.Sprintf("pelican://%s%s/async-put-wait-test.txt", discoveryUrl.Host, federationPrefix)

		cmd := exec.Command(pelicanBin, "object", "put", "--async", "--wait", uploadFile, uploadURL2, "--token", tokenFile)
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to run async put with wait: %s", output)

		outputStr := string(output)
		t.Logf("Command output: %s", outputStr)

		// Should contain completion message
		assert.Contains(t, outputStr, "Job created:")
		assert.Contains(t, outputStr, "Waiting for job to complete")
		assert.Contains(t, outputStr, "Job completed successfully")
		t.Logf("AsyncPutWithWait subtest took %s", time.Since(subtestStart))
	})

	t.Logf("TestCLIAsyncPut complete, total time: %s", time.Since(startTime))
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
	err := param.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	require.NoError(t, err)
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
	serverConfig, _ := client_agent.CreateTestServerConfig(t)

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	server, err := client_agent.NewServer(ctx, serverConfig)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		log.Debug("Shutting down client API server at end of TestCLIJobCommands")
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
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	assert.NoError(t, err)
	uploadURL := fmt.Sprintf("pelican://%s%s/job-cmd-test.txt", discoveryUrl.Host, federationPrefix)

	// Create an async job
	t.Logf("Creating async job uploading to %s", uploadURL)
	cmd := exec.Command(pelicanBin, "object", "put", "--async", uploadFile, uploadURL, "--token", tokenFile)
	cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create job: %s", output)

	// Extract job ID
	re := regexp.MustCompile(`Job created: ([a-f0-9-]+)`)
	matches := re.FindStringSubmatch(string(output))
	require.Len(t, matches, 2, "Could not extract job ID from output")
	jobID := matches[1]
	log.Debugln("Created job ID:", jobID)

	// Test job status command
	t.Run("JobStatus", func(t *testing.T) {
		log.Debugln("Running job status for job ID:", jobID)
		cmd := exec.Command(pelicanBin, "job", "status", jobID, "--debug")
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err := cmd.CombinedOutput()
		log.Debug("Job status output:", string(output))
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
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "Failed to list jobs: %s", output)

		outputStr := string(output)
		t.Logf("Job list output:\n%s", outputStr)

		// Should contain our job ID
		assert.Contains(t, outputStr, jobID)
	})

	// Test job list with status filter
	t.Run("JobListWithFilter", func(t *testing.T) {
		// Wait for at least one job to complete
		require.Eventually(t, func() bool {
			cmd := exec.Command(pelicanBin, "job", "list", "--status", "completed")
			cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))
			output, err := cmd.CombinedOutput()
			if err != nil {
				return false
			}
			return len(output) > 0
		}, 10*time.Second, 200*time.Millisecond, "At least one job should complete")

		cmd := exec.Command(pelicanBin, "job", "list", "--status", "completed")
		cmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

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

		cancelURL := fmt.Sprintf("pelican://%s%s/cancel-test.txt", discoveryUrl.Host, federationPrefix)

		// Create async job
		createCmd := exec.Command(pelicanBin, "object", "put", "--async", largeFile, cancelURL, "--token", tokenFile)
		createCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err := createCmd.CombinedOutput()
		require.NoError(t, err, "Failed to create job for cancellation: %s", output)

		// Extract job ID
		matches := re.FindStringSubmatch(string(output))
		require.Len(t, matches, 2, "Could not extract job ID from output")
		cancelJobID := matches[1]

		// Wait for job to start
		require.Eventually(t, func() bool {
			statusCmd := exec.Command(pelicanBin, "job", "status", cancelJobID)
			statusCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))
			output, err := statusCmd.CombinedOutput()
			if err != nil {
				return false
			}
			return len(output) > 0
		}, 5*time.Second, 100*time.Millisecond, "Job should start")

		// Cancel the job
		cancelCmd := exec.Command(pelicanBin, "job", "cancel", cancelJobID)
		cancelCmd.Env = append(os.Environ(), fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", serverConfig.SocketPath))

		output, err = cancelCmd.CombinedOutput()
		outputStr := string(output)
		t.Logf("Cancel output: %s", outputStr)

		// Accept either successful cancellation or already completed
		// (race condition where job finishes before we can cancel)
		if err != nil {
			// If there's an error, it should be because job already completed
			assert.Contains(t, outputStr, "already completed",
				"Expected either successful cancellation or 'already completed' error")
		} else {
			// If successful, should contain "cancelled"
			assert.Contains(t, outputStr, "cancelled")
		}
	})
}

// TestCLIAsyncAutoSpawn tests that async commands auto-spawn the agent when not running
func TestCLIAsyncAutoSpawn(t *testing.T) {
	tempDir := t.TempDir()

	// Build pelican binary
	pelicanBin := buildPelicanBinary(t)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test data"), 0644)
	require.NoError(t, err)

	socketPath := filepath.Join(tempDir, "agent.sock")
	pidFile := filepath.Join(tempDir, "agent.pid")
	dbFile := filepath.Join(tempDir, "agent.db")
	logFile := filepath.Join(tempDir, "agent.log")

	// Create clean environment to prevent test interference
	cleanEnv := make([]string, 0, len(os.Environ()))
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "PELICAN_CLIENTAGENT_") &&
			!strings.HasPrefix(env, "PELICAN_LOGGING_") {
			cleanEnv = append(cleanEnv, env)
		}
	}

	// Set paths for the auto-spawned agent
	testEnv := append(cleanEnv,
		fmt.Sprintf("PELICAN_CLIENTAGENT_SOCKET=%s", socketPath),
		fmt.Sprintf("PELICAN_CLIENTAGENT_PIDFILE=%s", pidFile),
		fmt.Sprintf("PELICAN_CLIENTAGENT_DBLOCATION=%s", dbFile),
		fmt.Sprintf("PELICAN_LOGGING_LOGLOCATION=%s", logFile))

	// Cleanup function
	defer func() {
		stopCmd := exec.Command(pelicanBin, "client-agent", "stop", "--socket", socketPath, "--pid-file", pidFile)
		stopCmd.Env = testEnv
		_ = stopCmd.Run()
	}()

	// Run async command - should auto-spawn agent (will fail due to fake URL, but agent should start)
	cmd := exec.Command(pelicanBin, "object", "get", "--async",
		"pelican://nonexistent.example.com/test", filepath.Join(tempDir, "output"))
	cmd.Env = testEnv
	output, _ := cmd.CombinedOutput() // Ignore error - transfer will fail, but agent should spawn
	t.Logf("Command output: %s", string(output))

	// Verify the agent auto-spawned by checking if it's running
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Agent should have auto-spawned")

	// Verify PID file was created
	pid, err := client_agent.GetServerPID(pidFile)
	require.NoError(t, err, "Should be able to read PID file")
	require.Greater(t, pid, 0, "PID should be positive")

	t.Logf("Agent successfully auto-spawned with PID: %d", pid)
}
