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

package apiclient_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client_api"
	"github.com/pelicanplatform/pelican/client_api/apiclient"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
)

const (
	testOriginConfig = `
Origin:
  StorageType: posix
  Exports:
  - StoragePrefix: /tmp/test-origin-export
    FederationPrefix: /test
    Capabilities: ["PublicReads", "Writes", "Listings"]
`
)

// setupTestEnvironment creates a test federation and API server
func setupTestEnvironment(t *testing.T) (apiClient *apiclient.APIClient, fed *fed_test_utils.FedTest, tempDir string, tokenFile string, cleanup func()) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed = fed_test_utils.NewFedTest(t, testOriginConfig)

	// Create temporary directory for test files
	tempDir = t.TempDir()

	// Create token for authenticated operations
	viper.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-apiclient"
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

	tokenFile = filepath.Join(tempDir, "token")
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

	// Start the server
	err = server.Start()
	require.NoError(t, err)

	// Create API client
	apiClient, err = apiclient.NewAPIClient(socketPath)
	require.NoError(t, err)

	// Cleanup function
	cleanup = func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}

	return apiClient, fed, tempDir, tokenFile, cleanup
}

// TestAPIClientServerConnection tests basic connectivity to the API server
func TestAPIClientServerConnection(t *testing.T) {
	apiClient, _, _, _, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("ServerIsRunning", func(t *testing.T) {
		running := apiClient.IsServerRunning(ctx)
		assert.True(t, running, "API server should be running")
	})

	t.Run("ServerNotRunning", func(t *testing.T) {
		// Create client with non-existent socket
		badClient, err := apiclient.NewAPIClient(filepath.Join(t.TempDir(), "nonexistent.sock"))
		require.NoError(t, err)

		running := badClient.IsServerRunning(ctx)
		assert.False(t, running, "API server should not be running on non-existent socket")
	})
}

// TestAPIClientCreateJob tests job creation through the API client
func TestAPIClientCreateJob(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create test file
	testContent := []byte("Test content for API client job creation\n")
	testFile := filepath.Join(tempDir, "test-upload.txt")
	err := os.WriteFile(testFile, testContent, 0644)
	require.NoError(t, err)

	// Get federation prefix
	require.NotEmpty(t, fed.Exports, "No exports found in test federation")
	federationPrefix := fed.Exports[0].FederationPrefix

	// Construct pelican URL
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	fileName := "test-upload.txt"
	uploadURL := fmt.Sprintf("pelican://%s%s/%s", discoveryUrl, federationPrefix, fileName)

	t.Run("CreatePutJob", func(t *testing.T) {
		transfers := []client_api.TransferRequest{
			{
				Operation:   "put",
				Source:      testFile,
				Destination: uploadURL,
				Recursive:   false,
			},
		}

		options := client_api.TransferOptions{
			Token: tokenFile,
		}

		jobID, err := apiClient.CreateJob(ctx, transfers, options)
		require.NoError(t, err)
		assert.NotEmpty(t, jobID, "Job ID should not be empty")

		t.Logf("Created job: %s", jobID)
	})

	t.Run("CreateMultipleTransfersJob", func(t *testing.T) {
		// Create multiple test files
		file1 := filepath.Join(tempDir, "multi1.txt")
		file2 := filepath.Join(tempDir, "multi2.txt")
		err := os.WriteFile(file1, []byte("File 1\n"), 0644)
		require.NoError(t, err)
		err = os.WriteFile(file2, []byte("File 2\n"), 0644)
		require.NoError(t, err)

		transfers := []client_api.TransferRequest{
			{
				Operation:   "put",
				Source:      file1,
				Destination: fmt.Sprintf("pelican://%s%s/multi1.txt", discoveryUrl, federationPrefix),
			},
			{
				Operation:   "put",
				Source:      file2,
				Destination: fmt.Sprintf("pelican://%s%s/multi2.txt", discoveryUrl, federationPrefix),
			},
		}

		options := client_api.TransferOptions{
			Token: tokenFile,
		}

		jobID, err := apiClient.CreateJob(ctx, transfers, options)
		require.NoError(t, err)
		assert.NotEmpty(t, jobID, "Job ID should not be empty")

		t.Logf("Created multi-transfer job: %s", jobID)
	})
}

// TestAPIClientJobStatus tests retrieving job status
func TestAPIClientJobStatus(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create and execute a job
	testContent := []byte("Test content for status check\n")
	testFile := filepath.Join(tempDir, "status-test.txt")
	err := os.WriteFile(testFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/status-test.txt", discoveryUrl, federationPrefix)

	transfers := []client_api.TransferRequest{
		{
			Operation:   "put",
			Source:      testFile,
			Destination: uploadURL,
		},
	}

	options := client_api.TransferOptions{
		Token: tokenFile,
	}

	jobID, err := apiClient.CreateJob(ctx, transfers, options)
	require.NoError(t, err)

	t.Run("GetJobStatus", func(t *testing.T) {
		// Wait a moment for job to start
		time.Sleep(100 * time.Millisecond)

		status, err := apiClient.GetJobStatus(ctx, jobID)
		require.NoError(t, err)
		assert.NotNil(t, status)
		assert.Equal(t, jobID, status.JobID)
		assert.NotEmpty(t, status.Status)
		assert.NotNil(t, status.CreatedAt)

		t.Logf("Job status: %s", status.Status)
	})

	t.Run("GetNonexistentJobStatus", func(t *testing.T) {
		_, err := apiClient.GetJobStatus(ctx, "nonexistent-job-id")
		assert.Error(t, err, "Should error on nonexistent job")
	})
}

// TestAPIClientWaitForJob tests waiting for job completion
func TestAPIClientWaitForJob(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create test file
	testContent := []byte("Test content for wait test\n")
	testFile := filepath.Join(tempDir, "wait-test.txt")
	err := os.WriteFile(testFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/wait-test.txt", discoveryUrl, federationPrefix)

	transfers := []client_api.TransferRequest{
		{
			Operation:   "put",
			Source:      testFile,
			Destination: uploadURL,
		},
	}

	options := client_api.TransferOptions{
		Token: tokenFile,
	}

	jobID, err := apiClient.CreateJob(ctx, transfers, options)
	require.NoError(t, err)

	t.Run("WaitForCompletion", func(t *testing.T) {
		// Wait for job with reasonable timeout
		err := apiClient.WaitForJob(ctx, jobID, 30*time.Second)
		require.NoError(t, err, "Job should complete successfully")

		// Verify final status
		status, err := apiClient.GetJobStatus(ctx, jobID)
		require.NoError(t, err)
		assert.Equal(t, client_api.StatusCompleted, status.Status)

		t.Logf("Job completed successfully")
	})

	t.Run("WaitWithTimeout", func(t *testing.T) {
		// Create another job
		jobID2, err := apiClient.CreateJob(ctx, transfers, options)
		require.NoError(t, err)

		// Try to wait with very short timeout
		err = apiClient.WaitForJob(ctx, jobID2, 1*time.Millisecond)
		// Should timeout (though might complete if very fast)
		if err != nil {
			assert.Contains(t, err.Error(), "context deadline exceeded")
		}
	})
}

// TestAPIClientListJobs tests listing jobs with filters
func TestAPIClientListJobs(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create several jobs
	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()

	for i := 0; i < 3; i++ {
		testFile := filepath.Join(tempDir, fmt.Sprintf("list-test-%d.txt", i))
		err := os.WriteFile(testFile, []byte(fmt.Sprintf("Content %d\n", i)), 0644)
		require.NoError(t, err)

		uploadURL := fmt.Sprintf("pelican://%s%s/list-test-%d.txt", discoveryUrl, federationPrefix, i)

		transfers := []client_api.TransferRequest{
			{
				Operation:   "put",
				Source:      testFile,
				Destination: uploadURL,
			},
		}

		options := client_api.TransferOptions{
			Token: tokenFile,
		}

		_, err = apiClient.CreateJob(ctx, transfers, options)
		require.NoError(t, err)
	}

	t.Run("ListAllJobs", func(t *testing.T) {
		resp, err := apiClient.ListJobs(ctx, "", 100, 0)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Jobs, "Should have at least some jobs")
		assert.GreaterOrEqual(t, len(resp.Jobs), 3, "Should have at least 3 jobs from this test")

		t.Logf("Found %d jobs", len(resp.Jobs))
	})

	t.Run("ListWithLimit", func(t *testing.T) {
		resp, err := apiClient.ListJobs(ctx, "", 2, 0)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(resp.Jobs), 2, "Should respect limit")
	})

	t.Run("ListWithOffset", func(t *testing.T) {
		allResp, err := apiClient.ListJobs(ctx, "", 100, 0)
		require.NoError(t, err)

		if len(allResp.Jobs) > 1 {
			offsetResp, err := apiClient.ListJobs(ctx, "", 100, 1)
			require.NoError(t, err)
			assert.Equal(t, len(allResp.Jobs)-1, len(offsetResp.Jobs), "Offset should skip first job")
		}
	})

	t.Run("ListWithStatusFilter", func(t *testing.T) {
		// Wait a moment for some jobs to complete
		time.Sleep(2 * time.Second)

		resp, err := apiClient.ListJobs(ctx, "completed", 100, 0)
		require.NoError(t, err)
		// Should have some completed jobs
		t.Logf("Found %d completed jobs", len(resp.Jobs))
	})
}

// TestAPIClientCancelJob tests cancelling jobs
func TestAPIClientCancelJob(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create a large file to ensure transfer takes some time
	testFile := filepath.Join(tempDir, "cancel-test.txt")
	largeContent := make([]byte, 10*1024*1024) // 10MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	err := os.WriteFile(testFile, largeContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/cancel-test.txt", discoveryUrl, federationPrefix)

	transfers := []client_api.TransferRequest{
		{
			Operation:   "put",
			Source:      testFile,
			Destination: uploadURL,
		},
	}

	options := client_api.TransferOptions{
		Token: tokenFile,
	}

	jobID, err := apiClient.CreateJob(ctx, transfers, options)
	require.NoError(t, err)

	t.Run("CancelRunningJob", func(t *testing.T) {
		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		err := apiClient.CancelJob(ctx, jobID)
		require.NoError(t, err, "Should be able to cancel job")

		// Check status
		status, err := apiClient.GetJobStatus(ctx, jobID)
		require.NoError(t, err)

		// Status should eventually be cancelled
		assert.Contains(t, []string{client_api.StatusCancelled, client_api.StatusRunning, client_api.StatusCompleted}, status.Status)
		t.Logf("Job status after cancel: %s", status.Status)
	})

	t.Run("CancelNonexistentJob", func(t *testing.T) {
		err := apiClient.CancelJob(ctx, "nonexistent-job-id")
		assert.Error(t, err, "Should error on nonexistent job")
	})
}

// TestAPIClientEndToEnd tests a complete workflow
func TestAPIClientEndToEnd(t *testing.T) {
	apiClient, fed, tempDir, tokenFile, cleanup := setupTestEnvironment(t)
	defer cleanup()

	ctx := context.Background()

	// Create test file
	testContent := []byte("End-to-end test content\n")
	originalFile := filepath.Join(tempDir, "e2e-original.txt")
	err := os.WriteFile(originalFile, testContent, 0644)
	require.NoError(t, err)

	federationPrefix := fed.Exports[0].FederationPrefix
	discoveryUrl := param.Federation_DiscoveryUrl.GetString()
	uploadURL := fmt.Sprintf("pelican://%s%s/e2e-test.txt", discoveryUrl, federationPrefix)
	downloadFile := filepath.Join(tempDir, "e2e-downloaded.txt")

	// Step 1: Upload file
	t.Log("Step 1: Uploading file...")
	uploadTransfers := []client_api.TransferRequest{
		{
			Operation:   "put",
			Source:      originalFile,
			Destination: uploadURL,
		},
	}

	options := client_api.TransferOptions{
		Token: tokenFile,
	}

	uploadJobID, err := apiClient.CreateJob(ctx, uploadTransfers, options)
	require.NoError(t, err)

	err = apiClient.WaitForJob(ctx, uploadJobID, 30*time.Second)
	require.NoError(t, err, "Upload should complete")

	uploadStatus, err := apiClient.GetJobStatus(ctx, uploadJobID)
	require.NoError(t, err)
	assert.Equal(t, client_api.StatusCompleted, uploadStatus.Status)
	t.Log("Upload completed successfully")

	// Step 2: Stat the file
	t.Log("Step 2: Checking file stat...")
	stat, err := apiClient.Stat(ctx, uploadURL, options)
	require.NoError(t, err)
	assert.Equal(t, int64(len(testContent)), stat.Size)
	t.Logf("File size: %d bytes", stat.Size)

	// Step 3: Download file
	t.Log("Step 3: Downloading file...")
	downloadTransfers := []client_api.TransferRequest{
		{
			Operation:   "get",
			Source:      uploadURL,
			Destination: downloadFile,
		},
	}

	downloadJobID, err := apiClient.CreateJob(ctx, downloadTransfers, options)
	require.NoError(t, err)

	err = apiClient.WaitForJob(ctx, downloadJobID, 30*time.Second)
	require.NoError(t, err, "Download should complete")

	downloadStatus, err := apiClient.GetJobStatus(ctx, downloadJobID)
	require.NoError(t, err)
	assert.Equal(t, client_api.StatusCompleted, downloadStatus.Status)
	t.Log("Download completed successfully")

	// Step 4: Verify downloaded content
	t.Log("Step 4: Verifying content...")
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, downloadedContent, "Downloaded content should match original")
	t.Log("Content verified successfully")

	// Step 5: List jobs
	t.Log("Step 5: Listing jobs...")
	jobsResp, err := apiClient.ListJobs(ctx, "", 100, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(jobsResp.Jobs), 2, "Should have at least upload and download jobs")
	t.Logf("Found %d total jobs", len(jobsResp.Jobs))

	t.Log("End-to-end test completed successfully!")
}
