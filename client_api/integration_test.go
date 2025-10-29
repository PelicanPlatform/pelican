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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// createUnixHTTPClient creates an HTTP client that communicates over a Unix socket
func createUnixHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// computeFileSHA256 computes the SHA256 hash of a file
func computeFileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// TestClientAPIIntegration performs end-to-end testing of the client API server
func TestClientAPIIntegration(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)

	// Get discovery URL
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create test file with unique content
	testContent := []byte("This is a test file for client API integration testing!\n")
	testContent = append(testContent, []byte(fmt.Sprintf("Created at: %s\n", time.Now().Format(time.RFC3339)))...)

	originalFile := filepath.Join(tempDir, "original.txt")
	err = os.WriteFile(originalFile, testContent, 0644)
	require.NoError(t, err)

	// Compute hash of original file
	originalHash, err := computeFileSHA256(originalFile)
	require.NoError(t, err)

	// Create token for authenticated operations
	viper.Set(param.IssuerKeysDirectory.GetName(), t.TempDir())
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-client-api"
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

	// Start the server
	err = server.Start()
	require.NoError(t, err)

	// Ensure cleanup
	t.Cleanup(func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	})

	// Create HTTP client for Unix socket
	httpClient := createUnixHTTPClient(socketPath)

	// Base URL for API requests (hostname doesn't matter for Unix sockets)
	baseURL := "http://localhost/api/v1/xfer"

	// Test 1: Health check
	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := httpClient.Get("http://localhost/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var health client_api.HealthResponse
		err = json.NewDecoder(resp.Body).Decode(&health)
		require.NoError(t, err)

		assert.Equal(t, "ok", health.Status)
		assert.NotEmpty(t, health.Version)
	})

	// Get the federation prefix
	require.NotEmpty(t, fed.Exports, "No exports found in test federation")
	federationPrefix := fed.Exports[0].FederationPrefix

	// Construct the pelican URL for upload
	fileName := "test-upload.txt"
	uploadURL := fmt.Sprintf("pelican://%s%s/%s", discoveryUrl.Host, federationPrefix, fileName)
	downloadedFile := filepath.Join(tempDir, "downloaded.txt")

	var jobID string

	// Test 2: Create a job to upload the file
	t.Run("CreateUploadJob", func(t *testing.T) {
		jobReq := client_api.JobRequest{
			Transfers: []client_api.TransferRequest{
				{
					Operation:   "put",
					Source:      originalFile,
					Destination: uploadURL,
					Recursive:   false,
				},
			},
			Options: client_api.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(jobReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/jobs", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var jobResp client_api.JobResponse
		err = json.NewDecoder(resp.Body).Decode(&jobResp)
		require.NoError(t, err)

		assert.NotEmpty(t, jobResp.JobID)
		assert.Equal(t, "pending", jobResp.Status)
		assert.Len(t, jobResp.Transfers, 1)

		jobID = jobResp.JobID
		t.Logf("Created upload job: %s", jobID)
	})

	// Test 3: Poll job status until completion
	t.Run("WaitForUploadCompletion", func(t *testing.T) {
		require.NotEmpty(t, jobID, "Job ID not set from previous test")

		// Poll for up to 30 seconds
		timeout := time.After(30 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				t.Fatal("Upload job did not complete within timeout")
			case <-ticker.C:
				resp, err := httpClient.Get(fmt.Sprintf("%s/jobs/%s", baseURL, jobID))
				require.NoError(t, err)

				var status client_api.JobStatus
				err = json.NewDecoder(resp.Body).Decode(&status)
				resp.Body.Close()
				require.NoError(t, err)

				t.Logf("Job status: %s, Progress: %.1f%%", status.Status, status.Progress.Percentage)

				if status.Status == "completed" {
					assert.Equal(t, 1, status.Progress.TransfersCompleted)
					assert.Equal(t, 0, status.Progress.TransfersFailed)
					return
				} else if status.Status == "failed" {
					t.Fatalf("Upload job failed: %s", status.Error)
				}
			}
		}
	})

	// Test 4: Stat the uploaded file
	t.Run("StatUploadedFile", func(t *testing.T) {
		statReq := client_api.StatRequest{
			URL: uploadURL,
			Options: client_api.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(statReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/stat", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var statResp client_api.StatResponse
		err = json.NewDecoder(resp.Body).Decode(&statResp)
		require.NoError(t, err)

		// Note: DoStat returns full path in Name, not just basename
		assert.Contains(t, statResp.Name, fileName, "Name should contain the file name")
		assert.Equal(t, int64(len(testContent)), statResp.Size)
		assert.False(t, statResp.IsCollection)

		t.Logf("Stat result - Name: %s, Size: %d bytes", statResp.Name, statResp.Size)
	})

	// Test 5: Create a job to download the file
	t.Run("CreateDownloadJob", func(t *testing.T) {
		jobReq := client_api.JobRequest{
			Transfers: []client_api.TransferRequest{
				{
					Operation:   "get",
					Source:      uploadURL,
					Destination: downloadedFile,
					Recursive:   false,
				},
			},
			Options: client_api.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(jobReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/jobs", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var jobResp client_api.JobResponse
		err = json.NewDecoder(resp.Body).Decode(&jobResp)
		require.NoError(t, err)

		jobID = jobResp.JobID
		t.Logf("Created download job: %s", jobID)
	})

	// Test 6: Wait for download to complete
	t.Run("WaitForDownloadCompletion", func(t *testing.T) {
		require.NotEmpty(t, jobID, "Job ID not set from previous test")

		timeout := time.After(30 * time.Second)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-timeout:
				t.Fatal("Download job did not complete within timeout")
			case <-ticker.C:
				resp, err := httpClient.Get(fmt.Sprintf("%s/jobs/%s", baseURL, jobID))
				require.NoError(t, err)

				var status client_api.JobStatus
				err = json.NewDecoder(resp.Body).Decode(&status)
				resp.Body.Close()
				require.NoError(t, err)

				t.Logf("Job status: %s, Progress: %.1f%%", status.Status, status.Progress.Percentage)

				if status.Status == "completed" {
					assert.Equal(t, 1, status.Progress.TransfersCompleted)
					assert.Equal(t, 0, status.Progress.TransfersFailed)
					return
				} else if status.Status == "failed" {
					t.Fatalf("Download job failed: %s", status.Error)
				}
			}
		}
	})

	// Test 7: Verify downloaded file matches original
	t.Run("VerifyDownloadedFile", func(t *testing.T) {
		// Check if file exists
		_, err := os.Stat(downloadedFile)
		require.NoError(t, err, "Downloaded file does not exist")

		// Read downloaded content
		downloadedContent, err := os.ReadFile(downloadedFile)
		require.NoError(t, err)

		// Compare content
		assert.Equal(t, testContent, downloadedContent, "Downloaded content does not match original")

		// Compare hashes
		downloadedHash, err := computeFileSHA256(downloadedFile)
		require.NoError(t, err)

		assert.Equal(t, originalHash, downloadedHash, "SHA256 hash mismatch between original and downloaded file")

		t.Logf("File verification successful - Original hash: %s, Downloaded hash: %s", originalHash, downloadedHash)
	})

	// Test 8: List jobs
	t.Run("ListJobs", func(t *testing.T) {
		resp, err := httpClient.Get(baseURL + "/jobs?limit=10")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp client_api.JobListResponse
		err = json.NewDecoder(resp.Body).Decode(&listResp)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, listResp.Total, 2, "Expected at least 2 jobs (upload and download)")
		assert.NotEmpty(t, listResp.Jobs)

		t.Logf("Found %d total jobs", listResp.Total)
	})

	// Test 9: Test job cancellation
	t.Run("CancelJob", func(t *testing.T) {
		// Create a job to cancel
		jobReq := client_api.JobRequest{
			Transfers: []client_api.TransferRequest{
				{
					Operation:   "get",
					Source:      uploadURL,
					Destination: filepath.Join(tempDir, "cancel-test.txt"),
					Recursive:   false,
				},
			},
			Options: client_api.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(jobReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/jobs", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)

		var jobResp client_api.JobResponse
		err = json.NewDecoder(resp.Body).Decode(&jobResp)
		resp.Body.Close()
		require.NoError(t, err)

		cancelJobID := jobResp.JobID

		// Immediately try to cancel it
		req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/jobs/%s", baseURL, cancelJobID), nil)
		require.NoError(t, err)

		resp, err = httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Should be OK or Conflict (if already completed)
		assert.Contains(t, []int{http.StatusOK, http.StatusConflict}, resp.StatusCode)

		if resp.StatusCode == http.StatusOK {
			var cancelResp client_api.CancelResponse
			err = json.NewDecoder(resp.Body).Decode(&cancelResp)
			require.NoError(t, err)

			assert.Equal(t, cancelJobID, cancelResp.JobID)
			t.Logf("Cancelled job: %s, Transfers cancelled: %d, Transfers completed: %d",
				cancelResp.JobID, cancelResp.TransfersCancelled, cancelResp.TransfersCompleted)
		}
	})
}

// TestClientAPIShutdown tests the shutdown API endpoint
func TestClientAPIShutdown(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)
	_ = fed // Keep the federation running for the test

	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Set up client API server - use short socket name
	socketPath := filepath.Join(tempDir, "api.sock")
	pidFile := filepath.Join(tempDir, "api.pid")

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

	// Create HTTP client for Unix socket
	httpClient := createUnixHTTPClient(socketPath)

	// Test 1: Verify server is running with health check
	t.Run("ServerIsRunning", func(t *testing.T) {
		resp, err := httpClient.Get("http://localhost/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var health client_api.HealthResponse
		err = json.NewDecoder(resp.Body).Decode(&health)
		require.NoError(t, err)

		assert.Equal(t, "ok", health.Status)
	})

	// Test 2: Call shutdown API
	t.Run("ShutdownAPI", func(t *testing.T) {
		resp, err := httpClient.Post("http://localhost/shutdown", "application/json", nil)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var shutdownResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&shutdownResp)
		require.NoError(t, err)

		assert.Equal(t, "Server shutdown initiated", shutdownResp["message"])
		t.Log("Shutdown API called successfully")
	})

	// Test 3: Wait for server to shut down and verify it's no longer accessible
	t.Run("VerifyServerShutdown", func(t *testing.T) {
		// Wait a bit for shutdown to complete
		time.Sleep(1 * time.Second)

		// Try to connect - should fail
		resp, err := httpClient.Get("http://localhost/health")
		if err == nil {
			resp.Body.Close()
			t.Error("Expected connection error after shutdown, but got successful response")
		} else {
			t.Logf("Server successfully shut down - connection error: %v", err)
		}
	})
}
