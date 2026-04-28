//go:build !windows

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/client_agent"
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

// integrationEnv holds shared state for the integration test subtests.
// Each ensure* method is idempotent and chains to its prerequisites,
// allowing individual subtests to be run via `go test -run`.
type integrationEnv struct {
	httpClient   *http.Client
	baseURL      string
	testContent  []byte
	originalFile string
	originalHash string
	tempDir      string
	tokenFile    string
	uploadURL    string
	copyDestURL  string

	uploaded    bool
	uploadResp  client_agent.JobResponse
	uploadJobID string

	downloaded     bool
	downloadResp   client_agent.JobResponse
	downloadJobID  string
	downloadedFile string

	copied    bool
	copyResp  client_agent.JobResponse
	copyJobID string
}

// submitJob creates a transfer job and returns the initial response.
func (e *integrationEnv) submitJob(t *testing.T, req client_agent.JobRequest) client_agent.JobResponse {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := e.httpClient.Post(e.baseURL+"/jobs", "application/json", bytes.NewBuffer(body))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var jobResp client_agent.JobResponse
	err = json.NewDecoder(resp.Body).Decode(&jobResp)
	require.NoError(t, err)
	require.NotEmpty(t, jobResp.JobID)

	return jobResp
}

// waitForJob polls until the given job reaches a terminal state, then asserts it completed.
func (e *integrationEnv) waitForJob(t *testing.T, jobID string) {
	t.Helper()
	var lastStatus, lastError string
	require.Eventually(t, func() bool {
		resp, err := e.httpClient.Get(fmt.Sprintf("%s/jobs/%s", e.baseURL, jobID))
		if err != nil {
			return false
		}
		var status client_agent.JobStatus
		err = json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()
		if err != nil {
			return false
		}
		lastStatus = status.Status
		lastError = status.Error
		return status.Status == "completed" || status.Status == "failed"
	}, 30*time.Second, 500*time.Millisecond, "Job %s did not reach terminal state", jobID)
	require.NotEqual(t, "failed", lastStatus, "Job %s failed: %s", jobID, lastError)
}

// ensureUploaded creates and waits for the upload job exactly once.
func (e *integrationEnv) ensureUploaded(t *testing.T) {
	t.Helper()
	if e.uploaded {
		return
	}
	e.uploadResp = e.submitJob(t, client_agent.JobRequest{
		Transfers: []client_agent.TransferRequest{
			{
				Operation:   "put",
				Source:      e.originalFile,
				Destination: e.uploadURL,
			},
		},
		Options: client_agent.TransferOptions{
			Token: e.tokenFile,
		},
	})
	e.uploadJobID = e.uploadResp.JobID
	t.Logf("Created upload job: %s", e.uploadJobID)
	e.waitForJob(t, e.uploadJobID)
	e.uploaded = true
}

// ensureDownloaded creates and waits for the download job exactly once, ensuring the upload
// prerequisite has completed first.
func (e *integrationEnv) ensureDownloaded(t *testing.T) {
	t.Helper()
	e.ensureUploaded(t)
	if e.downloaded {
		return
	}
	e.downloadedFile = filepath.Join(e.tempDir, "downloaded.txt")
	e.downloadResp = e.submitJob(t, client_agent.JobRequest{
		Transfers: []client_agent.TransferRequest{
			{
				Operation:   "get",
				Source:      e.uploadURL,
				Destination: e.downloadedFile,
			},
		},
		Options: client_agent.TransferOptions{
			Token: e.tokenFile,
		},
	})
	e.downloadJobID = e.downloadResp.JobID
	t.Logf("Created download job: %s", e.downloadJobID)
	e.waitForJob(t, e.downloadJobID)
	e.downloaded = true
}

// ensureCopied creates and waits for the third-party copy job exactly once, ensuring the
// upload prerequisite has completed first.
func (e *integrationEnv) ensureCopied(t *testing.T) {
	t.Helper()
	e.ensureUploaded(t)
	if e.copied {
		return
	}
	e.copyResp = e.submitJob(t, client_agent.JobRequest{
		Transfers: []client_agent.TransferRequest{
			{
				Operation:   "copy",
				Source:      e.uploadURL,
				Destination: e.copyDestURL,
			},
		},
		Options: client_agent.TransferOptions{
			Token: e.tokenFile,
		},
	})
	e.copyJobID = e.copyResp.JobID
	t.Logf("Created copy job: %s", e.copyJobID)
	e.waitForJob(t, e.copyJobID)
	e.copied = true
}

// TestClientAPIIntegration performs end-to-end testing of the client API server.
// Subtests can be run individually via `go test -run TestClientAPIIntegration/<SubtestName>`;
// each subtest calls its prerequisite ensure* methods to set up the required server-side state.
func TestClientAPIIntegration(t *testing.T) {
	// Reset test state
	server_utils.ResetTestState()

	// Create test federation
	fed := fed_test_utils.NewFedTest(t, testOriginConfig)

	// Get discovery URL
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	// Create temporary directory for test files with socket path length checks
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
	err = param.IssuerKeysDirectory.Set(t.TempDir())
	require.NoError(t, err)
	issuer, err := config.GetServerIssuerURL()
	require.NoError(t, err)

	tokenConfig := token.NewWLCGToken()
	tokenConfig.Lifetime = time.Minute * 5
	tokenConfig.Issuer = issuer
	tokenConfig.Subject = "test-client-agent"
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

	// Create context with errgroup
	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	server, err := client_agent.NewServer(ctx, serverConfig)
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
	httpClient := createUnixHTTPClient(serverConfig.SocketPath)

	// Base URL for API requests (hostname doesn't matter for Unix sockets)
	baseURL := "http://localhost/api/v1.0/transfer-agent"

	// Get the federation prefix
	require.NotEmpty(t, fed.Exports, "No exports found in test federation")
	federationPrefix := fed.Exports[0].FederationPrefix

	// Construct the pelican URL for upload
	fileName := "test-upload.txt"
	uploadURL := fmt.Sprintf("pelican://%s%s/%s", discoveryUrl.Host, federationPrefix, fileName)

	env := &integrationEnv{
		httpClient:   httpClient,
		baseURL:      baseURL,
		testContent:  testContent,
		originalFile: originalFile,
		originalHash: originalHash,
		tempDir:      tempDir,
		tokenFile:    tokenFile,
		uploadURL:    uploadURL,
		copyDestURL:  fmt.Sprintf("pelican://%s%s/%s", discoveryUrl.Host, federationPrefix, "test-copy-dest.txt"),
	}

	t.Run("HealthCheck", func(t *testing.T) {
		resp, err := httpClient.Get("http://localhost/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var health client_agent.HealthResponse
		err = json.NewDecoder(resp.Body).Decode(&health)
		require.NoError(t, err)

		assert.Equal(t, "ok", health.Status)
		assert.NotEmpty(t, health.Version)
	})

	t.Run("Upload", func(t *testing.T) {
		env.ensureUploaded(t)
		assert.Len(t, env.uploadResp.Transfers, 1)
	})

	t.Run("StatUploadedFile", func(t *testing.T) {
		env.ensureUploaded(t)

		statReq := client_agent.StatRequest{
			URL: uploadURL,
			Options: client_agent.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(statReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/stat", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var statResp client_agent.StatResponse
		err = json.NewDecoder(resp.Body).Decode(&statResp)
		require.NoError(t, err)

		// Note: DoStat returns full path in Name, not just basename
		assert.Contains(t, statResp.Name, fileName, "Name should contain the file name")
		assert.Equal(t, int64(len(testContent)), statResp.Size)
		assert.False(t, statResp.IsCollection)

		t.Logf("Stat result - Name: %s, Size: %d bytes", statResp.Name, statResp.Size)
	})

	t.Run("Download", func(t *testing.T) {
		env.ensureDownloaded(t)
		assert.Len(t, env.downloadResp.Transfers, 1)
	})

	t.Run("VerifyDownloadedFile", func(t *testing.T) {
		env.ensureDownloaded(t)

		// Check if file exists
		_, err := os.Stat(env.downloadedFile)
		require.NoError(t, err, "Downloaded file does not exist")

		// Read downloaded content
		downloadedContent, err := os.ReadFile(env.downloadedFile)
		require.NoError(t, err)

		// Compare content
		assert.Equal(t, testContent, downloadedContent, "Downloaded content does not match original")

		// Compare hashes
		downloadedHash, err := computeFileSHA256(env.downloadedFile)
		require.NoError(t, err)

		assert.Equal(t, originalHash, downloadedHash, "SHA256 hash mismatch between original and downloaded file")

		t.Logf("File verification successful - Original hash: %s, Downloaded hash: %s", originalHash, downloadedHash)
	})

	t.Run("Copy", func(t *testing.T) {
		env.ensureCopied(t)
		assert.Len(t, env.copyResp.Transfers, 1)
		assert.Equal(t, "copy", env.copyResp.Transfers[0].Operation)
	})

	// Download the copied file and verify content matches the original
	t.Run("VerifyCopiedFile", func(t *testing.T) {
		env.ensureCopied(t)

		copiedFile := filepath.Join(tempDir, "copied.txt")
		dlResp := env.submitJob(t, client_agent.JobRequest{
			Transfers: []client_agent.TransferRequest{
				{
					Operation:   "get",
					Source:      env.copyDestURL,
					Destination: copiedFile,
				},
			},
			Options: client_agent.TransferOptions{
				Token: tokenFile,
			},
		})
		env.waitForJob(t, dlResp.JobID)

		copiedContent, err := os.ReadFile(copiedFile)
		require.NoError(t, err)
		assert.Equal(t, testContent, copiedContent, "Copied file content does not match original")

		copiedHash, err := computeFileSHA256(copiedFile)
		require.NoError(t, err)
		assert.Equal(t, originalHash, copiedHash, "SHA256 hash mismatch between original and copied file")
		t.Logf("Copy verification successful — hash: %s", copiedHash)
	})

	t.Run("ListJobs", func(t *testing.T) {
		env.ensureUploaded(t)
		env.ensureDownloaded(t)
		env.ensureCopied(t)

		resp, err := httpClient.Get(baseURL + "/jobs?limit=10")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp client_agent.JobListResponse
		err = json.NewDecoder(resp.Body).Decode(&listResp)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, listResp.Total, 3, "Expected at least 3 jobs (upload, download, copy)")
		assert.NotEmpty(t, listResp.Jobs)

		t.Logf("Found %d total jobs", listResp.Total)
	})

	// Test job cancellation
	t.Run("CancelJob", func(t *testing.T) {
		env.ensureUploaded(t)

		// Create a job to cancel
		jobReq := client_agent.JobRequest{
			Transfers: []client_agent.TransferRequest{
				{
					Operation:   "get",
					Source:      uploadURL,
					Destination: filepath.Join(tempDir, "cancel-test.txt"),
				},
			},
			Options: client_agent.TransferOptions{
				Token: tokenFile,
			},
		}

		body, err := json.Marshal(jobReq)
		require.NoError(t, err)

		resp, err := httpClient.Post(baseURL+"/jobs", "application/json", bytes.NewBuffer(body))
		require.NoError(t, err)

		var jobResp client_agent.JobResponse
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
			var cancelResp client_agent.CancelResponse
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

	// Set up client API server - use short socket name
	serverConfig, _ := client_agent.CreateTestServerConfig(t)

	egrp, egrpCtx := errgroup.WithContext(context.Background())
	ctx := context.WithValue(egrpCtx, config.EgrpKey, egrp)

	server, err := client_agent.NewServer(ctx, serverConfig)
	require.NoError(t, err)

	// Start the server
	err = server.Start()
	require.NoError(t, err)

	// Create HTTP client for Unix socket
	httpClient := createUnixHTTPClient(serverConfig.SocketPath)

	// Test 1: Verify server is running with health check
	t.Run("ServerIsRunning", func(t *testing.T) {
		resp, err := httpClient.Get("http://localhost/health")
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var health client_agent.HealthResponse
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
		// Wait for server to shut down
		require.Eventually(t, func() bool {
			resp, err := httpClient.Get("http://localhost/health")
			if resp != nil {
				resp.Body.Close()
			}
			return err != nil
		}, 5*time.Second, 200*time.Millisecond, "Server should shut down")

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
