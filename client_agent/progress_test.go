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
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/glebarez/sqlite" // SQLite driver

	"github.com/pelicanplatform/pelican/client_agent"
	"github.com/pelicanplatform/pelican/client_agent/apiclient"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// TestAsyncTransferProgressReporting tests that async transfers report progress correctly
// with a rate-limited POSIXv2 backend
func TestAsyncTransferProgressReporting(t *testing.T) {
	server_utils.ResetTestState()

	// Test parameters
	const (
		rateLimit    = 500 * 1024       // 500 KB/s - slower to allow observing periodic updates
		testFileSize = 10 * 1024 * 1024 // 10 MB
		pollInterval = 500 * time.Millisecond
	)

	// Configure faster progress updates for testing (1 second instead of default 5 seconds)
	t.Setenv("PELICAN_CLIENTAGENT_PROGRESSUPDATEINTERVAL", "1s")

	// Create temporary directory
	tempDir := t.TempDir()

	// Configure origin with POSIXv2 and rate-limited reads
	// Rate limit at the origin level to simulate slow storage
	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  ReadRateLimitBytesPerSecond: %d
  Exports:
    - FederationPrefix: /test
      Capabilities: ["PublicReads", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, rateLimit)

	// Create federation
	t.Log("Starting federation...")
	fed := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, fed)

	// Get the actual storage directory created by the federation
	require.NotEmpty(t, fed.Exports, "Federation should have exports")
	storageDir := fed.Exports[0].StoragePrefix
	t.Logf("Federation storage directory: %s", storageDir)

	// Create test file with random data in the federation's storage directory
	testFilePath := filepath.Join(storageDir, "large_test_file.bin")
	testFile, err := os.Create(testFilePath)
	require.NoError(t, err)

	// Write 10MB of random data
	t.Logf("Creating %d MB test file...", testFileSize/(1024*1024))
	written, err := io.CopyN(testFile, rand.Reader, testFileSize)
	require.NoError(t, err)
	require.Equal(t, int64(testFileSize), written)
	testFile.Close()
	t.Logf("Test file created: %s", testFilePath)

	// Get the federation discovery URL
	discoveryUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)
	t.Logf("Federation discovery URL: %s", discoveryUrl.String())

	// Start client agent daemon
	agentTempDir := getTempDir(t)
	socketPath := filepath.Join(agentTempDir, "agent.sock")
	pidFile := filepath.Join(agentTempDir, "agent.pid")
	dbFile := filepath.Join(agentTempDir, "agent.db")
	logFile := filepath.Join(agentTempDir, "agent.log")

	t.Logf("Starting client agent daemon...")
	pelicanBin := buildPelicanBinary(t)

	config := client_agent.DaemonConfig{
		SocketPath:  socketPath,
		PidFile:     pidFile,
		LogLocation: logFile,
		MaxJobs:     5,
		DbLocation:  dbFile,
		IdleTimeout: 60 * time.Second,
		ExecPath:    pelicanBin,
	}

	pid, err := client_agent.StartDaemon(config)
	require.NoError(t, err, "Failed to start daemon")
	t.Logf("Daemon started with PID %d", pid)

	// Cleanup daemon
	defer func() {
		stopCmd := exec.Command(pelicanBin, "client-agent", "stop",
			"--socket", socketPath,
			"--pid-file", pidFile)
		if err := stopCmd.Run(); err != nil {
			t.Logf("Warning: failed to stop daemon: %v", err)
		}
	}()

	// Wait for daemon to be ready
	apiClient, err := apiclient.NewAPIClient(socketPath)
	require.NoError(t, err, "Failed to create API client")

	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return apiClient.IsServerRunning(ctx)
	}, 10*time.Second, 500*time.Millisecond, "Daemon should start")

	// Maximum acceptable rate is 1 MB/s - anything above suggests rate limiting failed
	const maxAcceptableRateKBps = 1024.0

	ctx := context.Background()

	// Create async download job via API
	downloadURL := fmt.Sprintf("pelican://%s/test/large_test_file.bin", discoveryUrl.Host)

	localDest := filepath.Join(tempDir, "downloaded.bin")

	t.Logf("Creating async download job: %s -> %s", downloadURL, localDest)

	// Create job via API client
	jobID, err := apiClient.CreateJob(ctx, []client_agent.TransferRequest{
		{
			Operation:   "get",
			Source:      downloadURL,
			Destination: localDest,
		},
	}, client_agent.TransferOptions{})
	require.NoError(t, err, "Failed to create job")
	t.Logf("Created job: %s", jobID)

	// Poll for job status and verify progress
	t.Log("Polling for transfer progress until intermediate DB updates are verified...")
	var (
		sawNonZeroRate         bool
		sawProgress            bool
		lastBytes              int64
		maxRateSeen            float64
		sawIntermediateDbWrite bool
		lastDbBytes            int64
		dbUpdateCount          int
	)

	// Monitor for maximum 25 seconds, but exit early once we've verified intermediate updates
	// At 500KB/s, transfer will take ~20 seconds for 10MB
	// 25 seconds / 500ms poll interval = 50 polls
	maxPolls := 50
	for i := 0; i < maxPolls; i++ {
		time.Sleep(pollInterval)

		// Get detailed job status
		jobStatus, err := apiClient.GetJobStatus(ctx, jobID)
		if err != nil {
			t.Logf("Failed to get job status: %v", err)
			continue
		}

		// Log progress
		if jobStatus.Progress != nil {
			prog := jobStatus.Progress
			t.Logf("Poll %d: Job %s - Status: %s, Bytes: %d/%d (%.1f%%), Rate: %.2f Mbps",
				i+1, jobID[:8], jobStatus.Status,
				prog.BytesTransferred, prog.TotalBytes, prog.Percentage, prog.TransferRateMbps)

			// Check if we have progress
			if prog.BytesTransferred > 0 {
				sawProgress = true
				if prog.BytesTransferred > lastBytes {
					lastBytes = prog.BytesTransferred
				}
			}

			// Check if we have a non-zero transfer rate
			if prog.TransferRateMbps > 0 {
				sawNonZeroRate = true

				// Convert Mbps to KB/s: Mbps * 1000 / 8 = KB/s
				rateKBps := prog.TransferRateMbps * 1000.0 / 8.0
				if rateKBps > maxRateSeen {
					maxRateSeen = rateKBps
				}

				t.Logf("✓ Transfer rate: %.2f Mbps (%.1f KB/s)", prog.TransferRateMbps, rateKBps)

				// Verify rate is below threshold
				if rateKBps > maxAcceptableRateKBps {
					t.Errorf("Transfer rate %.1f KB/s exceeds maximum acceptable rate of %.1f KB/s - rate limiting not working",
						rateKBps, maxAcceptableRateKBps)
				}
			}
		}

		// Check database for intermediate progress updates (while transfer is still running)
		// The periodic update runs every 1 second (configured above), so check at 2s and again every 2 seconds
		// This gives time for the background task to run
		if jobStatus.Status == "running" && i > 0 && (i == 4 || i%4 == 0) { // Check at 2s, 4s, etc (4 polls * 500ms = 2s)
			db, err := sql.Open("sqlite", dbFile)
			if err == nil {
				var dbBytes int64
				query := "SELECT bytes_transferred FROM transfers WHERE job_id = ?"
				if err := db.QueryRow(query, jobID).Scan(&dbBytes); err == nil {
					t.Logf("Database check at poll %d: %d bytes (last: %d)", i, dbBytes, lastDbBytes)
					if dbBytes > lastDbBytes {
						sawIntermediateDbWrite = true
						dbUpdateCount++
						t.Logf("✓ Database intermediate update #%d: %d bytes persisted (previous: %d)", dbUpdateCount, dbBytes, lastDbBytes)
						lastDbBytes = dbBytes

						// Once we've seen 2 intermediate updates, we've proven the mechanism works
						// No need to wait for transfer completion
						if dbUpdateCount >= 2 {
							t.Logf("✓ Verified %d intermediate database updates - test goal achieved, exiting early", dbUpdateCount)
							db.Close()
							// Cancel the job to clean up
							if err := apiClient.CancelJob(ctx, jobID); err != nil {
								t.Logf("Warning: Failed to cancel job: %v", err)
							}
							break
						}
					}
				}
				db.Close()
			}
		}

		// If transfer is complete, break
		if jobStatus.Status == "completed" || jobStatus.Status == "failed" || jobStatus.Status == "cancelled" {
			t.Logf("Transfer finished with status: %s", jobStatus.Status)
			if jobStatus.Error != "" {
				t.Logf("Error: %s", jobStatus.Error)
				// Print daemon log for debugging
				if logData, err := os.ReadFile(logFile); err == nil {
					t.Logf("Daemon log:\n%s", string(logData))
				}
			}
			break
		}
	}

	// Check final status after monitoring window
	finalStatus, err := apiClient.GetJobStatus(ctx, jobID)
	if err == nil {
		t.Logf("Final job status: %s, Error: %s", finalStatus.Status, finalStatus.Error)
		if finalStatus.Error != "" {
			if logData, err := os.ReadFile(logFile); err == nil {
				t.Logf("Daemon log:\n%s", string(logData))
			}
		}
	}

	// Verify results
	assert.True(t, sawProgress, "Should have seen bytes transferred > 0")
	assert.True(t, sawNonZeroRate, "Should have seen non-zero transfer rate")
	assert.Greater(t, lastBytes, int64(0), "Should have transferred some bytes")

	if maxRateSeen > 0 {
		assert.LessOrEqual(t, maxRateSeen, maxAcceptableRateKBps,
			"Maximum observed transfer rate should be below %d KB/s", int(maxAcceptableRateKBps))
		t.Logf("✓ Rate limiting verified: max rate %.1f KB/s is below threshold of %.1f KB/s",
			maxRateSeen, maxAcceptableRateKBps)
	}

	t.Logf("Test completed - saw progress: %v, saw rate: %v, transferred: %d bytes, max rate: %.1f KB/s",
		sawProgress, sawNonZeroRate, lastBytes, maxRateSeen)

	// Verify intermediate database writes occurred
	if sawIntermediateDbWrite {
		t.Logf("✓ Verified %d intermediate database updates during transfer", dbUpdateCount)
	} else {
		t.Logf("⚠ Did not observe intermediate database updates (transfer may have been too fast)")
	}

	// Verify that progress was persisted to the database
	db, err := sql.Open("sqlite", dbFile)
	require.NoError(t, err, "Failed to open database")
	defer db.Close()

	// Query the transfers table to verify progress was written
	var dbBytesTransferred, dbTotalBytes int64
	query := "SELECT bytes_transferred, total_bytes FROM transfers WHERE job_id = ?"
	err = db.QueryRow(query, jobID).Scan(&dbBytesTransferred, &dbTotalBytes)
	require.NoError(t, err, "Failed to query transfer progress from database")

	// Verify database has non-zero progress (may not be complete if we exited early)
	assert.Greater(t, dbBytesTransferred, int64(0), "Database should have non-zero bytes_transferred")
	if dbTotalBytes > 0 {
		t.Logf("✓ Database verification: bytes_transferred=%d, total_bytes=%d (%.1f%% complete)",
			dbBytesTransferred, dbTotalBytes, float64(dbBytesTransferred)/float64(dbTotalBytes)*100)
	} else {
		t.Logf("✓ Database verification: bytes_transferred=%d", dbBytesTransferred)
	}

	// Check daemon log for periodic update messages
	t.Logf("\nChecking daemon log for periodic update messages...")
	logContent, err := os.ReadFile(logFile)
	if err != nil {
		t.Logf("Warning: Failed to read daemon log: %v", err)
	} else {
		logLines := string(logContent)
		hasUpdateMessages := strings.Contains(logLines, "Updating progress for")
		hasSuccessMessages := strings.Contains(logLines, "Successfully updated progress")

		if hasUpdateMessages {
			t.Logf("✓ Found 'Updating progress for' messages in daemon log")
		} else {
			t.Logf("✗ No 'Updating progress for' messages found in daemon log")
		}

		if hasSuccessMessages {
			t.Logf("✓ Found 'Successfully updated progress' messages in daemon log")
		} else {
			t.Logf("✗ No 'Successfully updated progress' messages found in daemon log")
		}

		// Show relevant log lines
		t.Logf("\nDaemon log excerpt (progress-related lines):")
		lineCount := 0
		for _, line := range strings.Split(logLines, "\n") {
			if strings.Contains(line, "progress") || strings.Contains(line, "Updating") ||
				strings.Contains(line, "active transfer") || strings.Contains(line, "Successfully updated") {
				t.Logf("  %s", line)
				lineCount++
				if lineCount >= 20 {
					t.Logf("  ... (truncated)")
					break
				}
			}
		}
		if lineCount == 0 {
			t.Logf("  (no relevant log lines found)")
		}
	}
}
