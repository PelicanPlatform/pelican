//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package fed_tests

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/xrootd"
)

func waitForComponentStatus(t *testing.T, component metrics.HealthStatusComponent, desired metrics.HealthStatusEnum, timeout time.Duration) {
	t.Helper()
	require.Eventually(t, func() bool {
		status, err := metrics.GetComponentStatus(component)
		if err != nil {
			return false
		}
		return status == desired.String()
	}, timeout, 100*time.Millisecond, "component %s did not reach status %s", component, desired)
}

func waitForComponentStatusNotOK(t *testing.T, component metrics.HealthStatusComponent, timeout time.Duration) string {
	t.Helper()
	var observedStatus string
	require.Eventually(t, func() bool {
		status, err := metrics.GetComponentStatus(component)
		if err != nil {
			return false
		}
		if status != metrics.StatusOK.String() {
			observedStatus = status
			return true
		}
		return false
	}, timeout, 50*time.Millisecond, "component %s never left OK state", component)
	return observedStatus
}

// TestXRootDRestart tests that XRootD can be restarted and continues to function
func TestXRootDRestart(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a federation with origin and cache
	ft := fed_test_utils.NewFedTest(t, bothPubNamespaces)

	if param.Origin_StorageType.GetString() == "posixv2" {
		t.Skip("Skipping XRootD restart test with posixv2 storage type; not supported")
	}

	// Create a test file to upload
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "Hello from Pelican restart test"
	require.NoError(t, os.WriteFile(testFile, []byte(testContent), 0644))

	// Upload the file before restart
	destUrl := fmt.Sprintf("pelican://%s:%d/first/namespace/restart/test.txt", param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	transferDetailsUpload, err := client.DoPut(ft.Ctx, testFile, destUrl, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferDetailsUpload)
	assert.Greater(t, transferDetailsUpload[0].TransferredBytes, int64(0))

	// Download the file to verify it works before restart
	downloadFile := filepath.Join(tempDir, "download_before.txt")
	transferDetailsDownload, err := client.DoGet(ft.Ctx, destUrl, downloadFile, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferDetailsDownload)
	assert.Greater(t, transferDetailsDownload[0].TransferredBytes, int64(0))

	// Verify content
	downloadedContent, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContent))

	// Get the origin server from the fed test (would need to expose this or get it another way)
	// For now, we'll test the restart mechanism directly via RestartXrootd

	// Restart the XRootD processes
	oldPids := ft.Pids
	require.NotEmpty(t, oldPids, "No PIDs found for XRootD processes")

	waitForComponentStatus(t, metrics.OriginCache_XRootD, metrics.StatusOK, 10*time.Second)

	restartDone := make(chan struct{})
	var newPids []int
	var restartErr error

	go func() {
		newPids, restartErr = xrootd.RestartXrootd(ft.Ctx, oldPids)
		close(restartDone)
	}()

	// Wait for the component to leave OK state, indicating restart has begun.
	// Capture the observed status to verify it's an expected transitional state.
	observedStatus := waitForComponentStatusNotOK(t, metrics.OriginCache_XRootD, 5*time.Second)
	assert.True(t, observedStatus == metrics.StatusShuttingDown.String() || observedStatus == metrics.StatusCritical.String(),
		"Expected ShuttingDown or Critical status during restart, got %s", observedStatus)

	<-restartDone
	require.NoError(t, restartErr)
	require.NotEmpty(t, newPids)
	require.NotEqual(t, oldPids, newPids, "PIDs should be different after restart")

	// Update the PIDs in the fed test
	ft.Pids = newPids

	waitForComponentStatus(t, metrics.OriginCache_XRootD, metrics.StatusOK, 10*time.Second)

	// Try to download the file again after restart
	downloadFileAfter := filepath.Join(tempDir, "download_after.txt")
	transferDetailsAfter, err := client.DoGet(ft.Ctx, destUrl, downloadFileAfter, false, client.WithTokenLocation(ft.Token))
	require.NoError(t, err)
	require.NotEmpty(t, transferDetailsAfter)
	assert.Greater(t, transferDetailsAfter[0].TransferredBytes, int64(0))

	// Verify content after restart
	downloadedContentAfter, err := os.ReadFile(downloadFileAfter)
	require.NoError(t, err)
	assert.Equal(t, testContent, string(downloadedContentAfter))

	// Verify old PIDs are no longer running
	for _, pid := range oldPids {
		process, err := os.FindProcess(pid)
		if err == nil {
			// Try to signal the process - should fail if it's dead
			err = process.Signal(syscall.Signal(0))
			assert.Error(t, err, "Old PID %d should not be running after restart", pid)
		}
	}

	// Verify new PIDs are running
	for _, pid := range newPids {
		process, err := os.FindProcess(pid)
		require.NoError(t, err)
		err = process.Signal(syscall.Signal(0))
		require.NoError(t, err, "New PID %d should be running after restart", pid)
	}
}

// TestXRootDRestartConcurrent tests that concurrent restart attempts are properly serialized
func TestXRootDRestartConcurrent(t *testing.T) {
	if param.Origin_StorageType.GetString() == "posixv2" {
		t.Skip("Skipping XRootD restart test with posixv2 storage type; not supported")
	}

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	// Create a federation
	ft := fed_test_utils.NewFedTest(t, bothPubNamespaces)

	oldPids := ft.Pids
	require.NotEmpty(t, oldPids, "No PIDs found for XRootD processes")

	// Try two concurrent restarts
	done := make(chan error, 2)

	go func() {
		_, err := xrootd.RestartXrootd(ft.Ctx, oldPids)
		done <- err
	}()

	// Small delay to let first restart acquire the lock
	time.Sleep(10 * time.Millisecond)

	go func() {
		_, err := xrootd.RestartXrootd(ft.Ctx, oldPids)
		done <- err
	}()

	// Collect results
	err1 := <-done
	err2 := <-done

	// One should succeed, one should fail with "already in progress"
	if err1 == nil {
		require.Error(t, err2)
		assert.Contains(t, err2.Error(), "already in progress")
	} else if err2 == nil {
		require.Error(t, err1)
		assert.Contains(t, err1.Error(), "already in progress")
	} else {
		t.Fatal("Both restart attempts failed, at least one should have succeeded")
	}
}
