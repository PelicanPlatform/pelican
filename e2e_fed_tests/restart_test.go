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
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/launcher_utils"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
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

// hookRestartAdvertise wraps the advertisement RestartXrootd sends before and
// after it restarts the daemons, calling onAdvertise with the XRootD component
// status at the moment of each advertisement (before the real one goes out).
// A restart only lasts a few hundred milliseconds in a test federation, so
// sampling the status from outside can miss its transitional states entirely;
// the hook sees exactly what the director is told. ResetTestState restores
// the default advertisement function.
func hookRestartAdvertise(t *testing.T, onAdvertise func(status string)) {
	t.Helper()
	xrootd.SetRestartAdvertiseFn(func(ctx context.Context, servers []server_structs.XRootDServer) error {
		status, err := metrics.GetComponentStatus(metrics.OriginCache_XRootD)
		if err != nil {
			status = err.Error()
		}
		onAdvertise(status)
		return launcher_utils.Advertise(ctx, servers)
	})
}

// TestXRootDRestart tests that XRootD can be restarted and continues to function
func TestXRootDRestart(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

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

	// The director must be told the server is shutting down before the
	// daemons go away, and that it is healthy again once they are back.
	var advertisedStatuses []string
	hookRestartAdvertise(t, func(status string) { advertisedStatuses = append(advertisedStatuses, status) })

	newPids, restartErr := xrootd.RestartXrootd(ft.Ctx, ft.Ctx, oldPids)
	require.NoError(t, restartErr)
	assert.Equal(t, []string{metrics.StatusShuttingDown.String(), metrics.StatusOK.String()}, advertisedStatuses,
		"statuses advertised to the director before and after the restart")
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
	t.Cleanup(server_utils.ResetTestState)

	// Create a federation
	ft := fed_test_utils.NewFedTest(t, bothPubNamespaces)

	oldPids := ft.Pids
	require.NotEmpty(t, oldPids, "No PIDs found for XRootD processes")

	// Hold the first restart inside its pre-shutdown advertisement, so the
	// second attempt is made while the first one is certainly in progress.
	inProgress := make(chan struct{})
	release := make(chan struct{})
	var holdOnce sync.Once
	hookRestartAdvertise(t, func(string) {
		holdOnce.Do(func() {
			close(inProgress)
			<-release
		})
	})

	firstDone := make(chan error, 1)
	go func() {
		_, err := xrootd.RestartXrootd(ft.Ctx, ft.Ctx, oldPids)
		firstDone <- err
	}()
	select {
	case <-inProgress:
	case err := <-firstDone:
		t.Fatalf("the first restart ended before advertising its shutdown: %v", err)
	}

	_, err := xrootd.RestartXrootd(ft.Ctx, ft.Ctx, oldPids)
	close(release)
	require.Error(t, err, "a restart attempted while another is in progress must be refused")
	assert.Contains(t, err.Error(), "already in progress")

	require.NoError(t, <-firstDone, "the restart already in progress must complete")
}
