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

package fed_tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/xrootd"
)

func TestCLILoggingLevelChanges(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	ft := fed_test_utils.NewFedTest(t, bothPubNamespaces)

	cliPath := buildPelicanCLI(t)
	srvURL := param.Server_ExternalWebUrl.GetString()

	// Write current config to a temporary file so the subprocess can access issuer keys
	configFile, err := os.CreateTemp(t.TempDir(), "pelican-config-*.yaml")
	require.NoError(t, err)
	defer func() {
		_ = configFile.Close()
	}()

	// Ensure critical paths are set so they get written to the config file
	// The subprocess needs these to generate admin tokens
	require.NoError(t, param.Set(param.IssuerKeysDirectory.GetName(), param.IssuerKeysDirectory.GetString()))
	require.NoError(t, param.Set(param.Server_ExternalWebUrl.GetName(), srvURL))
	require.NoError(t, param.Set(param.Federation_DiscoveryUrl.GetName(), param.Federation_DiscoveryUrl.GetString()))

	err = viper.WriteConfigAs(configFile.Name())
	require.NoError(t, err, "Failed to write config file for subprocess")

	runSetLevel := func(paramName string, level string, duration string) {
		args := []string{cliPath, "server", "set-logging-level", level, duration}
		if paramName != "" {
			args = append(args, "--param", paramName)
		}
		cmd := exec.CommandContext(ft.Ctx, args[0], args[1:]...)
		// Pass config file so CLI can access issuer keys for token generation
		cmd.Env = append(os.Environ(),
			"PELICAN_CONFIG="+configFile.Name(),
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "CLI command failed: %s", string(output))
	}

	runSetLevelExpectFail := func(paramName string, level string, duration string) string {
		args := []string{cliPath, "server", "set-logging-level", level, duration}
		if paramName != "" {
			args = append(args, "--param", paramName)
		}
		cmd := exec.CommandContext(ft.Ctx, args[0], args[1:]...)
		// Pass config file so CLI can access issuer keys for token generation
		cmd.Env = append(os.Environ(),
			"PELICAN_CONFIG="+configFile.Name(),
		)
		output, err := cmd.CombinedOutput()
		require.Error(t, err, "CLI command should have failed")
		return string(output)
	}

	// Get initial PIDs for xrootd processes (should be origin and cache)
	initialPids := xrootd.GetTrackedPIDs()
	require.NotEmpty(t, initialPids, "Expected xrootd PIDs to be tracked")
	t.Logf("Initial xrootd PIDs: %v", initialPids)

	// Test 0: Verify invalid parameter names are rejected
	t.Log("Test 0: Verify invalid parameter names are rejected")
	output := runSetLevelExpectFail("Logging.Origin.foo", "debug", "10s")
	require.Contains(t, output, "Unsupported parameter", "Expected error message about unsupported parameter")
	t.Logf("✓ Invalid parameter correctly rejected: %s", output)

	// Capture the INITIAL log level BEFORE making any changes
	// Query via param, not log.GetLevel() which is unreliable
	initialLevelStr := param.Logging_Level.GetString()
	t.Logf("Initial log level before any changes: %s", initialLevelStr)

	// Test 1: Change to info level (should suppress debug logs), then verify it restores
	t.Log("Test 1: Change to info level, verify debug logs suppressed, then verify restoration")

	// Set to info level for 2 seconds
	runSetLevel(param.Logging_Level.GetName(), "info", "2s")

	// Wait for the change to take effect
	require.Eventually(t, func() bool {
		current := param.Logging_Level.GetString()
		t.Logf("Polling: Current param level = %s, Expected = info", current)
		return current == "info"
	}, 2*time.Second, 100*time.Millisecond, "Expected param level to change to info")

	// Now debug logs should NOT be captured
	require.Equal(t, log.InfoLevel, config.GetEffectiveLogLevel())

	// Wait for expiration - give extra time for the log level manager to check for expired changes
	// The manager checks every ~1 second, and we need to wait beyond the 3-second duration plus manager check time
	t.Log("Waiting for temporary change to expire and restore to initial level...")
	require.Eventually(t, func() bool {
		currentLevel := param.Logging_Level.GetString()
		t.Logf("Checking param level - Current: %s, Expected: %s", currentLevel, initialLevelStr)
		return currentLevel == initialLevelStr
	}, 6*time.Second, 100*time.Millisecond, "Expected param level to restore to initial level")

	require.Equal(t, log.DebugLevel, config.GetEffectiveLogLevel())
	t.Log("✓ Log level restored to initial level")

	// Test 2: Origin XRootD log level change and verify xrootd restart
	t.Log("Test 2: Verify Origin XRootD log level changes trigger restart")
	originBase := param.Logging_Origin_Xrootd.GetString()
	t.Logf("Origin base XRootD logging level: %s", originBase)

	runSetLevel(param.Logging_Origin_Xrootd.GetName(), "trace", "4s")

	require.Eventually(t, func() bool {
		level := param.Logging_Origin_Xrootd.GetString()
		t.Logf("Current Origin XRootD level: %s", level)
		return level == "trace"
	}, 5*time.Second, 250*time.Millisecond, "Expected Origin XRootD level to change to trace")
	t.Log("✓ Origin XRootD log level parameter changed to trace")

	// Verify xrootd processes have restarted by checking PID changes
	// Note: XRootD restarts are asynchronous, give it time
	pidChanged := false
	require.Eventually(t, func() bool {
		currentPids := xrootd.GetTrackedPIDs()
		t.Logf("Checking PIDs - Initial: %v, Current: %v", initialPids, currentPids)
		if len(currentPids) != len(initialPids) {
			t.Logf("PID count mismatch, waiting for stabilization")
			return false
		}
		// Check if at least one PID has changed (indicating restart)
		for i := range currentPids {
			if currentPids[i] != initialPids[i] {
				pidChanged = true
				t.Logf("✓ XRootD restart detected: PID[%d] changed from %d to %d", i, initialPids[i], currentPids[i])
				return true
			}
		}
		return false
	}, 15*time.Second, 500*time.Millisecond, "Expected xrootd processes to restart after Origin XRootD log level change")
	require.True(t, pidChanged, "Expected at least one xrootd process to restart")

	// Update baseline PIDs after restart
	restartedPids := xrootd.GetTrackedPIDs()
	t.Logf("PIDs after first restart: %v", restartedPids)

	// Wait for expiration and verify another restart
	t.Log("Waiting for log level to expire and verify second restart")
	require.Eventually(t, func() bool {
		level := param.Logging_Origin_Xrootd.GetString()
		t.Logf("Current Origin XRootD level (waiting for restore): %s", level)
		return level == originBase
	}, 7*time.Second, 500*time.Millisecond, "Expected Origin XRootD level to restore to base")
	t.Log("✓ Origin XRootD log level restored to base")

	// Verify another xrootd restart after restoration
	pidChanged = false
	require.Eventually(t, func() bool {
		currentPids := xrootd.GetTrackedPIDs()
		t.Logf("Checking PIDs after restoration - After restart: %v, Current: %v", restartedPids, currentPids)
		if len(currentPids) != len(restartedPids) {
			t.Logf("PID count mismatch after restoration, waiting")
			return false
		}
		for i := range currentPids {
			if currentPids[i] != restartedPids[i] {
				pidChanged = true
				t.Logf("✓ XRootD restart detected on restoration: PID[%d] changed from %d to %d", i, restartedPids[i], currentPids[i])
				return true
			}
		}
		return false
	}, 15*time.Second, 500*time.Millisecond, "Expected xrootd processes to restart after Origin XRootD log level restored")
	require.True(t, pidChanged, "Expected at least one xrootd process to restart on restoration")

	t.Log("✓ All tests passed: log output verification and xrootd restart detection working")
}

func buildPelicanCLI(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	cliPath := filepath.Join(tmpDir, "pelican-cli")

	// Build from the parent directory
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", cliPath, "../cmd")
	cmd.Env = os.Environ()
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to build CLI: %s", string(output))

	return cliPath
}
