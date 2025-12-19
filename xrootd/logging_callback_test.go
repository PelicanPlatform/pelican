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

package xrootd

import (
	"bytes"
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
)

// Mock launcher for testing
type mockLauncher struct {
	name    string
	killSig int
	killErr error
}

func (m *mockLauncher) Name() string {
	return m.name
}

func (m *mockLauncher) Launch(ctx context.Context) (context.Context, int, error) {
	return ctx, 0, nil
}

func (m *mockLauncher) KillFunc() func(pid int, sig int) error {
	return func(pid int, sig int) error {
		m.killSig = sig
		return m.killErr
	}
}

func TestXrootdLoggingCallback(t *testing.T) {
	// Reset and clear state for clean test
	viper.Reset()
	defer viper.Reset()
	ClearXrootdDaemons()
	param.ClearCallbacks()
	time.Sleep(100 * time.Millisecond) // Wait for any pending callbacks from other tests

	// Set initial xrootd logging config
	require.NoError(t, param.Set("Logging.Origin.Cms", "info"))
	require.NoError(t, param.Set("Logging.Cache.Http", "warn"))

	// Create mock launchers
	mockOrigin := &mockLauncher{name: "xrootd.origin"}
	mockCache := &mockLauncher{name: "xrootd.cache"}

	launchers := []daemon.Launcher{mockOrigin, mockCache}
	pids := []int{1234, 5678}

	// Register the daemons
	RegisterXrootdDaemons(launchers, pids)

	// Register the logging callback
	RegisterXrootdLoggingCallback()

	// Capture log output to verify warning message
	var logBuffer bytes.Buffer
	origOutput := log.StandardLogger().Out
	log.SetOutput(&logBuffer)
	defer log.SetOutput(origOutput)

	// Change xrootd logging config
	require.NoError(t, param.Set("Logging.Origin.Cms", "debug"))

	// Give callback time to execute
	time.Sleep(300 * time.Millisecond)

	// Verify warning message was logged
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "XRootD logging configuration changed", "Should log warning about config change")
	assert.Contains(t, logOutput, "Server restart required", "Should indicate restart is required")

	// Verify no signals were sent (since we're not actually restarting)
	assert.Equal(t, 0, mockOrigin.killSig, "No signal should be sent to origin")
	assert.Equal(t, 0, mockCache.killSig, "No signal should be sent to cache")
}

func TestXrootdLoggingCallbackNoChange(t *testing.T) {
	// Reset and clear state for clean test
	viper.Reset()
	defer viper.Reset()
	ClearXrootdDaemons()
	param.ClearCallbacks()
	time.Sleep(100 * time.Millisecond) // Wait for any pending callbacks from other tests

	// Set initial non-xrootd logging config BEFORE registering callback
	require.NoError(t, param.Set("Logging.Level", "info"))

	// Create mock launcher
	mockOrigin := &mockLauncher{name: "xrootd.origin"}

	launchers := []daemon.Launcher{mockOrigin}
	pids := []int{1234}

	// Register the daemons
	RegisterXrootdDaemons(launchers, pids)

	// Register the logging callback
	RegisterXrootdLoggingCallback()

	// NOW change the non-xrootd logging parameter (after callback registration)
	require.NoError(t, param.Set("Logging.Level", "debug"))

	// Give callback time to execute
	time.Sleep(300 * time.Millisecond)

	// Verify no signal was sent
	assert.Equal(t, 0, mockOrigin.killSig, "No signal should be sent for non-xrootd logging changes")
}

func TestXrootdLoggingCallbackCacheParams(t *testing.T) {
	// Reset and clear state for clean test
	viper.Reset()
	defer viper.Reset()
	ClearXrootdDaemons()
	param.ClearCallbacks()
	time.Sleep(100 * time.Millisecond) // Wait for any pending callbacks from other tests

	// Set initial cache logging config
	require.NoError(t, param.Set("Logging.Cache.Pfc", "info"))

	// Create mock launcher
	mockCache := &mockLauncher{name: "xrootd.cache"}

	launchers := []daemon.Launcher{mockCache}
	pids := []int{5678}

	// Register the daemons
	RegisterXrootdDaemons(launchers, pids)

	// Register the logging callback
	RegisterXrootdLoggingCallback()

	// Capture log output to verify warning message
	var logBuffer bytes.Buffer
	origOutput := log.StandardLogger().Out
	log.SetOutput(&logBuffer)
	defer log.SetOutput(origOutput)

	// Change cache xrootd logging config
	require.NoError(t, param.Set("Logging.Cache.Pfc", "debug"))

	// Give callback time to execute
	time.Sleep(300 * time.Millisecond)

	// Verify warning message was logged
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "XRootD logging configuration changed", "Should log warning about config change")
	
	// Verify no signals were sent
	assert.Equal(t, 0, mockCache.killSig, "No signal should be sent to cache")
}
