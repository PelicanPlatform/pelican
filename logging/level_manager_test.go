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

package logging_test

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestLogLevelManager_AddChange(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Reset global state for this test
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	// Set base level to Info
	log.SetLevel(log.InfoLevel)
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Add a debug level change
	require.NoError(t, manager.AddChange("test-1", "Logging.Level", log.DebugLevel, 1*time.Hour))

	// Verify the level changed to debug
	require.Eventually(t,
		func() bool { return log.DebugLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Verify the change is tracked
	changes := manager.GetActiveChanges()
	require.Len(t, changes, 1)
	assert.Equal(t, "test-1", changes[0].ChangeID)
	assert.Equal(t, log.DebugLevel, changes[0].Level)
}

func TestLogLevelManager_RemoveChange(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Reset global state for this test
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	// Set base level to Info
	log.SetLevel(log.InfoLevel)
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Add a debug level change
	require.NoError(t, manager.AddChange("test-1", "Logging.Level", log.DebugLevel, 1*time.Hour))

	// Verify the change was added
	changes := manager.GetActiveChanges()
	require.Len(t, changes, 1)
	assert.Equal(t, "test-1", changes[0].ChangeID)

	// Check that param was set (changes propagate asynchronously in real usage)
	require.Eventually(t, func() bool {
		return param.Logging_Level.GetString() == "debug"
	}, 1*time.Second, 50*time.Millisecond, "Parameter should be set to debug")

	// Remove the change
	manager.RemoveChange("test-1")

	// Verify no active changes
	changes = manager.GetActiveChanges()
	assert.Len(t, changes, 0)

	// Verify param reverted to base
	require.Eventually(t, func() bool {
		return param.Logging_Level.GetString() == "info"
	}, 1*time.Second, 50*time.Millisecond, "Parameter should revert to info")
}

func TestLogLevelManager_MultipleChanges(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Reset global state for this test
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	// Set base level to Info
	log.SetLevel(log.InfoLevel)
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Add multiple changes - most verbose should win
	log.Info("Adding multiple log level changes")
	require.NoError(t, manager.AddChange("test-1", "Logging.Level", log.DebugLevel, 1*time.Hour))

	require.Eventually(t,
		func() bool { return log.DebugLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	require.NoError(t, manager.AddChange("test-2", "Logging.Level", log.WarnLevel, 1*time.Hour))
	require.NoError(t, manager.AddChange("test-3", "Logging.Level", log.TraceLevel, 1*time.Hour))
	log.Info("Added log level changes: test-1 (Debug), test-2 (Warn), test-3 (Trace)")

	// Should be at Trace level (most verbose)
	require.Eventually(t,
		func() bool { return log.TraceLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Remove the most verbose change
	manager.RemoveChange("test-3")

	// Should now be at Debug level (more verbose than base Info or test-2 Warn)
	require.Eventually(t,
		func() bool { return log.DebugLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Remove debug change
	manager.RemoveChange("test-1")
	log.Info("Removed debug level change")

	// Still an active change (test-2 at Warn), so should be at Warn level,
	// even though original base is Info
	require.Eventually(t,
		func() bool { return log.WarnLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Remove last change
	manager.RemoveChange("test-2")

	// Should still be at base Info level
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)
}

func TestLogLevelManager_ExpiredChanges(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Reset global state for this test
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	// Set base level to Info
	log.SetLevel(log.InfoLevel)
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Add a change with very short duration
	require.NoError(t, manager.AddChange("test-1", "Logging.Level", log.DebugLevel, 100*time.Millisecond))

	require.Eventually(t,
		func() bool { return log.DebugLevel == log.GetLevel() },
		100*time.Millisecond,
		10*time.Millisecond,
	)

	// Wait for expiration
	time.Sleep(200 * time.Millisecond)

	// Verify level reverted
	assert.Equal(t, log.InfoLevel, config.GetEffectiveLogLevel())

	// Verify no active changes
	changes := manager.GetActiveChanges()
	assert.Len(t, changes, 0)
}

func TestLogLevelManager_SetBaseLevel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	// Reset global state for this test
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	// Set initial base level
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Add a temporary change
	require.NoError(t, manager.AddChange("test-1", "Logging.Level", log.DebugLevel, 1*time.Hour))

	require.Eventually(t,
		func() bool { return log.DebugLevel == log.GetLevel() },
		100*time.Millisecond,
		10*time.Millisecond,
	)

	// Change base level
	manager.SetBaseLevel(log.WarnLevel)

	// Should still be at debug (temporary change is more verbose)
	assert.Equal(t, log.DebugLevel, log.GetLevel())

	// Remove the temporary change
	manager.RemoveChange("test-1")

	// Should now be at the new base level
	require.Eventually(t,
		func() bool { return log.WarnLevel == log.GetLevel() },
		100*time.Millisecond,
		10*time.Millisecond,
	)
}

func TestLogLevelManager_BackgroundExpiry(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	logging.ResetGlobalManager()
	config.RegisterLoggingCallback()

	origLevel := log.GetLevel()
	defer log.SetLevel(origLevel)

	manager := logging.GetLogLevelManager()
	defer func() {
		manager.Shutdown()
		logging.ResetGlobalManager()
	}()

	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel == config.GetEffectiveLogLevel() },
		1*time.Second,
		10*time.Millisecond,
	)

	require.NoError(t, manager.AddChange("c1", "Logging.Level", log.DebugLevel, 250*time.Millisecond))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, log.DebugLevel, config.GetEffectiveLogLevel())

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, log.InfoLevel, config.GetEffectiveLogLevel())

	require.NoError(t, manager.AddChange("c2", "Logging.Level", log.TraceLevel, 250*time.Millisecond))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, log.TraceLevel, config.GetEffectiveLogLevel())

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, log.InfoLevel, config.GetEffectiveLogLevel())

	require.NoError(t, manager.AddChange("c3", "Logging.Level", log.DebugLevel, 250*time.Millisecond))
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, log.DebugLevel, config.GetEffectiveLogLevel())

	time.Sleep(200 * time.Millisecond)
	assert.Equal(t, log.InfoLevel, config.GetEffectiveLogLevel())
}
