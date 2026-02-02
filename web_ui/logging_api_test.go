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

package web_ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/test_utils"
)

func setupLoggingRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Middleware to inject a test user
	r.Use(func(c *gin.Context) {
		c.Set("User", "testuser")
		c.Next()
	})

	loggingAPI := r.Group("/api/v1.0/logging")
	{
		loggingAPI.POST("/level", HandleSetLogLevel)
		loggingAPI.GET("/level", HandleGetLogLevel)
		loggingAPI.DELETE("/level/:changeId", HandleDeleteLogLevel)
	}
	return r
}

// TestHandleSetLogLevel tests the API endpoint for setting log levels
// Note that log level changes are propagated asynchronously after they
// are accepted.  Hence, it's possible for the test to increase the
// log level and then decrease it -- but the decrease might be processed
// before the increase, leading to test failures.  To avoid this, we
// verify the effective log level using require.Eventually after each
// change to force sequential consistency.
func TestHandleSetLogLevel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := config.GetEffectiveLogLevel()
	t.Cleanup(func() {
		config.SetLogging(origLevel)
	})

	// Ensure a clean log level manager for each test
	logging.ResetGlobalManager()
	config.SetLogging(log.InfoLevel)

	router := setupLoggingRouter()
	manager := logging.GetLogLevelManager()
	defer manager.Shutdown()

	// Set base level
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)

	t.Run("ValidRequest", func(t *testing.T) {
		payload := map[string]interface{}{
			"level":    "debug",
			"duration": 300,
		}
		payloadBytes, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1.0/logging/level", bytes.NewBuffer(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response LogLevelChangeResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.NotEmpty(t, response.ChangeID)
		assert.Equal(t, "debug", response.Level)
		assert.Equal(t, 300, response.Remaining)

		// Verify level changed
		require.Eventually(
			t,
			func() bool { return log.DebugLevel.String() == config.GetEffectiveLogLevel().String() },
			1*time.Second,
			10*time.Millisecond,
		)

		// Clean up
		manager.RemoveChange(response.ChangeID)
	})

	t.Run("InvalidLevel", func(t *testing.T) {
		payload := map[string]interface{}{
			"level":    "invalid",
			"duration": 300,
		}
		payloadBytes, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1.0/logging/level", bytes.NewBuffer(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("DurationTooLarge", func(t *testing.T) {
		payload := map[string]interface{}{
			"level":    "debug",
			"duration": 86401, // More than 24 hours
		}
		payloadBytes, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1.0/logging/level", bytes.NewBuffer(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("UnknownParameter", func(t *testing.T) {
		payload := map[string]interface{}{
			"level":         "debug",
			"duration":      300,
			"parameterName": "Unknown.Parameter",
		}
		payloadBytes, _ := json.Marshal(payload)

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1.0/logging/level", bytes.NewBuffer(payloadBytes))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleGetLogLevel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Save original level
	origLevel := config.GetEffectiveLogLevel()
	t.Cleanup(func() {
		config.SetLogging(origLevel)
	})

	// Ensure a clean log level manager for each test
	logging.ResetGlobalManager()
	config.SetLogging(log.InfoLevel)

	router := setupLoggingRouter()
	manager := logging.GetLogLevelManager()
	defer manager.Shutdown()

	// Set base level
	manager.SetBaseLevel(log.InfoLevel)

	t.Run("NoActiveChanges", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/logging/level", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response LogLevelStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "info", response.CurrentLevel)
		assert.Len(t, response.ActiveChanges, 0)
		require.NotEmpty(t, response.Parameters)
		foundLoggingLevel := false
		for _, param := range response.Parameters {
			if param.ParameterName == "Logging.Level" {
				foundLoggingLevel = true
				assert.Equal(t, "info", param.CurrentLevel)
			}
		}
		assert.True(t, foundLoggingLevel)
	})

	t.Run("WithActiveChanges", func(t *testing.T) {
		// Add a temporary change
		require.NoError(t, manager.AddChange("test-change-1", "Logging.Level", log.DebugLevel, 1*time.Hour))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1.0/logging/level", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response LogLevelStatusResponse
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)

		assert.Equal(t, "debug", response.CurrentLevel)
		assert.Len(t, response.ActiveChanges, 1)
		assert.Equal(t, "test-change-1", response.ActiveChanges[0].ChangeID)
		assert.Equal(t, "debug", response.ActiveChanges[0].Level)
		require.NotEmpty(t, response.Parameters)

		// Clean up
		manager.RemoveChange("test-change-1")
	})
}

func TestHandleDeleteLogLevel(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.RegisterLoggingCallback()

	// Save original level
	origLevel := config.GetEffectiveLogLevel()
	t.Cleanup(func() {
		config.SetLogging(origLevel)
	})

	// Ensure a clean log level manager for each test
	logging.ResetGlobalManager()
	config.SetLogging(log.InfoLevel)

	router := setupLoggingRouter()
	manager := logging.GetLogLevelManager()
	defer manager.Shutdown()

	// Set base level
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)

	t.Run("DeleteExistingChange", func(t *testing.T) {
		// Add a change
		require.NoError(t, manager.AddChange("test-delete-1", "Logging.Level", log.DebugLevel, 1*time.Hour))
		require.Eventually(
			t,
			func() bool { return log.DebugLevel.String() == config.GetEffectiveLogLevel().String() },
			1*time.Second,
			10*time.Millisecond,
		)

		// Delete it
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/api/v1.0/logging/level/test-delete-1", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Verify level reverted
		require.Eventually(
			t,
			func() bool { return log.InfoLevel.String() == config.GetEffectiveLogLevel().String() },
			1*time.Second,
			10*time.Millisecond,
		)
	})

	t.Run("DeleteNonexistentChange", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("DELETE", "/api/v1.0/logging/level/nonexistent", nil)
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestLogLevelIntegration(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	// Save original level
	origLevel := config.GetEffectiveLogLevel()
	t.Cleanup(func() {
		config.SetLogging(origLevel)
	})

	router := setupLoggingRouter()
	manager := logging.GetLogLevelManager()
	defer manager.Shutdown()

	// Set base level
	config.SetLogging(log.InfoLevel)
	manager.SetBaseLevel(log.InfoLevel)
	require.Eventually(t,
		func() bool { return log.InfoLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Create a change via API
	payload := map[string]interface{}{
		"level":    "debug",
		"duration": 300,
	}
	payloadBytes, _ := json.Marshal(payload)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1.0/logging/level", bytes.NewBuffer(payloadBytes))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var createResponse LogLevelChangeResponse
	err := json.Unmarshal(w.Body.Bytes(), &createResponse)
	require.NoError(t, err)

	require.Eventually(t,
		func() bool { return log.DebugLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)

	// Get status
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/v1.0/logging/level", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var statusResponse LogLevelStatusResponse
	err = json.Unmarshal(w.Body.Bytes(), &statusResponse)
	require.NoError(t, err)

	assert.Equal(t, "debug", statusResponse.CurrentLevel)
	assert.Len(t, statusResponse.ActiveChanges, 1)

	// Delete the change
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/api/v1.0/logging/level/"+createResponse.ChangeID, nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	// Verify level reverted
	require.Eventually(t,
		func() bool { return log.InfoLevel.String() == config.GetEffectiveLogLevel().String() },
		1*time.Second,
		10*time.Millisecond,
	)
}
