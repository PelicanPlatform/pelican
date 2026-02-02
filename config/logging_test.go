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

package config

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func TestLoggingFilter(t *testing.T) {
	logger := log.New()
	logger.SetFormatter(&log.TextFormatter{DisableColors: true})
	entry := log.NewEntry(logger)
	// Actual log message observed; note this token is expired and hence useless
	entry.Message = `240229 14:13:55 18544 XrdPfc_Cache: info Attach() pelican://u221@itb-osdf-director-origins.dev.osgdev.chtc.io:443//ospool/ap20/data/dvp2/singularity_repos/iebe-music_dev.sif?&authz=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjhiNjkifQ.eyJzdWIiOiJkdnAyIiwic2NvcGUiOiJyZWFkOi9kYXRhL2R2cDIgd3JpdGU6L2RhdGEvZHZwMiIsInZlciI6InNjaXRva2VuczoyLjAiLCJhdWQiOlsiQU5ZIl0sImlzcyI6Imh0dHBzOi8vYXAyMC51Yy5vc2ctaHRjLm9yZzoxMDk0L29zcG9vbC9hcDIwIiwiZXhwIjoxNzA5MjM4MTk3LCJpYXQiOjE3MDkyMzY5OTcsIm5iZiI6MTcwOTIzNjk5NywianRpIjoiNGNhNGM0NmItZDBiNy00YTFhLTk4NmYtYzk0Mjc1MzAzNDc3In0.ImFc2WiTLJDjavsjDQWgVJhASAkmV-XE2LbJkogv_kjxdF0sazTKPPRqaLmQ7_Tab-1nDYixfHT58CmFLHeebQ`
	transform := globalTransform
	result := &bytes.Buffer{}
	testHook := &writer.Hook{Writer: &syncWriter{writer: result}}
	transform.hook.Store(testHook)
	assert.NoError(t, transform.Fire(entry))
	fmt.Println(result.String())
	assert.Equal(t, `time="0001-01-01T00:00:00Z" level=panic msg="240229 14:13:55 18544 XrdPfc_Cache: info Attach() pelican://u221@itb-osdf-director-origins.dev.osgdev.chtc.io:443//ospool/ap20/data/dvp2/singularity_repos/iebe-music_dev.sif?&authz=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IjhiNjkifQ.eyJzdWIiOiJkdnAyIiwic2NvcGUiOiJyZWFkOi9kYXRhL2R2cDIgd3JpdGU6L2RhdGEvZHZwMiIsInZlciI6InNjaXRva2VuczoyLjAiLCJhdWQiOlsiQU5ZIl0sImlzcyI6Imh0dHBzOi8vYXAyMC51Yy5vc2ctaHRjLm9yZzoxMDk0L29zcG9vbC9hcDIwIiwiZXhwIjoxNzA5MjM4MTk3LCJpYXQiOjE3MDkyMzY5OTcsIm5iZiI6MTcwOTIzNjk5NywianRpIjoiNGNhNGM0NmItZDBiNy00YTFhLTk4NmYtYzk0Mjc1MzAzNDc3In0.REDACTED"`+"\n", result.String())
}

func TestLoggingCallback(t *testing.T) {
	// Reset for clean test
	require.NoError(t, param.Reset())
	t.Cleanup(func() {
		require.NoError(t, param.Reset())
	})

	// Create a buffer to capture log output
	var logBuffer bytes.Buffer

	// Set up a custom logger for this test
	testLogger := log.New()
	testLogger.SetOutput(&logBuffer)
	testLogger.SetFormatter(&log.TextFormatter{DisableColors: true})

	// Set initial log level to INFO
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "info"))
	testLogger.SetLevel(log.InfoLevel)

	// Register the logging callback - note this affects the global logger,
	// not our test logger, so we'll verify indirectly
	RegisterLoggingCallback()

	// Test that INFO messages pass through
	logBuffer.Reset()
	testLogger.Info("test info message")
	testLogger.Debug("test debug message")
	infoOutput := logBuffer.String()
	assert.Contains(t, infoOutput, "test info message", "INFO message should be logged at INFO level")
	assert.NotContains(t, infoOutput, "test debug message", "DEBUG message should not be logged at INFO level")

	// Change log level via param to DEBUG
	require.NoError(t, param.Set(param.Logging_Level.GetName(), "debug"))

	// Poll briefly for the callback to apply the new level
	for i := 0; i < 5; i++ {
		if GetEffectiveLogLevel() == log.DebugLevel {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.Equal(t, log.DebugLevel, GetEffectiveLogLevel(), "log level should update to DEBUG")

	// Now set our test logger to debug as well
	testLogger.SetLevel(log.DebugLevel)

	// Test that DEBUG messages now pass through
	logBuffer.Reset()
	testLogger.Info("test info message 2")
	testLogger.Debug("test debug message 2")
	debugOutput := logBuffer.String()
	assert.Contains(t, debugOutput, "test info message 2", "INFO message should be logged at DEBUG level")
	assert.Contains(t, debugOutput, "test debug message 2", "DEBUG message should be logged at DEBUG level")
}
