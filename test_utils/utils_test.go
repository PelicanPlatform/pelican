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

package test_utils

import (
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// captureHook records every entry it receives, standing in for the harness's
// TestLogHook (which forwards to t.Log) so a test can assert that diagnostic
// output still reaches hooks.
type captureHook struct {
	mu     sync.Mutex
	levels []logrus.Level
	msgs   []string
}

func (h *captureHook) Levels() []logrus.Level { return logrus.AllLevels }
func (h *captureHook) Fire(e *logrus.Entry) error {
	h.mu.Lock()
	h.levels = append(h.levels, e.Level)
	h.msgs = append(h.msgs, e.Message)
	h.mu.Unlock()
	return nil
}

// A test calls SetupTestLogging, then InitClient with a quiet configured level
// (as hundreds of tests do). The harness's diagnostic hook (TestLogHook ->
// t.Log) must keep receiving debug/trace entries afterward, or a failing test
// emits no diagnostics. A capture hook stands in for TestLogHook (added the
// same way, via AddHook); this confirms a debug entry still reaches it AND that
// logrus's gate stayed at Trace while the configured level reads Error.
func TestDiagnosticOutputSurvivesInitClient(t *testing.T) {
	defer SetupTestLogging(t)()

	cap := &captureHook{}
	logrus.AddHook(cap)

	InitClient(t, map[param.Param]any{param.Logging_Level: "error"})

	logrus.Debug("diag-marker-xyz")

	require.Equal(t, logrus.TraceLevel, logrus.GetLevel(),
		"harness Trace floor must survive InitClient")
	require.Equal(t, logrus.ErrorLevel, config.GetEffectiveLogLevel(),
		"the operator-configured level should still read as Error")

	cap.mu.Lock()
	defer cap.mu.Unlock()
	found := false
	for i, l := range cap.levels {
		if l == logrus.DebugLevel && cap.msgs[i] == "diag-marker-xyz" {
			found = true
		}
	}
	require.True(t, found,
		"a debug entry must still reach hooks after InitClient (diagnostic output preserved)")
}

// TestGenerateJWK tests the GenerateJWK function.
func TestGenerateJWK(t *testing.T) {
	t.Cleanup(SetupTestLogging(t))
	jwkKey, jwks, jwksString, err := GenerateJWK()
	require.NoErrorf(t, err, "Failed to generate JWK and JWKS: %v", err)
	assert.NotNil(t, jwkKey)
	assert.NotNil(t, jwks)
	assert.NotEmpty(t, jwksString)
}

// TestSetupTestLogging verifies that the test logging hook is properly configured
func TestSetupTestLogging(t *testing.T) {
	t.Cleanup(SetupTestLogging(t))
	cleanup := SetupTestLogging(t)
	defer cleanup()

	// Log a message - it should be captured by the test hook
	logrus.Info("This message should only appear if the test fails")
	logrus.Warn("This warning should only appear if the test fails")

	// Verify that the hook was installed
	assert.Equal(t, 1, len(logrus.StandardLogger().Hooks[logrus.InfoLevel]), "Expected one hook to be installed")
}
