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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
