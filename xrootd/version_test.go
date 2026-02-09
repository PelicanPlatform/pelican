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

package xrootd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createMockXrootd creates a temporary mock xrootd binary that outputs the specified version
func createMockXrootd(t *testing.T, version string, exitCode int) string {
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "xrootd")

	// Create a shell script that acts as a mock xrootd binary
	scriptContent := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"-v\" ]; then\n  echo \"%s\" >&2\n  exit %d\nfi\nexit 0\n", version, exitCode)

	err := os.WriteFile(mockPath, []byte(scriptContent), 0755)
	require.NoError(t, err, "Failed to create mock xrootd binary")

	return tmpDir
}

// TestCheckXrootdVersion tests the version checking functionality with various scenarios
func TestCheckXrootdVersion(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		exitCode      int
		shouldError   bool
		errorContains string
	}{
		{
			name:        "Exact minimum version",
			version:     "5.8.2",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:        "Exact minimum version with v prefix",
			version:     "v5.8.2",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:        "Version above minimum",
			version:     "5.9.0",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:        "Version with prerelease suffix",
			version:     "5.8.2-rc1",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:        "Version with git suffix",
			version:     "5.8.2+git123",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:        "Much higher version",
			version:     "6.0.0",
			exitCode:    0,
			shouldError: false,
		},
		{
			name:          "Version below minimum",
			version:       "5.8.1",
			exitCode:      0,
			shouldError:   true,
			errorContains: "insufficient",
		},
		{
			name:          "Much lower version",
			version:       "5.0.0",
			exitCode:      0,
			shouldError:   true,
			errorContains: "insufficient",
		},
		{
			name:          "Version 4.x",
			version:       "4.12.0",
			exitCode:      0,
			shouldError:   true,
			errorContains: "insufficient",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock xrootd binary
			tmpDir := createMockXrootd(t, tt.version, tt.exitCode)

			// Temporarily modify PATH to use our mock
			oldPath := os.Getenv("PATH")
			newPath := tmpDir + string(os.PathListSeparator) + oldPath
			err := os.Setenv("PATH", newPath)
			require.NoError(t, err)
			defer func() {
				_ = os.Setenv("PATH", oldPath)
			}()

			// Run the version check
			err = CheckXrootdVersion()

			if tt.shouldError {
				assert.Error(t, err, "Expected error but got none")
				if tt.errorContains != "" {
					assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.errorContains),
						"Error message doesn't contain expected substring")
				}
			} else {
				assert.NoError(t, err, "Unexpected error: %v", err)
			}
		})
	}
}

// TestCheckXrootdVersion_BinaryNotFound tests the scenario where xrootd is not installed
func TestCheckXrootdVersion_BinaryNotFound(t *testing.T) {
	// Create an empty temporary directory
	tmpDir := t.TempDir()

	// Set PATH to only the empty directory (xrootd won't be found)
	oldPath := os.Getenv("PATH")
	err := os.Setenv("PATH", tmpDir)
	require.NoError(t, err)
	defer func() {
		_ = os.Setenv("PATH", oldPath)
	}()

	// Run the version check
	err = CheckXrootdVersion()

	// Should get an error about binary not found
	require.Error(t, err, "Expected error when xrootd binary is not found")
	assert.Contains(t, strings.ToLower(err.Error()), "not found", "Error should mention binary not found")
}

// TestCheckXrootdVersion_InvalidVersionFormat tests handling of unparsable version strings
func TestCheckXrootdVersion_InvalidVersionFormat(t *testing.T) {
	tests := []struct {
		name    string
		version string
	}{
		{
			name:    "Empty version string",
			version: "",
		},
		{
			name:    "Invalid version format",
			version: "invalid-version",
		},
		{
			name:    "Just text",
			version: "xrootd version unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock xrootd binary
			tmpDir := createMockXrootd(t, tt.version, 0)

			// Temporarily modify PATH
			oldPath := os.Getenv("PATH")
			newPath := tmpDir + string(os.PathListSeparator) + oldPath
			err := os.Setenv("PATH", newPath)
			require.NoError(t, err)
			defer func() {
				_ = os.Setenv("PATH", oldPath)
			}()

			// Run the version check
			err = CheckXrootdVersion()

			// Should get a parse error
			require.Error(t, err, "Expected error for invalid version format")
			assert.Contains(t, strings.ToLower(err.Error()), "parse", "Error should mention parsing failure")
		})
	}
}

// TestCheckXrootdVersion_RealBinary tests with the actual xrootd binary if available
func TestCheckXrootdVersion_RealBinary(t *testing.T) {
	// Check if xrootd is actually available
	_, err := exec.LookPath("xrootd")
	if err != nil {
		t.Skip("Skipping test: xrootd binary not found in PATH")
	}

	// Run the actual version check
	err = CheckXrootdVersion()

	// We can't assume the version, but we can test that it either succeeds or fails gracefully
	if err != nil {
		// If it fails, it should be a version mismatch error or parse error, not a crash
		errStr := strings.ToLower(err.Error())
		assert.True(t,
			strings.Contains(errStr, "insufficient") ||
				strings.Contains(errStr, "parse") ||
				strings.Contains(errStr, "not found"),
			"Unexpected error type: %v", err)
	}
	// If err is nil, the installed version is sufficient - that's also fine
}
