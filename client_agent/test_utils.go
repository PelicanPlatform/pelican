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

package client_agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// Unix socket paths have a maximum length of 108 characters on most systems
	// We use 80 as a conservative threshold to account for socket filename
	maxSocketPathLength = 80
)

// getTestTempDir returns a temporary directory suitable for Unix socket creation.
// Unix socket paths have strict length limits (typically 108 characters).
// If t.TempDir() would exceed the safe threshold, this creates a shorter path in /tmp.
// Cleanup is automatically scheduled via t.Cleanup().
func getTestTempDir(t *testing.T) string {
	// Try using t.TempDir() first
	tempDir := t.TempDir()

	// Check if the path would be too long for socket creation
	// (we need room for "/client-agent.sock" or similar filenames)
	testSocketPath := filepath.Join(tempDir, "test.sock")
	if len(testSocketPath) <= maxSocketPathLength {
		// Path is short enough, use t.TempDir() and let it handle cleanup
		return tempDir
	}

	// Path is too long, create a shorter one in /tmp
	shortDir, err := os.MkdirTemp("/tmp", "pelican-test-*")
	require.NoError(t, err, "failed to create short temp directory in /tmp")

	// Set secure permissions immediately
	err = os.Chmod(shortDir, 0700)
	require.NoError(t, err, "failed to set permissions on temp directory")

	// Register cleanup function
	t.Cleanup(func() {
		if err := os.RemoveAll(shortDir); err != nil {
			t.Logf("Warning: failed to clean up temp directory %s: %v", shortDir, err)
		}
	})

	return shortDir
}

// CreateTestServerConfig creates a ServerConfig for testing with proper temp directory handling.
// It ensures paths are short enough for Unix sockets and sets up proper cleanup.
func CreateTestServerConfig(t *testing.T) (ServerConfig, string) {
	tempDir := getTestTempDir(t)

	socketPath := filepath.Join(tempDir, "client-agent.sock")
	pidFile := filepath.Join(tempDir, "client-agent.pid")
	dbPath := filepath.Join(tempDir, "client-agent.db")

	config := ServerConfig{
		SocketPath:        socketPath,
		PidFile:           pidFile,
		DbLocation:        dbPath,
		MaxConcurrentJobs: 5,
	}

	return config, tempDir
}
