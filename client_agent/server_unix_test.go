//go:build unix

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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAcquireServerLock_Success(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire lock
	fd, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire initial lock")
	require.NotNil(t, fd, "Lock file descriptor should not be nil")
	defer fd.Close()

	// Verify PID file was created
	_, err = os.Stat(pidPath)
	require.NoError(t, err, "PID file should exist")

	// Verify our PID was written
	pidData, err := os.ReadFile(pidPath)
	require.NoError(t, err, "Failed to read PID file")
	assert.NotEmpty(t, string(pidData), "PID file should contain data")
}

func TestAcquireServerLock_AlreadyLocked(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire first lock
	fd1, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire first lock")
	require.NotNil(t, fd1, "First lock file descriptor should not be nil")
	defer fd1.Close()

	// Try to acquire second lock with short timeout
	fd2, err := acquireServerLock(pidPath, 100*time.Millisecond)
	require.Error(t, err, "Should fail to acquire second lock")
	assert.Nil(t, fd2, "Second lock file descriptor should be nil")
	assert.Contains(t, err.Error(), "server is already running", "Error should indicate server is running")
}

func TestAcquireServerLock_LockReleased(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire and release first lock
	fd1, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire first lock")
	require.NotNil(t, fd1, "First lock file descriptor should not be nil")
	fd1.Close() // Release lock

	// Acquire second lock (should succeed)
	fd2, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Should be able to acquire lock after release")
	require.NotNil(t, fd2, "Second lock file descriptor should not be nil")
	defer fd2.Close()
}

func TestAcquireServerLock_RetrySuccess(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire first lock
	fd1, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire first lock")
	require.NotNil(t, fd1, "First lock file descriptor should not be nil")

	// Release lock after short delay in goroutine
	go func() {
		time.Sleep(50 * time.Millisecond)
		fd1.Close()
	}()

	// Try to acquire second lock with timeout that should succeed after retry
	fd2, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Should acquire lock after retry")
	require.NotNil(t, fd2, "Second lock file descriptor should not be nil")
	defer fd2.Close()
}

func TestAcquireServerLock_InvalidPath(t *testing.T) {
	// Use a path that cannot be expanded
	pidPath := ""

	fd, err := acquireServerLock(pidPath, 100*time.Millisecond)
	require.Error(t, err, "Should fail with invalid path")
	assert.Nil(t, fd, "Lock file descriptor should be nil")
}

func TestAcquireServerLock_NonExistentParentDir(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	// Use a nested path where parent doesn't exist yet
	pidPath := filepath.Join(tmpDir, "subdir", "another", "test.pid")

	// Should succeed - acquireServerLock creates parent directories
	fd, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Should create parent directories and acquire lock")
	require.NotNil(t, fd, "Lock file descriptor should not be nil")
	defer fd.Close()

	// Verify directory was created
	parentDir := filepath.Dir(pidPath)
	info, err := os.Stat(parentDir)
	require.NoError(t, err, "Parent directory should exist")
	assert.True(t, info.IsDir(), "Parent should be a directory")
}

func TestAcquireServerLock_FilePermissions(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire lock
	fd, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire lock")
	require.NotNil(t, fd, "Lock file descriptor should not be nil")
	defer fd.Close()

	// Check file permissions
	info, err := os.Stat(pidPath)
	require.NoError(t, err, "Failed to stat PID file")

	// Should be 0600 (owner read/write only)
	expectedPerm := os.FileMode(0600)
	actualPerm := info.Mode().Perm()
	assert.Equal(t, expectedPerm, actualPerm, "PID file should have 0600 permissions")
}

func TestAcquireServerLock_OwnershipCheck(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Create PID file first (simulating a file owned by us)
	err := os.WriteFile(pidPath, []byte("12345"), 0600)
	require.NoError(t, err, "Failed to create initial PID file")

	// Try to acquire lock (should succeed since we own the file)
	fd, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Should acquire lock on file we own")
	require.NotNil(t, fd, "Lock file descriptor should not be nil")
	defer fd.Close()
}

func TestGetServerPIDFromLock_NoLock(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Create PID file but don't lock it
	err := os.WriteFile(pidPath, []byte("12345"), 0600)
	require.NoError(t, err, "Failed to create PID file")

	// Query lock status
	pid, err := getServerPIDFromLock(pidPath)
	require.NoError(t, err, "Should not error when no lock is held")
	assert.Equal(t, 0, pid, "PID should be 0 when no lock is held")
}

func TestGetServerPIDFromLock_NonExistentFile(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "nonexistent.pid")

	// Query lock status on non-existent file
	pid, err := getServerPIDFromLock(pidPath)
	require.NoError(t, err, "Should not error for non-existent file")
	assert.Equal(t, 0, pid, "PID should be 0 for non-existent file")
}

func TestAcquireServerLock_ShortTimeout(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Acquire first lock
	fd1, err := acquireServerLock(pidPath, 500*time.Millisecond)
	require.NoError(t, err, "Failed to acquire first lock")
	require.NotNil(t, fd1, "First lock file descriptor should not be nil")
	defer fd1.Close()

	// Try to acquire second lock with very short timeout (should fail quickly)
	start := time.Now()
	fd2, err := acquireServerLock(pidPath, 10*time.Millisecond)
	elapsed := time.Since(start)

	require.Error(t, err, "Should fail with short timeout when lock is held")
	assert.Nil(t, fd2, "Second lock file descriptor should be nil")
	assert.Less(t, elapsed, 200*time.Millisecond, "Should fail relatively quickly with short timeout")
}

func TestAcquireServerLock_SymlinkDetection(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real.pid")
	symlinkFile := filepath.Join(tmpDir, "symlink.pid")

	// Create a real file
	err := os.WriteFile(realFile, []byte("12345"), 0600)
	require.NoError(t, err, "Failed to create real file")

	// Create symlink to the real file
	err = os.Symlink(realFile, symlinkFile)
	require.NoError(t, err, "Failed to create symlink")

	// Try to acquire lock on symlink (should fail)
	fd, err := acquireServerLock(symlinkFile, 100*time.Millisecond)
	require.Error(t, err, "Should fail when PID file is a symlink")
	assert.Nil(t, fd, "Lock file descriptor should be nil")
	assert.Contains(t, err.Error(), "symlink", "Error should mention symlink")
}

func TestAcquireServerLock_ManualFlock(t *testing.T) {
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Manually create and lock a file (simulating another process)
	fd1, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0600)
	require.NoError(t, err, "Failed to create PID file")
	defer fd1.Close()

	// Acquire exclusive lock manually
	err = syscall.Flock(int(fd1.Fd()), syscall.LOCK_EX)
	require.NoError(t, err, "Failed to acquire manual lock")

	// Try to acquire lock via acquireServerLock with short timeout
	fd2, err := acquireServerLock(pidPath, 100*time.Millisecond)
	require.Error(t, err, "Should fail when file is manually locked")
	assert.Nil(t, fd2, "Lock file descriptor should be nil")
	assert.Contains(t, err.Error(), "server is already running", "Error should indicate server is running")
}

func TestAcquireServerLock_ZeroTimeoutAvailable(t *testing.T) {
	// Regression test: ensure lock acquisition is attempted at least once even with zero timeout
	// Create temp directory for test
	tmpDir := t.TempDir()
	pidPath := filepath.Join(tmpDir, "test.pid")

	// Try to acquire lock with zero timeout when no lock is held
	// This should succeed because the loop always runs at least once
	fd, err := acquireServerLock(pidPath, 0)
	require.NoError(t, err, "Should succeed with zero timeout when lock is available")
	require.NotNil(t, fd, "Lock file descriptor should not be nil")
	defer fd.Close()

	// Verify PID file was created and lock is held
	_, statErr := os.Stat(pidPath)
	require.NoError(t, statErr, "PID file should exist")
}
