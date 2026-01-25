//go:build unix

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

package client_agent

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// verifyOwnership verifies that the directory (represented by FileInfo) is owned by the expected UID
func verifyOwnership(info os.FileInfo, expectedUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("failed to get system-specific file info")
	}

	if int(stat.Uid) != expectedUID {
		return errors.Errorf("directory is owned by UID %d, expected %d (current user)", stat.Uid, expectedUID)
	}

	return nil
}

// acquireServerLock acquires an exclusive lock on the PID file
// This prevents multiple server instances and survives reboots (unlike simple PID files)
// timeout specifies how long to retry acquiring the lock before giving up
func acquireServerLock(pidPath string, timeout time.Duration) (*os.File, error) {
	expandedPath, err := ExpandPath(pidPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand PID path")
	}

	// Ensure PID directory exists with secure permissions and get Root filesystem
	// This prevents TOCTOU between directory verification and opening
	pidDir := filepath.Dir(expandedPath)
	root, err := ensureSecureDirectory(pidDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to ensure secure PID directory")
	}
	defer root.Close()

	// Open the PID file relative to the root, using O_NOFOLLOW to prevent symlink attacks
	// This prevents TOCTOU race conditions
	pidFileName := filepath.Base(expandedPath)
	fd, err := root.OpenFile(pidFileName, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open PID file")
	}

	// Verify the PID file is owned by us (security check to prevent attacks)
	info, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, errors.Wrap(err, "failed to stat PID file")
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		fd.Close()
		return nil, errors.New("failed to get system-specific file info for PID file")
	}

	expectedUID := os.Getuid()
	if int(stat.Uid) != expectedUID {
		fd.Close()
		return nil, errors.Errorf("PID file is owned by UID %d, expected %d (current user) - potential security issue", stat.Uid, expectedUID)
	}

	// Verify it's a regular file (check after opening to catch race conditions)
	if info.Mode()&os.ModeType != 0 {
		fd.Close()
		return nil, errors.Errorf("PID file is not a regular file (mode: %v)", info.Mode())
	}

	// Try to acquire exclusive lock with retries to reduce racing
	// Loop always runs at least once, even with zero timeout
	const retryInterval = 50 * time.Millisecond
	deadline := time.Now().Add(timeout)
	var lastErr error

	for {
		if err := syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			if err == syscall.EWOULDBLOCK {
				// Lock is held by another process, check if we should retry
				lastErr = err
				if time.Now().Before(deadline) {
					time.Sleep(retryInterval)
					continue
				}
				// Timeout exhausted
				break
			}
			// Other error, fail immediately
			fd.Close()
			return nil, errors.Wrap(err, "failed to acquire lock")
		}

		// Successfully acquired lock
		lastErr = nil
		break
	}

	// If we exhausted the timeout, report the lock holder
	if lastErr == syscall.EWOULDBLOCK {
		fd.Close()
		// Lock is still held by another process after retries
		// Try to get the PID of the lock holder
		holderPID, pidErr := getServerPIDFromLock(pidPath)
		if pidErr == nil && holderPID > 0 {
			return nil, errors.Errorf("server is already running (PID %d)", holderPID)
		}
		return nil, errors.New("server is already running")
	}

	// Write our PID to the PID file (for sysadmins to read)
	if err := fd.Truncate(0); err != nil {
		log.Warnf("Failed to truncate PID file: %v", err)
	}
	if _, err := fd.Seek(0, 0); err != nil {
		log.Warnf("Failed to seek PID file: %v", err)
	}
	if _, err := fd.WriteString(fmt.Sprintf("%d", os.Getpid())); err != nil {
		log.Warnf("Failed to write PID to PID file: %v", err)
	}

	log.Infof("Acquired server lock at %s", expandedPath)
	return fd, nil
}

// getServerPIDFromLock queries the PID of the process holding the lock on the PID file
// Returns 0 if no lock is held
func getServerPIDFromLock(pidPath string) (int, error) {
	expandedPath, err := ExpandPath(pidPath)
	if err != nil {
		return 0, errors.Wrap(err, "failed to expand PID path")
	}

	// Check if PID file exists
	if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
		return 0, nil // No PID file = no server running
	}

	// Open the PID file
	fd, err := os.Open(expandedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, errors.Wrap(err, "failed to open PID file")
	}
	defer fd.Close()

	// Use fcntl F_GETLK to query the lock holder
	lock := syscall.Flock_t{
		Type:   syscall.F_WRLCK, // We want to test for a write lock
		Whence: 0,
		Start:  0,
		Len:    0, // 0 means entire file
	}

	// F_GETLK: If lock would succeed, Type is set to F_UNLCK
	// If lock would block, Type remains F_WRLCK and Pid is set to holder's PID
	if err := syscall.FcntlFlock(fd.Fd(), syscall.F_GETLK, &lock); err != nil {
		return 0, errors.Wrap(err, "failed to query lock")
	}

	if lock.Type == syscall.F_UNLCK {
		// No lock held
		return 0, nil
	}

	// Lock is held, return the PID
	return int(lock.Pid), nil
}
