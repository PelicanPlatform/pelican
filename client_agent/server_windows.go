//go:build windows

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
	"strconv"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// verifyDirectoryOwnership checks that the directory is owned by the specified user
// On Windows, we can't easily verify ownership in the same way, so we just log a warning
func verifyDirectoryOwnership(path string, expectedUID int) error {
	log.Warn("Database directory ownership verification not implemented on Windows")
	return nil
}

// verifyOwnership verifies that the directory (represented by FileInfo) is owned by the expected UID
// On Windows, ownership verification is not implemented
func verifyOwnership(info os.FileInfo, expectedUID int) error {
	log.Warn("Directory ownership verification not implemented on Windows")
	return nil
}

// acquireServerLock acquires an exclusive lock on the PID file
// On Windows, we use a simple PID file without flock support
// Note: This can result in stale PIDs after system reboot
// timeout parameter is ignored on Windows for signature compatibility
func acquireServerLock(pidPath string, timeout time.Duration) (*os.File, error) {
	expandedPath, err := ExpandPath(pidPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand PID path")
	}

	// Ensure PID directory exists with secure permissions
	pidDir := filepath.Dir(expandedPath)
	// Note: On Windows, we don't use the returned Root (not available)
	if _, err := ensureSecureDirectory(pidDir); err != nil {
		return nil, errors.Wrap(err, "failed to ensure secure PID directory")
	}

	// Check if PID file already exists
	if existingPID, err := os.ReadFile(expandedPath); err == nil {
		// File exists, check if the process is still running
		if pid, parseErr := strconv.Atoi(string(existingPID)); parseErr == nil {
			// Check if process exists (this is a simple check and may have false positives)
			if process, findErr := os.FindProcess(pid); findErr == nil {
				// On Windows, FindProcess always succeeds, so we can't reliably detect stale PIDs
				// We'll assume the server is running if the PID file exists
				process.Release()
				return nil, errors.Errorf("server appears to be running (PID %d from PID file)", pid)
			}
		}
		// PID file exists but process is not running, remove stale PID file
		log.Warnf("Removing stale PID file: %s", expandedPath)
		if rmErr := os.Remove(expandedPath); rmErr != nil {
			log.Warnf("Failed to remove stale PID file: %v", rmErr)
		}
	}

	// Create new PID file
	fd, err := os.OpenFile(expandedPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create PID file")
	}

	// Write our PID to the file
	if _, err := fd.WriteString(fmt.Sprintf("%d", os.Getpid())); err != nil {
		fd.Close()
		return nil, errors.Wrap(err, "failed to write PID to file")
	}

	log.Infof("Created PID file at %s", expandedPath)
	return fd, nil
}

// getServerPIDFromLock queries the PID from the PID file
// On Windows, this is a simple file read (no flock support)
// Returns 0 if no PID file exists
func getServerPIDFromLock(pidPath string) (int, error) {
	expandedPath, err := ExpandPath(pidPath)
	if err != nil {
		return 0, errors.Wrap(err, "failed to expand PID path")
	}

	// Check if PID file exists
	if _, err := os.Stat(expandedPath); os.IsNotExist(err) {
		return 0, nil // No PID file = no server running
	}

	// Read PID from file
	pidBytes, err := os.ReadFile(expandedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, errors.Wrap(err, "failed to read PID file")
	}

	pid, err := strconv.Atoi(string(pidBytes))
	if err != nil {
		return 0, errors.Wrap(err, "failed to parse PID from file")
	}

	return pid, nil
}
