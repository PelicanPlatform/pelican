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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
)

// DaemonConfig holds configuration for daemon mode
type DaemonConfig struct {
	SocketPath  string
	PidFile     string
	LogLocation string
	MaxJobs     int
	DbLocation  string
	IdleTimeout time.Duration
	ExecPath    string // Optional: override executable path (primarily for testing)
}

// StartDaemon spawns the server as a background daemon
// It acquires the lock before forking to ensure only one daemon starts
// Returns the PID of the daemon process
func StartDaemon(config DaemonConfig) (int, error) {
	// Expand paths
	socketPath, err := ExpandPath(config.SocketPath)
	if err != nil {
		return 0, errors.Wrap(err, "failed to expand socket path")
	}

	pidFile, err := ExpandPath(config.PidFile)
	if err != nil {
		return 0, errors.Wrap(err, "failed to expand PID file path")
	}

	logLocation := config.LogLocation
	if logLocation == "" {
		// Check if standard Pelican logging is configured
		logLocation = param.Logging_LogLocation.GetString()
		if logLocation == "" {
			// Default to ~/.pelican/client-agent.log for daemon mode
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return 0, errors.Wrap(err, "failed to get home directory")
			}
			logLocation = filepath.Join(homeDir, ".pelican", "client-agent.log")
		}
	}

	logLocation, err = ExpandPath(logLocation)
	if err != nil {
		return 0, errors.Wrap(err, "failed to expand log file path")
	}

	// Ensure log directory exists
	logDir := filepath.Dir(logLocation)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return 0, errors.Wrap(err, "failed to create log directory")
	}

	if config.DbLocation == "" {
		config.DbLocation = param.ClientAgent_DbLocation.GetString()
	}
	if config.DbLocation == "" {
		// Default to ~/.pelican/client-agent.db
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return 0, errors.Wrap(err, "failed to get user home directory")
		}
		config.DbLocation = filepath.Join(homeDir, ".pelican", "client-agent.db")
	}

	// Check if server is already running
	running, err := CheckServerRunning(socketPath)
	if err != nil {
		return 0, errors.Wrap(err, "failed to check server status")
	}
	if running {
		// Try to get PID
		pid, _ := GetServerPID(pidFile)
		if pid > 0 {
			return 0, errors.Errorf("server is already running (PID %d)", pid)
		}
		return 0, errors.New("server is already running")
	}

	// Acquire lock BEFORE forking to prevent race conditions
	// This ensures only one daemon starts even if multiple clients try simultaneously
	pidLockFd, err := acquireServerLock(pidFile, 5*time.Second)
	if err != nil {
		return 0, err
	}
	defer func() {
		// We'll pass the lock to the child, so only close on error
		if pidLockFd != nil {
			pidLockFd.Close()
		}
	}()

	// Get executable path - use override if provided (for testing), otherwise current executable
	execPath := config.ExecPath
	if execPath == "" {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			return 0, errors.Wrap(err, "failed to get executable path")
		}
	}

	// Build command arguments
	args := []string{
		"client-agent", "start",
		"--socket", socketPath,
		"--pid-file", pidFile,
	}

	if config.MaxJobs > 0 {
		args = append(args, "--max-jobs", fmt.Sprintf("%d", config.MaxJobs))
	}

	if config.DbLocation != "" {
		args = append(args, "--database", config.DbLocation)
	}

	if logLocation != "" {
		args = append(args, "--log", logLocation)
	}

	// Add daemon-specific flag (internal use)
	args = append(args, "--daemon-mode=true")

	// Prepare command
	cmd := exec.Command(execPath, args...)

	// Set up file descriptors for the daemon
	// stdout and stderr go to log file
	logFd, err := os.OpenFile(logLocation, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 0, errors.Wrap(err, "failed to open log file")
	}
	defer logFd.Close()

	cmd.Stdout = logFd
	cmd.Stderr = logFd
	cmd.Stdin = nil

	// Set process attributes for daemon
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create new session
	}

	// Inherit the lock file descriptor
	// This is critical - the child must inherit the lock
	cmd.ExtraFiles = []*os.File{pidLockFd}

	// Set environment variable to tell child about inherited lock FD
	// File descriptor 3 is the first extra file (0=stdin, 1=stdout, 2=stderr)
	cmd.Env = append(os.Environ(), "_PELICAN_INTERNAL_LOCK_FD=3")

	// Set idle timeout if configured
	if config.IdleTimeout > 0 {
		cmd.Env = append(cmd.Env, fmt.Sprintf("PELICAN_CLIENTAGENT_IDLETIMEOUT=%s", config.IdleTimeout.String()))
	}

	// Start the daemon process
	log.Debugf("Spawning daemon process with args: %v", args)
	log.Debugf("Log file will be: %s", logLocation)
	log.Debugf("Socket path: %s, PID file: %s", socketPath, pidFile)
	if err := cmd.Start(); err != nil {
		return 0, errors.Wrap(err, "failed to start daemon")
	}

	daemonPID := cmd.Process.Pid
	log.Infof("Started client API daemon (PID: %d)", daemonPID)
	log.Infof("Log file: %s", logLocation)
	log.Infoln("Location of database:", config.DbLocation)

	// Don't close the lock - the child inherited it
	pidLockFd = nil

	// Don't wait for the process - it's a daemon
	return daemonPID, nil
}

// IsDaemonMode checks if we're running in daemon mode
func IsDaemonMode() bool {
	_, exists := os.LookupEnv("_PELICAN_INTERNAL_LOCK_FD")
	return exists
}

// InheritDaemonLock inherits the lock file descriptor from parent process
// This must be called early in daemon startup
func InheritDaemonLock() (*os.File, error) {
	log.Debugln("Attempting to inherit daemon lock from parent process")
	fdStr := os.Getenv("_PELICAN_INTERNAL_LOCK_FD")
	if fdStr == "" {
		log.Error("_PELICAN_INTERNAL_LOCK_FD environment variable not set")
		return nil, errors.New("_PELICAN_INTERNAL_LOCK_FD not set")
	}
	log.Debugf("Lock FD environment variable: %s", fdStr)

	// File descriptor 3 was passed as the first ExtraFile
	// We need to keep it open to maintain the lock
	lockFd := os.NewFile(3, "inherited-lock")
	if lockFd == nil {
		log.Error("os.NewFile(3) returned nil - FD 3 may not be valid")
		return nil, errors.New("failed to inherit lock file descriptor")
	}

	// Try to get file info to verify the FD is valid
	if stat, err := lockFd.Stat(); err != nil {
		log.Errorf("Failed to stat inherited lock FD: %v", err)
		return nil, errors.Wrap(err, "inherited lock FD is not valid")
	} else {
		log.Debugf("Inherited lock FD is valid, file: %s", stat.Name())
	}

	// The lock is already held (inherited from parent)
	// We cannot verify it by trying to acquire it again because flock is idempotent
	// within the same process - trying to lock an already-held lock succeeds.
	// We simply trust that the parent correctly passed us the locked FD.
	log.Debugln("Successfully inherited lock file descriptor from parent process")
	return lockFd, nil
}
