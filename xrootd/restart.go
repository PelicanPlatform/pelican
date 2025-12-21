//go:build !windows

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

package xrootd

import (
	"context"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

var (
	// restartMutex ensures only one restart operation happens at a time
	restartMutex sync.Mutex

	// Store launcher information for restart
	currentLaunchers []daemon.Launcher
	currentEgrp      *errgroup.Group
	currentCallback  func(int)
	isCache          bool
	useCMSD          bool
	privileged       bool
)

// StoreRestartInfo stores the information needed for restarting XRootD
// This should be called during initial launch
func StoreRestartInfo(launchers []daemon.Launcher, egrp *errgroup.Group, callback func(int), cache bool, cmsd bool, priv bool) {
	currentLaunchers = launchers
	currentEgrp = egrp
	currentCallback = callback
	isCache = cache
	useCMSD = cmsd
	privileged = priv
}

// RestartXrootd gracefully restarts the XRootD server processes
// This function is thread-safe and will prevent concurrent restart attempts
func RestartXrootd(ctx context.Context, oldPids []int) (newPids []int, err error) {
	// Acquire the restart mutex to prevent concurrent restarts
	if !restartMutex.TryLock() {
		return nil, errors.New("XRootD restart already in progress")
	}
	defer restartMutex.Unlock()
	defer daemon.SetExpectedRestart(false)

	log.Info("Beginning XRootD restart sequence")

	daemon.SetExpectedRestart(true)
	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusShuttingDown, "XRootD restart in progress")
	if useCMSD {
		metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusShuttingDown, "CMSD restart in progress")
	}

	if len(currentLaunchers) == 0 {
		log.Warn("Restart called without stored launchers; proceeding with reconfiguration")
	}

	// Step 1: Gracefully shutdown existing XRootD processes
	log.Debug("Sending SIGTERM to existing XRootD processes")
	for _, pid := range oldPids {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
			log.WithError(err).Warnf("Failed to send SIGTERM to PID %d", pid)
		}
	}

	// Wait for graceful shutdown with timeout
	shutdownTimeout := param.Xrootd_ShutdownTimeout.GetDuration()
	shutdownDeadline := time.Now().Add(shutdownTimeout)
	for time.Now().Before(shutdownDeadline) {
		allDead := true
		for _, pid := range oldPids {
			process, err := os.FindProcess(pid)
			if err == nil && process != nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					allDead = false
					break
				}
			}
		}
		if allDead {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Force kill any remaining processes
	for _, pid := range oldPids {
		process, err := os.FindProcess(pid)
		if err == nil && process != nil {
			if err := process.Signal(syscall.Signal(0)); err == nil {
				log.Warnf("Force killing PID %d that did not respond to SIGTERM", pid)
				if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
					log.WithError(err).Errorf("Failed to send SIGKILL to PID %d", pid)
				}
			}
		}
	}

	// Step 2: Reconfigure XRootD runtime directory
	log.Debug("Reconfiguring XRootD runtime directory")
	configPath, err := ConfigXrootd(ctx, !isCache)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to reconfigure XRootD")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "XRootD stopped during restart")
	if useCMSD {
		metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusCritical, "CMSD stopped during restart")
	}

	// Step 3: Configure new launchers with updated configuration
	log.Debug("Configuring new XRootD launchers")
	newLaunchers, err := ConfigureLaunchers(privileged, configPath, useCMSD, isCache)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to configure XRootD launchers")
	}

	// Update the stored launchers for future restarts
	currentLaunchers = newLaunchers

	// Step 4: Launch new XRootD daemons
	log.Info("Launching new XRootD daemons")
	newPids, err = LaunchDaemons(ctx, newLaunchers, currentEgrp, currentCallback)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to launch XRootD daemons")
	}

	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "XRootD restart complete")
	if useCMSD {
		metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusOK, "CMSD restart complete")
	}

	log.Infof("XRootD restart complete with new PIDs: %v", newPids)
	return newPids, nil
}

// RestartServer is a helper function that restarts XRootD and updates the server's PIDs
// This avoids circular dependencies by being in the xrootd package
func RestartServer(ctx context.Context, server server_structs.XRootDServer) error {
	oldPids := server.GetPids()
	newPids, err := RestartXrootd(ctx, oldPids)
	if err != nil {
		return err
	}
	server.SetPids(newPids)
	return nil
}
