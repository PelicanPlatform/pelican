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

type restartInfo struct {
	ctx             context.Context
	launchers       []daemon.Launcher
	egrp            *errgroup.Group
	callback        func(int)
	preRestartHook  func(ctx context.Context)
	isCache         bool
	useCMSD         bool
	privileged      bool
	pids            []int
}

var (
	// restartMutex ensures only one restart operation happens at a time
	restartMutex sync.Mutex

	// restartInfosMu guards access to restartInfos so callers can update PID snapshots.
	restartInfosMu sync.RWMutex

	// Store launcher information for restart; one entry per server role (origin/cache)
	restartInfos []restartInfo
)

// ResetRestartState clears restart tracking and callbacks for tests.
func ResetRestartState() {
	restartMutex = sync.Mutex{}
	restartInfosMu = sync.RWMutex{}
	restartInfos = nil
	ClearXrootdDaemons()
}

// StoreRestartInfo stores the information needed for restarting XRootD
// This should be called during initial launch after PIDs are known.
func StoreRestartInfo(launchers []daemon.Launcher, pids []int, egrp *errgroup.Group, callback func(int), ctx context.Context, cache bool, cmsd bool, priv bool, preRestartHook func(ctx context.Context)) {
	info := restartInfo{
		ctx:            ctx,
		launchers:      launchers,
		egrp:           egrp,
		callback:       callback,
		preRestartHook: preRestartHook,
		isCache:        cache,
		useCMSD:        cmsd,
		privileged:     priv,
		pids:           append([]int(nil), pids...),
	}

	// Replace any existing entry for the same server role; otherwise append.
	restartInfosMu.Lock()
	replaced := false
	for idx := range restartInfos {
		if restartInfos[idx].isCache == cache {
			restartInfos[idx] = info
			replaced = true
			break
		}
	}

	if !replaced {
		restartInfos = append(restartInfos, info)
	}
	restartInfosMu.Unlock()
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
	hasCMSD := false
	for _, info := range restartInfos {
		if info.useCMSD {
			hasCMSD = true
			break
		}
	}
	if hasCMSD {
		metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusShuttingDown, "CMSD restart in progress")
	}

	restartInfosMu.RLock()
	if len(restartInfos) == 0 {
		restartInfosMu.RUnlock()
		return nil, errors.New("restart requested before storing launcher information")
	}

	storedInfos := make([]restartInfo, len(restartInfos))
	copy(storedInfos, restartInfos)
	restartInfosMu.RUnlock()

	if len(oldPids) == 0 {
		oldPids = collectTrackedPIDs(storedInfos)
	}
	if len(oldPids) == 0 {
		return nil, errors.New("restart requested but no tracked PIDs are available")
	}

	// Run any pre-restart hooks (e.g., advertise shutdown to the Director and
	// wait for in-flight transfers to drain) before sending signals.
	for _, info := range storedInfos {
		if info.preRestartHook != nil {
			info.preRestartHook(info.ctx)
		}
	}

	// Step 1: Gracefully shutdown existing XRootD processes
	log.Debug("Sending SIGTERM to existing XRootD processes")
	for _, pid := range oldPids {
		if pid <= 1 {
			log.Warnf("Skipping restart signal for critical PID %d", pid)
			continue
		}
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
		time.Sleep(50 * time.Millisecond)
	}

	// Force kill any remaining processes
	for _, pid := range oldPids {
		if pid <= 1 {
			continue
		}
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
	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "XRootD stopped during restart")

	newPids = make([]int, 0, len(oldPids))
	updatedInfos := make([]restartInfo, 0, len(storedInfos))

	for _, info := range storedInfos {
		configPath, cfgErr := ConfigXrootd(ctx, !info.isCache)
		if cfgErr != nil {
			return nil, errors.Wrap(cfgErr, "Failed to reconfigure XRootD")
		}

		if info.useCMSD {
			metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusCritical, "CMSD stopped during restart")
		}

		log.Debug("Configuring new XRootD launchers")
		newLaunchers, cfgLaunchErr := ConfigureLaunchers(info.privileged, configPath, info.useCMSD, info.isCache)
		if cfgLaunchErr != nil {
			return nil, errors.Wrap(cfgLaunchErr, "Failed to configure XRootD launchers")
		}

		log.Info("Launching new XRootD daemons")
		pids, launchErr := LaunchDaemons(info.ctx, newLaunchers, info.egrp, info.callback)
		if launchErr != nil {
			return nil, errors.Wrap(launchErr, "Failed to launch XRootD daemons")
		}

		info.launchers = newLaunchers
		info.pids = append([]int(nil), pids...)
		updatedInfos = append(updatedInfos, info)
		newPids = append(newPids, pids...)

		if info.useCMSD {
			metrics.SetComponentHealthStatus(metrics.OriginCache_CMSD, metrics.StatusOK, "CMSD restart complete")
		}
	}

	restartInfosMu.Lock()
	restartInfos = updatedInfos
	restartInfosMu.Unlock()

	metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "XRootD restart complete")

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

func collectTrackedPIDs(infos []restartInfo) []int {
	var pids []int
	for _, info := range infos {
		pids = append(pids, info.pids...)
	}
	return pids
}

// GetTrackedPIDs returns a snapshot of currently tracked XRootD PIDs
// This is useful for tests that need to verify XRootD restarts
func GetTrackedPIDs() []int {
	restartInfosMu.RLock()
	defer restartInfosMu.RUnlock()
	return collectTrackedPIDs(restartInfos)
}
