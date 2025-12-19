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

package xrootd

import (
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
)

var (
	// Track running xrootd daemons for potential restart
	xrootdDaemons   []xrootdDaemonInfo
	xrootdDaemonsMu sync.RWMutex
)

type xrootdDaemonInfo struct {
	launcher daemon.Launcher
	pid      int
}

// RegisterXrootdDaemons registers the xrootd daemon launchers and PIDs
// so they can be restarted if xrootd logging configuration changes.
func RegisterXrootdDaemons(launchers []daemon.Launcher, pids []int) {
	xrootdDaemonsMu.Lock()
	defer xrootdDaemonsMu.Unlock()

	xrootdDaemons = make([]xrootdDaemonInfo, len(launchers))
	for i, launcher := range launchers {
		xrootdDaemons[i] = xrootdDaemonInfo{
			launcher: launcher,
			pid:      pids[i],
		}
	}
}

// RegisterXrootdLoggingCallback registers a callback to restart xrootd
// when xrootd-specific logging parameters change.
//
// NOTE: This is currently a placeholder. XRootD does not support configuration
// reload via SIGHUP. To properly implement this feature, we would need to:
// 1. Send SIGTERM to tear down the current XRootD processes
// 2. Wait for them to exit cleanly
// 3. Regenerate the XRootD configuration files with new logging settings
// 4. Relaunch the XRootD daemons with the new configuration
//
// This is a substantial undertaking that requires careful coordination with
// the daemon lifecycle management and server state. For now, XRootD logging
// configuration changes require a full server restart.
func RegisterXrootdLoggingCallback() {
	param.RegisterCallback("xrootd-logging", func(oldConfig, newConfig *param.Config) {
		if oldConfig == nil || newConfig == nil {
			return
		}

		// Check if any xrootd logging parameters changed
		needsRestart := false

		// Origin logging parameters
		if oldConfig.Logging.Origin.Cms != newConfig.Logging.Origin.Cms ||
			oldConfig.Logging.Origin.Http != newConfig.Logging.Origin.Http ||
			oldConfig.Logging.Origin.Ofs != newConfig.Logging.Origin.Ofs ||
			oldConfig.Logging.Origin.Oss != newConfig.Logging.Origin.Oss ||
			oldConfig.Logging.Origin.Scitokens != newConfig.Logging.Origin.Scitokens ||
			oldConfig.Logging.Origin.Xrd != newConfig.Logging.Origin.Xrd ||
			oldConfig.Logging.Origin.Xrootd != newConfig.Logging.Origin.Xrootd {
			needsRestart = true
		}

		// Cache logging parameters
		if oldConfig.Logging.Cache.Http != newConfig.Logging.Cache.Http ||
			oldConfig.Logging.Cache.Ofs != newConfig.Logging.Cache.Ofs ||
			oldConfig.Logging.Cache.Pfc != newConfig.Logging.Cache.Pfc ||
			oldConfig.Logging.Cache.Pss != newConfig.Logging.Cache.Pss ||
			oldConfig.Logging.Cache.PssSetOpt != newConfig.Logging.Cache.PssSetOpt ||
			oldConfig.Logging.Cache.Scitokens != newConfig.Logging.Cache.Scitokens ||
			oldConfig.Logging.Cache.Xrd != newConfig.Logging.Cache.Xrd ||
			oldConfig.Logging.Cache.Xrootd != newConfig.Logging.Cache.Xrootd {
			needsRestart = true
		}

		if needsRestart {
			log.Warn("XRootD logging configuration changed. Server restart required for changes to take effect.")
			// TODO: Implement proper XRootD restart mechanism
			// restartXrootdDaemons()
		}
	})
}

// TODO: Implement restartXrootdDaemons to properly tear down and relaunch XRootD
// restartXrootdDaemons would need to:
// 1. Send SIGTERM to all XRootD processes
// 2. Wait for graceful shutdown (with timeout)
// 3. Regenerate configuration files with new logging settings (call ConfigXrootd)
// 4. Relaunch daemons with new configuration
// 5. Update registered daemon info with new PIDs
//
// This requires significant refactoring to make the configuration and launch
// process repeatable and coordinated with the server lifecycle.

// ClearXrootdDaemons clears the registered xrootd daemons.
// This is primarily intended for testing.
func ClearXrootdDaemons() {
	xrootdDaemonsMu.Lock()
	defer xrootdDaemonsMu.Unlock()
	xrootdDaemons = nil
}
