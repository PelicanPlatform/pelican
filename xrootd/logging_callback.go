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
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
)

var (
	// restartXrootdFn allows tests to stub restart behavior.
	restartXrootdFn = RestartXrootd

	xrootdCallbackRegd bool
)

// RegisterXrootdLoggingCallback installs the callback (once) to trigger a restart
// when any XRootD logging parameter changes.
func RegisterXrootdLoggingCallback() {
	if xrootdCallbackRegd {
		return
	}
	param.RegisterCallback("xrootd-logging", handleXrootdLoggingChange)
	xrootdCallbackRegd = true
}

func handleXrootdLoggingChange(oldConfig, newConfig *param.Config) {
	if oldConfig == nil || newConfig == nil {
		return
	}

	restartOrigin, restartCache := logging.DetectXrootdLoggingChange(oldConfig, newConfig)
	if !restartOrigin && !restartCache {
		return
	}

	// Assume that restarting XRootD will require a graceful shutdown
	// and a correspondingly graceful startup.
	// For the timeout, make a best-guess as to how long that will take.
	ctx, cancel := context.WithTimeout(context.Background(), param.Xrootd_ShutdownTimeout.GetDuration()+time.Minute)
	defer cancel()

	_, err := restartXrootdFn(ctx, nil)
	if err != nil {
		log.WithError(err).Error("Failed to restart XRootD after logging configuration change")
		return
	}
}

// ClearXrootdDaemons clears registered servers and resets the logging callback.
// This is primarily intended for testing.
func ClearXrootdDaemons() {
	xrootdCallbackRegd = false
	restartXrootdFn = RestartXrootd
}
