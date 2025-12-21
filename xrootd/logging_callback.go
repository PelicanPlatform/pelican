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
	"context"
	"time"

	log "github.com/sirupsen/logrus"

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

	restartOrigin, restartCache := detectLoggingChange(oldConfig, newConfig)
	if !restartOrigin && !restartCache {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), param.Xrootd_ShutdownTimeout.GetDuration()+time.Minute)
	defer cancel()

	_, err := restartXrootdFn(ctx, nil)
	if err != nil {
		log.WithError(err).Error("Failed to restart XRootD after logging configuration change")
		return
	}
}

func detectLoggingChange(oldConfig, newConfig *param.Config) (originChanged, cacheChanged bool) {
	// Origin logging parameters
	if oldConfig.Logging.Origin.Cms != newConfig.Logging.Origin.Cms ||
		oldConfig.Logging.Origin.Http != newConfig.Logging.Origin.Http ||
		oldConfig.Logging.Origin.Ofs != newConfig.Logging.Origin.Ofs ||
		oldConfig.Logging.Origin.Oss != newConfig.Logging.Origin.Oss ||
		oldConfig.Logging.Origin.Scitokens != newConfig.Logging.Origin.Scitokens ||
		oldConfig.Logging.Origin.Xrd != newConfig.Logging.Origin.Xrd ||
		oldConfig.Logging.Origin.Xrootd != newConfig.Logging.Origin.Xrootd {
		originChanged = true
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
		cacheChanged = true
	}

	return
}

// ClearXrootdDaemons clears registered servers and resets the logging callback.
// This is primarily intended for testing.
func ClearXrootdDaemons() {
	xrootdCallbackRegd = false
	restartXrootdFn = RestartXrootd
}
