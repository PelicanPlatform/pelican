/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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

package origin_ui

import (
	"context"
	"time"

	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/utils"
	log "github.com/sirupsen/logrus"
)

func doSelfMonitor(ctx context.Context) {
	log.Debug("Starting a new self-test monitoring cycle")
	fileTests := utils.TestFileTransferImpl{}
	ok, err := fileTests.RunTests(ctx, param.Origin_Url.GetString(), param.Origin_Url.GetString(), utils.OriginSelfFileTest)
	if ok && err == nil {
		log.Debugln("Self-test monitoring cycle succeeded at", time.Now().Format(time.UnixDate))
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusOK, "Self-test monitoring cycle succeeded at "+time.Now().Format(time.RFC3339))
	} else {
		log.Warningln("Self-test monitoring cycle failed: ", err)
		metrics.SetComponentHealthStatus(metrics.OriginCache_XRootD, metrics.StatusCritical, "Self-test monitoring cycle failed: "+err.Error())
	}
}

// Start self-test monitoring of the origin.  This will upload, download, and delete
// a generated filename every 15 seconds to the local origin.  On failure, it will
// set the xrootd component's status to critical.
func PeriodicSelfTest(ctx context.Context) error {
	firstRound := time.After(5 * time.Second)
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-firstRound:
			doSelfMonitor(ctx)
		case <-ticker.C:
			doSelfMonitor(ctx)
		case <-ctx.Done():
			return nil
		}
	}
}
