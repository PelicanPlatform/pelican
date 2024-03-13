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

package origin

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	// Duration to wait before timeout
	directorTimeoutDuration = 30 * time.Second

	notifyResponseOnce sync.Once
	notifyChannel      chan bool
)

// Configure XrootD directory for both self-based and director-based file transfer tests
func ConfigureXrootdMonitoringDir() error {
	pelicanMonitoringPath := filepath.Join(param.Origin_RunLocation.GetString(),
		"export", "pelican", "monitoring")

	uid, err := config.GetDaemonUID()
	if err != nil {
		return err
	}
	gid, err := config.GetDaemonGID()
	if err != nil {
		return err
	}
	username, err := config.GetDaemonUser()
	if err != nil {
		return err
	}

	err = config.MkdirAll(pelicanMonitoringPath, 0755, uid, gid)
	if err != nil {
		return errors.Wrapf(err, "Unable to create pelican file trasnfer monitoring directory %v",
			pelicanMonitoringPath)
	}
	if err = os.Chown(pelicanMonitoringPath, uid, -1); err != nil {
		return errors.Wrapf(err, "Unable to change ownership of pelican file trasnfer monitoring directory %v"+
			" to desired daemon user %v", pelicanMonitoringPath, username)
	}

	return nil
}

// Notify the periodic ticker that we have received a new response and it
// should reset
func notifyNewDirectorResponse(ctx context.Context) {
	nChan := getNotifyChannel()
	select {
	case <-ctx.Done():
		return
	case nChan <- true:
		return
	}
}

// Get the notification channel in a thread-safe manner
func getNotifyChannel() chan bool {
	notifyResponseOnce.Do(func() {
		notifyChannel = make(chan bool)
	})
	return notifyChannel
}

// Reset the timer safely
func LaunchPeriodicDirectorTimeout(ctx context.Context, egrp *errgroup.Group) {
	directorTimeoutTicker := time.NewTicker(directorTimeoutDuration)
	nChan := getNotifyChannel()

	egrp.Go(func() error {
		for {
			select {
			case <-directorTimeoutTicker.C:
				// Timer fired because no message was received in time.
				log.Warningln("No director test report received within the time limit")
				metrics.SetComponentHealthStatus(metrics.OriginCache_Director, metrics.StatusCritical, "No director test report received within the time limit")
			case <-nChan:
				log.Debugln("Got notification from director")
				directorTimeoutTicker.Reset(directorTimeoutDuration)
			case <-ctx.Done():
				log.Infoln("Director health test timeout loop has been terminated")
				return nil
			}
		}
	})
}
