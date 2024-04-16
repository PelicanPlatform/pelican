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
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
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

// Remove tmp files under ${Origin_RunLocation}/export/pelican/monitoring
// from diector-based/self tests. There could be dangling files due to
// error in testing
func LaunchOriginFileTestMaintenance(ctx context.Context) {
	monitoringDir := filepath.Join(param.Origin_RunLocation.GetString(), "export", "pelican", "monitoring")

	server_utils.LaunchWatcherMaintenance(
		ctx,
		[]string{monitoringDir},
		"director-based origin tests clean up",
		1*time.Minute,
		func(notifyEvent bool) error {
			entries, err := os.ReadDir(monitoringDir)
			dirPrevFile := ""
			selfPrevFile := ""
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					fn := entry.Name()
					if strings.HasPrefix(fn, "director") {
						// Rolling basis to remove the previous item and leave the last item,
						// since the last item is the latest test file (by timestamp in the file name)
						// and that os.ReadDir sorted file name in the directory
						if dirPrevFile != "" {
							err := os.Remove(filepath.Join(monitoringDir, dirPrevFile))
							if err != nil {
								return err
							}
						}
						dirPrevFile = fn
					} else if strings.HasPrefix(fn, "self") {
						if selfPrevFile != "" {
							err := os.Remove(filepath.Join(monitoringDir, fn))
							if err != nil {
								return err
							}
						}
						selfPrevFile = fn
					} else {
						err := os.Remove(filepath.Join(monitoringDir, fn))
						if err != nil {
							return err
						}
					}
				}
			}
			return nil
		},
	)
}

func ConfigOriginTTLCache(ctx context.Context, egrp *errgroup.Group) {
	go registrationsStatus.Start()

	egrp.Go(func() error {
		<-ctx.Done()
		log.Info("Gracefully stopping origin TTL cache eviction...")
		registrationsStatus.DeleteAll()
		registrationsStatus.Stop()
		log.Info("Origin TTL cache eviction has been stopped")
		return nil
	})
}
