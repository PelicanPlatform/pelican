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

package cache

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"golang.org/x/sync/errgroup"
)

var (
	notificationChan = make(chan bool)
)

func RegisterCacheAPI(router *gin.Engine, ctx context.Context, egrp *errgroup.Group) {
	// start the timer for the director test report timeout
	server_utils.LaunchPeriodicDirectorTimeout(ctx, egrp, notificationChan)

	group := router.Group("/api/v1.0/cache")
	{
		group.POST("/directorTest", func(ctx *gin.Context) { server_utils.HandleDirectorTestResponse(ctx, notificationChan) })
	}
}

func LaunchDirectorTestFileCleanup(ctx context.Context) {
	server_utils.LaunchWatcherMaintenance(ctx,
		[]string{filepath.Join(param.Cache_DataLocation.GetString(), "pelican", "monitoring")},
		"cache director-based health test clean up",
		time.Minute,
		func(notifyEvent bool) error {
			if !notifyEvent {
				return nil
			} else {
				dirPath := filepath.Join(param.Cache_DataLocation.GetString(), "pelican", "monitoring")
				dirInfo, err := os.Stat(dirPath)
				if err != nil {
					return nil
				} else {
					if !dirInfo.IsDir() {
						return errors.New("monitoring path is not a directory: " + dirPath)
					}
				}
				dirItems, err := os.ReadDir(dirPath)
				if err != nil {
					return err
				}
				if len(dirItems) <= 2 { // At mininum there are the test file and .cinfo file, and we don't want to remove the last two
					return nil
				}
				for idx, item := range dirItems {
					if idx <= len(dirItems)-1-2 { // For all but the latest two files (test file and its .cinfo file)
						err := os.Remove(filepath.Join(dirPath, item.Name()))
						if err != nil {
							return err
						}
					}
				}
				return nil
			}
		},
	)
}
