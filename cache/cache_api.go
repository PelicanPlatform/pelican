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
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// Check for the sentinel file
func CheckCacheSentinelLocation() error {
	if param.Cache_SentinelLocation.IsSet() {
		sentinelPath := param.Cache_SentinelLocation.GetString()
		dataLoc := param.Cache_LocalRoot.GetString()
		sentinelPath = path.Clean(sentinelPath)
		if path.Base(sentinelPath) != sentinelPath {
			return errors.Errorf("invalid Cache.SentinelLocation path. File must not contain a directory. Got %s", sentinelPath)
		}
		fullPath := filepath.Join(dataLoc, sentinelPath)
		_, err := os.Stat(fullPath)
		if err != nil {
			return errors.Wrapf(err, "failed to open Cache.SentinelLocation %s. Directory check failed", fullPath)
		}
	}
	return nil
}

// Periodically scan the /<Cache.LocalRoot>/pelican/monitoring directory to clean up test files
// TODO: Director test files should be under /pelican/monitoring/directorTest and the file names
// should have director-test- as the prefix
func LaunchDirectorTestFileCleanup(ctx context.Context) {
	server_utils.LaunchWatcherMaintenance(ctx,
		[]string{filepath.Join(param.Cache_LocalRoot.GetString(), "pelican", "monitoring")},
		"cache director-based health test clean up",
		time.Minute,
		func(notifyEvent bool) error {
			// We run this function regardless of notifyEvent to do the cleanup
			dirPath := filepath.Join(param.Cache_LocalRoot.GetString(), "pelican", "monitoring")
			dirInfo, err := os.Stat(dirPath)
			if err != nil {
				return err
			} else {
				if !dirInfo.IsDir() {
					return errors.New("monitoring path is not a directory: " + dirPath)
				}
			}
			dirItems, err := os.ReadDir(dirPath)
			if err != nil {
				return err
			}
			directorItems := []fs.DirEntry{}
			for _, item := range dirItems {
				if item.IsDir() {
					continue
				}
				// Ignore self tests. They should be handled automatically by self test logic
				if strings.HasPrefix(item.Name(), selfTestPrefix) {
					continue
				}
				directorItems = append(directorItems, item)
			}
			if len(directorItems) <= 2 { // At mininum there are the test file and .cinfo file, and we don't want to remove the last two
				return nil
			}
			for idx, item := range directorItems {
				// For all but the latest two files (test file and its .cinfo file)
				// os.ReadDir sorts dirEntries in order of file names. Since our test file names are timestamped and is string comparable,
				// the last two files should be the latest test files, which we want to keep
				if idx < len(dirItems)-2 {
					err := os.Remove(filepath.Join(dirPath, item.Name()))
					if err != nil {
						return err
					}
				}
			}
			return nil
		},
	)
}
