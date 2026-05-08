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
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// Check for the sentinel file
func CheckCacheSentinelLocation() error {
	if param.Cache_SentinelLocation.IsSet() {
		sentinelPath := param.Cache_SentinelLocation.GetString()
		dataLoc := param.Cache_NamespaceLocation.GetString()
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

// dateSubdirPattern matches YYYY-MM-DD directory names used by daily-nested director test files
var dateSubdirPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// cleanupDirectorTestFiles removes old director test files from the directorTest directory.
// It handles both legacy flat files (director-test-*.txt directly in directorTest/) and
// daily-nested subdirectories (directorTest/YYYY-MM-DD/director-test-*.txt).
//
// For daily subdirectories: removes all directories older than today entirely, and within
// today's directory keeps only the two most recent files (test file + .cinfo).
// For legacy flat files: removes all if they exist.
func cleanupDirectorTestFiles(dirTestPath string) error {
	dirInfo, err := os.Stat(dirTestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Nothing to clean up yet
		}
		return err
	}
	if !dirInfo.IsDir() {
		return errors.New("director test path is not a directory: " + dirTestPath)
	}

	entries, err := os.ReadDir(dirTestPath)
	if err != nil {
		return err
	}

	todayStr := time.Now().Format("2006-01-02")

	// Collect legacy flat files (director-test-* files sitting directly in directorTest/)
	var legacyFiles []os.DirEntry
	for _, entry := range entries {
		if entry.IsDir() {
			// Handle date subdirectories
			if !dateSubdirPattern.MatchString(entry.Name()) {
				continue
			}
			subdirPath := filepath.Join(dirTestPath, entry.Name())
			if entry.Name() < todayStr {
				// Remove entire old day directories
				if err := os.RemoveAll(subdirPath); err != nil {
					log.WithError(err).Warnf("Failed to remove old director test directory: %s", subdirPath)
				}
			} else if entry.Name() == todayStr {
				// Clean today's directory, keeping only the latest 2 files
				if err := cleanupOldFilesInDir(subdirPath, 2); err != nil {
					log.WithError(err).Warnf("Failed to clean up today's director test directory: %s", subdirPath)
				}
			}
			// Future-dated directories are left alone (shouldn't happen, but be safe)
		} else {
			// Collect legacy flat files with the director-test prefix
			if strings.HasPrefix(entry.Name(), server_utils.DirectorTest.String()) {
				legacyFiles = append(legacyFiles, entry)
			}
		}
	}

	// Clean up legacy flat files
	if len(legacyFiles) > 0 {
		for i := 0; i < len(legacyFiles); i++ {
			filePath := filepath.Join(dirTestPath, legacyFiles[i].Name())
			if err := os.Remove(filePath); err != nil {
				log.WithError(err).Warnf("Failed to remove legacy director test file: %s", filePath)
			}
		}
	}

	return nil
}

// cleanupOldFilesInDir removes all but the keepCount most recent files in a directory.
// Files are sorted by name (which includes an RFC3339 timestamp), so the last entries
// are the most recent.
func cleanupOldFilesInDir(dirPath string, keepCount int) error {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return err
	}

	var matchingFiles []os.DirEntry
	for _, entry := range entries {
		if !entry.IsDir() {
			matchingFiles = append(matchingFiles, entry)
		}
	}

	if len(matchingFiles) <= keepCount {
		return nil
	}

	for i := 0; i < len(matchingFiles)-keepCount; i++ {
		filePath := filepath.Join(dirPath, matchingFiles[i].Name())
		if err := os.Remove(filePath); err != nil {
			log.WithError(err).Warnf("Failed to remove old test file: %s", filePath)
		}
	}
	return nil
}

// Periodically scan the directorTest directory to clean up test files.
// Handles both legacy flat files and daily-nested subdirectories (YYYY-MM-DD/).
func LaunchDirectorTestFileCleanup(ctx context.Context) {
	dirTestPath := filepath.Join(param.Cache_NamespaceLocation.GetString(), server_utils.MonitoringBaseNs, server_utils.DirectorTestDir)
	server_utils.LaunchWatcherMaintenance(ctx,
		[]string{dirTestPath},
		"cache director-based health test clean up",
		time.Minute,
		func(notifyEvent bool) error {
			return cleanupDirectorTestFiles(dirTestPath)
		},
	)
}
