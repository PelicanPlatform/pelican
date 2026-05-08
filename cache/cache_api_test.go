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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestCheckCacheSentinelLocation(t *testing.T) {
	t.Run("sentinel-not-set", func(t *testing.T) {
		server_utils.ResetTestState()
		err := CheckCacheSentinelLocation()
		assert.NoError(t, err)
	})

	t.Run("sentinel-contains-dir", func(t *testing.T) {
		server_utils.ResetTestState()
		require.NoError(t, param.Cache_SentinelLocation.Set("/test.txt"))
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Equal(t, "invalid Cache.SentinelLocation path. File must not contain a directory. Got /test.txt", err.Error())
	})

	t.Run("sentinel-dne", func(t *testing.T) {
		tmpDir := t.TempDir()
		server_utils.ResetTestState()
		require.NoError(t, param.Cache_SentinelLocation.Set("test.txt"))
		require.NoError(t, param.Cache_NamespaceLocation.Set(tmpDir))
		err := CheckCacheSentinelLocation()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open Cache.SentinelLocation")
	})

	t.Run("sentinel-exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		server_utils.ResetTestState()

		require.NoError(t, param.Cache_SentinelLocation.Set("test.txt"))
		require.NoError(t, param.Cache_NamespaceLocation.Set(tmpDir))

		file, err := os.Create(filepath.Join(tmpDir, "test.txt"))
		require.NoError(t, err)
		file.Close()

		err = CheckCacheSentinelLocation()
		require.NoError(t, err)
	})
}

// Helper to create a file with the given name in the given directory
func createTestFile(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	f.Close()
}

func TestCleanupDirectorTestFiles(t *testing.T) {
	t.Run("nonexistent-dir-is-noop", func(t *testing.T) {
		err := cleanupDirectorTestFiles(filepath.Join(t.TempDir(), "does-not-exist"))
		assert.NoError(t, err)
	})

	t.Run("empty-dir-is-noop", func(t *testing.T) {
		dirTestPath := t.TempDir()
		err := cleanupDirectorTestFiles(dirTestPath)
		assert.NoError(t, err)
	})

	t.Run("removes-old-daily-subdirs-keeps-today", func(t *testing.T) {
		dirTestPath := t.TempDir()
		todayStr := time.Now().Format("2006-01-02")
		yesterdayStr := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		oldDayStr := "2025-01-15"

		// Create old day directories with files
		for _, day := range []string{yesterdayStr, oldDayStr} {
			dayDir := filepath.Join(dirTestPath, day)
			require.NoError(t, os.Mkdir(dayDir, 0755))
			createTestFile(t, dayDir, "director-test-"+day+"T10:00:00Z.txt")
			createTestFile(t, dayDir, "director-test-"+day+"T10:00:00Z.txt.cinfo")
		}

		// Create today's directory with multiple files
		todayDir := filepath.Join(dirTestPath, todayStr)
		require.NoError(t, os.Mkdir(todayDir, 0755))
		createTestFile(t, todayDir, "director-test-"+todayStr+"T08:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T08:00:00Z.txt.cinfo")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T09:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T09:00:00Z.txt.cinfo")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(dirTestPath)
		require.NoError(t, err)

		// Old day directories should be gone
		_, err = os.Stat(filepath.Join(dirTestPath, yesterdayStr))
		assert.True(t, os.IsNotExist(err), "yesterday's directory should be removed")
		_, err = os.Stat(filepath.Join(dirTestPath, oldDayStr))
		assert.True(t, os.IsNotExist(err), "old day directory should be removed")

		// Today's directory should still exist with only the last 2 files
		todayEntries, err := os.ReadDir(todayDir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(todayEntries), "today's dir should have 2 files (latest test + .cinfo)")
		assert.Equal(t, "director-test-"+todayStr+"T10:00:00Z.txt", todayEntries[0].Name())
		assert.Equal(t, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo", todayEntries[1].Name())
	})

	t.Run("removes-all-legacy-flat-files", func(t *testing.T) {
		dirTestPath := t.TempDir()

		// Create legacy flat files (old format without daily subdirs)
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt.cinfo")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt.cinfo")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(dirTestPath)
		require.NoError(t, err)

		entries, err := os.ReadDir(dirTestPath)
		require.NoError(t, err)
		// All legacy flat files should be removed
		assert.Equal(t, 0, len(entries))
	})

	t.Run("handles-mixed-legacy-and-daily-subdirs", func(t *testing.T) {
		dirTestPath := t.TempDir()
		todayStr := time.Now().Format("2006-01-02")

		// Create legacy flat files
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt")

		// Create today's subdirectory
		todayDir := filepath.Join(dirTestPath, todayStr)
		require.NoError(t, os.Mkdir(todayDir, 0755))
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(dirTestPath)
		require.NoError(t, err)

		// All legacy flat files should be removed
		entries, err := os.ReadDir(dirTestPath)
		require.NoError(t, err)
		legacyCount := 0
		for _, e := range entries {
			if !e.IsDir() {
				legacyCount++
			}
		}
		assert.Equal(t, 0, legacyCount)

		// Today's subdir files are kept (only 2, within threshold)
		todayEntries, err := os.ReadDir(todayDir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(todayEntries))
	})

	t.Run("ignores-non-date-subdirs", func(t *testing.T) {
		dirTestPath := t.TempDir()

		// Create a non-date subdirectory — should be left alone
		otherDir := filepath.Join(dirTestPath, "some-other-dir")
		require.NoError(t, os.Mkdir(otherDir, 0755))
		createTestFile(t, otherDir, "somefile.txt")

		err := cleanupDirectorTestFiles(dirTestPath)
		require.NoError(t, err)

		// The non-date dir should still exist
		_, err = os.Stat(otherDir)
		assert.NoError(t, err, "non-date subdirectory should not be removed")
	})
}

func TestCleanupOldFilesInDir(t *testing.T) {
	t.Run("keeps-files-when-under-threshold", func(t *testing.T) {
		dir := t.TempDir()
		createTestFile(t, dir, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dir, "director-test-2025-01-10T10:00:00Z.txt.cinfo")

		err := cleanupOldFilesInDir(dir, 2)
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(entries))
	})

	t.Run("removes-oldest-files", func(t *testing.T) {
		dir := t.TempDir()
		createTestFile(t, dir, "director-test-2025-01-10T08:00:00Z.txt")
		createTestFile(t, dir, "director-test-2025-01-10T09:00:00Z.txt")
		createTestFile(t, dir, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dir, "director-test-2025-01-10T11:00:00Z.txt")

		err := cleanupOldFilesInDir(dir, 2)
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(entries))
		assert.Equal(t, "director-test-2025-01-10T10:00:00Z.txt", entries[0].Name())
		assert.Equal(t, "director-test-2025-01-10T11:00:00Z.txt", entries[1].Name())
	})
}
