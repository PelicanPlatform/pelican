//go:build !windows

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

// The fixtures in this file use RFC3339 timestamps (e.g. "T10:00:00Z") in
// filenames, matching what the cache writes in production. Windows reserves
// ":" in filenames, so these tests are excluded from Windows builds. The cache
// feature itself only runs on Linux deployments.

package cache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to create a file with the given name in the given directory
func createTestFile(t *testing.T, dir, name string) {
	t.Helper()
	f, err := os.Create(filepath.Join(dir, name))
	require.NoError(t, err)
	f.Close()
}

func TestCleanupDirectorTestFiles(t *testing.T) {
	t.Run("nonexistent-dir-is-noop", func(t *testing.T) {
		err := cleanupDirectorTestFiles(context.Background(), filepath.Join(t.TempDir(), "does-not-exist"))
		assert.NoError(t, err)
	})

	t.Run("empty-dir-is-noop", func(t *testing.T) {
		dirTestPath := t.TempDir()
		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
		assert.NoError(t, err)
	})

	t.Run("removes-old-daily-subdirs-keeps-today", func(t *testing.T) {
		dirTestPath := t.TempDir()
		todayStr := time.Now().Format("2006-01-02")
		yesterdayStr := time.Now().AddDate(0, 0, -1).Format("2006-01-02")
		oldDayStr := "2025-01-15"
		directorID := "director-1.example.com"
		directorSubtree := filepath.Join(dirTestPath, directorID)

		// Create old day directories with files inside the per-director subtree
		for _, day := range []string{yesterdayStr, oldDayStr} {
			dayDir := filepath.Join(directorSubtree, day)
			require.NoError(t, os.MkdirAll(dayDir, 0755))
			createTestFile(t, dayDir, "director-test-"+day+"T10:00:00Z.txt")
			createTestFile(t, dayDir, "director-test-"+day+"T10:00:00Z.txt.cinfo")
		}

		// Create today's directory with multiple files inside the per-director subtree
		todayDir := filepath.Join(directorSubtree, todayStr)
		require.NoError(t, os.MkdirAll(todayDir, 0755))
		createTestFile(t, todayDir, "director-test-"+todayStr+"T08:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T08:00:00Z.txt.cinfo")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T09:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T09:00:00Z.txt.cinfo")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
		require.NoError(t, err)

		// Old day directories under the director subtree should be gone
		_, err = os.Stat(filepath.Join(directorSubtree, yesterdayStr))
		assert.True(t, os.IsNotExist(err), "yesterday's directory should be removed")
		_, err = os.Stat(filepath.Join(directorSubtree, oldDayStr))
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

		// Create legacy flat files (pre-PR format with no subdirectories)
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt.cinfo")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt.cinfo")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
		require.NoError(t, err)

		entries, err := os.ReadDir(dirTestPath)
		require.NoError(t, err)
		assert.Equal(t, 0, len(entries))
	})

	t.Run("handles-legacy-flat-files-alongside-per-director-subtree", func(t *testing.T) {
		dirTestPath := t.TempDir()
		todayStr := time.Now().Format("2006-01-02")

		// Legacy flat files (pre-PR layout)
		createTestFile(t, dirTestPath, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-11T10:00:00Z.txt")
		createTestFile(t, dirTestPath, "director-test-2025-01-12T10:00:00Z.txt")

		// Current per-director subtree with today's directory
		todayDir := filepath.Join(dirTestPath, "director-1.example.com", todayStr)
		require.NoError(t, os.MkdirAll(todayDir, 0755))
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt")
		createTestFile(t, todayDir, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
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

		// Today's per-director dir is kept (only 2 files, within threshold)
		todayEntries, err := os.ReadDir(todayDir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(todayEntries))
	})

	t.Run("non-date-subdir-with-no-date-children-is-untouched", func(t *testing.T) {
		dirTestPath := t.TempDir()

		// Non-date top-level subdirs are now treated as director-id subtrees; without
		// any YYYY-MM-DD children inside, the cleanup walks in and does nothing.
		otherDir := filepath.Join(dirTestPath, "some-other-dir")
		require.NoError(t, os.Mkdir(otherDir, 0755))
		createTestFile(t, otherDir, "somefile.txt")

		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
		require.NoError(t, err)

		_, err = os.Stat(otherDir)
		assert.NoError(t, err, "non-date subdirectory should not be removed")
	})

	t.Run("trims-per-director-and-removes-old-day-dirs", func(t *testing.T) {
		dirTestPath := t.TempDir()
		todayStr := time.Now().Format("2006-01-02")
		oldDayStr := "2025-01-15"

		// Two directors, each with today's dir holding 3 .txt + 3 .cinfo files
		for _, dirID := range []string{"director-1.example.com", "director-2.example.com"} {
			todayDir := filepath.Join(dirTestPath, dirID, todayStr)
			require.NoError(t, os.MkdirAll(todayDir, 0755))
			for _, hour := range []string{"T08", "T09", "T10"} {
				createTestFile(t, todayDir, "director-test-"+todayStr+hour+":00:00Z.txt")
				createTestFile(t, todayDir, "director-test-"+todayStr+hour+":00:00Z.txt.cinfo")
			}
		}

		// Director 1 also has an old day directory that should be swept entirely
		oldDir := filepath.Join(dirTestPath, "director-1.example.com", oldDayStr)
		require.NoError(t, os.MkdirAll(oldDir, 0755))
		createTestFile(t, oldDir, "director-test-"+oldDayStr+"T10:00:00Z.txt")
		createTestFile(t, oldDir, "director-test-"+oldDayStr+"T10:00:00Z.txt.cinfo")

		err := cleanupDirectorTestFiles(context.Background(), dirTestPath)
		require.NoError(t, err)

		// Director 1's old day directory should be gone
		_, err = os.Stat(oldDir)
		assert.True(t, os.IsNotExist(err), "old day directory should be removed")

		// Each director's today dir keeps exactly the latest 2 files (the T10 pair)
		for _, dirID := range []string{"director-1.example.com", "director-2.example.com"} {
			todayDir := filepath.Join(dirTestPath, dirID, todayStr)
			entries, err := os.ReadDir(todayDir)
			require.NoError(t, err)
			assert.Equal(t, 2, len(entries), "%s today's dir should retain 2 files", dirID)
			assert.Equal(t, "director-test-"+todayStr+"T10:00:00Z.txt", entries[0].Name())
			assert.Equal(t, "director-test-"+todayStr+"T10:00:00Z.txt.cinfo", entries[1].Name())
		}
	})
}

func TestCleanupOldFilesInDir(t *testing.T) {
	t.Run("keeps-files-when-under-threshold", func(t *testing.T) {
		dir := t.TempDir()
		createTestFile(t, dir, "director-test-2025-01-10T10:00:00Z.txt")
		createTestFile(t, dir, "director-test-2025-01-10T10:00:00Z.txt.cinfo")

		err := cleanupOldFilesInDir(context.Background(), dir, 2)
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

		err := cleanupOldFilesInDir(context.Background(), dir, 2)
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Equal(t, 2, len(entries))
		assert.Equal(t, "director-test-2025-01-10T10:00:00Z.txt", entries[0].Name())
		assert.Equal(t, "director-test-2025-01-10T11:00:00Z.txt", entries[1].Name())
	})
}
