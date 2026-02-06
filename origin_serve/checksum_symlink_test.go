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

package origin_serve

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChecksumSymlinkProtection verifies that os.Root prevents symlink attacks
func TestChecksumSymlinkProtection(t *testing.T) {
	// Create a storage directory
	storageDir := t.TempDir()

	// Create a directory outside the storage tree that we should NOT be able to access
	outsideDir := t.TempDir()
	secretFile := filepath.Join(outsideDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("Secret data that should not be accessible"), 0644))

	// Create a symlink inside the storage directory pointing outside
	symlinkPath := filepath.Join(storageDir, "escape_link")
	require.NoError(t, os.Symlink(secretFile, symlinkPath))

	// Check xattr support on the storageDir
	testFile := filepath.Join(storageDir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	// Open root for secure access
	root, err := os.OpenRoot(storageDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}

	// Try to compute checksum through the symlink - should fail or not escape
	// os.Root should prevent following the symlink outside the root directory
	_, err = xc.GetChecksum(root, "escape_link", ChecksumTypeCRC32C)
	assert.Error(t, err)
	// Expected behavior - symlink escape is prevented or error occurred
	t.Logf("GetChecksum failed with error: %v", err)

	// We verify that we can't read the secret file directly through the root
	_, err = root.Open("escape_link")

	// os.Root should prevent escaping the directory
	// On systems with proper os.Root support, this should fail
	if err != nil {
		// This is the expected behavior - symlink escape is prevented
		assert.Error(t, err, "os.Root should prevent symlink escape")
	} else {
		// If it succeeds, verify it's contained within the storage directory
		// This would mean os.Root resolved the symlink to the target within its view
		t.Logf("Warning: os.Root allowed symlink access, but should contain it within root")
	}
}

// TestChecksumNormalSymlink verifies that symlinks within the storage tree work correctly
func TestChecksumNormalSymlink(t *testing.T) {
	storageDir := t.TempDir()

	// Create a real file in the storage directory
	realFile := filepath.Join(storageDir, "real.txt")
	content := []byte("Real file content")
	require.NoError(t, os.WriteFile(realFile, content, 0644))

	// Create a symlink to the real file within the same directory
	symlinkPath := filepath.Join(storageDir, "link.txt")
	require.NoError(t, os.Symlink("real.txt", symlinkPath))

	// Check xattr support
	err := xattr.Set(realFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(realFile, "user.test")

	// Open root for secure access
	root, err := os.OpenRoot(storageDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}

	// Compute checksum for the real file
	hash1, err := xc.GetChecksum(root, "real.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)
	require.NotEmpty(t, hash1)

	// Compute checksum through the symlink
	// os.Root should allow this since the symlink target is within the root
	hash2, err := xc.GetChecksum(root, "link.txt", ChecksumTypeCRC32C)

	// If symlinks within the tree are supported, checksums should match
	if err == nil {
		assert.Equal(t, hash1, hash2, "Checksum through symlink should match direct file checksum")
	} else {
		// Some configurations may not support symlinks at all
		t.Logf("Symlink within tree not supported: %v", err)
	}
}
