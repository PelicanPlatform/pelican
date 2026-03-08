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

// Tests for cache corruption scenarios: bit-flips in encrypted blocks,
// missing on-disk files, and re-download recovery.  These verify that
// AES-GCM authentication catches tampering and that the cache either
// serves an error or re-fetches from origin.

package fed_tests

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// ============================================================================
// Helpers
// ============================================================================

// corruptEnv holds a running federation plus the filesystem path to the
// cache's objects directory so that tests can tamper with on-disk data.
type corruptEnv struct {
	ft         *fed_test_utils.FedTest
	token      string
	objectsDir string // e.g. <cache-data>/objects
}

// setupCorruptEnv starts a federation with the persistent cache and
// locates the objects directory on disk.
func setupCorruptEnv(t *testing.T) *corruptEnv {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)

	token := getTempTokenForTest(t)

	// The Cache module stores persistent cache data under
	// Cache.StorageLocation/persistent-cache (see launchers/cache_serve.go).
	cacheStorageLocation := param.Cache_StorageLocation.GetString()
	require.NotEmpty(t, cacheStorageLocation, "Cache.StorageLocation should be set after federation startup")

	objectsDir := filepath.Join(cacheStorageLocation, "persistent-cache", "objects")
	return &corruptEnv{ft: ft, token: token, objectsDir: objectsDir}
}

// uploadAndPrime uploads content, downloads through the cache so the file
// is stored on disk, and returns the cache URL.
func uploadAndPrime(ctx context.Context, t *testing.T, env *corruptEnv, filename string, content []byte) string {
	t.Helper()

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, filename)
	require.NoError(t, os.WriteFile(localFile, content, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

	_, err := client.DoPut(ctx, localFile, uploadURL, false, client.WithToken(env.token))
	require.NoError(t, err)

	// Download through cache to populate it
	downloadFile := filepath.Join(localTmpDir, "prime_download")
	_, err = client.DoGet(ctx, uploadURL, downloadFile, false, client.WithToken(env.ft.Token))
	require.NoError(t, err)

	cacheURL := getCacheRedirectURL(ctx, t, "/test/"+filename, env.token)
	return cacheURL
}

// findObjectFileForContent walks the objects directory and returns the file
// whose size is consistent with the given content length (within one
// BlockTotalSize of the expected pre-allocated size).
func findObjectFileForContent(t *testing.T, objectsDir string, contentLength int) string {
	t.Helper()
	expectedBlocks := local_cache.CalculateBlockCount(int64(contentLength))
	expectedSize := int64(expectedBlocks) * local_cache.BlockTotalSize
	var found string
	err := filepath.Walk(objectsDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Size() > 0 && found == "" && info.Size() == expectedSize {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, found, "Expected object file of size %d in %s", expectedSize, objectsDir)
	return found
}

// ============================================================================
// Tests
// ============================================================================

// TestCorruption_BitFlip_FullRead flips a bit inside an encrypted block
// file and verifies that a subsequent full GET either returns an error
// (due to AES-GCM authentication failure) or falls back to re-downloading
// from origin.
func TestCorruption_BitFlip_FullRead(t *testing.T) {
	env := setupCorruptEnv(t)

	// Use a file larger than InlineThreshold so it's stored on disk
	content := generateTestData(16384) // 16KB ≈ 4 blocks
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_bitflip.bin", content)

	// Verify a clean read works and the trailer reports success
	r := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.statusCode)
	require.Equal(t, content, r.body)
	assert.Equal(t, "200: OK", r.transferStatus,
		"Clean read should have a successful X-Transfer-Status trailer")

	// Corrupt the on-disk file by flipping one bit in the first block
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	data, err := os.ReadFile(objFile)
	require.NoError(t, err)
	require.True(t, len(data) > 10, "on-disk file should be larger than 10 bytes")

	// Flip a bit in the data portion of the first block (not the header)
	data[10] ^= 0x01
	require.NoError(t, os.WriteFile(objFile, data, 0600))

	// Now try reading — the auto-repair logic should detect the
	// AES-GCM authentication failure, re-download the corrupt block
	// from origin, and return correct data transparently.
	r2 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r2.err, "HTTP request itself should succeed")

	// Auto-repair should produce a successful trailer and the full,
	// correct body.
	assert.Equal(t, "200: OK", r2.transferStatus,
		"Auto-repaired read should have a successful X-Transfer-Status trailer")
	assert.Equal(t, content, r2.body,
		"Auto-repaired read should return the original content")
	t.Logf("Trailer after auto-repair: %s (body %d bytes)", r2.transferStatus, len(r2.body))

	// A subsequent read should also succeed — the on-disk data is now
	// fixed and no re-download is needed.
	r3 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r3.err)
	assert.Equal(t, "200: OK", r3.transferStatus,
		"Post-repair read should succeed without re-download")
	assert.Equal(t, content, r3.body,
		"Post-repair read should return original content")

	// Verify the on-disk file has been repaired (not just in-memory caching)
	repairedData, err := os.ReadFile(objFile)
	require.NoError(t, err)
	assert.NotEqual(t, data, repairedData,
		"On-disk file should be different from corrupted version")
	// The 11th byte should no longer have the flipped bit
	assert.NotEqual(t, data[10], repairedData[10],
		"Corrupted byte at offset 10 should be fixed on disk")
	t.Logf("Verified on-disk file has been repaired: byte[10] changed from 0x%02x back to 0x%02x",
		data[10], repairedData[10])
}

// TestCorruption_BitFlip_RangeRead flips a bit and requests a range
// that touches the corrupted block.
func TestCorruption_BitFlip_RangeRead(t *testing.T) {
	env := setupCorruptEnv(t)

	content := generateTestData(20480) // 20KB ≈ 5 blocks
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_range.bin", content)

	// Corrupt the second block (bytes 4096..8191 on disk)
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	data, err := os.ReadFile(objFile)
	require.NoError(t, err)

	// Second block starts at offset BlockTotalSize = 4096
	corruptOffset := local_cache.BlockTotalSize + 5
	require.True(t, corruptOffset < len(data), "corrupt offset out of bounds")
	data[corruptOffset] ^= 0xFF
	require.NoError(t, os.WriteFile(objFile, data, 0600))

	// Request a range that spans the corrupted block
	// Block 1 covers content bytes 4080..8159 (data) so bytes=4080-8159 hits block 1
	r := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=4080-8159")
	expected := content[4080:8160]
	require.NoError(t, r.err, "HTTP request itself should succeed")

	// Auto-repair should detect the AES-GCM failure in the corrupted
	// block, re-download it from origin, and return correct data.
	assert.Equal(t, "200: OK", r.transferStatus,
		"Auto-repaired range read should have a successful trailer")
	assert.Equal(t, expected, r.body,
		"Auto-repaired range read should return correct content")
	t.Logf("Trailer after auto-repair (range): %s (body %d bytes)", r.transferStatus, len(r.body))

	// Subsequent range read should succeed without needing origin
	r2 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=4080-8159")
	require.NoError(t, r2.err)
	assert.Equal(t, "200: OK", r2.transferStatus,
		"Post-repair range read should succeed")
	assert.Equal(t, expected, r2.body,
		"Post-repair range read should return correct content")

	// Verify the on-disk file has been repaired
	repairedData, err := os.ReadFile(objFile)
	require.NoError(t, err)
	assert.NotEqual(t, data, repairedData,
		"On-disk file should be different from corrupted version")
	assert.NotEqual(t, data[corruptOffset], repairedData[corruptOffset],
		"Corrupted byte at offset %d should be fixed on disk", corruptOffset)
	t.Logf("Verified on-disk block has been repaired: byte[%d] changed from 0x%02x back to 0x%02x",
		corruptOffset, data[corruptOffset], repairedData[corruptOffset])
}

// TestCorruption_MissingBlockFile removes the on-disk encrypted file
// entirely and verifies the cache either returns an error or transparently
// re-downloads.
func TestCorruption_MissingBlockFile(t *testing.T) {
	env := setupCorruptEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_missing.bin", content)

	// Verify normal read works
	r := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.statusCode)

	// Delete the on-disk file
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	require.NoError(t, os.Remove(objFile))

	// Try to read — auto-repair should detect missing blocks and
	// re-download them from origin.
	r2 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r2.err, "HTTP request itself should succeed")

	// Auto-repair should succeed: trailer reports 200, body matches.
	assert.Equal(t, "200: OK", r2.transferStatus,
		"Auto-repaired read (missing file) should have a successful trailer")
	assert.Equal(t, content, r2.body,
		"Auto-repaired read (missing file) should return original content")
	t.Logf("Trailer after auto-repair (missing file): %s (body %d bytes)", r2.transferStatus, len(r2.body))

	// Verify the file has been recreated on disk
	info, err := os.Stat(objFile)
	require.NoError(t, err, "Object file should be recreated on disk after auto-repair")
	expectedSize := int64(local_cache.CalculateBlockCount(int64(len(content)))) * local_cache.BlockTotalSize
	assert.Equal(t, expectedSize, info.Size(),
		"Recreated file should have the correct size")
	t.Logf("Verified file was recreated on disk: size=%d bytes", info.Size())
}

// TestCorruption_TruncatedFile truncates the encrypted file to half its
// original size, simulating a partial write or disk error.
func TestCorruption_TruncatedFile(t *testing.T) {
	env := setupCorruptEnv(t)

	content := generateTestData(16384) // 4 blocks
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_trunc.bin", content)

	// Truncate the file to half
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	info, err := os.Stat(objFile)
	require.NoError(t, err)
	require.NoError(t, os.Truncate(objFile, info.Size()/2))

	// Full read — auto-repair should re-download the truncated blocks
	r := doRangeRead(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r.err, "HTTP request itself should succeed")
	assert.Equal(t, "200: OK", r.transferStatus,
		"Auto-repaired read (truncated file) should have a successful trailer")
	assert.Equal(t, content, r.body,
		"Auto-repaired read (truncated file) should return original content")
	t.Logf("Trailer after auto-repair (truncated): %s (body %d bytes)", r.transferStatus, len(r.body))

	// Verify the file has been restored to full size on disk
	restoredInfo, err := os.Stat(objFile)
	require.NoError(t, err)
	expectedSize := int64(local_cache.CalculateBlockCount(int64(len(content)))) * local_cache.BlockTotalSize
	assert.Equal(t, expectedSize, restoredInfo.Size(),
		"File should be restored to full size on disk")
	t.Logf("Verified file restored from %d to %d bytes on disk",
		info.Size()/2, restoredInfo.Size())

	// A range that was in the surviving half should also work
	r2 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=0-4079")
	if r2.statusCode == http.StatusPartialContent || r2.statusCode == http.StatusOK {
		expected := content[0:4080]
		assert.Equal(t, expected, r2.body, "Surviving range should still be readable")
		assert.Equal(t, "200: OK", r2.transferStatus,
			"Surviving-range trailer should report success")
	}
}

// TestCorruption_UncorruptedBlocksOK verifies that corrupting one block
// does NOT affect reads of other, uncorrupted blocks.
func TestCorruption_UncorruptedBlocksOK(t *testing.T) {
	env := setupCorruptEnv(t)

	content := generateTestData(20480) // 5 blocks
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_partial.bin", content)

	// Corrupt block 3 (content bytes 12240..16319 i.e. 3*4080..)
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	data, err := os.ReadFile(objFile)
	require.NoError(t, err)

	// Block 3 on disk starts at 3 * BlockTotalSize = 3 * 4096
	block3Start := 3 * local_cache.BlockTotalSize
	require.True(t, block3Start+10 < len(data))
	data[block3Start+10] ^= 0x42
	require.NoError(t, os.WriteFile(objFile, data, 0600))

	// Read block 0 only — should succeed because block 0 is intact
	r := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=0-4079")
	require.NoError(t, r.err)
	assert.Equal(t, content[0:4080], r.body, "Uncorrupted block 0 should read correctly")
	assert.Equal(t, "200: OK", r.transferStatus,
		"Trailer for uncorrupted block 0 should report success")

	// Read block 2 — also intact
	r2 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=8160-12239")
	require.NoError(t, r2.err)
	assert.Equal(t, content[8160:12240], r2.body, "Uncorrupted block 2 should read correctly")
	assert.Equal(t, "200: OK", r2.transferStatus,
		"Trailer for uncorrupted block 2 should report success")

	// Verify that the corrupted block is still corrupted on disk.
	// Reading blocks 0 and 2 must NOT trigger repair of block 3.
	midData, err := os.ReadFile(objFile)
	require.NoError(t, err)
	assert.Equal(t, data[block3Start+10], midData[block3Start+10],
		"Block 3 should still be corrupted on disk after reading only uncorrupted blocks")

	// Read the corrupted block 3 — auto-repair should fix it
	r3 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=12240-16319")
	require.NoError(t, r3.err)
	expected3 := content[12240:16320]
	assert.Equal(t, expected3, r3.body, "Auto-repaired block 3 should read correctly")
	assert.Equal(t, "200: OK", r3.transferStatus,
		"Trailer for auto-repaired block 3 should report success")

	// Verify block 3 has been repaired on disk
	repairedData, err := os.ReadFile(objFile)
	require.NoError(t, err)
	assert.NotEqual(t, data[block3Start+10], repairedData[block3Start+10],
		"Corrupted byte in block 3 should be fixed on disk")
	t.Logf("Verified block 3 has been repaired on disk: byte[%d] changed from 0x%02x back to 0x%02x",
		block3Start+10, data[block3Start+10], repairedData[block3Start+10])

	// Re-read block 3 — should succeed from the now-repaired on-disk data
	r4 := doRangeRead(env.ft.Ctx, cacheURL, env.token, "bytes=12240-16319")
	require.NoError(t, r4.err)
	assert.Equal(t, expected3, r4.body, "Re-read of repaired block 3 should return correct data")
	assert.Equal(t, "200: OK", r4.transferStatus,
		"Re-read of repaired block 3 should report success")
}

// TestCorruption_VerifyBlockIntegrity exercises the ConsistencyChecker's
// block-level integrity verification using the unit-test–level API.
// This stores an object directly via the storage manager, corrupts a block,
// and checks that VerifyBlockIntegrity reports the right block numbers.
func TestCorruption_VerifyBlockIntegrity(t *testing.T) {
	local_cache.InitIssuerKeyForTests(t)

	tmpDir, err := os.MkdirTemp("", "corruption_integrity_*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	db, err := local_cache.NewCacheDB(ctx, tmpDir)
	require.NoError(t, err)
	defer db.Close()

	storage, err := local_cache.NewStorageManager(db, []string{tmpDir}, 0)
	require.NoError(t, err)

	// Create a 3-block object (3 * 4080 = 12240 bytes)
	const contentLen = 3 * local_cache.BlockDataSize
	content := generateTestData(contentLen)

	fileHash := "deadbeef1234567890abcdef"

	// Get the assigned storage ID for the single directory.
	assignedDirs := storage.GetDirs()
	require.Len(t, assignedDirs, 1)
	var storageID uint8
	for id := range assignedDirs {
		storageID = id
	}

	_, err = storage.InitDiskStorage(ctx, fileHash, int64(contentLen), storageID)
	require.NoError(t, err)

	err = storage.WriteBlocks(fileHash, 0, content)
	require.NoError(t, err)

	// Verify integrity before corruption — should find no bad blocks
	checker := local_cache.NewConsistencyChecker(db, storage, local_cache.ConsistencyConfig{})
	corrupted, err := checker.VerifyBlockIntegrity(fileHash)
	require.NoError(t, err)
	assert.Empty(t, corrupted, "Should find no corrupted blocks on a clean object")

	// Verify the stored data reads back correctly
	readBack, err := storage.ReadBlocks(fileHash, 0, contentLen)
	require.NoError(t, err)
	assert.Equal(t, content, readBack, "Read-back should match original")

	// Corrupt block 1 on disk
	objPath := filepath.Join(tmpDir, "objects", local_cache.GetInstanceStoragePath(fileHash))
	diskData, err := os.ReadFile(objPath)
	require.NoError(t, err)

	block1Offset := local_cache.BlockTotalSize
	require.True(t, block1Offset+5 < len(diskData))
	diskData[block1Offset+5] ^= 0xFF
	require.NoError(t, os.WriteFile(objPath, diskData, 0600))

	// Verify integrity after corruption — should report block 1
	corrupted, err = checker.VerifyBlockIntegrity(fileHash)
	require.NoError(t, err)
	assert.Contains(t, corrupted, uint32(1), "Should detect corruption in block 1")
	assert.NotContains(t, corrupted, uint32(0), "Block 0 should be clean")
	assert.NotContains(t, corrupted, uint32(2), "Block 2 should be clean")
}

// TestCorruption_HeadAfterCorruption verifies that a HEAD request
// succeeds even when the on-disk data is corrupted (since HEAD doesn't
// read the body).
func TestCorruption_HeadAfterCorruption(t *testing.T) {
	env := setupCorruptEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrime(env.ft.Ctx, t, env, "corrupt_head.bin", content)

	// Corrupt the file
	objFile := findObjectFileForContent(t, env.objectsDir, len(content))
	data, err := os.ReadFile(objFile)
	require.NoError(t, err)
	data[42] ^= 0xAA
	require.NoError(t, os.WriteFile(objFile, data, 0600))

	// HEAD should still succeed because it doesn't read block data
	req, err := http.NewRequestWithContext(env.ft.Ctx, http.MethodHead, cacheURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+env.token)

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body) // drain

	// HEAD should return 200 with correct Content-Length
	assert.Equal(t, http.StatusOK, resp.StatusCode, "HEAD should succeed even with corrupted data")
	assert.Equal(t, fmt.Sprintf("%d", len(content)), resp.Header.Get("Content-Length"),
		"Content-Length should match original size")

	// Verify the on-disk file is still corrupted — HEAD must NOT trigger repair.
	dataAfterHead, err := os.ReadFile(objFile)
	require.NoError(t, err)
	assert.Equal(t, data, dataAfterHead,
		"On-disk data should be unchanged after HEAD (no repair triggered)")
}
