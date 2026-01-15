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
	"encoding/base64"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestChecksumStaleDetection verifies that modified files have their xattrs recomputed
func TestChecksumStaleDetection(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content1 := []byte("Original content")
	content2 := []byte("Modified content is longer")

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	// Write initial file and compute checksum
	require.NoError(t, os.WriteFile(testFile, content1, 0644))
	time.Sleep(10 * time.Millisecond) // Ensure mtime differences
	modTime1, _ := os.Stat(testFile)

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}
	hash1, err := xc.GetChecksum(root, "test.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)

	// Verify xattr was written
	xattrData, err := xattr.Get(testFile, "user.XrdCks.crc32c")
	require.NoError(t, err)
	require.NotEmpty(t, xattrData)

	// Modify file and wait for mtime change
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, os.WriteFile(testFile, content2, 0644))
	modTime2, _ := os.Stat(testFile)

	// Verify mtime changed
	assert.NotEqual(t, modTime1.ModTime().Unix(), modTime2.ModTime().Unix(), "mtime should have changed")

	// Get checksum again - should detect stale and recompute
	hash2, err := xc.GetChecksum(root, "test.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)

	// Hashes should differ because content changed
	assert.NotEqual(t, hash1, hash2, "Checksum should change when file is modified")
}

// TestDefaultChecksumTypes verifies that multiple default checksums are computed together
func TestDefaultChecksumTypes(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Test content for multiple checksums")

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	require.NoError(t, os.WriteFile(testFile, content, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	types := []ChecksumType{ChecksumTypeMD5, ChecksumTypeCRC32C}
	merged := mergeWithDefault(types)

	// Should include both requested and defaults
	assert.Greater(t, len(merged), 0, "Merged list should not be empty")
	assert.NotEmpty(t, merged, "Should have merged types")

	// Compute and verify all are stored
	xc := &XattrChecksummer{}
	digests, err := xc.GetChecksumsRFC3230(root, "test.txt", types)
	require.NoError(t, err)
	require.Equal(t, len(types), len(digests), "Should return digest for each requested type")

	// Verify xattrs were written for all
	for _, checksumType := range types {
		xattrName := getXattrName(checksumType)
		data, err := xattr.Get(testFile, xattrName)
		assert.NoError(t, err, "Xattr %s should be present", xattrName)
		assert.NotEmpty(t, data, "Xattr %s should not be empty", xattrName)
	}
}

// TestConcurrentChecksumComputation verifies thread-safe concurrent access
func TestConcurrentChecksumComputation(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("Content for concurrent test")

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	require.NoError(t, os.WriteFile(testFile, content, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}
	var wg sync.WaitGroup
	numGoroutines := 10
	results := make(chan string, numGoroutines)
	errors := make(chan error, numGoroutines)

	// Launch concurrent requests for the same checksum
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hash, err := xc.GetChecksum(root, "test.txt", ChecksumTypeCRC32C)
			if err != nil {
				errors <- err
			} else {
				results <- hash
			}
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// All should succeed and produce same checksum
	checksums := make([]string, 0)
	for result := range results {
		checksums = append(checksums, result)
	}

	for err := range errors {
		t.Fatalf("Error during concurrent computation: %v", err)
	}

	assert.Equal(t, numGoroutines, len(checksums), "All goroutines should succeed")

	// All checksums should be identical
	for i := 1; i < len(checksums); i++ {
		assert.Equal(t, checksums[0], checksums[i], "All checksums should match")
	}
}

// TestRFC3230DigestFormat verifies correct RFC 3230 format
func TestRFC3230DigestFormat(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("RFC 3230 format test")

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	require.NoError(t, os.WriteFile(testFile, content, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}

	tests := []struct {
		name         string
		checksumType ChecksumType
		prefix       string
		validate     func(string) bool
	}{
		{
			name:         "MD5 base64 encoding",
			checksumType: ChecksumTypeMD5,
			prefix:       "md5=",
			validate: func(value string) bool {
				parts := strings.Split(value, "=")
				if len(parts) != 2 {
					return false
				}
				// MD5 should be base64-encoded (32 hex chars = 16 bytes -> 24 base64 chars)
				_, err := base64.StdEncoding.DecodeString(parts[1])
				return err == nil
			},
		},
		{
			name:         "SHA1 base64 encoding",
			checksumType: ChecksumTypeSHA1,
			prefix:       "sha=",
			validate: func(value string) bool {
				parts := strings.Split(value, "=")
				if len(parts) != 2 {
					return false
				}
				// SHA1 should be base64-encoded (40 hex chars = 20 bytes -> 28 base64 chars)
				_, err := base64.StdEncoding.DecodeString(parts[1])
				return err == nil
			},
		},
		{
			name:         "CRC32 hex encoding",
			checksumType: ChecksumTypeCRC32,
			prefix:       "crc32=",
			validate: func(value string) bool {
				parts := strings.Split(value, "=")
				if len(parts) != 2 {
					return false
				}
				// CRC32 should be 8-digit hex
				return len(parts[1]) == 8 && isHexString(parts[1])
			},
		},
		{
			name:         "CRC32C hex encoding",
			checksumType: ChecksumTypeCRC32C,
			prefix:       "crc32c=",
			validate: func(value string) bool {
				parts := strings.Split(value, "=")
				if len(parts) != 2 {
					return false
				}
				// CRC32C should be 8-digit hex
				return len(parts[1]) == 8 && isHexString(parts[1])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := xc.GetChecksumRFC3230(root, "test.txt", tt.checksumType)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(digest, tt.prefix), "Digest should start with %s", tt.prefix)
			assert.True(t, tt.validate(digest), "Digest format should be valid: %s", digest)
		})
	}
}

// TestEmptyFileSumption verifies checksums work with empty files
func TestEmptyFileChecksum(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "empty.txt")

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		t.Skipf("Xattrs not supported: %v", err)
	}
	_ = xattr.Remove(testFile, "user.test")

	require.NoError(t, os.WriteFile(testFile, []byte{}, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	xc := &XattrChecksummer{}
	digest, err := xc.GetChecksumRFC3230(root, "empty.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)

	// Empty file has deterministic checksums
	// CRC32C of empty data: 0
	assert.True(t, strings.HasPrefix(digest, "crc32c="), "Should have crc32c prefix")
	assert.Contains(t, digest, "00000000", "Empty file should have 0 CRC32C")
}

// TestComputeChecksumBytesConsistency verifies raw byte computation is consistent
func TestComputeChecksumBytesConsistency(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "consistency.txt")
	content := []byte("Consistency test content")

	require.NoError(t, os.WriteFile(testFile, content, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(t, err)
	defer root.Close()

	// Compute raw bytes twice
	bytes1, err := computeChecksumBytes(root, "consistency.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)

	bytes2, err := computeChecksumBytes(root, "consistency.txt", ChecksumTypeCRC32C)
	require.NoError(t, err)

	// Should be identical
	assert.Equal(t, bytes1, bytes2, "Raw checksum bytes should be consistent")

	// Verify against manual computation
	f, err := os.Open(testFile)
	require.NoError(t, err)
	defer f.Close()

	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, err = io.Copy(h, f)
	require.NoError(t, err)

	expected := h.Sum(nil)
	assert.Equal(t, expected, bytes1, "Computed bytes should match manual hash")
}

// isHexString checks if a string contains only valid hex characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// TestRFC3230ValueFormatting verifies rfc3230Value helper function
func TestRFC3230ValueFormatting(t *testing.T) {
	tests := []struct {
		name     string
		algType  ChecksumType
		bytes    []byte
		expected string
	}{
		{
			name:     "MD5 base64",
			algType:  ChecksumTypeMD5,
			bytes:    []byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92},
			expected: base64.StdEncoding.EncodeToString([]byte{0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76, 0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92}),
		},
		{
			name:     "CRC32C hex",
			algType:  ChecksumTypeCRC32C,
			bytes:    []byte{0x12, 0x34, 0x56, 0x78},
			expected: "12345678",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := rfc3230Value(tt.algType, tt.bytes)
			assert.Equal(t, tt.expected, result, "RFC 3230 value formatting should be correct")
		})
	}
}

// BenchmarkChecksumComputation benchmarks checksum computation
func BenchmarkChecksumComputation(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench.txt")
	content := make([]byte, 1024*1024) // 1MB file
	for i := range content {
		content[i] = byte(i % 256)
	}

	require.NoError(b, os.WriteFile(testFile, content, 0644))

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(b, err)
	defer root.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = computeChecksumBytes(root, "bench.txt", ChecksumTypeCRC32C)
	}
}

// BenchmarkXattrRoundTrip benchmarks xattr read/write cycle
func BenchmarkXattrRoundTrip(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "bench_xattr.txt")
	require.NoError(b, os.WriteFile(testFile, []byte("test"), 0644))

	// Check xattr support
	err := xattr.Set(testFile, "user.test", []byte("test"))
	if err != nil {
		b.Skipf("Xattrs not supported: %v", err)
	}

	// Open root for secure access
	root, err := os.OpenRoot(tmpDir)
	require.NoError(b, err)
	defer root.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = readChecksumFromXattr(root, "bench_xattr.txt", ChecksumTypeCRC32C)
	}
}

// TestChecksumTypeStringConversion verifies checksum types can be converted to/from strings
func TestChecksumTypeStringConversion(t *testing.T) {
	tests := []struct {
		checksumType ChecksumType
		expectedName string
	}{
		{ChecksumTypeMD5, "md5"},
		{ChecksumTypeSHA1, "sha1"},
		{ChecksumTypeCRC32, "crc32"},
		{ChecksumTypeCRC32C, "crc32c"},
	}

	for _, tt := range tests {
		t.Run(string(tt.checksumType), func(t *testing.T) {
			assert.Equal(t, tt.expectedName, string(tt.checksumType))
		})
	}
}

// TestIsValidChecksumType verifies checksum type validation
func TestIsValidChecksumType(t *testing.T) {
	validTypes := []ChecksumType{ChecksumTypeMD5, ChecksumTypeSHA1, ChecksumTypeCRC32, ChecksumTypeCRC32C}
	invalidTypes := []string{"md5c", "sha2", "crc", "unknown", "MD5", "SHA1"}

	// Test valid types
	for _, checksumType := range validTypes {
		assert.True(t, isValidChecksumType(checksumType), "Should recognize %s as valid", checksumType)
	}

	// Test invalid types
	for _, invalidType := range invalidTypes {
		assert.False(t, isValidChecksumType(ChecksumType(invalidType)), "Should reject %s as invalid", invalidType)
	}
}

// TestMergeWithDefault verifies that requested checksum types are merged with defaults
func TestMergeWithDefault(t *testing.T) {
	// Empty requested list should use defaults
	merged := mergeWithDefault([]ChecksumType{})
	assert.GreaterOrEqual(t, len(merged), 1, "Should include at least default checksums")

	// Requested types should be preserved (at minimum)
	requested := []ChecksumType{ChecksumTypeMD5, ChecksumTypeSHA1}
	merged = mergeWithDefault(requested)
	for _, req := range requested {
		found := false
		for _, m := range merged {
			if m == req {
				found = true
				break
			}
		}
		assert.True(t, found, "Requested type %s should be in merged list", req)
	}

	// Defaults should always be present unless explicitly requesting a different set
	merged = mergeWithDefault([]ChecksumType{ChecksumTypeCRC32})
	foundDefault := false
	for _, m := range merged {
		if m == ChecksumTypeCRC32C {
			foundDefault = true
			break
		}
	}
	assert.True(t, foundDefault, "Default checksum type should be in merged list")
}
