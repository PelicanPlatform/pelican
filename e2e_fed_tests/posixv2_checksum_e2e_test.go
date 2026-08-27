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

// E2E coverage for POSIXv2 checksum behavior and the ETag uniqueness fix.
//
// These tests focus on three related properties:
//
//  1. POSIXv2 defaults checksums to CRC32C even when the operator has not set
//     Origin.DefaultChecksumTypes -- this matches the Pelican client's own
//     default and avoids paying the cost of an extra MD5 pass on every HEAD.
//  2. The same checksum infrastructure works under the multiuser variant of
//     POSIXv2 (the inner filesystem wrapped by multiuser_fs).
//  3. ETags for different files are actually distinct -- previously two files
//     with the same size and mtime could collapse to the same ETag.

package fed_tests

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/fed_test_utils"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// originServerURL returns the https://host:port string for the running origin.
func originServerURL() string {
	return fmt.Sprintf("https://%s:%d",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
}

// skipUnlessXattrs ensures the filesystem under tmpPath supports user xattrs,
// which the checksum-cache layer requires. macOS tmpfs / some Linux mounts
// silently reject these.
func skipUnlessXattrs(t *testing.T, tmpPath string) {
	t.Helper()
	probe := filepath.Join(tmpPath, ".xattr-probe")
	if err := os.WriteFile(probe, []byte("x"), 0o644); err != nil {
		t.Skipf("could not write probe file: %v", err)
	}
	defer os.Remove(probe)
	if err := xattr.Set(probe, "user.test.pelican", []byte("y")); err != nil {
		t.Skipf("xattrs not supported on this filesystem: %v", err)
	}
}

// expectedCRC32CHex returns the RFC 3230-style 8-char lowercase hex CRC32C
// digest of the given content, matching origin_serve.rfc3230Value's encoding.
func expectedCRC32CHex(content []byte) string {
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write(content)
	return fmt.Sprintf("%08x", h.Sum32())
}

// expectedCRC32CRaw returns the 4-byte big-endian CRC32C digest of content,
// in the same shape the client decodes into ChecksumInfo.Value.
func expectedCRC32CRaw(content []byte) []byte {
	h := crc32.New(crc32.MakeTable(crc32.Castagnoli))
	_, _ = h.Write(content)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, h.Sum32())
	return buf
}

// expectedMD5Raw returns the raw 16-byte MD5 digest of content.
func expectedMD5Raw(content []byte) []byte {
	sum := md5.Sum(content)
	return sum[:]
}

// summarizeChecksums turns a slice of ChecksumInfo into a logging-friendly
// list of (algorithm name, byte count) pairs so test failures are diagnosable
// without dumping raw digest bytes.
func summarizeChecksums(cks []client.ChecksumInfo) []string {
	out := make([]string, 0, len(cks))
	for _, c := range cks {
		out = append(out, fmt.Sprintf("%s(%d bytes)",
			client.HttpDigestFromChecksum(c.Algorithm), len(c.Value)))
	}
	return out
}

// TestPosixv2_DefaultDigestIsCRC32C verifies that, with no explicit
// Origin.DefaultChecksumTypes set, a HEAD request that omits Want-Digest still
// receives a CRC32C digest -- not the legacy MD5 fallback. This is the
// behavior the Pelican client relies on (AlgDefault = AlgCRC32C).
func TestPosixv2_DefaultDigestIsCRC32C(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	storage := t.TempDir()
	skipUnlessXattrs(t, storage)

	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	content := []byte("default crc32c content")
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "default_crc32c.txt")
	require.NoError(t, os.WriteFile(backendFile, content, 0o644))

	tok := getTempTokenForTest(t)
	httpClient := config.GetClientNoRedirect()

	req, err := http.NewRequest(http.MethodHead,
		originServerURL()+"/api/v1.0/origin/data/test/default_crc32c.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	// Deliberately omit Want-Digest so the server has to pick the default.

	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "HEAD should succeed")

	digest := resp.Header.Get("Digest")
	require.NotEmpty(t, digest, "Digest header should be populated by default")

	// Strict: the default must be CRC32C, not MD5.
	require.Contains(t, digest, "crc32c=",
		"Default digest should be CRC32C (matches Pelican client default); got %q", digest)
	require.NotContains(t, digest, "md5=",
		"Default digest must not silently fall back to MD5 anymore; got %q", digest)

	// Verify the value as well.
	want := expectedCRC32CHex(content)
	for _, part := range strings.Split(digest, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "crc32c=") {
			assert.Equal(t, want, strings.TrimPrefix(part, "crc32c="),
				"CRC32C digest value should match the actual content checksum")
		}
	}

	// And the same checksum should be cached as an xattr next to the file
	// (so subsequent HEADs are O(1) rather than re-hashing the file).
	xattrData, err := xattr.Get(backendFile, "user.XrdCks.crc32c")
	require.NoError(t, err, "CRC32C xattr should be persisted by the default HEAD path")
	assert.NotEmpty(t, xattrData)
}

// TestPosixv2_UploadCachesDefaultChecksum exercises the full client round-trip
// to confirm that a Pelican PUT followed by a client.DoStat with the default
// CRC32C algorithm returns the matching value, and that the value persists in
// the xattr cache (i.e. POSIXv2's checksum behavior matches what Pelican
// clients expect by default).
func TestPosixv2_UploadCachesDefaultChecksum(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	storage := t.TempDir()
	skipUnlessXattrs(t, storage)

	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	content := []byte("payload that should yield a stable CRC32C digest")
	localDir := t.TempDir()
	local := filepath.Join(localDir, "obj.bin")
	require.NoError(t, os.WriteFile(local, content, 0o644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/obj.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

	tok := getTempTokenForTest(t)
	_, err := client.DoPut(ft.Ctx, local, uploadURL, false, client.WithToken(tok))
	require.NoError(t, err)

	statInfo, err := client.DoStat(ft.Ctx, uploadURL, client.WithToken(tok),
		client.WithRequestChecksums([]client.ChecksumType{client.AlgCRC32C}))
	require.NoError(t, err)
	require.NotNil(t, statInfo)
	require.NotNil(t, statInfo.Checksums, "Checksums must be present when requested")
	got, ok := statInfo.Checksums["crc32c"]
	require.True(t, ok, "CRC32C entry should be present: %+v", statInfo.Checksums)

	// statInfo.Checksums values are hex-encoded raw digest bytes (see
	// client/main.go: hex.EncodeToString(info.Value)). That's the same
	// encoding as expectedCRC32CHex.
	assert.Equal(t, expectedCRC32CHex(content), got,
		"CRC32C value reported via Stat must match the actual content checksum")

	// xattr should be cached for fast subsequent reads.
	backendFile := filepath.Join(ft.Exports[0].StoragePrefix, "obj.bin")
	xattrData, err := xattr.Get(backendFile, "user.XrdCks.crc32c")
	require.NoError(t, err)
	assert.NotEmpty(t, xattrData)
}

// Download a POSIXv2-served object *through the cache* (V1 XRootD-based and
// V2 Pelican-native) with WithRequireChecksum() so the client must successfully
// verify the digest returned by the cache against the file it just downloaded.
func TestPosixv2_DoGetVerifiesChecksum_ThroughCache(t *testing.T) {
	cases := []struct {
		name        string
		enableV2    bool
		description string
	}{
		{
			name:        "V1_XRootD_cache",
			enableV2:    false,
			description: "Default cache implementation backed by XRootD",
		},
		{
			name:        "V2_Pelican_cache",
			enableV2:    true,
			description: "Pelican-native cache implementation (Cache.EnableV2)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(test_utils.SetupTestLogging(t))
			server_utils.ResetTestState()
			t.Cleanup(server_utils.ResetTestState)

			if tc.enableV2 {
				require.NoError(t, param.Cache_EnableV2.Set(true))
			}

			storage := t.TempDir()
			skipUnlessXattrs(t, storage)

			originConfig := fmt.Sprintf(`
Origin:
  DefaultChecksumTypes: ["crc32c", "md5"]
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

			ft := fed_test_utils.NewFedTest(t, originConfig)
			require.NotNil(t, ft)

			content := []byte("POSIXv2 checksum-verify through " + tc.name + ": " +
				strings.Repeat("x", 4096))

			localDir := t.TempDir()
			local := filepath.Join(localDir, "verify.bin")
			require.NoError(t, os.WriteFile(local, content, 0o644))

			objectURL := fmt.Sprintf("pelican://%s:%d/test/verify.bin",
				param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())

			tok := getTempTokenForTest(t)
			_, err := client.DoPut(ft.Ctx, local, objectURL, false, client.WithToken(tok))
			require.NoError(t, err)

			// Download via the cache. WithRequireChecksum() makes the client
			// return ErrServerChecksumMissing if no algorithm verified.
			dst := filepath.Join(t.TempDir(), "got.bin")
			results, err := client.DoGet(ft.Ctx, objectURL, dst, false,
				client.WithToken(tok),
				client.WithRequestChecksums([]client.ChecksumType{client.AlgCRC32C}),
				client.WithRequireChecksum(),
			)
			require.NoError(t, err,
				"%s: DoGet with WithRequireChecksum must succeed -- "+
					"a failure indicates the cache failed to relay a verifiable digest "+
					"from POSIXv2 to the client", tc.description)
			require.NotEmpty(t, results)
			r := results[0]

			// Body must round-trip intact.
			got, err := os.ReadFile(dst)
			require.NoError(t, err)
			require.Equal(t, content, got, "downloaded bytes must match uploaded bytes")

			clientByAlg := map[client.ChecksumType][]byte{
				client.AlgCRC32C: expectedCRC32CRaw(content),
				client.AlgMD5:    expectedMD5Raw(content),
			}

			t.Logf("%s: cache returned digests: %v",
				tc.name, summarizeChecksums(r.ServerChecksums))

			// Both cache implementations must relay at least one digest from
			// POSIXv2. (V1/XRootD computes its own digest of the served bytes;
			// V2/Pelican relays the digests it persisted at download time.)
			require.NotEmpty(t, r.ServerChecksums,
				"%s: cache must relay at least one digest from POSIXv2 to the client", tc.name)

			matched := 0
			for _, sck := range r.ServerChecksums {
				wantBytes, known := clientByAlg[sck.Algorithm]
				if !known {
					// SHA-1 / CRC32 are not asserted here, but log them
					// so a future regression is easy to spot.
					t.Logf("%s: cache returned %s digest of %d bytes (not asserted): %x",
						tc.name, client.HttpDigestFromChecksum(sck.Algorithm),
						len(sck.Value), sck.Value)
					continue
				}
				assert.Equal(t, wantBytes, sck.Value,
					"%s: %s digest from cache must equal locally-computed %s",
					tc.name, client.HttpDigestFromChecksum(sck.Algorithm),
					client.HttpDigestFromChecksum(sck.Algorithm))
				matched++
			}
			assert.Greater(t, matched, 0,
				"%s: at least one of CRC32C/MD5 should round-trip from POSIXv2 through the cache; "+
					"got server entries: %v", tc.name, summarizeChecksums(r.ServerChecksums))
		})
	}
}

// Previously, the ETag of every POSIXv2 object looked the same because it was
// just `mtime|size` concatenated as hex. With the inode included, two distinct
// files -- even with identical size and mtime -- have observably distinct ETags
// over the wire.
func TestPosixv2_ETagDistinctForDifferentObjects(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	storage := t.TempDir()

	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	exportRoot := ft.Exports[0].StoragePrefix

	// Three files: same size, two with the same mtime forced to a fixed value,
	// one with a naturally-fresh mtime. The first two are the "collision" case
	// that the old size+mtime ETag could not distinguish.
	const sz = 5
	a := filepath.Join(exportRoot, "a.bin")
	b := filepath.Join(exportRoot, "b.bin")
	c := filepath.Join(exportRoot, "c.bin")
	require.NoError(t, os.WriteFile(a, []byte("AAAAA"), 0o644))
	require.NoError(t, os.WriteFile(b, []byte("BBBBB"), 0o644))
	require.NoError(t, os.WriteFile(c, []byte("CCCCC"), 0o644))
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	require.NoError(t, os.Chtimes(a, fixed, fixed))
	require.NoError(t, os.Chtimes(b, fixed, fixed))

	require.Equal(t, int64(sz), mustSize(t, a))
	require.Equal(t, int64(sz), mustSize(t, b))

	tok := getTempTokenForTest(t)
	httpClient := config.GetClientNoRedirect()

	etagOf := func(name string) string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet,
			originServerURL()+"/api/v1.0/origin/data/test/"+name, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "GET %s should succeed", name)
		_, _ = io.Copy(io.Discard, resp.Body)
		etag := resp.Header.Get("ETag")
		require.NotEmpty(t, etag, "GET %s should return an ETag header", name)
		return etag
	}

	etagA := etagOf("a.bin")
	etagB := etagOf("b.bin")
	etagC := etagOf("c.bin")

	// The core regression check: two files with the same size+mtime must not
	// share an ETag any more.
	assert.NotEqual(t, etagA, etagB,
		"two files with identical size and mtime must have distinct ETags (a=%q b=%q)", etagA, etagB)
	// And c must differ from both, since its mtime is different.
	assert.NotEqual(t, etagA, etagC)
	assert.NotEqual(t, etagB, etagC)
}

// TestPosixv2_ETagIfNoneMatch_RoundTrip verifies the conditional-request
// happy path: a fresh ETag yields 304 on a repeat GET, and the ETag returned
// in the 304 response matches the original. Hand-wired (not e2e-fed) tests
// already cover the format itself; this test guards against a regression in
// the integration with the federation's router and TLS path.
func TestPosixv2_ETagIfNoneMatch_RoundTrip(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	storage := t.TempDir()

	originConfig := fmt.Sprintf(`
Origin:
  StorageType: posixv2
  Exports:
    - FederationPrefix: /test
      StoragePrefix: %s
      Capabilities: ["PublicReads", "Writes", "Listings"]
Director:
  MinStatResponse: 1
  MaxStatResponse: 1
`, storage)

	ft := fed_test_utils.NewFedTest(t, originConfig)
	require.NotNil(t, ft)

	// NewFedTest may rewrite the StoragePrefix; use the effective value.
	path := filepath.Join(ft.Exports[0].StoragePrefix, "etag_rt.bin")
	require.NoError(t, os.WriteFile(path, []byte("conditional payload"), 0o644))

	tok := getTempTokenForTest(t)
	httpClient := config.GetClientNoRedirect()

	url := originServerURL() + "/api/v1.0/origin/data/test/etag_rt.bin"

	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "initial GET should succeed, body=%q", string(body))
	etag := resp.Header.Get("ETag")
	require.NotEmpty(t, etag, "POSIXv2 GET must return an ETag")

	// The new ETag is an opaque, quoted 16-char hex digest. We don't assert
	// the bytes, but we do guard against regressing to a format that lets
	// two files with the same size and mtime collide.
	require.True(t, strings.HasPrefix(etag, `"`) && strings.HasSuffix(etag, `"`),
		"ETag must be quoted: %q", etag)
	require.Equal(t, 16, len(strings.Trim(etag, `"`)),
		"ETag should be a 16-char opaque hex digest: %q", etag)

	req2, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("If-None-Match", etag)
	resp2, err := httpClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusNotModified, resp2.StatusCode,
		"matching If-None-Match should yield 304")
	assert.Equal(t, etag, resp2.Header.Get("ETag"),
		"304 response should echo the matching ETag")
}

func mustSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info.Size()
}
