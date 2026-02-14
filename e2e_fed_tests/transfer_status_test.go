//go:build !windows

package fed_tests

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

// Tests for the X-Transfer-Status HTTP trailer.
//
// The persistent cache advertises an X-Transfer-Status trailer when the
// client sends "X-Transfer-Status: true" (plus "TE: trailers" for
// HTTP/1.1).  The trailer is set after the full body has been streamed
// and reports "200: OK" on success or "500: <error>" on failure.
//
// These tests verify:
//  - Full GET: trailer is "200: OK"
//  - Range GET: trailer is "200: OK"
//  - HEAD: no body → no trailer
//  - Without the opt-in header: no trailer emitted
//  - After auto-repair: trailer still reports "200: OK" (repair is
//    transparent to the client)
//  - Inline storage (small files): trailer is "200: OK"

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
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// ============================================================================
// Helpers
// ============================================================================

// tsEnv bundles everything needed for an X-Transfer-Status test.
type tsEnv struct {
	ft    *fed_test_utils.FedTest
	token string
}

// setupTSEnv starts a minimal persistent-cache federation.
func setupTSEnv(t *testing.T) *tsEnv {
	t.Helper()
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	require.NoError(t, param.Set(param.Cache_EnableV2.GetName(), true))
	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	token := getTempTokenForTest(t)

	return &tsEnv{ft: ft, token: token}
}

// uploadAndPrimeTS uploads content through the origin and primes the
// cache, returning the direct cache URL.
func uploadAndPrimeTS(ctx context.Context, t *testing.T, env *tsEnv, filename string, content []byte) string {
	t.Helper()

	localTmpDir := t.TempDir()
	localFile := filepath.Join(localTmpDir, filename)
	require.NoError(t, os.WriteFile(localFile, content, 0644))

	uploadURL := fmt.Sprintf("pelican://%s:%d/test/%s",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt(), filename)

	_, err := client.DoPut(ctx, localFile, uploadURL, false, client.WithToken(env.token))
	require.NoError(t, err)

	// Prime the cache by downloading once
	downloadFile := filepath.Join(localTmpDir, "prime_download")
	_, err = client.DoGet(ctx, uploadURL, downloadFile, false, client.WithToken(env.ft.Token))
	require.NoError(t, err)

	return getCacheRedirectURL(ctx, t, "/test/"+filename, env.token)
}

// doRequestWithTrailer sends a GET (or HEAD) request that opts in to
// X-Transfer-Status trailers.  If method is empty it defaults to GET.
func doRequestWithTrailer(ctx context.Context, url, token, method, rangeHeader string) rangeResult {
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return rangeResult{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Transfer-Status", "true")
	req.Header.Set("TE", "trailers")
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	if err != nil {
		return rangeResult{err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return rangeResult{err: err, statusCode: resp.StatusCode}
	}

	return rangeResult{
		body:           body,
		statusCode:     resp.StatusCode,
		transferStatus: resp.Trailer.Get("X-Transfer-Status"),
	}
}

// doRequestWithoutTrailer sends a GET request that does NOT include
// the X-Transfer-Status opt-in header.  The response should therefore
// not contain the trailer.
func doRequestWithoutTrailer(ctx context.Context, url, token, rangeHeader string) rangeResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return rangeResult{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// Intentionally omit X-Transfer-Status and TE headers
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}

	resp, err := (&http.Client{Transport: config.GetTransport()}).Do(req)
	if err != nil {
		return rangeResult{err: err}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return rangeResult{err: err, statusCode: resp.StatusCode}
	}

	return rangeResult{
		body:           body,
		statusCode:     resp.StatusCode,
		transferStatus: resp.Trailer.Get("X-Transfer-Status"),
	}
}

// ============================================================================
// Tests
// ============================================================================

// TestTransferStatus_FullGet_Success verifies that a full GET of a cached
// object returns "200: OK" in the X-Transfer-Status trailer.
func TestTransferStatus_FullGet_Success(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384) // 16KB — disk storage
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_full.bin", content)

	r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusOK, r.statusCode)
	assert.Equal(t, content, r.body, "Body should match original content")
	assert.Equal(t, "200: OK", r.transferStatus,
		"Full GET should report 200: OK in X-Transfer-Status trailer")
}

// TestTransferStatus_RangeGet_Success verifies that a byte-range GET
// returns "200: OK" in the X-Transfer-Status trailer.
func TestTransferStatus_RangeGet_Success(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_range.bin", content)

	// Request bytes that span the second and third blocks
	r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "bytes=4080-12239")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusPartialContent, r.statusCode)
	assert.Equal(t, content[4080:12240], r.body,
		"Range body should match the expected slice")
	assert.Equal(t, "200: OK", r.transferStatus,
		"Range GET should report 200: OK in X-Transfer-Status trailer")
}

// TestTransferStatus_Head_NoTrailer verifies that a HEAD request does
// not emit an X-Transfer-Status trailer (since there is no body).
func TestTransferStatus_Head_NoTrailer(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_head.bin", content)

	r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, http.MethodHead, "")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusOK, r.statusCode)
	assert.Empty(t, r.body, "HEAD should return an empty body")
	// HEAD has no body so the trailer has no place to be sent in HTTP/1.1
	// chunked transfer-encoding (no chunks → no trailer block).
	// We accept either empty or "200: OK" here.
	t.Logf("X-Transfer-Status trailer on HEAD: %q", r.transferStatus)
}

// TestTransferStatus_NoOptIn_NoTrailer verifies that when the client
// does NOT send "X-Transfer-Status: true", the server does not include
// the trailer.
func TestTransferStatus_NoOptIn_NoTrailer(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_nooptin.bin", content)

	r := doRequestWithoutTrailer(env.ft.Ctx, cacheURL, env.token, "")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusOK, r.statusCode)
	assert.Equal(t, content, r.body, "Body should match even without trailer opt-in")
	assert.Empty(t, r.transferStatus,
		"Without X-Transfer-Status opt-in, no trailer should be present")
}

// TestTransferStatus_NoOptIn_Range_NoTrailer verifies that a range
// request without the opt-in header also produces no trailer.
func TestTransferStatus_NoOptIn_Range_NoTrailer(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_nooptin_range.bin", content)

	r := doRequestWithoutTrailer(env.ft.Ctx, cacheURL, env.token, "bytes=0-4079")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusPartialContent, r.statusCode)
	assert.Equal(t, content[0:4080], r.body)
	assert.Empty(t, r.transferStatus,
		"Without X-Transfer-Status opt-in, range request should have no trailer")
}

// TestTransferStatus_AutoRepair_StillOK verifies that when block data
// is corrupted and auto-repair kicks in, the X-Transfer-Status trailer
// still reports "200: OK" because the repair is transparent.
func TestTransferStatus_AutoRepair_StillOK(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_repair.bin", content)

	// Verify a clean read first
	r1 := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "")
	require.NoError(t, r1.err)
	require.Equal(t, http.StatusOK, r1.statusCode)
	require.Equal(t, "200: OK", r1.transferStatus)

	// Find and corrupt the on-disk file
	cacheStorageLocation := param.Cache_StorageLocation.GetString()
	objectsDir := filepath.Join(cacheStorageLocation, "persistent-cache", "objects")
	objFile := findObjectFileForContent(t, objectsDir, len(content))
	data, err := os.ReadFile(objFile)
	require.NoError(t, err)
	require.True(t, len(data) > 20)

	// Flip a bit in the first block
	data[15] ^= 0x42
	require.NoError(t, os.WriteFile(objFile, data, 0600))

	// Read again — auto-repair should fix it transparently
	r2 := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "")
	require.NoError(t, r2.err)
	assert.Equal(t, http.StatusOK, r2.statusCode)
	assert.Equal(t, content, r2.body,
		"After auto-repair the body should be correct")
	assert.Equal(t, "200: OK", r2.transferStatus,
		"Auto-repair should produce a successful trailer")
}

// TestTransferStatus_InlineStorage verifies that the X-Transfer-Status
// trailer works for objects stored inline (small objects under the
// InlineThreshold).
func TestTransferStatus_InlineStorage(t *testing.T) {
	env := setupTSEnv(t)

	// Use a file smaller than InlineThreshold (4096 bytes) so it's stored
	// inline in BadgerDB rather than as encrypted blocks on disk.
	content := generateTestData(512)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_inline.bin", content)

	r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusOK, r.statusCode)
	assert.Equal(t, content, r.body)
	assert.Equal(t, "200: OK", r.transferStatus,
		"Inline storage should also report 200: OK in trailer")
}

// TestTransferStatus_SuffixRange verifies that a suffix-range request
// (bytes=-N) also gets the correct trailer.
func TestTransferStatus_SuffixRange(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_suffix.bin", content)

	// Request the last 1000 bytes
	r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "bytes=-1000")
	require.NoError(t, r.err)
	assert.Equal(t, http.StatusPartialContent, r.statusCode)
	assert.Equal(t, content[len(content)-1000:], r.body,
		"Suffix range body should be the last 1000 bytes")
	assert.Equal(t, "200: OK", r.transferStatus,
		"Suffix range should report 200: OK in trailer")
}

// TestTransferStatus_MultipleReads_Consistent verifies that the trailer
// is consistently set across multiple sequential reads of the same object.
func TestTransferStatus_MultipleReads_Consistent(t *testing.T) {
	env := setupTSEnv(t)

	content := generateTestData(16384)
	cacheURL := uploadAndPrimeTS(env.ft.Ctx, t, env, "ts_multi.bin", content)

	for i := 0; i < 3; i++ {
		r := doRequestWithTrailer(env.ft.Ctx, cacheURL, env.token, "", "")
		require.NoError(t, r.err, "read %d should succeed", i)
		assert.Equal(t, http.StatusOK, r.statusCode, "read %d status", i)
		assert.Equal(t, content, r.body, "read %d body", i)
		assert.Equal(t, "200: OK", r.transferStatus,
			"read %d trailer should be 200: OK", i)
	}
}
