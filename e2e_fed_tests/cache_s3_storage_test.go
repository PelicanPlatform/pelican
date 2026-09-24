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

// End-to-end tests for the persistent cache's S3 storage targets: a full
// federation (director, registry, origin, V2 cache) plus a live minio
// bucket.  Objects fetched through the cache are tiered to the bucket once
// complete, after which GETs are answered with a 307 to a pre-signed S3
// URL (or proxied through the cache when redirect is disabled).

package fed_tests

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// noRedirectHTTPClient returns a client that trusts the federation's TLS
// certificates and does not follow redirects, so tests can observe the
// cache's 307 responses directly.
func noRedirectHTTPClient() *http.Client {
	return &http.Client{
		Transport: config.GetTransport(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// getWithToken issues a GET (optionally with a Range header) and returns
// the response; callers own the body.
func getWithToken(t *testing.T, httpClient *http.Client, url, token, rangeHeader string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if rangeHeader != "" {
		req.Header.Set("Range", rangeHeader)
	}
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestCacheS3StorageFederationE2E spins up a complete federation with an
// S3 storage target on the V2 cache and verifies the whole tiering +
// serving lifecycle against a live minio server.
func TestCacheS3StorageFederationE2E(t *testing.T) {
	test_utils.SkipIfNoMinio(t)
	endpoint, accessKey, secretKey := test_utils.StartMinio(t, "pelican-cache-fed-e2e")

	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	keyDir := t.TempDir()
	accessKeyfile := filepath.Join(keyDir, "access")
	secretKeyfile := filepath.Join(keyDir, "secret")
	require.NoError(t, os.WriteFile(accessKeyfile, []byte(accessKey), 0600))
	require.NoError(t, os.WriteFile(secretKeyfile, []byte(secretKey), 0600))

	require.NoError(t, param.Cache_EnableV2.Set(true))
	require.NoError(t, param.Cache_S3UploadThreshold.Set("4KB"))
	require.NoError(t, param.Cache_S3StorageTargets.Set([]interface{}{
		map[string]interface{}{
			"ServiceUrl":    endpoint,
			"Bucket":        "pelican-cache-fed-e2e",
			"Prefix":        "cache",
			"MaxSize":       "1GB",
			"AccessKeyfile": accessKeyfile,
			"SecretKeyfile": secretKeyfile,
		},
	}))

	ft := fed_test_utils.NewFedTest(t, persistentCacheConfig)
	token := getTempTokenForTest(t)

	// A large object (above the threshold) that should be tiered, and a
	// small one that must stay on local storage.
	bigContent := writeOriginFile(t, ft, "s3_tier_big.bin", 64*1024)
	smallContent := writeOriginFile(t, ft, "s3_tier_small.bin", 512)

	bigCacheURL := waitForCacheRedirectURL(t, ft, "/test/s3_tier_big.bin", token)
	httpClient := noRedirectHTTPClient()

	// First GET is a cache miss served from local storage: a plain 200
	// with the full body (tiering happens only after completion).
	resp := getWithToken(t, httpClient, bigCacheURL, token, "")
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "cache-miss GET failed: %s", string(body))
	require.Equal(t, bigContent, body)

	// The completion hook enqueues the object for tiering; once the upload
	// commits, the cache answers with a 307 to a pre-signed bucket URL.
	var location string
	require.Eventually(t, func() bool {
		resp := getWithToken(t, httpClient, bigCacheURL, token, "")
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusTemporaryRedirect {
			return false
		}
		location = resp.Header.Get("Location")
		return location != ""
	}, 30*time.Second, 250*time.Millisecond, "cache never redirected to the S3 bucket")

	assert.Contains(t, location, "pelican-cache-fed-e2e", "redirect should point at the bucket")
	assert.Contains(t, location, "X-Amz-Signature", "redirect should be pre-signed")

	// The pre-signed URL is self-authenticating: a bare client with no
	// token downloads the object bytes directly from the bucket.
	presignResp, err := http.Get(location)
	require.NoError(t, err)
	body, err = io.ReadAll(presignResp.Body)
	presignResp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, presignResp.StatusCode)
	assert.Equal(t, bigContent, body)

	// A redirect-following client gets the object transparently through
	// the cache endpoint.
	followClient := &http.Client{Transport: config.GetTransport()}
	resp = getWithToken(t, followClient, bigCacheURL, token, "")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, bigContent, body)

	// Range requests survive the redirect: the client re-applies the Range
	// header to the pre-signed URL and S3 honors it.
	resp = getWithToken(t, followClient, bigCacheURL, token, "bytes=1000-1999")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, bigContent[1000:2000], body)

	// The full Pelican transfer client works end-to-end through the
	// director -> cache -> pre-signed-URL chain.
	downloadDir := t.TempDir()
	downloadFile := filepath.Join(downloadDir, "via_client.bin")
	fedURL := fmt.Sprintf("pelican://%s:%d/test/s3_tier_big.bin",
		param.Server_Hostname.GetString(), param.Server_WebPort.GetInt())
	_, err = client.DoGet(ft.Ctx, fedURL, downloadFile, false, client.WithToken(token))
	require.NoError(t, err)
	downloaded, err := os.ReadFile(downloadFile)
	require.NoError(t, err)
	assert.Equal(t, bigContent, downloaded)

	// The small object stays on local storage: served directly with a 200
	// even though the big object has already been tiered (which proves the
	// upload workers have drained past it).
	smallCacheURL := waitForCacheRedirectURL(t, ft, "/test/s3_tier_small.bin", token)
	resp = getWithToken(t, httpClient, smallCacheURL, token, "")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	// A 200 here is itself the assertion that the object was not tiered: a
	// tiered object would have answered the same request with a 307.
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"below-threshold object must be served from local storage, not redirected")
	assert.Equal(t, smallContent, body)

	// With redirect disabled, the same tiered object is proxied through
	// the cache: plain 200 with the bytes streamed from the bucket.
	require.NoError(t, param.Cache_S3DisableRedirect.Set(true))
	t.Cleanup(func() { _ = param.Cache_S3DisableRedirect.Set(false) })
	resp = getWithToken(t, httpClient, bigCacheURL, token, "")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "proxy-mode GET failed: %s", string(body))
	assert.Equal(t, bigContent, body)

	// Proxy-mode range request is served by the cache itself.
	resp = getWithToken(t, httpClient, bigCacheURL, token, "bytes=4000-4999")
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusPartialContent, resp.StatusCode)
	assert.Equal(t, bigContent[4000:5000], body)

	// Sanity: the local copy of the tiered object is gone — the objects
	// directory holds only the small object's file.
	cacheStorageLocation := param.Cache_StorageLocation.GetString()
	require.NotEmpty(t, cacheStorageLocation)
	objectsDir := filepath.Join(cacheStorageLocation, "persistent-cache", "objects")
	bigOnDiskSize := int64(0)
	_ = filepath.Walk(objectsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.HasSuffix(path, ".pelican-cache-id") {
			return nil
		}
		if info.Size() > bigOnDiskSize {
			bigOnDiskSize = info.Size()
		}
		return nil
	})
	assert.Less(t, bigOnDiskSize, int64(32*1024),
		"the 64KB object should no longer have a local file after tiering")
}
