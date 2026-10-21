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

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestServiceDigestDefaults verifies that per-service digest memory drives
// the default verification set: unknown services get the platform default
// (CRC32C), while services that previously reported digests get those.
func TestServiceDigestDefaults(t *testing.T) {
	// Unknown service: platform default.
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService("origin-a.example.com:8443"))

	// A service that reported MD5 becomes the default for that service only.
	rememberServiceDigests("origin-a.example.com:8443", []ChecksumInfo{
		{Algorithm: AlgMD5, Value: []byte{0x01}},
	})
	assert.Equal(t, []ChecksumType{AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService("origin-b.example.com:8443"))

	// A later report (e.g. after a server upgrade) replaces the remembered set.
	rememberServiceDigests("origin-a.example.com:8443", []ChecksumInfo{
		{Algorithm: AlgCRC32C, Value: []byte{0x02}},
		{Algorithm: AlgMD5, Value: []byte{0x03}},
	})
	assert.Equal(t, []ChecksumType{AlgCRC32C, AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))

	// Empty reports and empty hosts must not poison the cache.
	rememberServiceDigests("origin-a.example.com:8443", nil)
	assert.Equal(t, []ChecksumType{AlgCRC32C, AlgMD5}, defaultChecksumTypesForService("origin-a.example.com:8443"))
	rememberServiceDigests("", []ChecksumInfo{{Algorithm: AlgSHA1}})
	assert.Equal(t, []ChecksumType{AlgDefault}, defaultChecksumTypesForService(""))
}

// TestChecksumFallbackWarningQuietUnrequested covers the symptom reported in
// issue #3614: a plain `pelican object get` against a server that computes
// only MD5 warned "Requested checksum type(s) not provided by server" on
// every transfer, even though the caller never asked for a particular digest
// and could do nothing about the answer.
//
// The two cases are deliberately contrasted. A caller who asked for nothing
// gets no warning at all -- including on first contact, since the service's
// digests are remembered before the verification decision is made. A caller
// who explicitly asked for CRC32C still learns it did not get it, but only
// once per process rather than once per object.
func TestChecksumFallbackWarningQuietUnrequested(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[param.Param]any{
		param.Logging_Level: "debug",
	})

	// MD5 of "test file content", base64-encoded per RFC 3230.
	const correctMD5Base64 = "x4UGDIZnlswqFwjJlxVMjg=="
	const body = "test file content"

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.Header().Set("Content-Length", "17")
			// This server computes only MD5, whatever was asked for.
			w.Header().Set("Digest", "md5="+correctMD5Base64)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.Header().Set("Content-Length", "17")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(body))
			assert.NoError(t, err)
		default:
			t.Fatal("Unexpected method:", r.Method)
		}
	}))
	defer svr.Close()
	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	newTransfer := func(requested []ChecksumType) *transferFile {
		return &transferFile{
			xferType: transferTypeDownload,
			ctx:      context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/test.txt",
				},
			},
			localPath:          os.DevNull,
			remoteURL:          svrURL,
			attempts:           []transferAttemptDetails{{Url: svrURL}},
			requestedChecksums: requested,
		}
	}

	fallbackWarnings := func(entries []*logrus.Entry) (n int) {
		for _, entry := range entries {
			if entry.Level == logrus.WarnLevel &&
				strings.Contains(entry.Message, "not provided by server") {
				n++
			}
		}
		return
	}

	// Both the per-service digest memory and the warn-once memory are
	// process-wide, so clear this server's entries before each case: neither
	// assertion may pass merely because an earlier test primed them.
	reset := func() {
		checksumFallbacksSeen.Delete(AlgMD5)
		serviceDigests.Delete(svrURL.Host)
	}

	t.Run("unrequested is silent", func(t *testing.T) {
		reset()
		hook := logrustest.NewGlobal()
		defer hook.Reset()

		results, err := downloadObject(newTransfer(nil))
		require.NoError(t, err)
		require.NoError(t, results.Error, "MD5 should still verify the transfer")

		assert.Zero(t, fallbackWarnings(hook.AllEntries()),
			"a caller that requested no checksum type must not be warned about the one it got")
	})

	t.Run("explicit request warns once", func(t *testing.T) {
		reset()
		hook := logrustest.NewGlobal()
		defer hook.Reset()

		for range 2 {
			results, err := downloadObject(newTransfer([]ChecksumType{AlgCRC32C}))
			require.NoError(t, err)
			require.NoError(t, results.Error, "MD5 should still verify the transfer")
		}

		assert.Equal(t, 1, fallbackWarnings(hook.AllEntries()),
			"a caller that asked for CRC32C should be told once, not once per object")
	})
}
