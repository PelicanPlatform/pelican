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
	"crypto/md5"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// TestSkipChecksumsSuppressesDigestRequest covers WithSkipChecksums.
//
// A download normally follows the body with a HEAD carrying Want-Digest, and
// that request is what verifies the transfer -- so the default must keep
// making it. A caller that will neither verify nor keep the response (a cache
// passing a collection's index through) can opt out, and then no digest
// request may be sent at all: against a server that declines to answer
// Want-Digest for the path, that request sits until the transport's response
// header timeout, and everyone waiting on the download waits with it.
func TestSkipChecksumsSuppressesDigestRequest(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[param.Param]any{
		param.Logging_Level: "debug",
	})

	body := []byte("collection index stand-in")
	sum := md5.Sum(body)
	md5Base64 := base64.StdEncoding.EncodeToString(sum[:])
	contentLen := strconv.Itoa(len(body))

	var digestRequests atomic.Int32
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			if r.Header.Get("Want-Digest") != "" {
				digestRequests.Add(1)
				w.Header().Set("Digest", "md5="+md5Base64)
			}
			w.Header().Set("Content-Length", contentLen)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Length", contentLen)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		assert.NoError(t, err)
	}))
	defer svr.Close()

	svrURL, err := url.Parse(svr.URL)
	require.NoError(t, err)

	newTransfer := func(skip bool) *transferFile {
		return &transferFile{
			xferType: transferTypeDownload,
			ctx:      context.Background(),
			job: &TransferJob{
				remoteURL: &pelican_url.PelicanURL{
					Scheme: "pelican://",
					Host:   svrURL.Host,
					Path:   svrURL.Path + "/object",
				},
			},
			localPath:     os.DevNull,
			remoteURL:     svrURL,
			attempts:      []transferAttemptDetails{{Url: svrURL}},
			skipChecksums: skip,
		}
	}

	t.Run("default asks for a digest", func(t *testing.T) {
		digestRequests.Store(0)
		results, err := downloadObject(newTransfer(false))
		require.NoError(t, err)
		require.NoError(t, results.Error)
		assert.Positive(t, digestRequests.Load(),
			"a normal download must still fetch the digest that verifies it")
	})

	t.Run("skip sends none", func(t *testing.T) {
		digestRequests.Store(0)
		results, err := downloadObject(newTransfer(true))
		require.NoError(t, err)
		require.NoError(t, results.Error,
			"skipping the digest must not fail the transfer")
		assert.Zero(t, digestRequests.Load(),
			"no Want-Digest request may be sent once the caller has opted out")
	})
}
