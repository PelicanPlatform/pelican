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
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The sent-bytes threshold callback fires exactly once, on the read that
// crosses the threshold, no matter how many reads follow.
func TestProgressReaderSentThreshold(t *testing.T) {
	fired := 0
	pr := &progressReader{
		reader:          io.NopCloser(strings.NewReader(strings.Repeat("x", 1024))),
		sizer:           &ConstantSizer{size: 1024},
		closed:          make(chan bool, 1),
		sentThreshold:   512,
		onSentThreshold: func() { fired++ },
	}
	buf := make([]byte, 128)
	for {
		if _, err := pr.Read(buf); err == io.EOF {
			break
		} else {
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 1, fired, "threshold callback must fire exactly once")
}

// An upload destination that consumes the request body but does not answer
// until the body is complete (no 100-continue negotiated) must still be
// marked non-starving once uploadNonStarvingSentBytes have been consumed —
// otherwise a long upload to a healthy-but-quiet destination would hold a
// starving-cap slot for its whole duration.
func TestUploadSentBytesMarksNonStarving(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	test_utils.InitClient(t, map[param.Param]any{})

	const payloadSize = 6 << 20 // comfortably past the 4 MiB threshold

	var fired atomic.Bool
	firedCh := make(chan struct{})
	release := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Report the destination object as absent for the pre-upload stat.
		if r.Method == "PROPFIND" || r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Consume most of the body, then stall without sending a single
		// response byte until the test has observed the signal. This pins
		// the sent-bytes path: neither Got100Continue nor
		// GotFirstResponseByte can have fired yet.
		if _, err := io.CopyN(io.Discard, r.Body, 5<<20); err != nil {
			return
		}
		<-release
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	localFile := filepath.Join(t.TempDir(), "upload.bin")
	require.NoError(t, os.WriteFile(localFile, bytes.Repeat([]byte("u"), payloadSize), 0o644))

	transfer := &transferFile{
		ctx:       context.Background(),
		localPath: localFile,
		remoteURL: serverURL,
		xferType:  transferTypeUpload,
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{
				Scheme: "pelican://",
				Host:   serverURL.Host,
				Path:   "/test/upload.bin",
			},
			dirResp: server_structs.DirectorResponse{
				XPelNsHdr: server_structs.XPelNs{
					CollectionsUrl: serverURL,
				},
			},
		},
		attempts: []transferAttemptDetails{{Url: serverURL, Proxy: false}},
		schedFirstByte: func() {
			if fired.CompareAndSwap(false, true) {
				close(firedCh)
			}
		},
	}

	done := make(chan error, 1)
	go func() {
		result, err := uploadObject(transfer)
		if err == nil {
			err = result.Error
		}
		done <- err
	}()

	// The non-starving signal must arrive while the server is still mute.
	select {
	case <-firedCh:
	case err := <-done:
		t.Fatalf("upload finished (err=%v) before the sent-bytes signal fired", err)
	case <-time.After(30 * time.Second):
		t.Fatal("sent-bytes threshold never marked the upload non-starving")
	}

	close(release)
	select {
	case err := <-done:
		require.NoError(t, err, "upload should complete cleanly once the server drains")
	case <-time.After(30 * time.Second):
		t.Fatal("upload did not complete after the server was released")
	}
}
