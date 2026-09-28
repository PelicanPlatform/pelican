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

package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/studio-b12/gowebdav"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// hostileMultistatus renders a PROPFIND response whose first <D:response> is
// the collection itself (gowebdav requires that, or ReadDir returns 405)
// followed by a single hostile entry.  The href and displayname are inserted
// verbatim; gowebdav derives the entry name from path.Base of the unescaped
// href, falling back to displayname when the href has an invalid escape.
func hostileMultistatus(href, displayName string, isCollection bool) string {
	resourceType := "<D:resourcetype/>"
	if isCollection {
		resourceType = "<D:resourcetype><D:collection/></D:resourcetype>"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:">
  <D:response>
    <D:href>/root/</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>root</D:displayname>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
  <D:response>
    <D:href>%s</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>%s</D:displayname>
        %s
        <D:getcontentlength>5</D:getcontentlength>
        <D:getlastmodified>Mon, 01 Jan 2024 00:00:00 GMT</D:getlastmodified>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>
</D:multistatus>`, href, displayName, resourceType)
}

// TestRecursiveDownloadRejectsHostileListing drives walkDirDownloadHelper
// against a WebDAV server that returns entry names a well-behaved origin
// never would.  Every case must fail before any file is submitted to the
// engine (nothing reads te.files, so a real submission would park forever),
// and nothing may be created on disk.
func TestRecursiveDownloadRejectsHostileListing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		href         string
		displayName  string
		isCollection bool
	}{
		{
			// path.Base("/root/..") == ".."; as a collection this would also
			// recurse upward through the remote tree indefinitely.
			name:         "dot-dot collection href",
			href:         "/root/..",
			displayName:  "..",
			isCollection: true,
		},
		{
			// %zz is an invalid escape, so gowebdav falls back to displayname.
			name:        "invalid escape with traversal displayname",
			href:        "/root/%zz",
			displayName: "../../canary",
		},
		{
			name:        "invalid escape with nested displayname",
			href:        "/root/%zz",
			displayName: "sub/canary",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := hostileMultistatus(tc.href, tc.displayName, tc.isCollection)
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PROPFIND" {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "application/xml; charset=utf-8")
				w.WriteHeader(http.StatusMultiStatus)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(mock.Close)
			mockURL, err := url.Parse(mock.URL)
			require.NoError(t, err)

			parent := t.TempDir()
			dest := filepath.Join(parent, "dest")
			require.NoError(t, os.Mkdir(dest, 0755))

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			// This branch's walk emits into a caller-supplied channel instead of
			// submitting through the engine, so no engine state is needed.
			te := &TransferEngine{ctx: ctx}
			files := make(chan *clientTransferFile, 16)
			job := &clientTransferJob{
				uuid: uuid.New(),
				job: &TransferJob{
					uuid:      uuid.New(),
					ctx:       ctx,
					xferType:  transferTypeDownload,
					localPath: dest,
					remoteURL: &pelican_url.PelicanURL{
						Scheme: "pelican://",
						Host:   "example-federation.org",
						Path:   "/root",
					},
					dirResp: server_structs.DirectorResponse{
						XPelNsHdr: server_structs.XPelNs{CollectionsUrl: mockURL},
					},
				},
			}
			transfers := []transferAttemptDetails{
				{Url: &url.URL{Scheme: mockURL.Scheme, Host: mockURL.Host, Path: "/root"}},
			}

			err = te.walkDirDownloadHelper(job, transfers, files, "/root", gowebdav.NewClient(mock.URL, "", ""))
			require.Error(t, err)
			t.Logf("walk refused: %v", err)
			assert.Contains(t, err.Error(), "invalid entry")
			assert.Empty(t, files, "no transfer may be emitted for a hostile entry")

			// Nothing was created: dest is empty and the parent holds only dest.
			assert.Empty(t, dirNames(t, dest))
			assert.Equal(t, []string{"dest"}, dirNames(t, parent))
		})
	}
}
