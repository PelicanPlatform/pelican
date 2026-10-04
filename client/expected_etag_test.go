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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/test_utils"
)

// bufferWriteCloser collects what a download writes.
type bufferWriteCloser struct{ bytes.Buffer }

func (b *bufferWriteCloser) Close() error { return nil }

// versionServer serves body with the given entity tag.  When cut is
// positive, it promises the whole body but sends only cut bytes and then
// drops the connection, as a server failing mid-transfer would.
func versionServer(t *testing.T, etag string, body []byte, cut int) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := 0
		if rg := r.Header.Get("Range"); rg != "" {
			_, _ = fmt.Sscanf(rg, "bytes=%d-", &start)
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)-start))
		if start > 0 {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(body)-1, len(body)))
			w.WriteHeader(http.StatusPartialContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		if cut > 0 {
			_, _ = w.Write(body[start:cut])
			w.(http.Flusher).Flush()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		_, _ = w.Write(body[start:])
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u
}

func versionedDownload(t *testing.T, expected string, servers ...*url.URL) (TransferResults, *bufferWriteCloser) {
	t.Helper()
	out := &bufferWriteCloser{}
	attempts := make([]transferAttemptDetails, 0, len(servers))
	for _, u := range servers {
		attempts = append(attempts, transferAttemptDetails{Url: u})
	}
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{Scheme: "pelican://", Host: servers[0].Host, Path: "/test.txt"},
		},
		remoteURL:     servers[0],
		writer:        out,
		attempts:      attempts,
		expectedETag:  expected,
		skipChecksums: true,
	}
	results, err := downloadObject(transfer)
	require.NoError(t, err)
	return results, out
}

// TestDownloadRefusesAnotherVersion checks WithExpectedETag: a response for
// another version of the object is refused before any of its body is
// written.
func TestDownloadRefusesAnotherVersion(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	body := []byte("the second version of the object")
	results, out := versionedDownload(t, `"v1"`, versionServer(t, `"v2"`, body, 0))
	require.Error(t, results.Error)
	assert.True(t, errors.Is(results.Error, ErrObjectVersionChanged), "got %v", results.Error)
	assert.Zero(t, out.Len(), "nothing of the other version may be written")
}

// TestDownloadRetryCannotSwitchVersions checks that, without an expected
// entity tag, a retry is held to the version the first attempt started
// writing: a second server with a newer version is refused before its bytes
// are spliced in after the first server's.
func TestDownloadRetryCannotSwitchVersions(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	v1 := bytes.Repeat([]byte("1"), 64*1024)
	v2 := bytes.Repeat([]byte("2"), 64*1024)
	results, out := versionedDownload(t, "",
		versionServer(t, `"v1"`, v1, 16*1024), versionServer(t, `"v2"`, v2, 0))
	require.Error(t, results.Error)
	assert.True(t, errors.Is(results.Error, ErrObjectVersionChanged), "got %v", results.Error)
	assert.NotContains(t, out.String(), "2", "no byte of the other version may be written")
}

// TestDownloadRefusalDoesNotPoisonTheRetry checks that a refused response
// does not become the version later attempts are held to: the next server,
// serving the expected version, completes the download.
func TestDownloadRefusalDoesNotPoisonTheRetry(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	v1 := []byte("the expected version of the object")
	results, out := versionedDownload(t, `"v1"`,
		versionServer(t, `"v2"`, []byte("another version entirely, longer"), 0), versionServer(t, `"v1"`, v1, 0))
	require.NoError(t, results.Error)
	assert.Equal(t, v1, out.Bytes())
}

// TestDownloadFailedAttemptThatWroteNothingDoesNotHoldTheRetry checks that
// an attempt which announced a version but wrote none of its body -- a stale
// cache dropping the connection right after its headers -- does not hold the
// next attempt to that version: the next server's current version is
// delivered.
func TestDownloadFailedAttemptThatWroteNothingDoesNotHoldTheRetry(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	stale := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(stale.Close)
	staleURL, err := url.Parse(stale.URL)
	require.NoError(t, err)

	v2 := []byte("the current version of the object")
	results, out := versionedDownload(t, "", staleURL, versionServer(t, `"v2"`, v2, 0))
	require.NoError(t, results.Error)
	assert.Equal(t, v2, out.Bytes())
	assert.Equal(t, `"v2"`, results.ETag)
}

// downloadWithMetadata is versionedDownload with an early-metadata channel,
// as the cache uses: it returns the metadata the caller was given too.
func downloadWithMetadata(t *testing.T, servers ...*url.URL) (TransferResults, *bufferWriteCloser, []TransferMetadata) {
	t.Helper()
	out := &bufferWriteCloser{}
	attempts := make([]transferAttemptDetails, 0, len(servers))
	for _, u := range servers {
		attempts = append(attempts, transferAttemptDetails{Url: u})
	}
	metadata := make(chan TransferMetadata, len(servers))
	transfer := &transferFile{
		xferType: transferTypeDownload,
		ctx:      context.Background(),
		job: &TransferJob{
			remoteURL: &pelican_url.PelicanURL{Scheme: "pelican://", Host: servers[0].Host, Path: "/test.txt"},
		},
		remoteURL:     servers[0],
		writer:        out,
		attempts:      attempts,
		metadataChan:  metadata,
		skipChecksums: true,
	}
	results, err := downloadObject(transfer)
	require.NoError(t, err)
	close(metadata)
	var got []TransferMetadata
	for m := range metadata {
		got = append(got, m)
	}
	return results, out, got
}

// headersThenDrop is a server that announces a version of a 1 KB object and
// drops the connection before sending any of it.
func headersThenDrop(t *testing.T, etag string) *url.URL {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
			conn.Close()
		}
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u
}

// TestDownloadHeldToTheVersionItsCallerWasTold checks that once an attempt
// has handed its headers to the caller, the download is committed to that
// version even though the attempt wrote nothing: the cache keys what it
// stores on that first metadata, so another version's bytes must never
// follow it.
func TestDownloadHeldToTheVersionItsCallerWasTold(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	results, out, metadata := downloadWithMetadata(t,
		headersThenDrop(t, `"v1"`), versionServer(t, `"v2"`, []byte("the current version of the object"), 0))
	require.Len(t, metadata, 1)
	assert.Equal(t, `"v1"`, metadata[0].ETag)
	require.Error(t, results.Error, "the caller was told v1; v2's bytes must be refused")
	assert.True(t, errors.Is(results.Error, ErrObjectVersionChanged), "got %v", results.Error)
	assert.Zero(t, out.Len())
}

// TestDownloadMetadataComesFromTheFirstAttemptThatHasSome checks that an
// attempt that fails before any response arrives does not use up the
// caller's one delivery of early metadata.
func TestDownloadMetadataComesFromTheFirstAttemptThatHasSome(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	down := httptest.NewServer(http.NotFoundHandler())
	downURL, err := url.Parse(down.URL)
	require.NoError(t, err)
	down.Close() // connection refused

	body := []byte("the object")
	results, out, metadata := downloadWithMetadata(t, downURL, versionServer(t, `"v2"`, body, 0))
	require.NoError(t, results.Error)
	assert.Equal(t, body, out.Bytes())
	require.Len(t, metadata, 1, "the attempt that answered must deliver the metadata")
	assert.Equal(t, `"v2"`, metadata[0].ETag)
}

// TestDownloadRetriesTheVersionItsCallerWasTold checks the case that makes
// committing to a version on its headers safe: an attempt that sent its
// headers and dropped before its body is followed by one serving the same
// version, which completes the download.
func TestDownloadRetriesTheVersionItsCallerWasTold(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{})
	body := []byte("the only version of the object")
	results, out, metadata := downloadWithMetadata(t, headersThenDrop(t, `"v1"`), versionServer(t, `"v1"`, body, 0))
	require.NoError(t, results.Error)
	assert.Equal(t, body, out.Bytes())
	assert.Equal(t, `"v1"`, results.ETag)
	require.Len(t, metadata, 1)
	assert.Equal(t, `"v1"`, metadata[0].ETag)
}
