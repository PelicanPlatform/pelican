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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// anycastTokenHintHandler simulates a cache acting as a TCP anycast endpoint: it
// returns 403 with director-style X-Pelican-* token-hint headers when no bearer
// token is presented, and 200 with the object body once a token arrives.
func anycastTokenHintHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			ad := server_structs.NamespaceAdV2{
				Path: "/protected",
				Caps: server_structs.Capabilities{Reads: true},
			}
			issuer, _ := url.Parse("https://issuer.example.com")
			ad.Issuer = []server_structs.TokenIssuer{{IssuerUrl: *issuer, BasePaths: []string{"/protected"}}}
			ad.Generation = []server_structs.TokenGen{{
				Strategy:         server_structs.OAuthStrategy,
				MaxScopeDepth:    3,
				CredentialIssuer: *issuer,
			}}
			h := w.Header()
			server_structs.SetXNamespaceHeader(h, nil, ad)
			server_structs.SetXAuthHeader(h, ad)
			server_structs.SetXTokenGenHeader(h, ad)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("authorization required"))
			return
		}
		// Authorized: report size for HEAD (used to size the object), serve
		// the body for GET.
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	}
}

// TestDownloadHTTP_403YieldsTokenHint verifies that a 403 carrying X-Pelican
// token-hint headers is surfaced as a tokenHintError whose parsed DirectorResponse
// indicates a token is required -- the signal the attempt loop uses to acquire a
// token and retry the same (anycast) endpoint.
func TestDownloadHTTP_403YieldsTokenHint(t *testing.T) {
	svr := httptest.NewServer(anycastTokenHintHandler("hello anycast"))
	t.Cleanup(svr.Close)

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.NotEmpty(t, transfers)

	fname := filepath.Join(t.TempDir(), "out.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	// No token -> 403 with hints -> tokenHintError.
	_, _, _, _, _, err = downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
	require.Error(t, err)

	var hintErr *tokenHintError
	require.True(t, errors.As(err, &hintErr), "expected a tokenHintError, got %T: %v", err, err)
	assert.True(t, hintErr.dirResp.XPelNsHdr.RequireToken)
	assert.Equal(t, "/protected", hintErr.dirResp.XPelNsHdr.Namespace)
	require.Len(t, hintErr.dirResp.XPelAuthHdr.Issuers, 1)
	assert.Equal(t, "https://issuer.example.com", hintErr.dirResp.XPelAuthHdr.Issuers[0].String())
}

// TestDownloadHTTP_403NoHintIsTerminal verifies that a plain 403 (no X-Pelican
// headers) keeps the existing terminal authorization-error behavior and does NOT
// produce a tokenHintError.
func TestDownloadHTTP_403NoHintIsTerminal(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("nope"))
	}))
	t.Cleanup(svr.Close)

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.NotEmpty(t, transfers)

	fname := filepath.Join(t.TempDir(), "out.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	_, _, _, _, _, err = downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, "", "", nil)
	require.Error(t, err)

	var hintErr *tokenHintError
	assert.False(t, errors.As(err, &hintErr), "plain 403 must not be a tokenHintError")
}

// TestDownloadHTTP_SucceedsWithToken verifies the anycast endpoint serves the
// object once a bearer token is supplied (the retry path's second attempt).
func TestDownloadHTTP_SucceedsWithToken(t *testing.T) {
	body := "hello anycast"
	svr := httptest.NewServer(anycastTokenHintHandler(body))
	t.Cleanup(svr.Close)

	transfers := generateTransferDetails(svr.URL, transferDetailsOptions{false, ""})
	require.NotEmpty(t, transfers)

	fname := filepath.Join(t.TempDir(), "out.txt")
	writer, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	require.NoError(t, err)
	defer writer.Close()

	downloaded, _, _, _, _, err := downloadHTTP(context.Background(), nil, nil, transfers[0], fname, writer, 0, -1, -1, "fake-token", "", nil)
	require.NoError(t, err)
	assert.Equal(t, int64(len(body)), downloaded)
}

// TestBuildUploadTransfers_AnycastPolicy verifies the director-preferred default
// and the Client.PreferAnycast opt-in / director-failure fallback for uploads.
func TestBuildUploadTransfers_AnycastPolicy(t *testing.T) {
	anycastUrl, err := url.Parse("https://anycast.example.com")
	require.NoError(t, err)
	originUrl, err := url.Parse("https://origin.example.com")
	require.NoError(t, err)

	t.Run("default-prefers-director-origin", func(t *testing.T) {
		test_utils.InitClient(t, map[param.Param]any{}) // PreferAnycast defaults to false
		job := &clientTransferJob{job: &TransferJob{
			anycastUrl: anycastUrl,
			dirResp:    server_structs.DirectorResponse{ObjectServers: []*url.URL{originUrl}},
		}}
		transfers, err := buildUploadTransfers(job, "")
		require.NoError(t, err)
		require.Len(t, transfers, 1)
		assert.Equal(t, "origin.example.com", transfers[0].Url.Host, "default should write to the director-supplied origin")
	})

	t.Run("opt-in-prefers-anycast", func(t *testing.T) {
		test_utils.InitClient(t, map[param.Param]any{param.Client_PreferAnycast: true})
		job := &clientTransferJob{job: &TransferJob{
			anycastUrl: anycastUrl,
			dirResp:    server_structs.DirectorResponse{ObjectServers: []*url.URL{originUrl}},
		}}
		transfers, err := buildUploadTransfers(job, "")
		require.NoError(t, err)
		require.Len(t, transfers, 1)
		assert.Equal(t, "anycast.example.com", transfers[0].Url.Host)
	})

	t.Run("director-failure-falls-back-to-anycast", func(t *testing.T) {
		test_utils.InitClient(t, map[param.Param]any{}) // default; no origins available
		job := &clientTransferJob{job: &TransferJob{
			anycastUrl: anycastUrl,
			dirResp:    server_structs.DirectorResponse{ObjectServers: []*url.URL{}},
		}}
		transfers, err := buildUploadTransfers(job, "")
		require.NoError(t, err)
		require.Len(t, transfers, 1)
		assert.Equal(t, "anycast.example.com", transfers[0].Url.Host, "with no origin, anycast is the fallback target")
	})

	t.Run("no-anycast-no-origin-errors", func(t *testing.T) {
		test_utils.InitClient(t, map[param.Param]any{})
		job := &clientTransferJob{job: &TransferJob{
			dirResp: server_structs.DirectorResponse{ObjectServers: []*url.URL{}},
		}}
		_, err := buildUploadTransfers(job, "")
		assert.Error(t, err)
	})
}

// TestUploadWriteThroughAnycast drives the client's upload path against a mock
// cache acting as the anycast endpoint, demonstrating an end-to-end write-through:
// the anycast endpoint is resolved into the upload target via buildUploadTransfers,
// and uploadObject PUTs the object to the cache (which would proxy it to the origin).
func TestUploadWriteThroughAnycast(t *testing.T) {
	test_utils.InitClient(t, map[param.Param]any{
		param.TLSSkipVerify:           true,
		param.Client_EnableOverwrites: true, // skip the pre-upload existence check
		param.Client_PreferAnycast:    true, // opt in to anycast write-through
	})

	var gotPut bool
	var gotBody string
	var gotAuth string
	svr := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			gotPut = true
			gotAuth = r.Header.Get("Authorization")
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.WriteHeader(http.StatusOK)
		case "HEAD":
			w.WriteHeader(http.StatusNotFound)
		case "PROPFIND":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(svr.Close)

	anycastUrl, err := url.Parse(svr.URL)
	require.NoError(t, err)

	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "upload.txt")
	require.NoError(t, os.WriteFile(tempFile, []byte("write-through payload"), 0o644))

	// Build the upload target the way NewTransferJob would for an anycast upload.
	// A distinct director-supplied origin proves the anycast endpoint is chosen
	// over it when PreferAnycast is set.
	originUrl, err := url.Parse("https://origin.example.com")
	require.NoError(t, err)
	job := &clientTransferJob{job: &TransferJob{
		anycastUrl: anycastUrl,
		dirResp:    server_structs.DirectorResponse{ObjectServers: []*url.URL{originUrl}},
	}}
	attempts, err := buildUploadTransfers(job, "")
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	assert.Equal(t, anycastUrl.Host, attempts[0].Url.Host, "upload must target the anycast endpoint")

	tokenGen := newTokenGenerator(nil, nil, config.TokenWrite, false)
	tokenGen.SetToken("write-token")

	remotePUrl := &pelican_url.PelicanURL{Scheme: "pelican://", Host: anycastUrl.Host, Path: "/protected/upload.txt"}
	transfer := &transferFile{
		ctx:       context.Background(),
		job:       job.job,
		remoteURL: anycastUrl,
		localPath: tempFile,
		token:     tokenGen,
		attempts:  attempts,
	}
	transfer.job.remoteURL = remotePUrl

	result, err := uploadObject(transfer)
	require.NoError(t, err)
	require.NoError(t, result.Error)

	assert.True(t, gotPut, "cache (anycast endpoint) should have received the PUT")
	assert.Equal(t, "write-through payload", gotBody)
	assert.Equal(t, "Bearer write-token", gotAuth, "write-through PUT should carry the bearer token")
}

// TestNewTransferJob_SeedsAnycastEndpoint is covered indirectly; here we assert
// the '+' fallback sentinel parses as expected by generateSortedObjServers so
// that director-discovered servers remain reachable after the anycast prepend.
func TestAnycastPlusFallbackParses(t *testing.T) {
	anycastUrl, err := url.Parse("https://anycast.example.com")
	require.NoError(t, err)
	plus, err := url.Parse("+")
	require.NoError(t, err)
	assert.Equal(t, "+", plus.String())

	dirResp := server_structs.DirectorResponse{
		ObjectServers: []*url.URL{{Scheme: "https", Host: "cache1.example.com"}},
	}
	servers, nPreferred, err := generateSortedObjServers(dirResp, []*url.URL{anycastUrl, plus})
	require.NoError(t, err)
	// anycast is preferred and first; the director cache is appended as fallback.
	require.GreaterOrEqual(t, len(servers), 2)
	assert.Equal(t, "anycast.example.com", servers[0].Host)
	assert.Equal(t, 1, nPreferred)
	assert.Equal(t, "cache1.example.com", servers[len(servers)-1].Host)
}
