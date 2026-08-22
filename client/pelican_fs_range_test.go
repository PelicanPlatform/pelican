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
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

// rangeFile builds a PelicanFile that reads `body` from a test server, with
// no file info -- the state a deferred (WithLazyStat) open leaves behind.
func rangeFile(t *testing.T, body []byte) *PelicanFile {
	t.Helper()
	require.NoError(t, config.InitClient())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "obj", time.Time{}, bytes.NewReader(body))
	}))
	t.Cleanup(srv.Close)

	base, err := url.Parse(srv.URL)
	require.NoError(t, err)

	return &PelicanFile{
		ctx:      context.Background(),
		name:     "/obj",
		pUrl:     &pelican_url.PelicanURL{Path: "/obj"},
		readMode: true,
		lazyStat: true,
		dirResp: server_structs.DirectorResponse{
			ObjectServers: []*url.URL{base},
		},
	}
}

// A reader past the end of the object is at EOF. Without an eager stat there
// is no size to compare against, so the server's 416 has to carry that
// meaning; anything else and a caller reading to the end loops or fails.
func TestRangeReadPastEndIsEOF(t *testing.T) {
	body := []byte("0123456789")
	pf := rangeFile(t, body)

	buf := make([]byte, 4)

	n, err := pf.doRangeRead(buf, 0)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "0123", string(buf[:n]))

	// Exactly at the end.
	_, err = pf.doRangeRead(buf, int64(len(body)))
	assert.ErrorIs(t, err, io.EOF, "a range starting at the end is EOF")

	// Beyond the end.
	_, err = pf.doRangeRead(buf, int64(len(body))+100)
	assert.ErrorIs(t, err, io.EOF, "a range starting past the end is EOF")
}

// A read that straddles the end returns the bytes that exist rather than
// failing: the server answers 206 with a truncated range.
func TestRangeReadStraddlingEnd(t *testing.T) {
	body := []byte("0123456789")
	pf := rangeFile(t, body)

	buf := make([]byte, 8)
	n, err := pf.doRangeRead(buf, 6)
	require.NoError(t, err)
	assert.Equal(t, 4, n, "only the bytes that exist are returned")
	assert.Equal(t, "6789", string(buf[:n]))
}

// A deferred open cannot report a missing object until something reads it,
// so the read has to say so in a way callers can test for.
func TestRangeReadMissingObjectIsNotExist(t *testing.T) {
	require.NoError(t, config.InitClient())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)

	pf := &PelicanFile{
		ctx:      context.Background(),
		name:     "/gone",
		pUrl:     &pelican_url.PelicanURL{Path: "/gone"},
		readMode: true,
		lazyStat: true,
		dirResp: server_structs.DirectorResponse{
			ObjectServers: []*url.URL{base},
		},
	}

	_, err = pf.doRangeRead(make([]byte, 8), 0)
	require.Error(t, err)
	assert.ErrorIs(t, err, fs.ErrNotExist, "a read of a missing object must be distinguishable from an unreachable one")
}
