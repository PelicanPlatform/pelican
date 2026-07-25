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
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

func TestXPelDirectEndpointsParse(t *testing.T) {
	parse := func(value string) (server_structs.XPelDirectEndpoints, error) {
		h := http.Header{}
		if value != "" {
			h.Set("X-Pelican-Direct-Endpoints", value)
		}
		var x server_structs.XPelDirectEndpoints
		err := (&x).ParseRawHeader(&h)
		return x, err
	}

	t.Run("slug and ordered endpoints", func(t *testing.T) {
		x, err := parse("sni=18f1jk5, 192.0.2.10:8443, [2001:db8::1]:8443")
		require.NoError(t, err)
		assert.Equal(t, "18f1jk5", x.Slug)
		assert.Equal(t, []string{"192.0.2.10:8443", "[2001:db8::1]:8443"}, x.Endpoints)
	})

	t.Run("missing header is an error (caller treats as non-fatal)", func(t *testing.T) {
		_, err := parse("")
		require.Error(t, err)
	})

	t.Run("endpoints without an sni field yield an empty slug", func(t *testing.T) {
		x, err := parse("192.0.2.10:8443")
		require.NoError(t, err)
		assert.Empty(t, x.Slug)
		assert.Equal(t, []string{"192.0.2.10:8443"}, x.Endpoints)
	})
}

func TestPrependDirectEndpoints(t *testing.T) {
	mustParse := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	origin := mustParse("https://origin.example.org:8443/foo/bar")
	normal := []transferAttemptDetails{{Url: origin}}

	t.Run("direct attempts are prepended, slug-authenticated, path preserved", func(t *testing.T) {
		dirResp := server_structs.DirectorResponse{
			ObjectServers: []*url.URL{origin},
			XPelDirectHdr: server_structs.XPelDirectEndpoints{
				Slug:      "18f1jk5",
				Endpoints: []string{"192.0.2.10:8443", "[2001:db8::1]:8443"},
			},
		}
		got := prependDirectEndpoints(normal, dirResp, "")
		require.Len(t, got, 3)
		assert.Equal(t, "192.0.2.10:8443", got[0].Url.Host)
		assert.Equal(t, "18f1jk5", got[0].SNI)
		assert.Equal(t, "/foo/bar", got[0].Url.Path, "object path is preserved on the direct attempt")
		assert.Equal(t, "https", got[0].Url.Scheme)
		assert.Equal(t, "[2001:db8::1]:8443", got[1].Url.Host)
		// The normal DNS attempt survives, last, with no SNI override (fallback).
		assert.Equal(t, "origin.example.org:8443", got[2].Url.Host)
		assert.Empty(t, got[2].SNI)
	})

	t.Run("no-op without a slug", func(t *testing.T) {
		dirResp := server_structs.DirectorResponse{
			ObjectServers: []*url.URL{origin},
			XPelDirectHdr: server_structs.XPelDirectEndpoints{Endpoints: []string{"192.0.2.10:8443"}},
		}
		assert.Equal(t, normal, prependDirectEndpoints(normal, dirResp, ""))
	})

	t.Run("no-op without endpoints", func(t *testing.T) {
		dirResp := server_structs.DirectorResponse{
			ObjectServers: []*url.URL{origin},
			XPelDirectHdr: server_structs.XPelDirectEndpoints{Slug: "18f1jk5"},
		}
		assert.Equal(t, normal, prependDirectEndpoints(normal, dirResp, ""))
	})
}

func TestBuildUploadTransfersDirectEndpoint(t *testing.T) {
	origin, err := url.Parse("https://origin.example.org:8443/foo/bar")
	require.NoError(t, err)

	t.Run("targets the direct endpoint with slug SNI when advertised", func(t *testing.T) {
		job := &clientTransferJob{job: &TransferJob{dirResp: server_structs.DirectorResponse{
			ObjectServers: []*url.URL{origin},
			XPelDirectHdr: server_structs.XPelDirectEndpoints{Slug: "18f1jk5", Endpoints: []string{"192.0.2.10:8443"}},
		}}}
		got, err := buildUploadTransfers(job, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "192.0.2.10:8443", got[0].Url.Host)
		assert.Equal(t, "18f1jk5", got[0].SNI)
		assert.Equal(t, "/foo/bar", got[0].Url.Path)
	})

	t.Run("uses the normal host with no SNI when no direct endpoint is advertised", func(t *testing.T) {
		job := &clientTransferJob{job: &TransferJob{dirResp: server_structs.DirectorResponse{
			ObjectServers: []*url.URL{origin},
		}}}
		got, err := buildUploadTransfers(job, "")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, "origin.example.org:8443", got[0].Url.Host)
		assert.Empty(t, got[0].SNI)
	})
}
