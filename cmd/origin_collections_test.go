//go:build server

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

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// The collection commands manage the origin named by the configuration they
// read, and nothing else.
func TestCollectionOriginWebUrl(t *testing.T) {
	setup := func(t *testing.T) {
		t.Cleanup(test_utils.SetupTestLogging(t))
		server_utils.ResetTestState()
		t.Cleanup(server_utils.ResetTestState)
	}

	t.Run("configured external web url", func(t *testing.T) {
		setup(t)
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://my-origin.example.com:8444"))

		got, err := collectionOriginWebUrl()
		require.NoError(t, err)
		assert.Equal(t, "https://my-origin.example.com:8444", got)
	})

	t.Run("configured hostname", func(t *testing.T) {
		setup(t)
		require.NoError(t, param.Server_Hostname.Set("my-origin.example.com"))
		// Client initialization derives Server.ExternalWebUrl from the hostname
		// and publishes it to the param getters; do the same here.
		require.NoError(t, config.ComputeExternalWebUrl(viper.GetViper()))
		_, err := param.Refresh()
		require.NoError(t, err)

		got, err := collectionOriginWebUrl()
		require.NoError(t, err)
		assert.Equal(t, "https://my-origin.example.com:8444", got)
	})

	t.Run("no web url at all", func(t *testing.T) {
		setup(t)

		_, err := collectionOriginWebUrl()
		require.Error(t, err)
		assert.Contains(t, err.Error(), param.Server_ExternalWebUrl.GetName())
	})
}

// Before any device-code approval, the command must confirm that the address
// it resolved is an origin with a collections API, and say so plainly when it
// is not.
func TestCheckCollectionOrigin(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	ctx := t.Context()

	newServer := func(t *testing.T, status int) *httptest.Server {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1.0/origin_ui/collections", r.URL.Path)
			assert.Empty(t, r.Header.Get("Authorization"), "the probe must be unauthenticated")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"status":"error","msg":"probe"}`))
		}))
		t.Cleanup(ts.Close)
		return ts
	}

	t.Run("origin answers 401", func(t *testing.T) {
		require.NoError(t, checkCollectionOrigin(ctx, newServer(t, http.StatusUnauthorized).URL))
	})

	t.Run("403 is not taken as proof of an origin", func(t *testing.T) {
		err := checkCollectionOrigin(ctx, newServer(t, http.StatusForbidden).URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
	})

	t.Run("non-origin server answers 404", func(t *testing.T) {
		err := checkCollectionOrigin(ctx, newServer(t, http.StatusNotFound).URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "runs on the origin host only")
	})

	t.Run("unexpected status", func(t *testing.T) {
		err := checkCollectionOrigin(ctx, newServer(t, http.StatusInternalServerError).URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("nothing listening", func(t *testing.T) {
		ts := newServer(t, http.StatusUnauthorized)
		addr := ts.URL
		// Stop the server before probing, so nothing answers at this URL.
		// newServer closes it again at cleanup; closing twice is harmless.
		ts.Close()
		err := checkCollectionOrigin(ctx, addr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot reach an origin at "+addr)
		assert.Contains(t, err.Error(), param.Server_ExternalWebUrl.GetName())
	})
}
