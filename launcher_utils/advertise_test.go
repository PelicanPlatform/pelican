/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package launcher_utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestGetSitenameFromReg(t *testing.T) {
	t.Cleanup(func() {
		server_utils.ResetTestState()
	})

	t.Run("no-registry-url", func(t *testing.T) {
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{})
		sitename, err := getSitenameFromReg(context.Background(), "/foo")
		require.Error(t, err)
		assert.Equal(t, "unable to fetch site name from the registry. Federation.RegistryUrl or Federation.DiscoveryUrl is unset", err.Error())
		assert.Empty(t, sitename)
	})

	t.Run("registry-returns-404", func(t *testing.T) {
		server_utils.ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: ts.URL})
		sitename, err := getSitenameFromReg(context.Background(), "/foo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "replied with status code 404")
		assert.Empty(t, sitename)
	})

	t.Run("registry-returns-correct-object", func(t *testing.T) {
		server_utils.ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/api/v1.0/registry") {
				prefix := strings.TrimPrefix(req.URL.Path, "/api/v1.0/registry")
				ns := server_structs.Namespace{Prefix: prefix, ID: 1, AdminMetadata: server_structs.AdminMetadata{SiteName: "bar"}}
				bytes, err := json.Marshal(ns)
				require.NoError(t, err)
				_, err = w.Write(bytes)
				require.NoError(t, err)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: ts.URL})
		sitename, err := getSitenameFromReg(context.Background(), "/foo")
		require.NoError(t, err)
		assert.Equal(t, "bar", sitename)
	})
}
