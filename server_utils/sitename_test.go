/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package server_utils

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
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestGetServerMetadataFromReg(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		ResetTestState()
	})

	t.Run("no-registry-url", func(t *testing.T) {
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{})
		server, err := getServerMetadataFromReg(context.Background(), "/foo")
		require.Error(t, err)
		assert.Equal(t, "unable to fetch site name from the registry. Federation.RegistryUrl or Federation.DiscoveryUrl is unset", err.Error())
		assert.Empty(t, server.Name)
	})

	t.Run("registry-returns-404", func(t *testing.T) {
		ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: ts.URL})
		server, err := getServerMetadataFromReg(context.Background(), "/foo")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "replied with status code 404")
		assert.Empty(t, server.Name)
	})

	t.Run("registry-returns-correct-object", func(t *testing.T) {
		ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/api/v1.0/registry") {
				ns := server_structs.ServerRegistration{Name: "bar", ID: "testsvrid"}
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
		server, err := getServerMetadataFromReg(context.Background(), "/foo")
		require.NoError(t, err)
		assert.Equal(t, "bar", server.Name)
	})
}

// Covers the name-resolution behavior of GetServerMetadata for origin/cache:
//   - A failed registry lookup must not propagate an error to the caller
//     (otherwise the advertise cycle in launcher_utils/advertise.go aborts).
//   - When Xrootd.Sitename is set locally, it takes priority over whatever
//     the registry returns.
//   - When Xrootd.Sitename is unset and the registry lookup fails, the
//     caller must see an error (no name available from any source).
func TestGetServerMetadataFallbackOnRegistryError(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	t.Cleanup(func() {
		ResetTestState()
	})

	// Registry that always responds with 500 so getServerMetadataFromReg
	// returns an error, exercising the fallback path.
	failingRegistry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failingRegistry.Close()

	t.Run("origin-falls-back-to-sitename-without-error", func(t *testing.T) {
		ResetTestState()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: failingRegistry.URL})
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))
		require.NoError(t, param.Xrootd_Sitename.Set("local-origin-name"))

		serverType := server_structs.NewServerType()
		serverType.Set(server_structs.OriginType)
		metadata, err := GetServerMetadata(context.Background(), serverType)
		require.NoError(t, err, "registry failure must not propagate; fallback is expected")
		assert.Equal(t, "local-origin-name", metadata.Name)
	})

	t.Run("cache-falls-back-to-sitename-without-error", func(t *testing.T) {
		ResetTestState()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: failingRegistry.URL})
		require.NoError(t, param.Xrootd_Sitename.Set("local-cache-name"))

		serverType := server_structs.NewServerType()
		serverType.Set(server_structs.CacheType)
		metadata, err := GetServerMetadata(context.Background(), serverType)
		require.NoError(t, err, "registry failure must not propagate; fallback is expected")
		assert.Equal(t, "local-cache-name", metadata.Name)
	})

	t.Run("origin-local-sitename-overrides-registry-name", func(t *testing.T) {
		ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/api/v1.0/registry") {
				ns := server_structs.ServerRegistration{Name: "registered-origin", ID: "testsvrid"}
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
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))
		require.NoError(t, param.Xrootd_Sitename.Set("local-origin-name"))

		serverType := server_structs.NewServerType()
		serverType.Set(server_structs.OriginType)
		metadata, err := GetServerMetadata(context.Background(), serverType)
		require.NoError(t, err)
		assert.Equal(t, "local-origin-name", metadata.Name,
			"local Xrootd.Sitename must take precedence over the registry's Name")
	})

	t.Run("origin-registry-name-used-when-sitename-unset", func(t *testing.T) {
		ResetTestState()
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if strings.HasPrefix(req.URL.Path, "/api/v1.0/registry") {
				ns := server_structs.ServerRegistration{Name: "registered-origin", ID: "testsvrid"}
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
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))

		serverType := server_structs.NewServerType()
		serverType.Set(server_structs.OriginType)
		metadata, err := GetServerMetadata(context.Background(), serverType)
		require.NoError(t, err)
		assert.Equal(t, "registered-origin", metadata.Name,
			"with no local sitename, the registry-supplied Name must be used")
	})

	t.Run("origin-registry-fails-and-sitename-unset-returns-error", func(t *testing.T) {
		ResetTestState()
		config.ResetFederationForTest()
		config.SetFederation(pelican_url.FederationDiscovery{RegistryEndpoint: failingRegistry.URL})
		require.NoError(t, param.Server_ExternalWebUrl.Set("https://origin.example.com:8444"))

		serverType := server_structs.NewServerType()
		serverType.Set(server_structs.OriginType)
		_, err := GetServerMetadata(context.Background(), serverType)
		require.Error(t, err, "with no registry name and no sitename, GetServerMetadata must surface an error")
		assert.Contains(t, err.Error(), param.Xrootd_Sitename.GetName())
	})
}
