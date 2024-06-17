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

package origin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

func mockRegistryCheck(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if req.URL.Path != "/api/v1.0/registry/namespaces/check/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		reqBytes, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		if len(reqBytes) < 1 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reqStruct := server_structs.CheckNamespaceCompleteReq{}
		err = json.Unmarshal(reqBytes, &reqStruct)
		require.NoError(t, err)

		resResult := server_structs.CheckNamespaceCompleteRes{}
		resResult.Results = make(map[string]server_structs.NamespaceCompletenessResult)
		for _, prefix := range reqStruct.Prefixes {
			resResult.Results[prefix] = server_structs.NamespaceCompletenessResult{EditUrl: "https://mockurl.org", Completed: true}
		}
		jsonbytes, err := json.Marshal(resResult)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(jsonbytes)
		require.NoError(t, err)
	}))
}

func TestFetchRegStatus(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		config.ResetFederationForTest()
	})

	t.Run("successful-fetch", func(t *testing.T) {
		ts := mockRegistryCheck(t)
		defer ts.Close()
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: ts.URL,
		})

		result, err := FetchRegStatus([]string{"/foo", "/bar"})
		require.NoError(t, err)

		foo, ok := result.Results["/foo"]
		require.True(t, ok)
		assert.True(t, foo.Completed)
		assert.Equal(t, "https://mockurl.org", foo.EditUrl)
	})

	t.Run("fetch-with-registry-404/405", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if req.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: ts.URL,
		})

		_, err := FetchRegStatus([]string{"/foo", "/bar"})
		require.Error(t, err)
		assert.Equal(t, RegistryNotImplErr, err)
	})

	t.Run("fetch-with-registry-500", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if req.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		viper.Reset()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: ts.URL,
		})

		_, err := FetchRegStatus([]string{"/foo", "/bar"})
		require.Error(t, err)
		assert.Equal(t, "response returns 500 with body: ", err.Error())
	})
}

func TestWrapExportsByStatus(t *testing.T) {
	t.Cleanup(func() {
		viper.Reset()
		config.ResetFederationForTest()
	})

	viper.Reset()
	config.SetFederation(config.FederationDiscovery{
		NamespaceRegistrationEndpoint: "https://mock-registry.org",
	})
	registrationsStatus.DeleteAll()

	mockRegistrationStatus := func() {
		registrationsStatus.Set(
			"/foo",
			RegistrationStatus{Status: RegCompleted},
			ttlcache.DefaultTTL,
		)
		registrationsStatus.Set(
			"/bar",
			RegistrationStatus{Status: RegIncomplete},
			ttlcache.DefaultTTL,
		)
		registrationsStatus.Set(
			"/barz",
			RegistrationStatus{Status: RegError},
			ttlcache.DefaultTTL,
		)
	}

	t.Run("all-items-cached", func(t *testing.T) {
		registrationsStatus.DeleteAll()

		mockExports := []server_utils.OriginExport{
			{FederationPrefix: "/foo"},
			{FederationPrefix: "/bar"},
			{FederationPrefix: "/barz"},
		}

		expected := []exportWithStatus{
			{Status: RegCompleted, OriginExport: server_utils.OriginExport{FederationPrefix: "/foo"}},
			{Status: RegIncomplete, OriginExport: server_utils.OriginExport{FederationPrefix: "/bar"}},
			{Status: RegError, OriginExport: server_utils.OriginExport{FederationPrefix: "/barz"}},
		}
		mockRegistrationStatus()
		got, err := wrapExportsByStatus(mockExports)
		require.NoError(t, err)
		assert.Equal(t, 3, len(got))
		assert.EqualValues(t, expected, got)

		registrationsStatus.DeleteAll()
	})

	t.Run("partial-cached", func(t *testing.T) {
		viper.Reset()
		ts := mockRegistryCheck(t)
		defer ts.Close()
		config.ResetFederationForTest()
		config.SetFederation(config.FederationDiscovery{
			NamespaceRegistrationEndpoint: ts.URL,
		})
		registrationsStatus.DeleteAll()

		mockRegistrationStatus := func() {
			registrationsStatus.Set(
				"/barz",
				RegistrationStatus{Status: RegError},
				ttlcache.DefaultTTL,
			)
		}

		mockExports := []server_utils.OriginExport{
			{FederationPrefix: "/foo"},
			{FederationPrefix: "/bar"},
			{FederationPrefix: "/barz"},
		}

		expected := []exportWithStatus{
			{
				Status:       RegError,
				OriginExport: server_utils.OriginExport{FederationPrefix: "/barz"},
			},
			{
				Status:       RegCompleted,
				EditUrl:      "https://mockurl.org",
				OriginExport: server_utils.OriginExport{FederationPrefix: "/foo"},
			},
			{
				Status:       RegCompleted,
				EditUrl:      "https://mockurl.org",
				OriginExport: server_utils.OriginExport{FederationPrefix: "/bar"},
			},
		}
		mockRegistrationStatus()
		got, err := wrapExportsByStatus(mockExports)
		require.NoError(t, err)
		assert.Equal(t, 3, len(got))
		assert.EqualValues(t, expected, got)

		registrationsStatus.DeleteAll()
		viper.Reset()
	})
}
