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

package cache

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestFilterNsAdsForCache(t *testing.T) {
	tests := []struct {
		desc          string
		permittedNS   []string
		expectedNumNS int
	}{
		{
			desc:          "no-matching-namespaces",
			permittedNS:   []string{"/noexist", "/bad"},
			expectedNumNS: 0,
		},
		{
			desc:          "matching-namespaces",
			permittedNS:   []string{"/ns1", "/ns2"},
			expectedNumNS: 2,
		},
		{
			desc:          "mix-matching-namespaces",
			permittedNS:   []string{"/ns3/foo", "/noexist", "/ns1"},
			expectedNumNS: 2,
		},
		{
			desc:          "matching-prefix",
			permittedNS:   []string{"/ns3", "/ns4/foo"},
			expectedNumNS: 3,
		},
		{
			desc:          "no-filters-set",
			expectedNumNS: 7,
		},
		{
			desc:          "empty-filter-list",
			permittedNS:   []string{},
			expectedNumNS: 7,
		},
		{
			desc:          "trailing-/",
			permittedNS:   []string{"/ns1/", "/ns4/"},
			expectedNumNS: 3,
		},
		{
			desc:          "no-trailing-/",
			permittedNS:   []string{"/ns5", "/ns3"},
			expectedNumNS: 3,
		},
		{
			desc:          "no-starting/",
			permittedNS:   []string{"ns4/foo/bar", "ns5"},
			expectedNumNS: 2,
		},
	}
	viper.Reset()
	defer viper.Reset()

	nsAds := []server_structs.NamespaceAdV2{
		{
			Path: "/ns1",
		},
		{
			Path: "/ns2",
		},
		{
			Path: "/ns3/foo",
		},
		{
			Path: "/ns3/",
		},
		{
			Path: "/ns4/foo/bar/",
		},
		{
			Path: "/ns4",
		},
		{
			Path: "/ns5/",
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		jsonbytes, err := json.Marshal(nsAds)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(jsonbytes)
		require.NoError(t, err)
	}))
	defer ts.Close()

	cacheServer := &CacheServer{}

	for _, testInput := range tests {
		t.Run(testInput.desc, func(t *testing.T) {
			err := config.InitClient()
			require.NoError(t, err)
			viper.Set("Federation.DirectorURL", ts.URL)
			if testInput.permittedNS != nil {
				viper.Set("Cache.PermittedNamespaces", testInput.permittedNS)
			}
			defer viper.Reset()

			cacheServer.SetFilters()
			err = cacheServer.GetNamespaceAdsFromDirector()
			require.NoError(t, err)
			filteredNS := cacheServer.GetNamespaceAds()

			require.Equal(t, testInput.expectedNumNS, len(filteredNS))

		})
	}
}
