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

package cache_ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pelicanplatform/pelican/common"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestFilterNsAdsForCache(t *testing.T) {
	tests := []struct {
		desc          string
		acceptedNS    []string
		expectedNumNS int
	}{
		{
			desc:          "no-matching-namespaces",
			acceptedNS:    []string{"noexist", "bad"},
			expectedNumNS: 0,
		},
		{
			desc:          "matching-namespaces",
			acceptedNS:    []string{"ns1", "ns2"},
			expectedNumNS: 2,
		},
		{
			desc:          "mix-matching-namespaces",
			acceptedNS:    []string{"ns3/foo", "noexist", "ns1"},
			expectedNumNS: 2,
		},
		{
			desc:          "matching-prefix",
			acceptedNS:    []string{"ns3", "ns4/foo"},
			expectedNumNS: 3,
		},
		{
			desc:          "no-filters-set",
			expectedNumNS: 6,
		},
	}
	viper.Reset()
	defer viper.Reset()

	nsAds := []common.NamespaceAdV2{
		{
			Path: "ns1",
		},
		{
			Path: "ns2",
		},
		{
			Path: "ns3/foo",
		},
		{
			Path: "ns3",
		},
		{
			Path: "ns4/foo/bar",
		},
		{
			Path: "ns4",
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

			viper.Set("Federation.DirectorURL", ts.URL)
			if testInput.acceptedNS != nil {
				viper.Set("Cache.AcceptedNamespaces", testInput.acceptedNS)
			}
			defer viper.Reset()

			cacheServer.SetFilters()
			err := cacheServer.GetNamespaceAdsFromDirector()
			require.NoError(t, err)
			filteredNS := cacheServer.GetNamespaceAds()

			require.Equal(t, testInput.expectedNumNS, len(filteredNS))

		})
	}
}
