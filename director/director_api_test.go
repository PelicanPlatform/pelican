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

package director

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

var mockOriginServerAd server_structs.ServerAd = server_structs.ServerAd{
	Name:      "test-origin-server",
	URL:       url.URL{Host: "origin.com", Scheme: "https"},
	Type:      server_structs.OriginType,
	Latitude:  123.05,
	Longitude: 456.78,
}

var mockCacheServerAd server_structs.ServerAd = server_structs.ServerAd{
	Name:      "test-cache-server",
	URL:       url.URL{Host: "cache.com", Scheme: "https"},
	Type:      server_structs.CacheType,
	Latitude:  45.67,
	Longitude: 123.05,
}

const mockPathPreix string = "/foo/bar/"

func mockNamespaceAds(size int, serverPrefix string) []server_structs.NamespaceAdV2 {
	namespaceAds := make([]server_structs.NamespaceAdV2, size)
	for i := 0; i < size; i++ {
		namespaceAds[i] = server_structs.NamespaceAdV2{
			Caps: server_structs.Capabilities{
				PublicReads: false,
			},
			Path: mockPathPreix + serverPrefix + "/" + fmt.Sprint(i),
			Issuer: []server_structs.TokenIssuer{{
				IssuerUrl: url.URL{},
			}},
			Generation: []server_structs.TokenGen{{
				MaxScopeDepth: 1,
				Strategy:      "",
				VaultServer:   "",
			}},
		}
	}
	return namespaceAds
}

func namespaceAdContainsPath(ns []server_structs.NamespaceAdV2, path string) bool {
	for _, v := range ns {
		if v.Path == path {
			return true
		}
	}
	return false
}

func TestListNamespaces(t *testing.T) {
	setup := func() {
		serverAds.DeleteAll()
	}

	t.Run("empty-entry", func(t *testing.T) {
		setup()
		ns := listNamespacesFromOrigins()

		// Initially there should be 0 namespaces registered
		assert.Equal(t, 0, len(ns), "List is not empty for empty namespace cache.")
	})
	t.Run("one-origin-namespace-entry", func(t *testing.T) {
		setup()
		serverAds.Set(mockOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockNamespaceAds(1, "origin1"),
		}, ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		// Only one entry added
		assert.Equal(t, 1, len(ns), "List has length not equal to 1 for namespace cache with 1 entry.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(0)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-same-origin", func(t *testing.T) {
		setup()
		serverAds.Set(mockOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockNamespaceAds(10, "origin1"),
		}, ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		assert.Equal(t, 10, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(5)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-different-origins", func(t *testing.T) {
		setup()

		serverAds.Set(mockOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockNamespaceAds(10, "origin1"),
		}, ttlcache.DefaultTTL)
		// change the name field of serverAD as same name will cause cache to merge
		oldServerUrl := mockOriginServerAd.URL
		mockOriginServerAd.URL.Host = "origin2.com"

		serverAds.Set(mockOriginServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: mockNamespaceAds(10, "origin2"),
		}, ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		assert.Equal(t, 20, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(5)), "Returned namespace path does not match what's added")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin2/"+fmt.Sprint(9)), "Returned namespace path does not match what's added")
		mockOriginServerAd.URL = oldServerUrl
	})
	t.Run("one-cache-namespace-entry", func(t *testing.T) {
		setup()
		serverAds.Set(mockCacheServerAd.URL.String(), &server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: mockNamespaceAds(1, "cache1"),
		}, ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		// Should not show namespace from cache server
		assert.Equal(t, 0, len(ns), "List is not empty for namespace cache with entry from cache server.")
	})
}

func TestListServerAds(t *testing.T) {

	t.Run("empty-cache", func(t *testing.T) {
		func() {
			serverAds.DeleteAll()
		}()
		ads := listAdvertisement([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
		assert.Equal(t, 0, len(ads))
	})

	t.Run("get-by-server-type", func(t *testing.T) {
		func() {
			serverAds.DeleteAll()
		}()
		mockOriginAd := server_structs.Advertisement{
			ServerAd:     mockOriginServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{},
		}
		mockCacheAd := server_structs.Advertisement{
			ServerAd:     mockCacheServerAd,
			NamespaceAds: []server_structs.NamespaceAdV2{},
		}

		serverAds.Set(mockOriginServerAd.URL.String(),
			&mockOriginAd, ttlcache.DefaultTTL)
		serverAds.Set(mockCacheServerAd.URL.String(),
			&mockCacheAd,
			ttlcache.DefaultTTL)

		adsAll := listAdvertisement([]server_structs.ServerType{server_structs.OriginType, server_structs.CacheType})
		assert.Equal(t, 2, len(adsAll))

		adsOrigin := listAdvertisement([]server_structs.ServerType{server_structs.OriginType})
		require.Equal(t, 1, len(adsOrigin))
		assert.EqualValues(t, &mockOriginAd, adsOrigin[0])

		adsCache := listAdvertisement([]server_structs.ServerType{server_structs.CacheType})
		require.Equal(t, 1, len(adsCache))
		assert.EqualValues(t, &mockCacheAd, adsCache[0])
	})
}

func TestCheckFilter(t *testing.T) {
	testCases := []struct {
		name         string
		mapItems     map[string]filterType
		serverToTest string
		filtered     bool
		ft           filterType
	}{
		{
			name:         "empty-list-return-false",
			serverToTest: "mock",
			filtered:     false,
		},
		{
			name:         "dne-return-false",
			serverToTest: "mock",
			mapItems:     map[string]filterType{"no-your-server": permFiltered},
			filtered:     false,
		},
		{
			name:         "perm-return-true",
			serverToTest: "mock",
			mapItems:     map[string]filterType{"mock": permFiltered, "no-your-server": tempFiltered},
			filtered:     true,
			ft:           permFiltered,
		},
		{
			name:         "temp-filter-return-true",
			serverToTest: "mock",
			mapItems:     map[string]filterType{"mock": tempFiltered, "no-your-server": permFiltered},
			filtered:     true,
			ft:           tempFiltered,
		},
		{
			name:         "temp-allow-return-false",
			serverToTest: "mock",
			mapItems:     map[string]filterType{"mock": tempAllowed, "no-your-server": permFiltered},
			filtered:     false,
			ft:           tempAllowed,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filteredServersMutex.Lock()
			tmpMap := filteredServers
			filteredServers = tc.mapItems
			filteredServersMutex.Unlock()

			defer func() {
				filteredServersMutex.Lock()
				filteredServers = tmpMap
				filteredServersMutex.Unlock()
			}()

			getFilter, getType := checkFilter(tc.serverToTest)
			assert.Equal(t, tc.filtered, getFilter)
			assert.Equal(t, tc.ft, getType)

		})
	}
}
