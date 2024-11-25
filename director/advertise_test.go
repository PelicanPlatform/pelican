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
	"bytes"
	"context"
	_ "embed"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
)

var (
	//go:embed resources/mock_topology.json
	mockTopology string
	//go:embed resources/multi_export_topology.json
	multiExportTopology string
)

func TestConsolidateDupServerAd(t *testing.T) {
	t.Run("union-capabilities", func(t *testing.T) {
		existingAd := server_structs.ServerAd{Caps: server_structs.Capabilities{Writes: false}}
		newAd := server_structs.ServerAd{Caps: server_structs.Capabilities{Writes: true}}
		get := consolidateDupServerAd(newAd, existingAd)
		assert.True(t, get.Caps.Writes)

		existingAd = server_structs.ServerAd{Caps: server_structs.Capabilities{DirectReads: false}}
		newAd = server_structs.ServerAd{Caps: server_structs.Capabilities{DirectReads: true}}
		get = consolidateDupServerAd(newAd, existingAd)
		assert.True(t, get.Caps.DirectReads)

		existingAd = server_structs.ServerAd{Caps: server_structs.Capabilities{Listings: false}}
		newAd = server_structs.ServerAd{Caps: server_structs.Capabilities{Listings: true}}
		get = consolidateDupServerAd(newAd, existingAd)
		assert.True(t, get.Caps.Listings)

		// All false
		existingAd = server_structs.ServerAd{Caps: server_structs.Capabilities{}}
		newAd = server_structs.ServerAd{Caps: server_structs.Capabilities{Reads: true, Writes: true, DirectReads: true, Listings: true}}
		get = consolidateDupServerAd(newAd, existingAd)
		assert.EqualValues(t, server_structs.Capabilities{Reads: true, Writes: true, Listings: true, DirectReads: true}, get.Caps)
	})

	t.Run("take-existing-one-for-non-cap-fields", func(t *testing.T) {
		existingAd := server_structs.ServerAd{
			Name:         "fool",
			AuthURL:      url.URL{Host: "example.org"},
			BrokerURL:    url.URL{Host: "example.org"},
			URL:          url.URL{Host: "example.org"},
			WebURL:       url.URL{Host: "example.org"},
			Type:         server_structs.OriginType.String(),
			FromTopology: true,
		}
		newAd := server_structs.ServerAd{
			Name:         "bar",
			AuthURL:      url.URL{Host: "diff.org"},
			BrokerURL:    url.URL{Host: "diff.org"},
			URL:          url.URL{Host: "example.org"},
			WebURL:       url.URL{Host: "diff.org"},
			Type:         server_structs.OriginType.String(),
			FromTopology: false,
		}
		get := consolidateDupServerAd(newAd, existingAd)
		assert.Equal(t, get.AuthURL, existingAd.AuthURL)
		assert.Equal(t, get.BrokerURL, existingAd.BrokerURL)
		assert.Equal(t, get.WebURL, existingAd.WebURL)
		assert.Equal(t, get.Name, existingAd.Name)
		assert.Equal(t, get.Type, existingAd.Type)
		assert.Equal(t, get.FromTopology, existingAd.FromTopology)
	})
}

func TestParseServerAdFromTopology(t *testing.T) {

	server := server_structs.TopoServer{
		Endpoint:     "http://my-endpoint.com",
		AuthEndpoint: "https://my-auth-endpoint.com",
		Resource:     "MY_SERVER",
	}

	t.Run("test-setting-name", func(t *testing.T) {
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.Equal(t, "MY_SERVER", ad.Name)
	})

	t.Run("parse-server-ads-with-scheme", func(t *testing.T) {
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.Equal(t, "http://my-endpoint.com", ad.URL.String())
		assert.Equal(t, "https://my-auth-endpoint.com", ad.AuthURL.String())
	})

	t.Run("parse-server-ads-no-scheme", func(t *testing.T) {
		server.Endpoint = "my-endpoint.com"
		server.AuthEndpoint = "my-auth-endpoint.com"
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.Equal(t, "http://my-endpoint.com", ad.URL.String())
		assert.Equal(t, "https://my-auth-endpoint.com", ad.AuthURL.String())
	})

	t.Run("test-ad-type", func(t *testing.T) {
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.True(t, ad.Type == server_structs.OriginType.String())
		ad = parseServerAdFromTopology(server, server_structs.CacheType, server_structs.Capabilities{})
		assert.True(t, ad.Type == server_structs.CacheType.String())
	})
	t.Run("test-from-topology", func(t *testing.T) {
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.True(t, ad.FromTopology)
		ad = parseServerAdFromTopology(server, server_structs.CacheType, server_structs.Capabilities{})
		assert.True(t, ad.FromTopology)
	})

	t.Run("test-caps-parsing", func(t *testing.T) {
		// Only testing the caps that also get set as top level fields
		caps := server_structs.Capabilities{
			Writes:      true,
			Listings:    true,
			DirectReads: true,
			PublicReads: true,
		}
		ad := parseServerAdFromTopology(server, server_structs.OriginType, caps)
		assert.True(t, ad.Caps.Writes)
		assert.True(t, ad.Caps.Listings)
		assert.True(t, ad.Caps.DirectReads)
		assert.True(t, ad.Caps.PublicReads)

		ad = parseServerAdFromTopology(server, server_structs.CacheType, caps)
		assert.False(t, ad.Caps.Writes)
		assert.False(t, ad.Caps.Listings)
		assert.False(t, ad.Caps.DirectReads)
		assert.True(t, ad.Caps.PublicReads)
	})

	t.Run("test-invalid-url", func(t *testing.T) {
		// Capture logs
		hook := logrustest.NewLocal(logrus.StandardLogger())
		defer hook.Reset()

		server.Endpoint = "http://a server "
		server.AuthEndpoint = "https://a different server "
		ad := parseServerAdFromTopology(server, server_structs.OriginType, server_structs.Capabilities{})
		assert.Empty(t, ad.URL.String())
		assert.Empty(t, ad.AuthURL.String())
		assert.Len(t, hook.AllEntries(), 2)
		assert.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.Entries[0].Message, "invalid unauthenticated URL")
		assert.Contains(t, hook.Entries[1].Message, "invalid authenticated URL")
	})
}

func mockTopoJSONHandler(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to indicate JSON.
	w.Header().Set("Content-Type", "application/json")

	// Write the JSON response to the response body.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(mockTopology))
}

func multiExportsTopoJSONHandler(w http.ResponseWriter, r *http.Request) {
	// Set the Content-Type header to indicate JSON.
	w.Header().Set("Content-Type", "application/json")

	// Write the JSON response to the response body.
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(multiExportTopology))
}

func TestAdvertiseOSDF(t *testing.T) {
	t.Run("mock-topology-parse-correctly", func(t *testing.T) {
		server_utils.ResetTestState()
		serverAds.DeleteAll()
		defer func() {
			server_utils.ResetTestState()
			serverAds.DeleteAll()
		}()

		topoServer := httptest.NewServer(http.HandlerFunc(mockTopoJSONHandler))
		defer topoServer.Close()
		viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

		err := AdvertiseOSDF(context.Background())
		require.NoError(t, err)

		var foundServer *server_structs.Advertisement
		for _, item := range serverAds.Items() {
			if item.Value().URL.Host == "origin1-endpoint.com" {
				foundServer = item.Value()
				break
			}
		}
		require.NotNil(t, foundServer)
		assert.True(t, foundServer.FromTopology)
		require.NotNil(t, foundServer.NamespaceAds)
		assert.True(t, foundServer.NamespaceAds[0].FromTopology)

		// Override the check for prohibited caches
		prohibitedCachesLastSetTimestamp.Store(time.Now().Unix())

		// Test a few values. If they're correct, it indicates the whole process likely succeeded
		nsAd, oAds, cAds := getAdsForPath("/my/server/path/to/file")
		assert.Equal(t, "/my/server", nsAd.Path)
		assert.Equal(t, uint(3), nsAd.Generation[0].MaxScopeDepth)
		assert.Equal(t, "https://origin1-auth-endpoint.com", oAds[0].AuthURL.String())
		assert.Equal(t, "https://cache2.com", cAds[0].URL.String())
		// Check that various capabilities have survived until this point. Because these are from topology,
		// origin and namespace caps should be the same
		assert.True(t, oAds[0].Caps.Writes)
		assert.True(t, oAds[0].Caps.Listings)
		assert.False(t, oAds[0].Caps.PublicReads)
		assert.True(t, nsAd.Caps.Writes)
		assert.True(t, nsAd.Caps.Listings)
		assert.False(t, nsAd.Caps.PublicReads)
		assert.True(t, nsAd.Caps.Listings)

		nsAd, oAds, cAds = getAdsForPath("/my/server/2/path/to/file")
		assert.Equal(t, "/my/server/2", nsAd.Path)
		assert.True(t, nsAd.Caps.PublicReads)
		assert.Equal(t, "https://origin2-auth-endpoint.com", oAds[0].AuthURL.String())
		assert.Equal(t, "http://cache-endpoint.com", cAds[0].URL.String())
	})

	t.Run("multiple-ns-single-origin", func(t *testing.T) {
		server_utils.ResetTestState()
		serverAds.DeleteAll()
		defer func() {
			server_utils.ResetTestState()
			serverAds.DeleteAll()
		}()

		topoServer := httptest.NewServer(http.HandlerFunc(multiExportsTopoJSONHandler))
		defer topoServer.Close()
		viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

		err := AdvertiseOSDF(context.Background())
		require.NoError(t, err)

		// This origin should export 3 namespaces
		found := serverAds.Has("http://sdsc-origin.nationalresearchplatform.org:1094")
		require.True(t, found)
		foundAd := serverAds.Get("http://sdsc-origin.nationalresearchplatform.org:1094").Value()
		require.NotNil(t, foundAd)
		assert.Equal(t, server_structs.OriginType.String(), foundAd.Type)
		assert.Len(t, foundAd.NamespaceAds, 3)
		// This origin has at least one namespace enables the following capacity
		assert.True(t, foundAd.Caps.DirectReads)
		assert.True(t, foundAd.Caps.Writes)
		assert.True(t, foundAd.Caps.PublicReads)
	})

	t.Run("caches-serving-multiple-nss", func(t *testing.T) {
		server_utils.ResetTestState()
		serverAds.DeleteAll()
		defer func() {
			server_utils.ResetTestState()
			serverAds.DeleteAll()
		}()

		topoServer := httptest.NewServer(http.HandlerFunc(multiExportsTopoJSONHandler))
		defer topoServer.Close()
		viper.Set("Federation.TopologyNamespaceUrl", topoServer.URL)

		err := AdvertiseOSDF(context.Background())
		require.NoError(t, err)

		// This cache should serve 2 namespaces
		found := serverAds.Has("http://dtn-pas.bois.nrp.internet2.edu:8000")
		require.True(t, found)
		foundAd := serverAds.Get("http://dtn-pas.bois.nrp.internet2.edu:8000").Value()
		require.NotNil(t, foundAd)
		assert.Equal(t, server_structs.CacheType.String(), foundAd.Type)
		assert.Len(t, foundAd.NamespaceAds, 2)
	})
}

func mockTopoDowntimeXMLHandler(w http.ResponseWriter, r *http.Request) {
	downtimeInfo := server_structs.TopoCurrentDowntimes{
		Downtimes: []server_structs.TopoServerDowntime{
			{
				// Current time falls in start-end window. SHould be filtered
				ResourceName: "BOISE_INTERNET2_OSDF_CACHE",
				ResourceFQDN: "dtn-pas.bois.nrp.internet2.edu",
				StartTime:    time.Now().Add(-24 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
				EndTime:      time.Now().Add(24 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
			},
			{
				// start time is after current time. Should NOT be filtered
				ResourceName: "DENVER_INTERNET2_OSDF_CACHE",
				ResourceFQDN: "dtn-pas.denv.nrp.internet2.edu",
				StartTime:    time.Now().Add(24 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
				EndTime:      time.Now().Add(25 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
			},
			{
				// end time is before current time. Should NOT be filtered
				ResourceName: "HOW_MUCH_CASH_COULD_A_STASHCACHE_STASH",
				ResourceFQDN: "stash-cache.cache.osdf.biz",
				StartTime:    time.Now().Add(-24 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
				EndTime:      time.Now().Add(-1 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
			},
			{
				// Invalid time should cause updateDowntimeFromTopology to log an error but not return one
				ResourceName: "FOOBAR",
				ResourceFQDN: "foo.bar",
				StartTime:    "The second of January, 2006 03:04 PM MST",
				EndTime:      time.Now().Add(1 * time.Hour).Format("Jan 2, 2006 03:04 PM MST"),
			},
		},
	}

	tmpl, err := template.ParseFiles("resources/mock_topology_downtime_template.xml")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	err = tmpl.Execute(w, downtimeInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func TestUpdateDowntimeFromTopology(t *testing.T) {
	// Create a buffer to capture log output
	var logBuffer bytes.Buffer
	originalOutput := logrus.StandardLogger().Out
	logrus.SetOutput(&logBuffer)
	t.Cleanup(func() {
		logrus.SetOutput(originalOutput)
	})

	server := httptest.NewServer(http.HandlerFunc(mockTopoDowntimeXMLHandler))
	t.Cleanup(func() {
		server.Close()
	})
	viper.Set("Federation.TopologyDowntimeUrl", server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(func() {
		cancel()
	})

	err := updateDowntimeFromTopology(ctx)
	if err != nil {
		t.Fatalf("updateDowntimeFromTopology() error = %v", err)
	}

	// There should be a logged warning about the invalid time
	logOutput := logBuffer.String()
	assert.Contains(t, logOutput, "Could not put FOOBAR into downtime because its start time")

	assert.True(t, filteredServers["BOISE_INTERNET2_OSDF_CACHE"] == topoFiltered)
	_, keyExists := filteredServers["DENVER_INTERNET2_OSDF_CACHE"]
	assert.False(t, keyExists, "DENVER_INTERNET2_OSDF_CACHE should not be in filteredServers")
	_, keyExists = filteredServers["HOW_MUCH_CASH_COULD_A_STASHCACHE_STASH"]
	assert.False(t, keyExists, "HOW_MUCH_CASH_COULD_A_STASHCACHE_STASH should not be in filteredServers")
}
