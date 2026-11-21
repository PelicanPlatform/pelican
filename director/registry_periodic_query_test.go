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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/metrics"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

// fakeRegistry serves the two endpoints the director polls, with responses
// the test changes between polls
type fakeRegistry struct {
	mu        sync.Mutex
	prefixes  map[string][]string
	ads       []server_structs.NamespaceAd
	adsStatus int // status code of the advertised-namespaces endpoint; the ads are served only with 200
	server    *httptest.Server
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{prefixes: map[string][]string{}, adsStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1.0/registry/caches/allowedPrefixes", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(f.prefixes); err != nil {
			log.Errorf("Failed to encode response: %v", err)
		}
	})
	mux.HandleFunc("/api/v1.0/registry/namespaces/advertised", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.adsStatus != http.StatusOK {
			// What a registry answers on its error paths, including the 404
			// of one that routes the path to its namespace lookup
			w.WriteHeader(f.adsStatus)
			_, _ = w.Write([]byte(`{"status":"error","msg":"namespace prefix '/namespaces/advertised', was not found"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(f.ads); err != nil {
			log.Errorf("Failed to encode response: %v", err)
		}
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeRegistry) setPrefixes(prefixes map[string][]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefixes = prefixes
}

func (f *fakeRegistry) setAds(status int, ads ...server_structs.NamespaceAd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adsStatus = status
	f.ads = ads
}

// launchPollerAgainst points the director at the fake registry and starts
// the poller at a 200ms interval; it is stopped when the test ends
func launchPollerAgainst(t *testing.T, f *fakeRegistry) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	resetRegistryQueryState()
	t.Cleanup(resetRegistryQueryState)

	test_utils.MockFederationRoot(t, &pelican_url.FederationDiscovery{
		RegistryEndpoint: f.server.URL,
	}, nil)
	require.NoError(t, param.Director_RegistryQueryInterval.SetString("200ms"))

	ctx, cancel, egrp := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		require.NoError(t, egrp.Wait())
	})
	LaunchRegistryPeriodicQuery(ctx, egrp)
}

// registryAd builds an ad the way the registry serves one: with a token
// issuer and generation entry for issuer when it is non-empty
func registryAd(t *testing.T, path string, caps server_structs.Capabilities, issuer string) server_structs.NamespaceAd {
	ad := server_structs.NamespaceAd{Path: path, Caps: caps}
	if issuer != "" {
		issuerUrl, err := url.Parse(issuer)
		require.NoError(t, err)
		ad.Issuer = []server_structs.TokenIssuer{{IssuerUrl: *issuerUrl, BasePaths: []string{path}}}
		ad.Generation = []server_structs.TokenGen{{Strategy: server_structs.OAuthStrategy, MaxScopeDepth: 3, CredentialIssuer: *issuerUrl}}
	}
	return ad
}

func adPaths(ads []server_structs.NamespaceAd) []string {
	paths := make([]string, 0, len(ads))
	for _, ad := range ads {
		paths = append(paths, ad.Path)
	}
	return paths
}

func TestLaunchRegistryPeriodicQuery(t *testing.T) {
	const issuer = "https://issuer.example.org"
	public := server_structs.Capabilities{PublicReads: true, Reads: true}
	authenticated := server_structs.Capabilities{Reads: true}

	reg := newFakeRegistry(t)
	prefixes := map[string][]string{"cacheHostname1": {"/ns1/ns2", "/ns3/ns4"}}
	reg.setPrefixes(prefixes)
	reg.setAds(http.StatusOK, registryAd(t, "/ns1", public, ""))

	launchPollerAgainst(t, reg)

	prefixesMatch := func(want map[string][]string) func() bool {
		return func() bool {
			return reflect.DeepEqual(*allowedPrefixesForCaches.Load(), convertMapOfListToMapOfSet(want))
		}
	}
	adsMatch := func(want ...string) func() bool {
		return func() bool { return reflect.DeepEqual(adPaths(getRegistryNamespaceAds()), want) }
	}

	t.Run("initial-load-fills-both-datasets", func(t *testing.T) {
		require.Eventually(t, prefixesMatch(prefixes), 5*time.Second, 50*time.Millisecond, "allowedPrefixesForCaches was not updated with the initial mock data")
		require.Eventually(t, adsMatch("/ns1"), 5*time.Second, 50*time.Millisecond, "registryNamespaceAds was not updated with the initial mock data")

		ads := getRegistryNamespaceAds()
		assert.True(t, ads[0].FromRegistry, "an ad from the registry is marked as such")
		assert.Equal(t, public, ads[0].Caps)
		assert.Equal(t, 1.0, testutil.ToFloat64(metrics.PelicanDirectorRegistryNamespaces))
		assert.NotZero(t, registryNamespaceAdsLastSetTimestamp.Load())
	})

	t.Run("update-reaches-both-datasets", func(t *testing.T) {
		prefixes = map[string][]string{"cacheHostname2": {"/ns5/ns6", "/ns7/ns8"}}
		reg.setPrefixes(prefixes)
		reg.setAds(http.StatusOK, registryAd(t, "/ns1", public, ""), registryAd(t, "/ns2", authenticated, issuer))

		require.Eventually(t, prefixesMatch(prefixes), 5*time.Second, 50*time.Millisecond, "allowedPrefixesForCaches was not updated with the new mock data")
		require.Eventually(t, adsMatch("/ns1", "/ns2"), 5*time.Second, 50*time.Millisecond, "registryNamespaceAds was not updated with the new mock data")

		ads := getRegistryNamespaceAds()
		require.Len(t, ads[1].Issuer, 1)
		assert.Equal(t, issuer, ads[1].Issuer[0].IssuerUrl.String(), "the issuer survives the trip through JSON")
		assert.Equal(t, []string{"/ns2"}, ads[1].Issuer[0].BasePaths)
		assert.True(t, ads[1].FromRegistry)
		assert.Equal(t, 2.0, testutil.ToFloat64(metrics.PelicanDirectorRegistryNamespaces))
	})

	t.Run("server-error-keeps-the-last-good-ads-and-the-other-dataset-still-refreshes", func(t *testing.T) {
		reg.setAds(http.StatusInternalServerError)
		// Two further updates of the other dataset prove at least one full
		// poll happened with the error in place
		for _, host := range []string{"cacheHostname3", "cacheHostname4"} {
			prefixes = map[string][]string{host: {"/ns9"}}
			reg.setPrefixes(prefixes)
			require.Eventually(t, prefixesMatch(prefixes), 5*time.Second, 50*time.Millisecond, "allowedPrefixesForCaches stopped refreshing while the other endpoint fails")
		}
		assert.Equal(t, []string{"/ns1", "/ns2"}, adPaths(getRegistryNamespaceAds()))
		assert.Equal(t, 2.0, testutil.ToFloat64(metrics.PelicanDirectorRegistryNamespaces))
	})

	t.Run("not-found-means-an-empty-list-from-a-registry-without-the-endpoint", func(t *testing.T) {
		// Nothing stores the ads while the endpoint fails, so a cleared
		// timestamp stays cleared until the 404 is accepted as a fetch
		registryNamespaceAdsLastSetTimestamp.Store(0)
		reg.setAds(http.StatusNotFound)

		require.Eventually(t, func() bool {
			return registryNamespaceAdsLastSetTimestamp.Load() != 0
		}, 5*time.Second, 50*time.Millisecond, "a 404 was not accepted as a successful, empty fetch")
		assert.Empty(t, getRegistryNamespaceAds())
		assert.Equal(t, 0.0, testutil.ToFloat64(metrics.PelicanDirectorRegistryNamespaces))
		assert.True(t, prefixesMatch(prefixes)(), "the other dataset is untouched")
	})

	t.Run("ads-come-back-once-the-endpoint-does", func(t *testing.T) {
		reg.setAds(http.StatusOK, registryAd(t, "/ns2", authenticated, issuer))
		require.Eventually(t, adsMatch("/ns2"), 5*time.Second, 50*time.Millisecond, "registryNamespaceAds was not refilled after the endpoint returned")
	})
}

func TestIngestRegistryNamespaceAds(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	const issuer = "https://issuer.example.org"
	public := server_structs.Capabilities{PublicReads: true, Reads: true}
	authenticated := server_structs.Capabilities{Reads: true}
	publicWithWrites := server_structs.Capabilities{PublicReads: true, Reads: true, Writes: true}

	tests := []struct {
		name string
		ad   server_structs.NamespaceAd
		kept bool
	}{
		{name: "public-read-without-issuer-is-kept", ad: registryAd(t, "/pub", public, ""), kept: true},
		{name: "listing-only-without-issuer-is-kept", ad: registryAd(t, "/list", server_structs.Capabilities{Listings: true}, ""), kept: true},
		{name: "read-with-issuer-is-kept", ad: registryAd(t, "/auth", authenticated, issuer), kept: true},
		{name: "public-read-with-writes-and-issuer-is-kept", ad: registryAd(t, "/rw", publicWithWrites, issuer), kept: true},
		{name: "read-without-issuer-is-dropped", ad: registryAd(t, "/auth", authenticated, ""), kept: false},
		{name: "public-read-with-writes-without-issuer-is-dropped", ad: registryAd(t, "/rw", publicWithWrites, ""), kept: false},
		{name: "origin-registration-is-dropped", ad: registryAd(t, "/origins/origin.example.org", public, ""), kept: false},
		{name: "cache-registration-is-dropped", ad: registryAd(t, "/caches/cache.example.org", public, ""), kept: false},
		{name: "relative-path-is-dropped", ad: registryAd(t, "foo", public, ""), kept: false},
		{name: "empty-path-is-dropped", ad: registryAd(t, "", public, ""), kept: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ingestRegistryNamespaceAds([]server_structs.NamespaceAd{tt.ad})
			if !tt.kept {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, 1)
			assert.Equal(t, tt.ad.Path, got[0].Path)
			assert.Equal(t, tt.ad.Caps, got[0].Caps)
			assert.Equal(t, tt.ad.Issuer, got[0].Issuer)
			assert.True(t, got[0].FromRegistry)
			assert.False(t, got[0].FromTopology)
		})
	}

	t.Run("order-is-kept-and-the-topology-flag-is-cleared", func(t *testing.T) {
		fromTopology := registryAd(t, "/auth", authenticated, issuer)
		fromTopology.FromTopology = true
		got := ingestRegistryNamespaceAds([]server_structs.NamespaceAd{
			registryAd(t, "/pub", public, ""),
			registryAd(t, "/dropped", authenticated, ""),
			fromTopology,
		})
		assert.Equal(t, []string{"/pub", "/auth"}, adPaths(got))
		for _, ad := range got {
			assert.True(t, ad.FromRegistry)
			assert.False(t, ad.FromTopology)
		}
	})

	t.Run("nil-input-gives-an-empty-non-nil-list", func(t *testing.T) {
		got := ingestRegistryNamespaceAds(nil)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})
}

func TestGetRegistryNamespaceAdsReturnsACopy(t *testing.T) {
	resetRegistryQueryState()
	t.Cleanup(resetRegistryQueryState)

	ads := []server_structs.NamespaceAd{{Path: "/a", FromRegistry: true}}
	registryNamespaceAds.Store(&ads)

	got := getRegistryNamespaceAds()
	got[0].Path = "/changed"
	got = append(got, server_structs.NamespaceAd{Path: "/b"})
	require.Len(t, got, 2)

	stored := *registryNamespaceAds.Load()
	require.Len(t, stored, 1)
	assert.Equal(t, "/a", stored[0].Path)
}
