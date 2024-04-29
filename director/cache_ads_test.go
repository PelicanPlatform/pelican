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
	"net/url"
	"testing"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func hasServerAdWithName(serverAds []server_structs.ServerAd, name string) bool {
	for _, serverAd := range serverAds {
		if serverAd.Name == name {
			return true
		}
	}
	return false
}

// Test getAdsForPath to make sure various nuanced cases work. Under the hood
// this really tests matchesPrefix, but we test this higher level function to
// avoid having to mess with the cache.
func TestGetAdsForPath(t *testing.T) {
	/*
		FLOW:
			- Set up a few dummy namespaces, origin, and cache ads
			- Record the ads
			- Query for a few paths and make sure the correct ads are returned
	*/
	nsAd1 := server_structs.NamespaceAdV2{
		PublicRead: false,
		Caps:       server_structs.Capabilities{PublicReads: false},
		Path:       "/chtc",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd2 := server_structs.NamespaceAdV2{
		PublicRead: true,
		Caps:       server_structs.Capabilities{PublicReads: true},
		Path:       "/chtc/PUBLIC",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAd3 := server_structs.NamespaceAdV2{
		PublicRead: true,
		Caps:       server_structs.Capabilities{PublicReads: true},
		Path:       "/chtc/PUBLIC2/",
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	nsAdTopo1 := server_structs.NamespaceAdV2{
		PublicRead:   true,
		Caps:         server_structs.Capabilities{PublicReads: true},
		Path:         "/chtc",
		FromTopology: true,
		Issuer: []server_structs.TokenIssuer{{
			IssuerUrl: url.URL{
				Scheme: "https",
				Host:   "wisc.edu",
			},
		},
		},
	}

	cacheAd1 := server_structs.ServerAd{
		Name: "cache1",
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: server_structs.CacheType,
	}

	cacheAd2 := server_structs.ServerAd{
		Name: "cache2",
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: server_structs.CacheType,
	}

	originAd1 := server_structs.ServerAd{
		Name: "origin1",
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: server_structs.OriginType,
	}

	originAd2 := server_structs.ServerAd{
		Name: "origin2",
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: server_structs.OriginType,
	}

	originAdTopo1 := server_structs.ServerAd{
		Name: "topology origin 1",
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type:         server_structs.OriginType,
		FromTopology: true,
	}

	o1Slice := []server_structs.NamespaceAdV2{nsAd1}
	o2Slice := []server_structs.NamespaceAdV2{nsAd2, nsAd3}
	c1Slice := []server_structs.NamespaceAdV2{nsAd1, nsAd2}
	topoSlice := []server_structs.NamespaceAdV2{nsAdTopo1}
	recordAd(originAd2, &o2Slice)
	recordAd(originAd1, &o1Slice)
	// Add a server from Topology that serves /chtc namespace
	recordAd(originAdTopo1, &topoSlice)
	recordAd(cacheAd1, &c1Slice)
	recordAd(cacheAd2, &o1Slice)

	// If /chtc is served both from topology and Pelican, the Topology server/namespace should be ignored
	nsAd, oAds, cAds := getAdsForPath("/chtc")
	assert.Equal(t, "/chtc", nsAd.Path)
	// Make sure it's not from Topology
	assert.False(t, nsAd.FromTopology)
	assert.False(t, nsAd.PublicRead) // Topology one has public read turned on while Pelican one doesn't

	assert.Equal(t, 1, len(oAds))
	assert.Equal(t, 2, len(cAds))
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))
	assert.False(t, oAds[0].FromTopology)

	nsAd, oAds, cAds = getAdsForPath("/chtc/")
	assert.Equal(t, "/chtc", nsAd.Path)
	assert.Equal(t, 1, len(oAds))
	assert.Equal(t, 2, len(cAds))
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLI")
	assert.Equal(t, "/chtc", nsAd.Path)
	assert.Equal(t, 1, len(oAds))
	assert.Equal(t, 2, len(cAds))
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLIC")
	assert.Equal(t, "/chtc/PUBLIC", nsAd.Path)
	assert.Equal(t, 1, len(oAds))
	assert.Equal(t, 1, len(cAds))
	assert.True(t, hasServerAdWithName(oAds, "origin2"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLIC2")
	// since the stored path is actually /chtc/PUBLIC2/, the extra / is returned
	assert.Equal(t, "/chtc/PUBLIC2/", nsAd.Path)
	assert.Equal(t, 1, len(oAds))
	assert.Equal(t, 0, len(cAds))
	assert.True(t, hasServerAdWithName(oAds, "origin2"))

	// Finally, let's throw in a test for a path we know shouldn't exist
	// in the ttlcache
	nsAd, oAds, cAds = getAdsForPath("/does/not/exist")
	assert.Equal(t, "", nsAd.Path)
	assert.Equal(t, 0, len(oAds))
	assert.Equal(t, 0, len(cAds))

	// Filtered server should not be included
	filteredServersMutex.Lock()
	tmp := filteredServers
	filteredServers = map[string]filterType{"origin1": permFiltered, "cache1": tempFiltered}
	filteredServersMutex.Unlock()
	defer func() {
		filteredServersMutex.Lock()
		filteredServers = tmp
		filteredServersMutex.Unlock()
	}()

	// /chtc has two servers, one is from topology the other is from Pelican
	nsAd, oAds, cAds = getAdsForPath("/chtc")
	assert.Equal(t, "/chtc", nsAd.Path)
	assert.Equal(t, 1, len(cAds))
	require.Equal(t, 1, len(oAds))
	assert.True(t, oAds[0].FromTopology)
	assert.False(t, hasServerAdWithName(oAds, "origin1"))
	assert.False(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))
}

func TestConfigCacheEviction(t *testing.T) {
	mockPelicanOriginServerAd := server_structs.ServerAd{
		Name:    "test-origin-server",
		AuthURL: url.URL{},
		URL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8443",
		},
		WebURL: url.URL{
			Scheme: "https",
			Host:   "fake-origin.org:8444",
		},
		Type:      server_structs.OriginType,
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockNamespaceAd := server_structs.NamespaceAdV2{
		PublicRead: false,
		Caps:       server_structs.Capabilities{PublicReads: false},
		Path:       "/foo/bar/",
		Issuer:     []server_structs.TokenIssuer{{IssuerUrl: url.URL{}}},
		Generation: []server_structs.TokenGen{{
			MaxScopeDepth: 1,
			Strategy:      "",
			VaultServer:   "",
		},
		},
	}

	t.Run("evicted-origin-can-cancel-health-test", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		ConfigTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		errgrp, errgrpCtx := errgroup.WithContext(shutdownCtx)
		ctx, cancelFunc := context.WithDeadline(errgrpCtx, time.Now().Add(time.Second*5))

		func() {
			serverAds.DeleteAll()
			serverAds.Set(mockPelicanOriginServerAd, []server_structs.NamespaceAdV2{mockNamespaceAd}, ttlcache.DefaultTTL)
			healthTestUtilsMutex.Lock()
			defer healthTestUtilsMutex.Unlock()
			// Clear the map for the new test
			healthTestUtils = make(map[server_structs.ServerAd]*healthTestUtil)
			healthTestUtils[mockPelicanOriginServerAd] = &healthTestUtil{
				Cancel:        cancelFunc,
				ErrGrp:        errgrp,
				ErrGrpContext: errgrpCtx,
			}

			require.True(t, serverAds.Has(mockPelicanOriginServerAd), "serverAds failed to register the originAd")
		}()

		cancelChan := make(chan int)
		go func() {
			<-ctx.Done()
			if ctx.Err() == context.Canceled {
				cancelChan <- 1
			}
		}()

		func() {
			serverAds.Delete(mockPelicanOriginServerAd) // This should call onEviction handler and close the context

			require.False(t, serverAds.Has(mockPelicanOriginServerAd), "serverAds didn't delete originAd")
		}()

		// OnEviction is handled on a different goroutine than the cache management
		// So we want to wait for a bit so that OnEviction can have time to be
		// executed
		select {
		case <-cancelChan:
			require.True(t, true)
		case <-time.After(3 * time.Second):
			require.False(t, true)
		}
	})
}

func TestServerAdsCacheEviction(t *testing.T) {
	mockServerAd := server_structs.ServerAd{Name: "foo", Type: server_structs.OriginType, URL: url.URL{}}

	t.Run("evict-after-expire-time", func(t *testing.T) {
		// Start cache eviction
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		egrp, ctx := errgroup.WithContext(shutdownCtx)
		ConfigTTLCache(ctx, egrp)
		defer func() {
			shutdownCancel()
			err := egrp.Wait()
			assert.NoError(t, err)
		}()

		deletedChan := make(chan int)
		cancelChan := make(chan int)

		func() {
			serverAds.DeleteAll()

			serverAds.Set(mockServerAd, []server_structs.NamespaceAdV2{}, time.Second*2)
			require.True(t, serverAds.Has(mockServerAd), "Failed to register server Ad")
		}()

		// Keep checking if the cache item is present until absent or cancelled
		go func() {
			for {
				select {
				case <-cancelChan:
					return
				default:
					if !serverAds.Has(mockServerAd) {
						deletedChan <- 1
						return
					}
				}
			}
		}()

		// Wait for 3s to check if the expired cache item is evicted
		select {
		case <-deletedChan:
			require.True(t, true)
		case <-time.After(3 * time.Second):
			cancelChan <- 1
			require.False(t, true, "Cache didn't evict expired item")
		}
	})
}
