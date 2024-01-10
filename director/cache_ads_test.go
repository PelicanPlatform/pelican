/***************************************************************
 *
 * Copyright (C) 2023, Pelican Project, Morgridge Institute for Research
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func hasServerAdWithName(serverAds []serverDesc, name string) bool {
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
	nsAd1 := NamespaceAd{
		RequireToken: true,
		Path:         "/chtc",
		Issuer: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
	}

	nsAd2 := NamespaceAd{
		RequireToken: false,
		Path:         "/chtc/PUBLIC",
		Issuer: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
	}

	nsAd3 := NamespaceAd{
		RequireToken: false,
		Path:         "/chtc/PUBLIC2/",
		Issuer: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
	}

	cacheAd1 := serverDesc{
		Name: "cache1",
		AuthURL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: CacheType,
	}

	cacheAd2 := serverDesc{
		Name: "cache2",
		AuthURL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: CacheType,
	}

	originAd1 := serverDesc{
		Name: "origin1",
		AuthURL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: OriginType,
	}

	originAd2 := serverDesc{
		Name: "origin2",
		AuthURL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		URL: url.URL{
			Scheme: "https",
			Host:   "wisc.edu",
		},
		Type: OriginType,
	}

	o1Slice := []NamespaceAd{nsAd1}
	o2Slice := []NamespaceAd{nsAd2, nsAd3}
	c1Slice := []NamespaceAd{nsAd1, nsAd2}
	recordAd(originAd2, &o2Slice)
	recordAd(originAd1, &o1Slice)
	recordAd(cacheAd1, &c1Slice)
	recordAd(cacheAd2, &o1Slice)

	nsAd, oAds, cAds := getAdsForPath("/chtc")
	assert.Equal(t, nsAd.Path, "/chtc")
	assert.Equal(t, len(oAds), 1)
	assert.Equal(t, len(cAds), 2)
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/")
	assert.Equal(t, nsAd.Path, "/chtc")
	assert.Equal(t, len(oAds), 1)
	assert.Equal(t, len(cAds), 2)
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLI")
	assert.Equal(t, nsAd.Path, "/chtc")
	assert.Equal(t, len(oAds), 1)
	assert.Equal(t, len(cAds), 2)
	assert.True(t, hasServerAdWithName(oAds, "origin1"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))
	assert.True(t, hasServerAdWithName(cAds, "cache2"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLIC")
	assert.Equal(t, nsAd.Path, "/chtc/PUBLIC")
	assert.Equal(t, len(oAds), 1)
	assert.Equal(t, len(cAds), 1)
	assert.True(t, hasServerAdWithName(oAds, "origin2"))
	assert.True(t, hasServerAdWithName(cAds, "cache1"))

	nsAd, oAds, cAds = getAdsForPath("/chtc/PUBLIC2")
	// since the stored path is actually /chtc/PUBLIC2/, the extra / is returned
	assert.Equal(t, nsAd.Path, "/chtc/PUBLIC2/")
	assert.Equal(t, len(oAds), 1)
	assert.Equal(t, len(cAds), 0)
	assert.True(t, hasServerAdWithName(oAds, "origin2"))

	// Finally, let's throw in a test for a path we know shouldn't exist
	// in the ttlcache
	nsAd, oAds, cAds = getAdsForPath("/does/not/exist")
	assert.Equal(t, nsAd.Path, "")
	assert.Equal(t, len(oAds), 0)
	assert.Equal(t, len(cAds), 0)
}

func TestConfigCacheEviction(t *testing.T) {
	mockPelicanOriginServerAd := serverDesc{
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
		Type:      OriginType,
		Latitude:  123.05,
		Longitude: 456.78,
	}
	mockNamespaceAd := NamespaceAd{
		RequireToken:  true,
		Path:          "/foo/bar/",
		Issuer:        url.URL{},
		MaxScopeDepth: 1,
		Strategy:      "",
		BasePath:      "",
		VaultServer:   "",
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

		ctx, cancelFunc := context.WithDeadline(ctx, time.Now().Add(time.Second*5))

		func() {
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()
			serverAds.Set(mockPelicanOriginServerAd, []NamespaceAd{mockNamespaceAd}, ttlcache.DefaultTTL)
			healthTestCancelFuncsMutex.Lock()
			defer healthTestCancelFuncsMutex.Unlock()
			// Clear the map for the new test
			healthTestCancelFuncs = make(map[serverDesc]context.CancelFunc)
			healthTestCancelFuncs[mockPelicanOriginServerAd] = cancelFunc

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
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
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
		func() {
			healthTestCancelFuncsMutex.RLock()
			defer healthTestCancelFuncsMutex.RUnlock()
			assert.True(t, healthTestCancelFuncs[mockPelicanOriginServerAd] == nil, "Evicted origin didn't clear cancelFunc in the map")
		}()
	})
}

func TestServerAdsCacheEviction(t *testing.T) {
	mockServerAd := serverDesc{Name: "foo", Type: OriginType, URL: url.URL{}}

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
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()

			serverAds.Set(mockServerAd, []NamespaceAd{}, time.Second*2)
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
