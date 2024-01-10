package director

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockOriginServerAd serverDesc = serverDesc{
	Name:      "test-origin-server",
	AuthURL:   url.URL{},
	URL:       url.URL{},
	Type:      OriginType,
	Latitude:  123.05,
	Longitude: 456.78,
}

var mockCacheServerAd serverDesc = serverDesc{
	Name:      "test-cache-server",
	AuthURL:   url.URL{},
	URL:       url.URL{},
	Type:      CacheType,
	Latitude:  45.67,
	Longitude: 123.05,
}

const mockPathPreix string = "/foo/bar/"

func mockNamespaceAds(size int, serverPrefix string) []NamespaceAd {
	namespaceAds := make([]NamespaceAd, size)
	for i := 0; i < size; i++ {
		namespaceAds[i] = NamespaceAd{
			RequireToken:  true,
			Path:          mockPathPreix + serverPrefix + "/" + fmt.Sprint(i),
			Issuer:        url.URL{},
			MaxScopeDepth: 1,
			Strategy:      "",
			BasePath:      "",
			VaultServer:   "",
		}
	}
	return namespaceAds
}

func namespaceAdContainsPath(ns []NamespaceAd, path string) bool {
	for _, v := range ns {
		if v.Path == path {
			return true
		}
	}
	return false
}

func TestListNamespaces(t *testing.T) {
	setup := func() {
		serverAdMutex.Lock()
		defer serverAdMutex.Unlock()
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
		serverAds.Set(mockOriginServerAd, mockNamespaceAds(1, "origin1"), ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		// Only one entry added
		assert.Equal(t, 1, len(ns), "List has length not equal to 1 for namespace cache with 1 entry.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(0)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-same-origin", func(t *testing.T) {
		setup()
		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin1"), ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		assert.Equal(t, 10, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(5)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-different-origins", func(t *testing.T) {
		setup()

		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin1"), ttlcache.DefaultTTL)

		// change the name field of serverAD as same name will cause cache to merge
		oldServerName := mockOriginServerAd.Name
		mockOriginServerAd.Name = "test-origin-server-2"

		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin2"), ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		assert.Equal(t, 20, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin1/"+fmt.Sprint(5)), "Returned namespace path does not match what's added")
		assert.True(t, namespaceAdContainsPath(ns, mockPathPreix+"origin2/"+fmt.Sprint(9)), "Returned namespace path does not match what's added")
		mockOriginServerAd.Name = oldServerName
	})
	t.Run("one-cache-namespace-entry", func(t *testing.T) {
		setup()
		serverAds.Set(mockCacheServerAd, mockNamespaceAds(1, "cache1"), ttlcache.DefaultTTL)
		ns := listNamespacesFromOrigins()

		// Should not show namespace from cache server
		assert.Equal(t, 0, len(ns), "List is not empty for namespace cache with entry from cache server.")
	})
}

func TestListServerAds(t *testing.T) {

	t.Run("emtpy-cache", func(t *testing.T) {
		func() {
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()
		}()
		ads := listServerAds([]ServerType{OriginType, CacheType})
		assert.Equal(t, 0, len(ads))
	})

	t.Run("get-by-server-type", func(t *testing.T) {
		func() {
			serverAdMutex.Lock()
			defer serverAdMutex.Unlock()
			serverAds.DeleteAll()
		}()
		serverAds.Set(mockOriginServerAd, []NamespaceAd{}, ttlcache.DefaultTTL)
		serverAds.Set(mockCacheServerAd, []NamespaceAd{}, ttlcache.DefaultTTL)
		adsAll := listServerAds([]ServerType{OriginType, CacheType})
		assert.Equal(t, 2, len(adsAll))

		adsOrigin := listServerAds([]ServerType{OriginType})
		require.Equal(t, 1, len(adsOrigin))
		assert.True(t, adsOrigin[0] == mockOriginServerAd)

		adsCache := listServerAds([]ServerType{CacheType})
		require.Equal(t, 1, len(adsCache))
		assert.True(t, adsCache[0] == mockCacheServerAd)
	})
}
