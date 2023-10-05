package director

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/jellydator/ttlcache/v3"
	"github.com/stretchr/testify/assert"
)

var mockOriginServerAd ServerAd = ServerAd{
	Name: "test-origin-server",
	AuthURL:   url.URL{},
	URL:       url.URL{},
	Type:      OriginType,
	Latitude:  123.05,
	Longitude: 456.78,
}

var mockCacheServerAd ServerAd = ServerAd{
	Name: "test-cache-server",
	AuthURL: 	 url.URL{},
	URL:       url.URL{},
	Type:      CacheType,
	Latitude:  45.67,
	Longitude: 123.05,
}

const pathPreix string = "/foo/bar/"

func mockNamespaceAds(size int, serverPrefix string) []NamespaceAd {
	namespaceAds := make([]NamespaceAd, size)
	for i:=0; i<size; i++ {
		namespaceAds[i] = NamespaceAd{
			RequireToken: true,
			Path: pathPreix + serverPrefix + "/" + fmt.Sprint(i),
			Issuer: url.URL{},
			MaxScopeDepth: 1,
			Strategy: "",
			BasePath: "",
			VaultServer: "",
		}
	}
	return namespaceAds
}

func namespaceAdContainsPath (ns []NamespaceAd, path string) bool {
	for _, v := range(ns) {
		if v.Path == path {
			return true
		}
	}
	return false
}

func setup() {
	serverAds.DeleteAll()
}


func teardown() {
	serverAds.DeleteAll()
}

func TestListNamespaces(t *testing.T) {
	t.Run("empty-entry", func(t *testing.T) {
		setup() 
		defer teardown()
		ns := ListNamespacesFromOrigins()

		// Initially there should be 0 namespaces registered
		assert.Equal(t, 0, len(ns), "List is not empty for empty namespace cache.")
	})
	t.Run("one-origin-namespace-entry", func(t *testing.T) {
		setup() 
		defer teardown()
		serverAds.Set(mockOriginServerAd, mockNamespaceAds(1,"origin1"), ttlcache.DefaultTTL)
		ns := ListNamespacesFromOrigins()

		// Only one entry added
		assert.Equal(t, 1, len(ns), "List has length not equal to 1 for namespace cache with 1 entry.")
		assert.True(t, namespaceAdContainsPath(ns, pathPreix + "origin1/" + fmt.Sprint(0)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-same-origin", func(t *testing.T) {
		setup() 
		defer teardown()
		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin1"), ttlcache.DefaultTTL)
		ns := ListNamespacesFromOrigins()

		assert.Equal(t, 10, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, pathPreix + "origin1/" + fmt.Sprint(5)), "Returned namespace path does not match what's added")
	})
	t.Run("multiple-origin-namespace-entries-from-different-origins", func(t *testing.T) {
		setup() 
		defer teardown()

		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin1"), ttlcache.DefaultTTL)
		
		// change the name field of serverAD as same name will cause cache to merge
		oldServerName := mockOriginServerAd.Name
		mockOriginServerAd.Name = "test-origin-server-2"

		serverAds.Set(mockOriginServerAd, mockNamespaceAds(10, "origin2"), ttlcache.DefaultTTL)
		ns := ListNamespacesFromOrigins()

		assert.Equal(t, 20, len(ns), "List has length not equal to 10 for namespace cache with 10 entries.")
		assert.True(t, namespaceAdContainsPath(ns, pathPreix + "origin1/" + fmt.Sprint(5)), "Returned namespace path does not match what's added")
		assert.True(t, namespaceAdContainsPath(ns, pathPreix + "origin2/" + fmt.Sprint(9)), "Returned namespace path does not match what's added")
		mockOriginServerAd.Name = oldServerName
	})
	t.Run("one-cache-namespace-entry", func(t *testing.T) {
		setup() 
		defer teardown()
		serverAds.Set(mockCacheServerAd, mockNamespaceAds(1, "cache1"), ttlcache.DefaultTTL)
		ns := ListNamespacesFromOrigins()

		// Should not show namespace from cache server
		assert.Equal(t, 0, len(ns), "List is not empty for namespace cache with entry from cache server.")
	})
}