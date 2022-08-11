package stashcp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMatchNamespace calls MatchNamespace with a hostname, checking
// for a valid return value.
func TestMatchNamespace(t *testing.T) {

	namespacesJson = []byte(`
{
  "caches": [
    {
      "auth_endpoint": "osg.kans.nrp.internet2.edu:8443",
      "endpoint": "osg.kans.nrp.internet2.edu:8000",
      "resource": "Stashcache-Kansas"
    },
    {
      "auth_endpoint": "osg-sunnyvale-stashcache.nrp.internet2.edu:8443",
      "endpoint": "osg-sunnyvale-stashcache.nrp.internet2.edu:8000",
      "resource": "Stashcache-Sunnyvale"
    },
    {
      "auth_endpoint": "osg-houston-stashcache.nrp.internet2.edu:8443",
      "endpoint": "osg-houston-stashcache.nrp.internet2.edu:8000",
      "resource": "Stashcache-Houston"
    },
    {
      "auth_endpoint": "osg.newy32aoa.nrp.internet2.edu:8443",
      "endpoint": "osg.newy32aoa.nrp.internet2.edu:8000",
      "resource": "Stashcache-Manhattan"
    },
    {
      "auth_endpoint": "osg-chicago-stashcache.nrp.internet2.edu:8443",
      "endpoint": "osg-chicago-stashcache.nrp.internet2.edu:8000",
      "resource": "Stashcache-Chicago"
    }
  ],
  "namespaces": [
    {
      "path": "/ospool/PROTECTED",
      "readhttps": true,
      "usetokenonread": true,
      "writebackhost": "https://origin-auth2001.chtc.wisc.edu:1095",
      "dirlisthost": "https://origin-auth2001.chtc.wisc.edu:1095"
    },
	{
	"path": "/osgconnect/private",
	"readhttps": true,
	"usetokenonread": true,
	"writebackhost": "https://stash-xrd.osgconnect.net:1095",
	"dirlisthost": "https://stash.osgconnect.net:1095"
  	},
    {
      "path": "/osgconnect",
      "writebackhost": "https://stash-xrd.osgconnect.net:1094",
      "dirlisthost": "http://stash.osgconnect.net:1094"
    }
  ]
}
`)

	os.Setenv("STASH_NAMESPACE_URL", "https://doesnotexist.edu/blah/nope")
	ns, err := MatchNamespace("/osgconnect/private/path/to/file.txt")
	assert.NoError(t, err, "Failed to parse namespace")

	assert.Equal(t, "/osgconnect/private", ns.Path)
	assert.Equal(t, true, ns.ReadHTTPS)

	// Check for empty
	ns, err = MatchNamespace("/does/not/exist.txt")
	assert.NoError(t, err, "Failed to parse namespace")
	assert.Equal(t, "", ns.Path)
	assert.Equal(t, Namespace{}.UseTokenOnRead, ns.UseTokenOnRead)

	// Check for not private
	ns, err = MatchNamespace("/osgconnect/public/path/to/file.txt")
	assert.NoError(t, err, "Failed to parse namespace")
	assert.Equal(t, "/osgconnect", ns.Path)
	assert.Equal(t, false, ns.ReadHTTPS)
	assert.Equal(t, false, ns.UseTokenOnRead)

	os.Unsetenv("STASH_NAMESPACE_URL")

}

func TestFullNamespace(t *testing.T) {
	ns, err := MatchNamespace("/ospool/PROTECTED/dweitzel/test.txt")
	assert.NoError(t, err, "Failed to parse namespace")
	assert.Equal(t, true, ns.ReadHTTPS)
	assert.Equal(t, true, ns.UseTokenOnRead)
	assert.Equal(t, "/ospool/PROTECTED", ns.Path)
	assert.Equal(t, "https://origin-auth2001.chtc.wisc.edu:1095", ns.WriteBackHost)

}

// TestDownloadNamespaces tests the download of the namespaces JSON
func TestDownloadNamespaces(t *testing.T) {
	os.Setenv("STASH_NAMESPACE_URL", "https://topology-itb.opensciencegrid.org/stashcache/namespaces")
	defer os.Unsetenv("STASH_NAMESPACE_URL")
	namespaceBytes, err := downloadNamespace()
	assert.NoError(t, err, "Failed to download namespaces")
	assert.NotNil(t, namespaceBytes, "Namespace bytes is nil")

}

func TestDownloadNamespacesFail(t *testing.T) {
	os.Setenv("STASH_NAMESPACE_URL", "https://doesnotexist.org.blah/namespaces.json")
	defer os.Unsetenv("STASH_NAMESPACE_URL")
	namespaceBytes, err := downloadNamespace()
	assert.Error(t, err, "Failed to download namespaces")
	assert.Nil(t, namespaceBytes, "Namespace bytes is nil")
}

func TestGetNamespaces(t *testing.T) {
	// Set the environment to an invalid URL, so it is forced to use the "built-in" namespaces.json
	os.Setenv("STASH_NAMESPACE_URL", "https://doesnotexist.org.blah/namespaces.json")
	defer os.Unsetenv("STASH_NAMESPACE_URL")
	namespaces, err := GetNamespaces()
	assert.NoError(t, err, "Failed to get namespaces")
	assert.NotNil(t, namespaces, "Namespaces is nil")
	assert.Equal(t, 3, len(namespaces))
}

func Test_intersect(t *testing.T) {
	var a = []string{"a", "b", "c"}
	var b = []string{"b", "c", "d"}
	var c = []string{"b", "c"}
	assert.Equal(t, c, intersect(a, b))

	a = []string{"4", "3", "2", "1"}
	b = []string{"2", "4", "5"}
	c = []string{"4", "2"}
	assert.Equal(t, c, intersect(a, b))
}

func TestNamespace_MatchCaches(t *testing.T) {
	cache1 := Cache{
		Endpoint: "cache1.ospool.org:8000",
	}
	cache2 := Cache{
		Endpoint: "cache2.ospool.org:8001",
	}
	cache3 := Cache{
		Endpoint: "cache3.ospool.org:8002",
	}
	namespace := Namespace{
		Path: "/ospool/PROTECTED",
		Caches: []Cache{
			cache1,
			cache2,
			cache3,
		},
	}
	assert.Equal(t, []Cache{cache1}, namespace.MatchCaches([]string{"cache1.ospool.org"}))
	assert.Equal(t, []Cache{cache2}, namespace.MatchCaches([]string{"cache2.ospool.org"}))
	assert.Equal(t, []Cache{cache3}, namespace.MatchCaches([]string{"cache3.ospool.org"}))
	assert.Equal(t, []Cache(nil), namespace.MatchCaches([]string{"cache4.ospool.org"}))

	assert.Equal(t, []Cache{cache2, cache3, cache1}, namespace.MatchCaches([]string{"cache2.ospool.org", "cache3.ospool.org", "cache1.ospool.org"}))

	assert.Equal(t, []Cache{cache2, cache1}, namespace.MatchCaches([]string{"cache5.ospool.org", "cache2.ospool.org", "cache4.ospool.org", "cache1.ospool.org"}))
}
