package stashcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMatchNamespace calls MatchNamespace with a hostname, checking
// for a valid return value.
func TestMatchNamespace(t *testing.T) {
	namespacesYaml = []byte(`
- path: /ospool/PROTECTED
  readhttps: true
  usetokenonread: true
  writebackhost: https://origin-auth2001.chtc.wisc.edu:1095
  dirlisthost: https://origin-auth2001.chtc.wisc.edu:1095

- path: /osgconnect/private
  readhttps: true
  usetokenonread: true
  writebackhost: https://stash-xrd.osgconnect.net:1094

- path: /osgconnect
  writebackhost: https://stash-xrd.osgconnect.net:1094
  dirlisthost: http://stash.osgconnect.net:1094
`)
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

}
