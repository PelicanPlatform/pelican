/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

package local_cache

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseStorageDirsConfig(t *testing.T) {
	defer viper.Reset()

	t.Run("Unset", func(t *testing.T) {
		viper.Reset()
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		assert.Nil(t, dirs)
	})

	t.Run("EmptyList", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		assert.Nil(t, dirs)
	})

	t.Run("StringList", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{"/mnt/cache1", "/mnt/cache2"})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)
		assert.Equal(t, "/mnt/cache1", dirs[0].Path)
		assert.Equal(t, uint64(0), dirs[0].MaxSize)
		assert.Equal(t, "/mnt/cache2", dirs[1].Path)
	})

	t.Run("StringSliceNative", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []string{"/a", "/b"})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)
		assert.Equal(t, "/a", dirs[0].Path)
		assert.Equal(t, "/b", dirs[1].Path)
	})

	t.Run("StructuredEntries", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":                    "/mnt/nvme",
				"MaxSize":                 "500GB",
				"HighWaterMarkPercentage": 95,
				"LowWaterMarkPercentage":  85,
			},
			map[string]interface{}{
				"Path":    "/mnt/hdd",
				"MaxSize": "2TB",
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 2)

		assert.Equal(t, "/mnt/nvme", dirs[0].Path)
		assert.Equal(t, uint64(500*1024*1024*1024), dirs[0].MaxSize)
		assert.Equal(t, 95, dirs[0].HighWaterMarkPercentage)
		assert.Equal(t, 85, dirs[0].LowWaterMarkPercentage)

		assert.Equal(t, "/mnt/hdd", dirs[1].Path)
		assert.Equal(t, uint64(2*1024*1024*1024*1024), dirs[1].MaxSize)
		assert.Equal(t, 0, dirs[1].HighWaterMarkPercentage)
	})

	t.Run("NumericMaxSize", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":    "/data",
				"MaxSize": 1073741824, // 1 GiB as integer
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, uint64(1073741824), dirs[0].MaxSize)
	})

	t.Run("LowercaseKeys", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"path":                    "/lower",
				"maxsize":                 "10GB",
				"highwatermarkpercentage": 90,
				"lowwatermarkpercentage":  80,
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, "/lower", dirs[0].Path)
		assert.Equal(t, uint64(10*1024*1024*1024), dirs[0].MaxSize)
		assert.Equal(t, 90, dirs[0].HighWaterMarkPercentage)
		assert.Equal(t, 80, dirs[0].LowWaterMarkPercentage)
	})

	t.Run("MissingPath", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{"MaxSize": "10GB"},
		})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing or empty Path")
	})

	t.Run("EmptyStringPath", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{""})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty path")
	})

	t.Run("InvalidMaxSize", func(t *testing.T) {
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[string]interface{}{
				"Path":    "/data",
				"MaxSize": "notasize",
			},
		})
		_, err := ParseStorageDirsConfig()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "MaxSize")
	})

	t.Run("YAMLMapInterfaceInterface", func(t *testing.T) {
		// Simulate the map[interface{}]interface{} that raw YAML sometimes produces
		viper.Reset()
		viper.Set("LocalCache.StorageDirs", []interface{}{
			map[interface{}]interface{}{
				"Path":    "/yaml-style",
				"MaxSize": "100GB",
			},
		})
		dirs, err := ParseStorageDirsConfig()
		require.NoError(t, err)
		require.Len(t, dirs, 1)
		assert.Equal(t, "/yaml-style", dirs[0].Path)
		assert.Equal(t, uint64(100*1024*1024*1024), dirs[0].MaxSize)
	})
}

// TestNormalizeURLPreservesPathCase holds down a cache correctness property:
// two objects whose paths differ only in case must not collapse onto one cache
// entry.
//
// Object paths are case-sensitive on every backend Pelican serves, and the
// read path (resolveObject) does not compare SourceURL before serving, so a
// collision here silently returns whichever object was fetched most recently
// for a request for the other one.
func TestNormalizeURLPreservesPathCase(t *testing.T) {
	upper := normalizeURL("pelican://example.org/ns/Data.txt")
	lower := normalizeURL("pelican://example.org/ns/data.txt")

	assert.Equal(t, "pelican://example.org/ns/Data.txt", upper, "path case is preserved verbatim")
	assert.NotEqual(t, upper, lower, "paths differing only in case must not normalize alike")
}

// TestNormalizeURLFoldsSchemeAndHost covers the half of the URL that is
// case-insensitive per RFC 3986 6.2.2.1 and therefore must fold.
func TestNormalizeURLFoldsSchemeAndHost(t *testing.T) {
	cases := []string{
		"pelican://example.org/ns/Obj",
		"PELICAN://example.org/ns/Obj",
		"pelican://EXAMPLE.ORG/ns/Obj",
		"PELICAN://Example.Org/ns/Obj",
	}
	want := "pelican://example.org/ns/Obj"
	for _, in := range cases {
		assert.Equal(t, want, normalizeURL(in), "normalizing %q", in)
	}
}

func TestNormalizeURLCleansPath(t *testing.T) {
	for in, want := range map[string]string{
		"pelican://h/ns//a":     "pelican://h/ns/a",
		"pelican://h/ns/./a":    "pelican://h/ns/a",
		"pelican://h/ns/b/../a": "pelican://h/ns/a",
		"pelican://h/ns/a/":     "pelican://h/ns/a",
	} {
		assert.Equal(t, want, normalizeURL(in), "normalizing %q", in)
	}
}

// TestObjectHashDistinguishesCaseVariants checks the property that actually
// matters: distinct objects get distinct cache keys, so one cannot be served
// in place of the other.
func TestObjectHashDistinguishesCaseVariants(t *testing.T) {
	salt := []byte("test-salt-for-hashing-purposes--")

	upper := ComputeObjectHash(salt, "pelican://example.org/ns/Data.txt")
	lower := ComputeObjectHash(salt, "pelican://example.org/ns/data.txt")
	assert.NotEqual(t, upper, lower, "case-variant paths must hash to different objects")

	// Scheme and host case must still not change the identity of an object.
	a := ComputeObjectHash(salt, "pelican://Example.ORG/ns/Data.txt")
	b := ComputeObjectHash(salt, "pelican://example.org/ns/Data.txt")
	assert.Equal(t, a, b, "scheme and host case must not change an object's identity")
}

// TestNormalizePelicanURLPreservesCase covers the exported wrapper the
// introspection and API paths use.  It takes both full URLs and bare paths,
// and must agree with normalizeURL on the case of the object path either way:
// the same object spelled two ways has to normalize to one answer.
func TestNormalizePelicanURLPreservesCase(t *testing.T) {
	assert.Equal(t, "pelican://example.org/ns/Data.txt",
		NormalizePelicanURL("pelican://example.org/ns/Data.txt"))
	assert.Equal(t, "osdf:///ns/Data.txt", NormalizePelicanURL("osdf:///ns/Data.txt"))
	assert.Equal(t, "/ns/Data.txt", NormalizePelicanURL("/ns/Data.txt"),
		"a bare path keeps its case")
}

// TestNormalizeHost covers the folding of the authority: ASCII case, the two
// spellings of an internationalized name, and the things that must be left
// alone -- ports and IP literals.
func TestNormalizeHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"Empty", "", ""},
		{"ASCII", "example.org", "example.org"},
		{"MixedCase", "Example.ORG", "example.org"},
		{"UpperCase", "EXAMPLE.ORG", "example.org"},
		{"TrailingDot", "Example.ORG.", "example.org."},
		{"WithPort", "Example.ORG:8443", "example.org:8443"},
		{"UnicodeIDN", "bücher.example", "xn--bcher-kva.example"},
		{"UnicodeIDNUpper", "BÜCHER.example", "xn--bcher-kva.example"},
		{"PunycodeIDN", "xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"UnicodeIDNWithPort", "BÜCHER.example:8443", "xn--bcher-kva.example:8443"},
		{"IPv4", "192.168.1.1", "192.168.1.1"},
		{"IPv4WithPort", "192.168.1.1:8443", "192.168.1.1:8443"},
		{"IPv6Bracketed", "[2001:DB8::1]", "[2001:db8::1]"},
		{"IPv6BracketedWithPort", "[2001:DB8::1]:8443", "[2001:db8::1]:8443"},
		{"IPv6Loopback", "[::1]:8443", "[::1]:8443"},
		// IDNA rejects an underscore under STD3 rules; normalizeHost has no
		// error to return, so it must still answer, deterministically.
		{"IDNARejected", "My_Host.Example", "my_host.example"},
		{"IDNARejectedWithPort", "My_Host.Example:443", "my_host.example:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeHost(tc.in))
		})
	}
}

// TestObjectHashFoldsIDNSpellings is the property normalizeHost exists for: a
// Unicode domain name and its punycode A-label are the same host, so a URL
// spelled either way must reach the same cached object.
func TestObjectHashFoldsIDNSpellings(t *testing.T) {
	salt := []byte("test-salt-for-hashing-purposes--")

	unicode := ComputeObjectHash(salt, "pelican://bücher.example/ns/Data.txt")
	upper := ComputeObjectHash(salt, "pelican://BÜCHER.example/ns/Data.txt")
	puny := ComputeObjectHash(salt, "pelican://xn--bcher-kva.example/ns/Data.txt")

	assert.Equal(t, unicode, puny, "an IDN and its A-label name one object")
	assert.Equal(t, unicode, upper, "IDNA case folding must not change identity")

	// A different host is still a different object.
	other := ComputeObjectHash(salt, "pelican://bucher.example/ns/Data.txt")
	assert.NotEqual(t, unicode, other)

	// The port is part of the authority, not of the domain name, and
	// distinguishes hosts.
	withPort := ComputeObjectHash(salt, "pelican://bücher.example:8443/ns/Data.txt")
	assert.NotEqual(t, unicode, withPort)
}
