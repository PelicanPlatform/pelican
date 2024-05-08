/***************************************************************
 *
 * Copyright (C) 2024, University of Nebraska-Lincoln
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

package client

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/mock"
	"github.com/pelicanplatform/pelican/namespaces"
)

// TestGetIps calls main.get_ips with a hostname, checking
// for a valid return value.
func TestGetIps(t *testing.T) {
	t.Parallel()

	ips := getIPs("wlcg-wpad.fnal.gov")
	for _, ip := range ips {
		parsedIP := net.ParseIP(ip)
		if parsedIP.To4() != nil {
			// Make sure that the ip doesn't start with a "[", breaks downloads
			if strings.HasPrefix(ip, "[") {
				t.Fatal("IPv4 address has brackets, will break downloads")
			}
		} else if parsedIP.To16() != nil {
			if !strings.HasPrefix(ip, "[") {
				t.Fatal("IPv6 address doesn't have brackets, downloads will parse it as invalid ports")
			}
		}
	}

}

func TestGetCachesFromNamespace(t *testing.T) {
	// Get our list of caches for our namespace:
	directorCaches := make([]namespaces.DirectorCache, 3)
	for i := 0; i < 3; i++ {
		directorCache := namespaces.DirectorCache{
			EndpointUrl: "https://some/cache/" + strconv.Itoa(i),
			Priority:    0,
			AuthedReq:   false,
		}
		directorCaches[i] = directorCache
	}

	// Make our namespace:
	namespace := namespaces.Namespace{
		SortedDirectorCaches: directorCaches,
		ReadHTTPS:            false,
		UseTokenOnRead:       false,
	}

	// Check getCachesFromNamespace works with a director
	t.Run("testNoPreferredCache", func(t *testing.T) {
		caches, err := getCachesFromNamespace(namespace, true, nil)
		assert.NoError(t, err)
		require.Len(t, caches, 3)
		assert.Equal(t, "https://some/cache/0", caches[0].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/1", caches[1].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/2", caches[2].(namespaces.DirectorCache).EndpointUrl)
	})

	// Test that the function fails if the preferred cache is ""
	t.Run("testPreferredCacheEmpty", func(t *testing.T) {
		preferredCacheURL, _ := url.Parse("")
		someEmptyUrlList := []*url.URL{preferredCacheURL}
		_, err := getCachesFromNamespace(namespace, true, someEmptyUrlList)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Preferred cache was specified as an empty string")
	})

	// Test we work with multiple preferred caches
	t.Run("testMultiplePreferredCaches", func(t *testing.T) {
		preferredCache1, _ := url.Parse("https://I/like/this/cache")
		preferredCache2, _ := url.Parse("https://I/like/this/cache/too")
		preferredCacheList := []*url.URL{preferredCache1, preferredCache2}
		caches, err := getCachesFromNamespace(namespace, true, preferredCacheList)
		assert.NoError(t, err)
		require.Len(t, caches, 2)
		assert.Equal(t, "https://I/like/this/cache", caches[0].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://I/like/this/cache/too", caches[1].(namespaces.DirectorCache).EndpointUrl)
	})

	// Test our prepend works with multiple preferred caches
	t.Run("testMutliPreferredCachesPrepend", func(t *testing.T) {
		preferredCache1, _ := url.Parse("https://I/like/this/cache")
		preferredCache2, _ := url.Parse("https://I/like/this/cache/too")
		preferredCache3, _ := url.Parse("+")
		preferredCacheList := []*url.URL{preferredCache1, preferredCache2, preferredCache3}
		caches, err := getCachesFromNamespace(namespace, true, preferredCacheList)
		assert.NoError(t, err)
		require.Len(t, caches, 5)
		assert.Equal(t, "https://I/like/this/cache", caches[0].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://I/like/this/cache/too", caches[1].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/0", caches[2].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/1", caches[3].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/2", caches[4].(namespaces.DirectorCache).EndpointUrl)
	})

	// Test the function fails if the + character is not at the end of the list
	t.Run("testPlusNotAtEnd", func(t *testing.T) {
		preferredCache1, _ := url.Parse("https://I/like/this/cache")
		preferredCache2, _ := url.Parse("+")
		preferredCache3, _ := url.Parse("https://I/like/this/cache/too")
		preferredCacheList := []*url.URL{preferredCache1, preferredCache2, preferredCache3}
		_, err := getCachesFromNamespace(namespace, true, preferredCacheList)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The special character '+' must be the last item in the list of preferred caches")
	})

	// Test that the list of caches we get back has more than just the preferred cache when a + is at the end of the list
	t.Run("testPreferredCachePrepend", func(t *testing.T) {
		preferredCacheURL, _ := url.Parse("https://I/Like/This/Cache/The/Most")
		preferredPlusURL, _ := url.Parse("+")
		preferredCacheList := []*url.URL{preferredCacheURL, preferredPlusURL}
		caches, err := getCachesFromNamespace(namespace, true, preferredCacheList)
		assert.NoError(t, err)
		require.Len(t, caches, 4)
		assert.Equal(t, "https://I/Like/This/Cache/The/Most", caches[0].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/0", caches[1].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/1", caches[2].(namespaces.DirectorCache).EndpointUrl)
		assert.Equal(t, "https://some/cache/2", caches[3].(namespaces.DirectorCache).EndpointUrl)
	})

	// Test that we only get the preferred cache back when it is specified without a "+" at the end
	t.Run("testPreferredCacheNoPrepend", func(t *testing.T) {
		preferredCacheURL, _ := url.Parse("https://I/Like/This/Cache/The/Most")
		preferredCacheList := []*url.URL{preferredCacheURL}
		caches, err := getCachesFromNamespace(namespace, true, preferredCacheList)
		assert.NoError(t, err)
		require.Len(t, caches, 1)
		assert.Equal(t, "https://I/Like/This/Cache/The/Most", caches[0].(namespaces.DirectorCache).EndpointUrl)
	})
}

// TestGetToken tests getToken
func TestGetToken(t *testing.T) {
	// Need a namespace for token acquisition
	defer os.Unsetenv("PELICAN_FEDERATION_TOPOLOGYNAMESPACEURL")
	os.Setenv("PELICAN_TOPOLOGY_NAMESPACE_URL", "https://topology.opensciencegrid.org/osdf/namespaces")
	viper.Reset()
	err := config.InitClient()
	assert.Nil(t, err)

	mock.MockTopology(t, config.GetTransport())

	namespace, err := namespaces.MatchNamespace(context.Background(), "/user/foo")
	assert.NoError(t, err)

	url, err := url.Parse("osdf:///user/foo")
	assert.NoError(t, err)

	// ENVs to test: BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR/bt_u<uid>, TOKEN, _CONDOR_CREDS/scitoken.use, .condor_creds/scitokens.use
	os.Setenv("BEARER_TOKEN", "bearer_token_contents")
	token, err := getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, "bearer_token_contents", token)
	os.Unsetenv("BEARER_TOKEN")

	// BEARER_TOKEN_FILE
	tmpDir := t.TempDir()
	token_contents := "bearer_token_file_contents"
	tmpFile := []byte(token_contents)
	bearer_token_file := filepath.Join(tmpDir, "bearer_token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("BEARER_TOKEN_FILE", bearer_token_file)
	token, err = getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("BEARER_TOKEN_FILE")

	// XDG_RUNTIME_DIR/bt_u<uid>
	token_contents = "bearer_token_file_contents xdg"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "bt_u"+strconv.Itoa(os.Getuid()))
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("XDG_RUNTIME_DIR", tmpDir)
	token, err = getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("XDG_RUNTIME_DIR")

	// TOKEN
	token_contents = "bearer_token_file_contents token"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("TOKEN", bearer_token_file)
	token, err = getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("TOKEN")

	// _CONDOR_CREDS/scitokens.use
	token_contents = "bearer_token_file_contents scitokens.use"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "scitokens.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	token, err = getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err := url.Parse("renamed+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err := namespaces.MatchNamespace(context.Background(), "/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed_handle1.use via renamed_handle1+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed_handle1.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed_handle1.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	// Use a valid URL, then replace the scheme
	renamedUrl, err = url.Parse("renamed.handle1+osdf:///user/ligo/frames")
	renamedUrl.Scheme = "renamed_handle1+osdf"
	assert.NoError(t, err)
	renamedNamespace, err = namespaces.MatchNamespace(context.Background(), "/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed_handle2.use via renamed.handle2+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed.handle2.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed_handle2.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err = url.Parse("renamed.handle2+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err = namespaces.MatchNamespace(context.Background(), "/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.handle3.use via renamed.handle3+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed.handle3.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.handle3.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err = url.Parse("renamed.handle3+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err = namespaces.MatchNamespace(context.Background(), "/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	renamedUrl, err = url.Parse("/user/ligo/frames")
	assert.NoError(t, err)
	renamedNamespace, err = namespaces.MatchNamespace(context.Background(), "/user/ligo/frames")
	assert.NoError(t, err)
	token, err = getToken(renamedUrl, renamedNamespace, false, "renamed", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	os.Unsetenv("_CONDOR_CREDS")

	// Current directory .condor_creds/scitokens.use
	token_contents = "bearer_token_file_contents .condor_creds/scitokens.use"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, ".condor_creds", "scitokens.use")
	err = os.Mkdir(filepath.Join(tmpDir, ".condor_creds"), 0755)
	assert.NoError(t, err)
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	currentDir, err := os.Getwd()
	assert.NoError(t, err)
	err = os.Chdir(tmpDir)
	assert.NoError(t, err)
	token, err = getToken(url, namespace, true, "", "", false)
	assert.NoError(t, err)
	assert.Equal(t, token_contents, token)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

	_, err = getToken(url, namespace, true, "", "", false)
	assert.EqualError(t, err, "Credential is required for osdf:///user/foo but is currently missing")
}

// TestGetTokenName tests getTokenName
func TestGetTokenName(t *testing.T) {
	cases := []struct {
		url    string
		name   string
		scheme string
	}{
		{"osdf://blah+asdf", "", "osdf"},
		{"stash://blah+asdf", "", "stash"},
		{"file://blah+asdf", "", "file"},
		{"tokename+osdf://blah+asdf", "tokename", "osdf"},
		{"tokename+stash://blah+asdf", "tokename", "stash"},
		{"tokename+file://blah+asdf", "tokename", "file"},
		{"tokename+tokename2+osdf://blah+asdf", "tokename+tokename2", "osdf"},
		{"token+tokename2+stash://blah+asdf", "token+tokename2", "stash"},
		{"token.use+stash://blah+asdf", "token.use", "stash"},
		{"token.blah.asdf+stash://blah+asdf", "token.blah.asdf", "stash"},
	}
	for _, c := range cases {
		url, err := url.Parse(c.url)
		assert.NoError(t, err)
		scheme, tokenName := getTokenName(url)
		assert.Equal(t, c.name, tokenName)
		assert.Equal(t, c.scheme, scheme)
	}

}

func FuzzGetTokenName(f *testing.F) {
	testcases := []string{"", "tokename", "tokename+tokename2"}
	for _, tc := range testcases {
		f.Add(tc) // Use f.Add to provide a seed corpus
	}
	f.Fuzz(func(t *testing.T, orig string) {
		// Make sure it's a valid URL
		urlString := orig + "+osdf://blah+asdf"
		url, err := url.Parse(urlString)
		// If it's not a valid URL, then it's not a valid token name
		if err != nil || url.Scheme == "" {
			return
		}
		assert.NoError(t, err)
		_, tokenName := getTokenName(url)
		assert.Equal(t, strings.ToLower(orig), tokenName, "URL: "+urlString+"URL String: "+url.String()+" Scheme: "+url.Scheme)
	})
}

func TestCorrectURLWithUnderscore(t *testing.T) {
	tests := []struct {
		name           string
		url            string
		expectedURL    string
		expectedScheme string
	}{
		{
			name:           "LIGO URL with underscore",
			url:            "ligo_data://ligo.org/data/1",
			expectedURL:    "ligo.data://ligo.org/data/1",
			expectedScheme: "ligo_data",
		},
		{
			name:           "URL without underscore",
			url:            "http://example.com",
			expectedURL:    "http://example.com",
			expectedScheme: "http",
		},
		{
			name:           "URL with no scheme",
			url:            "example.com",
			expectedURL:    "example.com",
			expectedScheme: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualURL, actualScheme := correctURLWithUnderscore(tt.url)
			if actualURL != tt.expectedURL || actualScheme != tt.expectedScheme {
				t.Errorf("correctURLWithUnderscore(%v) = %v, %v; want %v, %v", tt.url, actualURL, actualScheme, tt.expectedURL, tt.expectedScheme)
			}
		})
	}
}

func TestSchemeUnderstood(t *testing.T) {
	t.Run("TestProperSchemeOsdf", func(t *testing.T) {
		scheme := "osdf"
		err := schemeUnderstood(scheme)
		assert.NoError(t, err)
	})
	t.Run("TestProperSchemeStash", func(t *testing.T) {
		scheme := "stash"
		err := schemeUnderstood(scheme)
		assert.NoError(t, err)
	})
	t.Run("TestProperSchemePelican", func(t *testing.T) {
		scheme := "pelican"
		err := schemeUnderstood(scheme)
		assert.NoError(t, err)
	})
	t.Run("TestProperSchemeFile", func(t *testing.T) {
		scheme := "file"
		err := schemeUnderstood(scheme)
		assert.NoError(t, err)
	})
	t.Run("TestProperSchemeEmpty", func(t *testing.T) {
		scheme := ""
		err := schemeUnderstood(scheme)
		assert.NoError(t, err)
	})
	t.Run("TestImproperScheme", func(t *testing.T) {
		scheme := "ThisSchemeDoesNotExistAndHopefullyNeverWill"
		err := schemeUnderstood(scheme)
		assert.Error(t, err)
	})
}
