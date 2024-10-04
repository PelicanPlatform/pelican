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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/mock"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
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

func TestGenerateSortedObjectServers(t *testing.T) {
	dirResp := server_structs.DirectorResponse{
		ObjectServers: []*url.URL{
			{Scheme: "https", Host: "server1.com", Path: "/foo"},
			{Scheme: "https", Host: "server2.com", Path: "/foo"},
			{Scheme: "https", Host: "server3.com", Path: "/foo"},
		},
	}

	t.Run("testNoPreferredServers", func(t *testing.T) {
		oServers, err := generateSortedObjServers(dirResp, []*url.URL{})
		assert.NoError(t, err)
		require.Len(t, oServers, 3)
		assert.Equal(t, "https://server1.com/foo", oServers[0].String())
		assert.Equal(t, "https://server2.com/foo", oServers[1].String())
		assert.Equal(t, "https://server3.com/foo", oServers[2].String())
	})

	// Test that the function fails if the preferred server is ""
	t.Run("testPreferredCacheEmpty", func(t *testing.T) {
		preferredUrl, _ := url.Parse("")
		someEmptyUrlList := []*url.URL{preferredUrl}
		_, err := generateSortedObjServers(dirResp, someEmptyUrlList)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Preferred server was specified as an empty string")
	})

	// Test we work with multiple preferred caches
	t.Run("testMultiplePreferredCaches", func(t *testing.T) {
		preferredOServers := []*url.URL{
			{Scheme: "https", Host: "preferred1.com", Path: "/foo"},
			{Scheme: "https", Host: "preferred2.com", Path: "/foo"},
		}
		oServers, err := generateSortedObjServers(dirResp, preferredOServers)
		assert.NoError(t, err)
		require.Len(t, oServers, 2)
		assert.Equal(t, "https://preferred1.com/foo", oServers[0].String())
		assert.Equal(t, "https://preferred2.com/foo", oServers[1].String())
	})

	// Test our prepend works with multiple preferred caches
	t.Run("testMutliPreferredCachesPrepend", func(t *testing.T) {
		preferredOServers := []*url.URL{
			{Scheme: "https", Host: "preferred1.com", Path: "/foo"},
			{Scheme: "https", Host: "preferred2.com", Path: "/foo"},
			{Scheme: "", Host: "", Path: "+"},
		}
		oServers, err := generateSortedObjServers(dirResp, preferredOServers)
		assert.NoError(t, err)
		require.Len(t, oServers, 5)
		assert.Equal(t, "https://preferred1.com/foo", oServers[0].String())
		assert.Equal(t, "https://preferred2.com/foo", oServers[1].String())
		assert.Equal(t, "https://server1.com/foo", oServers[2].String())
		assert.Equal(t, "https://server2.com/foo", oServers[3].String())
		assert.Equal(t, "https://server3.com/foo", oServers[4].String())
	})

	// Test the function fails if the + character is not at the end of the list
	t.Run("testPlusNotAtEnd", func(t *testing.T) {
		preferredOServers := []*url.URL{
			{Scheme: "https", Host: "preferred1.com", Path: "/foo"},
			{Scheme: "", Host: "", Path: "+"},
			{Scheme: "https", Host: "preferred2.com", Path: "/foo"},
		}
		_, err := generateSortedObjServers(dirResp, preferredOServers)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "The special character '+' must be the last item in the list of preferred servers")
	})
}

// TestGetToken tests getToken
func TestGetToken(t *testing.T) {
	// Need a namespace for token acquisition
	defer os.Unsetenv("PELICAN_FEDERATION_TOPOLOGYNAMESPACEURL")
	os.Setenv("PELICAN_TOPOLOGY_NAMESPACE_URL", "https://topology.opensciencegrid.org/osdf/namespaces")
	server_utils.Reset()
	err := config.InitClient()
	assert.Nil(t, err)

	mock.MockTopology(t, config.GetTransport())

	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/user/foo",
		},
	}

	pUrl, err := pelican_url.Parse("osdf:///user/foo", nil, nil)
	assert.NoError(t, err)

	// ENVs to test: BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR/bt_u<uid>, TOKEN, _CONDOR_CREDS/scitoken.use, .condor_creds/scitokens.use
	os.Setenv("BEARER_TOKEN", "bearer_token_contents")
	token := newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err := token.get()
	assert.NoError(t, err)
	assert.Equal(t, "bearer_token_contents", tokenContents)
	os.Unsetenv("BEARER_TOKEN")

	// BEARER_TOKEN_FILE
	tmpDir := t.TempDir()
	token_contents := "bearer_token_file_contents"
	tmpFile := []byte(token_contents)
	bearer_token_file := filepath.Join(tmpDir, "bearer_token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("BEARER_TOKEN_FILE", bearer_token_file)
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("BEARER_TOKEN_FILE")

	// XDG_RUNTIME_DIR/bt_u<uid>
	token_contents = "bearer_token_file_contents xdg"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "bt_u"+strconv.Itoa(os.Getuid()))
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("XDG_RUNTIME_DIR", tmpDir)
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("XDG_RUNTIME_DIR")

	// TOKEN
	token_contents = "bearer_token_file_contents token"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "token_file")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("TOKEN", bearer_token_file)
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("TOKEN")

	// _CONDOR_CREDS/scitokens.use
	token_contents = "bearer_token_file_contents scitokens.use"
	tmpFile = []byte(token_contents)
	bearer_token_file = filepath.Join(tmpDir, "scitokens.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	pUrl, err = pelican_url.Parse("renamed+osdf:///user/ligo/frames", nil, nil)
	assert.NoError(t, err)
	ligoDirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/user/ligo/frames",
		},
	}
	token = newTokenGenerator(pUrl, &ligoDirResp, false, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed_handle1.use via renamed_handle1+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed_handle1.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed_handle1.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	pUrl, err = pelican_url.Parse("renamed.handle1+osdf:///user/ligo/frames", nil, nil)
	assert.NoError(t, err)
	token = newTokenGenerator(pUrl, &ligoDirResp, false, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed_handle2.use via renamed.handle2+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed.handle2.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed_handle2.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	pUrl.RawScheme = "renamed.handle2+osdf"
	assert.NoError(t, err)
	token = newTokenGenerator(pUrl, &ligoDirResp, false, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.handle3.use via renamed.handle3+osdf:///user/ligo/frames
	token_contents = "bearer_token_file_contents renamed.handle3.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.handle3.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	pUrl.RawScheme = "renamed.handle3+osdf"
	assert.NoError(t, err)
	token = newTokenGenerator(pUrl, &ligoDirResp, false, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	os.Unsetenv("_CONDOR_CREDS")

	// _CONDOR_CREDS/renamed.use
	token_contents = "bearer_token_file_contents renamed.use"
	tmpFile = []byte(token_contents)
	tmpDir = t.TempDir()
	bearer_token_file = filepath.Join(tmpDir, "renamed.use")
	err = os.WriteFile(bearer_token_file, tmpFile, 0644)
	assert.NoError(t, err)
	os.Setenv("_CONDOR_CREDS", tmpDir)
	pUrl, err = pelican_url.Parse("osdf:///user/ligo/frames", nil, nil)
	assert.NoError(t, err)
	token = newTokenGenerator(pUrl, &ligoDirResp, false, false)
	token.SetTokenName("renamed")
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
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
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

	// Check that we haven't regressed on our error messages
	token = newTokenGenerator(pUrl, &dirResp, true, false)
	_, err = token.get()
	assert.EqualError(t, err, "credential is required for osdf:///user/ligo/frames but was not discovered")
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
		{"tokename+osdf://blah+asdf", "tokename", "osdf"},
		{"tokename+stash://blah+asdf", "tokename", "stash"},
		{"tokename+tokename2+osdf://blah+asdf", "tokename+tokename2", "osdf"},
		{"token+tokename2+stash://blah+asdf", "token+tokename2", "stash"},
		{"token.use+stash://blah+asdf", "token.use", "stash"},
		{"token.blah.asdf+stash://blah+asdf", "token.blah.asdf", "stash"},
	}
	for _, c := range cases {
		pUrl, err := pelican_url.Parse(c.url, nil, []pelican_url.DiscoveryOption{pelican_url.WithContext(context.Background())})
		assert.NoError(t, err)
		tokenName := pUrl.GetTokenName()
		assert.Equal(t, c.name, tokenName)
		assert.Equal(t, c.scheme, pUrl.Scheme)
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
		pUrl, err := pelican_url.Parse(urlString, nil, nil)
		assert.NoError(t, err)
		tokenName := pUrl.GetTokenName()
		assert.Equal(t, strings.ToLower(orig), tokenName, "URL: "+urlString+"URL String: "+url.String()+" Scheme: "+url.Scheme)
	})
}

// Spin up a discovery server for testing purposes
func getTestDiscoveryServer(t *testing.T) *httptest.Server {
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/pelican-configuration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{
				"director_endpoint": "https://director.com",
				"namespace_registration_endpoint": "https://registration.com",
				"broker_endpoint": "https://broker.com",
				"jwks_uri": "https://tokens.com"
			}`))
			assert.NoError(t, err)
		} else {
			http.NotFound(w, r)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(handler))
	return server
}

func assertPelicanURLEqual(t *testing.T, expected, actual *pelican_url.PelicanURL) {
	assert.Equal(t, expected.Scheme, actual.Scheme, "Scheme mismatch")
	assert.Equal(t, expected.Host, actual.Host, "Discovery Host mismatch")
	assert.Equal(t, expected.Path, actual.Path, "Path mismatch")
	assert.Equal(t, expected.FedInfo, actual.FedInfo, "Federation Info mismatch")
}

func TestParseRemoteAsPUrl(t *testing.T) {
	discServer := getTestDiscoveryServer(t)
	defer discServer.Close()
	discUrl, err := url.Parse(discServer.URL)
	require.NoError(t, err)

	oldHost, err := pelican_url.SetOsdfDiscoveryHost(discUrl.Host)
	t.Cleanup(func() {
		_, _ = pelican_url.SetOsdfDiscoveryHost(oldHost)
	})
	require.NoError(t, err)

	tests := []struct {
		name     string
		rp       string
		discEP   string // for setting global federation metadata
		dirEP    string // for setting global federation metadata
		expected *pelican_url.PelicanURL
		errMsg   string
	}{
		{
			name:     "test valid pelican url, no global metadata",
			rp:       fmt.Sprintf("pelican://%s/foo/bar", discUrl.Host),
			discEP:   "",
			dirEP:    "",
			expected: &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", BrokerEndpoint: "https://broker.com", JwksUri: "https://tokens.com"}},
			errMsg:   "",
		},
		{
			name:     "test valid osdf url, no global metadata",
			rp:       "osdf:///foo/bar",
			discEP:   "",
			dirEP:    "",
			expected: &pelican_url.PelicanURL{Scheme: "osdf", Host: "", Path: "/foo/bar", FedInfo: pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", BrokerEndpoint: "https://broker.com", JwksUri: "https://tokens.com"}},
			errMsg:   "",
		},
		{
			name:     "test valid stash url, no global metadata",
			rp:       "stash:///foo/bar",
			discEP:   "",
			dirEP:    "",
			expected: &pelican_url.PelicanURL{Scheme: "stash", Host: "", Path: "/foo/bar", FedInfo: pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", BrokerEndpoint: "https://broker.com", JwksUri: "https://tokens.com"}},
			errMsg:   "",
		},
		{
			name:     "test valid path with configured global discovery url",
			rp:       "/foo/bar",
			discEP:   discUrl.Host,
			dirEP:    "",
			expected: &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", BrokerEndpoint: "https://broker.com", JwksUri: "https://tokens.com"}},
			errMsg:   "",
		},
		{
			name:     "test valid path that falls back to configured director for discovery",
			rp:       "/foo/bar",
			discEP:   "",
			dirEP:    discUrl.Host,
			expected: &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: pelican_url.FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", BrokerEndpoint: "https://broker.com", JwksUri: "https://tokens.com"}},
			errMsg:   "",
		},
		{
			name:     "test failure for path with no discovery metadata",
			rp:       "/foo/bar",
			discEP:   "",
			dirEP:    "",
			expected: nil,
			errMsg:   "schemeless Pelican URLs must be used with a federation discovery URL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up global metadata if we have it. We do this because the function may
			// fall back to configured discovery/director URLs if it can't find them in the URL
			configOpts := map[string]any{"TLSSkipVerify": true}
			if test.discEP != "" {
				configOpts["Federation.DiscoveryUrl"] = test.discEP
			}
			if test.dirEP != "" {
				configOpts["Federation.DirectorUrl"] = test.dirEP
			}

			test_utils.InitClient(t, configOpts)

			pUrl, err := ParseRemoteAsPUrl(context.Background(), test.rp)
			if test.errMsg == "" {
				assert.NoError(t, err)
				assertPelicanURLEqual(t, test.expected, pUrl)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.errMsg)
			}
		})
	}
}
