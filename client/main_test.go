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
	"github.com/pelicanplatform/pelican/server_structs"
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
	viper.Reset()
	err := config.InitClient()
	assert.Nil(t, err)

	mock.MockTopology(t, config.GetTransport())

	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/user/foo",
		},
	}

	url, err := url.Parse("osdf:///user/foo")
	assert.NoError(t, err)

	// ENVs to test: BEARER_TOKEN, BEARER_TOKEN_FILE, XDG_RUNTIME_DIR/bt_u<uid>, TOKEN, _CONDOR_CREDS/scitoken.use, .condor_creds/scitokens.use
	os.Setenv("BEARER_TOKEN", "bearer_token_contents")
	token := newTokenGenerator(url, &dirResp, true, false)
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
	token = newTokenGenerator(url, &dirResp, true, false)
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
	token = newTokenGenerator(url, &dirResp, true, false)
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
	token = newTokenGenerator(url, &dirResp, true, false)
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
	token = newTokenGenerator(url, &dirResp, true, false)
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
	renamedUrl, err := url.Parse("renamed+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	ligoDirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/user/ligo/frames",
		},
	}
	token = newTokenGenerator(renamedUrl, &ligoDirResp, false, false)
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
	// Use a valid URL, then replace the scheme
	renamedUrl, err = url.Parse("renamed.handle1+osdf:///user/ligo/frames")
	renamedUrl.Scheme = "renamed_handle1+osdf"
	assert.NoError(t, err)
	token = newTokenGenerator(renamedUrl, &ligoDirResp, false, false)
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
	renamedUrl, err = url.Parse("renamed.handle2+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	token = newTokenGenerator(renamedUrl, &ligoDirResp, false, false)
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
	renamedUrl, err = url.Parse("renamed.handle3+osdf:///user/ligo/frames")
	assert.NoError(t, err)
	token = newTokenGenerator(renamedUrl, &ligoDirResp, false, false)
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
	renamedUrl, err = url.Parse("/user/ligo/frames")
	assert.NoError(t, err)
	token = newTokenGenerator(renamedUrl, &ligoDirResp, false, false)
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
	token = newTokenGenerator(url, &dirResp, true, false)
	tokenContents, err = token.get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

	// Check that we haven't regressed on our error messages
	token = newTokenGenerator(url, &dirResp, true, false)
	_, err = token.get()
	assert.EqualError(t, err, "credential is required for osdf:///user/foo but was not discovered")
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
