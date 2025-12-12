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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/mock"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
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
	t.Run("testMultiPreferredCachesPrepend", func(t *testing.T) {
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
	os.Setenv("PELICAN_FEDERATION_TOPOLOGYNAMESPACEURL", "https://topology.opensciencegrid.org/osdf/namespaces")
	server_utils.ResetTestState()
	defer server_utils.ResetTestState()

	test_utils.InitClient(t, nil)

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
	token := NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err := token.Get()
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
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &ligoDirResp, config.TokenSharedRead, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &ligoDirResp, config.TokenSharedRead, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &ligoDirResp, config.TokenSharedRead, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &ligoDirResp, config.TokenSharedRead, false)
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &ligoDirResp, config.TokenSharedRead, false)
	token.SetTokenName("renamed")
	tokenContents, err = token.Get()
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
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	tokenContents, err = token.Get()
	assert.NoError(t, err)
	assert.Equal(t, token_contents, tokenContents)
	err = os.Chdir(currentDir)
	assert.NoError(t, err)

	// Check that we haven't regressed on our error messages
	token = NewTokenGenerator(pUrl, &dirResp, config.TokenSharedWrite, false)
	_, err = token.Get()
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

func assertPelicanURLEqual(t *testing.T, expected, actual *pelican_url.PelicanURL) {
	assert.Equal(t, expected.Scheme, actual.Scheme, "Scheme mismatch")
	assert.Equal(t, expected.Host, actual.Host, "Discovery Host mismatch")
	assert.Equal(t, expected.Path, actual.Path, "Path mismatch")
	assert.Equal(t, expected.FedInfo, actual.FedInfo, "Federation Info mismatch")
}

func TestParseRemoteAsPUrl(t *testing.T) {
	// A federation discovery object that'll act as the metadata
	// these tests find through discovery.
	//
	// Note that while some of the tests fall back to discovery via
	// the Director endpoint, those tests use the test server below
	// for the Director only discover "director.com", which should
	// never be queried.
	//
	// The discovery endpoint is set after the federation mock server is created.
	fedInfo := pelican_url.FederationDiscovery{
		DirectorEndpoint: "https://director.com",
		RegistryEndpoint: "https://registration.com",
		BrokerEndpoint:   "https://broker.com",
		JwksUri:          "https://tokens.com",
	}
	test_utils.MockFederationRoot(t, &fedInfo, nil)
	discUrl, err := url.Parse(param.Federation_DiscoveryUrl.GetString())
	require.NoError(t, err)

	fedInfo.DiscoveryEndpoint = discUrl.String()

	// Unset the global discovery endpoint set by MockFederationRoot so that these
	// tests can set it as needed
	viper.Set(param.Federation_DiscoveryUrl.GetName(), "")

	oldHost, err := pelican_url.SetOsdfDiscoveryHost(discUrl.Host)
	t.Cleanup(func() {
		_, _ = pelican_url.SetOsdfDiscoveryHost(oldHost)
	})
	require.NoError(t, err)

	tests := []struct {
		name      string
		rp        string
		discEP    string // for setting global federation metadata. Otherwise values are set via the constructed Pelican URL.
		dirEP     string // for setting global federation metadata
		expected  *pelican_url.PelicanURL
		expectErr bool
	}{
		{
			name:      "test valid pelican url, no global metadata",
			rp:        fmt.Sprintf("pelican://%s/foo/bar", discUrl.Host),
			discEP:    "",
			dirEP:     "",
			expected:  &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: fedInfo},
			expectErr: false,
		},
		{
			name:      "test valid osdf url, no global metadata",
			rp:        "osdf:///foo/bar",
			discEP:    "",
			dirEP:     "",
			expected:  &pelican_url.PelicanURL{Scheme: "osdf", Host: "", Path: "/foo/bar", FedInfo: fedInfo},
			expectErr: false,
		},
		{
			name:      "test valid stash url, no global metadata",
			rp:        "stash:///foo/bar",
			discEP:    "",
			dirEP:     "",
			expected:  &pelican_url.PelicanURL{Scheme: "stash", Host: "", Path: "/foo/bar", FedInfo: fedInfo},
			expectErr: false,
		},
		{
			name:     "test valid path with configured global discovery url",
			rp:       "/foo/bar",
			discEP:   discUrl.Host,
			dirEP:    "",
			expected: &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: fedInfo},
		},
		{
			name:      "test valid path that falls back to configured director for discovery",
			rp:        "/foo/bar",
			discEP:    "",
			dirEP:     discUrl.Host,
			expected:  &pelican_url.PelicanURL{Scheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: fedInfo},
			expectErr: false,
		},
		{
			name:      "test failure for path with no discovery metadata",
			rp:        "/foo/bar",
			discEP:    "",
			dirEP:     "",
			expected:  nil,
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Set up global metadata if we have it. We do this because the function may
			// fall back to configured discovery/director URLs if it can't find them in the URL
			configOpts := map[string]any{"TLSSkipVerify": true}
			if test.discEP != "" {
				configOpts[param.Federation_DiscoveryUrl.GetName()] = test.discEP
			}
			if test.dirEP != "" {
				configOpts["Federation.DirectorUrl"] = test.dirEP
			}

			test_utils.InitClient(t, configOpts)

			pUrl, err := ParseRemoteAsPUrl(context.Background(), test.rp)
			if test.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assertPelicanURLEqual(t, test.expected, pUrl)
		})
	}
}

// Verify if a scitoken‐profile JWT is acceptable for a given namespace
func TestTokenIsAcceptableForSciTokens(t *testing.T) {
	issuerURL, err := url.Parse("https://issuer.example")
	require.NoError(t, err)

	// 1) Build a minimal DirectorResponse whose namespace is "/foo"
	dirResp := server_structs.DirectorResponse{
		XPelNsHdr: server_structs.XPelNs{
			Namespace: "/foo",
		},
		XPelTokGenHdr: server_structs.XPelTokGen{
			Issuers:   []*url.URL{issuerURL},
			BasePaths: []string{"/foo"},
		},
	}

	opts := config.TokenGenerationOpts{
		Operation: config.TokenSharedRead,
	}

	// 2) Construct a SciToken JWT with ver="scitokens:2.0" and scope "storage.read:/bar"
	tc, err := token.NewTokenConfig(token.Scitokens2Profile{})
	require.NoError(t, err)
	tc.Lifetime = time.Hour
	tc.Issuer = "https://issuer.example"
	tc.AddAudienceAny()
	tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Read, "/bar"))

	// Generate an ECDSA P‑256 key so that ES256 signing works
	privEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwkKey, err := jwk.FromRaw(privEC)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.KeyIDKey, "test-ec-key"))
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))

	// Inject the SciTokens version claim
	require.NoError(t, jwkKey.Set("ver", "scitokens:2.0"))

	// Create the serialized token
	sciTokBytes, err := tc.CreateTokenWithKey(jwkKey)
	require.NoError(t, err)
	sciTok := string(sciTokBytes)

	// 3a) Positive case: resource "/foo/bar/baz" is inside namespace and matches scope
	accepted := tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
	assert.True(t, accepted, "expected SciToken to be acceptable for /foo/bar/baz")

	// 3b) Negative case: resource "/other/bar" lies outside the declared namespace
	accepted = tokenIsAcceptable(sciTok, "/other/bar", dirResp, opts)
	assert.False(t, accepted, "expected SciToken for /other/bar to be rejected")

	// 3c) Test with TokenDelete operation and storage.modify scope
	opts.Operation = config.TokenDelete
	// Create a new token config to ensure we don't have the "storage.read" scope from the previous test
	tc, err = token.NewTokenConfig(token.Scitokens2Profile{})
	require.NoError(t, err)
	tc.Lifetime = time.Hour
	tc.Issuer = "https://issuer.example"
	tc.AddAudienceAny()
	tc.AddResourceScopes(token_scopes.NewResourceScope(token_scopes.Scitokens_Write, "/bar"))
	sciTokBytes, err = tc.CreateTokenWithKey(jwkKey)
	require.NoError(t, err)
	sciTok = string(sciTokBytes)
	accepted = tokenIsAcceptable(sciTok, "/foo/bar/baz", dirResp, opts)
	assert.True(t, accepted, "expected SciToken with storage.modify scope to be acceptable for TokenDelete operation")
}
