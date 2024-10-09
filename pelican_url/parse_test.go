/***************************************************************
*
* Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package pelican_url

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCorrectURLWithUnderscore(t *testing.T) {
	tests := []struct {
		name        string
		url         *url.URL
		expectedUrl *url.URL
	}{
		{
			name: "LIGO URL with underscore",
			url: &url.URL{
				Scheme: "ligo_data",
				Host:   "ligo.org",
				Path:   "/data/1",
			},
			expectedUrl: &url.URL{
				Scheme: "ligo.data",
				Host:   "ligo.org",
				Path:   "/data/1",
			},
		},
		{
			name: "URL without underscore",
			url: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
			expectedUrl: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
		},
		{
			name: "URL with no scheme",
			url: &url.URL{
				Scheme: "",
				Host:   "example.com",
			},
			expectedUrl: &url.URL{
				Scheme: "",
				Host:   "example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			correctUrlWithUnderscore(tt.url)
			if tt.url.Scheme != tt.expectedUrl.Scheme || tt.url.Host != tt.expectedUrl.Host || tt.url.Path != tt.expectedUrl.Path {
				t.Errorf("correctURLWithUnderscore(%v) = %v; want %v", tt.url, tt.url.Scheme, tt.expectedUrl.Scheme)
			}
		})
	}
}

func TestNormalizeScheme(t *testing.T) {
	tests := []struct {
		scheme       string
		normedScheme string
	}{
		{
			scheme:       "pelican",
			normedScheme: "pelican",
		},
		{
			scheme:       "osdf",
			normedScheme: "osdf",
		},
		{
			scheme:       "stash",
			normedScheme: "stash",
		},
		{
			scheme:       "token+pelican",
			normedScheme: "pelican",
		},
		{
			scheme:       "token+osdf",
			normedScheme: "osdf",
		},
		{
			scheme:       "token+stash",
			normedScheme: "stash",
		},
		{
			scheme:       "unknown",
			normedScheme: "unknown",
		},
		{
			scheme:       "token+unknown",
			normedScheme: "unknown",
		},
		{
			scheme:       "token+",
			normedScheme: "",
		},
		{
			scheme:       "+pelican",
			normedScheme: "pelican",
		},
		{
			scheme:       "",
			normedScheme: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			normedScheme := normalizeScheme(tt.scheme)
			if normedScheme != tt.normedScheme {
				t.Errorf("normalizeScheme(%v) = %v; want %v", tt.scheme, normedScheme, tt.normedScheme)
			}
		})
	}
}

func TestSchemeUnderstood(t *testing.T) {
	tests := []struct {
		scheme     string
		understood bool
	}{
		{
			scheme:     "pelican",
			understood: true,
		},
		{
			scheme:     "osdf",
			understood: true,
		},
		{
			scheme:     "stash",
			understood: true,
		},
		{
			scheme:     "",
			understood: false,
		},
		{
			scheme:     "ThisSchemeDoesNotExistAndHopefullyNeverWill",
			understood: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			ok := schemeUnderstood(tt.scheme)
			if ok != tt.understood {
				t.Errorf("schemeUnderstood(%v) = %v; want %v", tt.scheme, ok, tt.understood)
			}
		})
	}
}

func TestNormalizeOsdfTripleSlash(t *testing.T) {
	tests := []struct {
		url       string
		normedUrl string
	}{
		{
			url:       "osdf:///foo/bar",
			normedUrl: "osdf:///foo/bar",
		},
		{
			url:       "osdf://bar/foo",
			normedUrl: "osdf:///bar/foo",
		},
		{
			url:       "stash:///foo/bar",
			normedUrl: "stash:///foo/bar",
		},
		{
			url:       "stash://bar/foo",
			normedUrl: "stash:///bar/foo",
		},
		{
			url:       "pelican://director.com/foo/bar",
			normedUrl: "pelican://director.com/foo/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			parsedUrl, err := url.Parse(tt.url)
			if err != nil {
				t.Errorf("Failed to parse URL: %v", err)
			}
			err = normalizeOSDFTripleSlash(parsedUrl)
			if err != nil {
				t.Errorf("normalizeOSDFTripleSlash(%v) = %v; want nil", tt.url, err)
			}
			if parsedUrl.String() != tt.normedUrl {
				t.Errorf("normalizeOSDFTripleSlash(%v) = %v; want %v", tt.url, parsedUrl.String(), tt.normedUrl)
			}
		})
	}
}

func TestStripTokenFromUrl(t *testing.T) {
	tests := []struct {
		url       string
		tokenName string
	}{
		{"pelican://director.com/foo/bar", ""},
		{"osdf:///blah+asdf", ""},
		{"stash:///blah+asdf", ""},
		{"tokename+pelican://blah+asdf", "tokename"},
		{"tokename+osdf:///blah+asdf", "tokename"},
		{"tokename+stash:///blah+asdf", "tokename"},
		{"tokename+tokename2+osdf:///blah+asdf", "tokename+tokename2"},
		{"token+tokename2+stash:///blah+asdf", "token+tokename2"},
		{"token.use+stash:///blah+asdf", "token.use"},
		{"token.blah.asdf+stash:///blah+asdf", "token.blah.asdf"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			parsedUrl, err := url.Parse(tt.url)
			if err != nil {
				t.Errorf("Failed to parse URL: %v", err)
			}
			tokenName := stripTokenFromUrl(parsedUrl)
			if tokenName != tt.tokenName {
				t.Errorf("stripTokenFromUrl(%v) = %v; want %v", tt.url, tokenName, tt.tokenName)
			}
		})
	}
}

func TestParse(t *testing.T) {
	discServer := getTestDiscoveryServer(t)
	defer discServer.Close()
	discUrl, err := url.Parse(discServer.URL)
	require.NoError(t, err)

	// Create an insecure client to skip tls stuff in some tests. Note we can't use Pelican's
	// TLSSkipVerify, because that comes from config and can't be imported here.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	oldDiscovery, err := SetOsdfDiscoveryHost(discUrl.Host)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = SetOsdfDiscoveryHost(oldDiscovery)
	})

	tests := []struct {
		name      string
		url       string
		dOpts     []DiscoveryOption
		pOpts     []ParseOption
		pUrl      *PelicanURL
		errString string
	}{
		// Pelican scheme tests
		{
			name:      "vanilla pelican, no discovery",
			url:       "pelican://director.com/foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "token in scheme",
			url:       "mytoken+pelican://director.com/foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "mytoken+pelican", Host: "director.com", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "pelican with discovery",
			url:       fmt.Sprintf("pelican://%s/foo/bar", discUrl.Host),
			dOpts:     []DiscoveryOption{WithClient(client)},
			pOpts:     []ParseOption{ShouldDiscover(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: discUrl.Host, Path: "/foo/bar", FedInfo: FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", JwksUri: "https://tokens.com"}},
			errString: "",
		},
		{
			name:      "pelican with one query param",
			url:       "pelican://director.com/foo/bar?directread",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ValidateQueryParams(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar", RawQuery: "directread"},
			errString: "",
		},
		{
			name:      "pelican with two query params",
			url:       "pelican://director.com/foo/bar?directread&recursive",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ValidateQueryParams(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar", RawQuery: "directread&recursive"},
			errString: "",
		},
		{
			name:      "pelican with unknown query param",
			url:       "pelican://director.com/foo/bar?badquery",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ValidateQueryParams(true)},
			pUrl:      nil,
			errString: "Unknown query parameter 'badquery'",
		},
		{
			name:      "pelican with two query params, allowed",
			url:       "pelican://director.com/foo/bar?badquery",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ValidateQueryParams(true), AllowUnknownQueryParams(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar", RawQuery: "badquery"},
			errString: "",
		},
		{
			name:      "pelican with two valid-but-conflicting query params",
			url:       "pelican://director.com/foo/bar?directread&prefercached",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ValidateQueryParams(true)},
			pUrl:      nil,
			errString: "Cannot have both 'directread' and 'prefercached' query parameters",
		},
		{
			name:      "pelican with bad discovery",
			url:       "pelican://bad-director.com/foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{ShouldDiscover(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "bad-director.com", Path: "/foo/bar"},
			errString: "Error occurred when querying for metadata",
		},
		{
			name:      "pelican with no host",
			url:       "pelican:///foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "bad-director.com", Path: "/foo/bar"},
			errString: "pelican URL 'pelican:///foo/bar' is invalid because it has no host",
		},

		// OSDF/Stash scheme tests. Most of the underlying machinery is shared, so only testing the things that are more likely
		// to cause problems.
		{
			name:      "vanilla osdf, no discovery",
			url:       "osdf:///foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "osdf", RawScheme: "osdf", Host: "", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "vanilla osdf with discovery",
			url:       "osdf:///foo/bar",
			dOpts:     []DiscoveryOption{WithClient(client)},
			pOpts:     []ParseOption{ShouldDiscover(true)},
			pUrl:      &PelicanURL{Scheme: "osdf", RawScheme: "osdf", Host: "", Path: "/foo/bar", FedInfo: FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", JwksUri: "https://tokens.com"}},
			errString: "",
		},
		{
			name:      "osdf without triple slash",
			url:       "osdf://foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "osdf", RawScheme: "osdf", Host: "", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "vanilla stash, no discovery",
			url:       "stash:///foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "stash", RawScheme: "stash", Host: "", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "vanilla stash with discovery",
			url:       "stash:///foo/bar",
			dOpts:     []DiscoveryOption{WithClient(client)},
			pOpts:     []ParseOption{ShouldDiscover(true)},
			pUrl:      &PelicanURL{Scheme: "stash", RawScheme: "stash", Host: "", Path: "/foo/bar", FedInfo: FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", JwksUri: "https://tokens.com"}},
			errString: "",
		},
		{
			name:      "stash without triple slash",
			url:       "stash://foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "stash", RawScheme: "stash", Host: "", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "no host, with discovery URL but no discovery",
			url:       "/foo/bar",
			dOpts:     []DiscoveryOption{WithDiscoveryUrl(&url.URL{Host: "director.com"})},
			pOpts:     []ParseOption{},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar"},
			errString: "",
		},
		{
			name:      "no host, with discovery URL and discovery",
			url:       "/foo/bar",
			dOpts:     []DiscoveryOption{WithDiscoveryUrl(&url.URL{Host: "director.com"})},
			pOpts:     []ParseOption{ShouldDiscover(true)},
			pUrl:      &PelicanURL{Scheme: "pelican", RawScheme: "pelican", Host: "director.com", Path: "/foo/bar", FedInfo: FederationDiscovery{DirectorEndpoint: "https://director.com", RegistryEndpoint: "https://registration.com", JwksUri: "https://tokens.com"}},
			errString: "",
		},
		{
			name:      "no host, no discovery URL",
			url:       "/foo/bar",
			dOpts:     []DiscoveryOption{},
			pOpts:     []ParseOption{},
			pUrl:      nil,
			errString: "schemeless Pelican URLs must be used with a federation discovery URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			pUrl, err := Parse(tt.url, tt.pOpts, tt.dOpts)
			if err != nil {
				if !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("Parse(%v) = %v; want %v", tt.url, err.Error(), tt.errString)
				}
			} else if tt.pUrl != nil {
				if pUrl.Scheme != tt.pUrl.Scheme || pUrl.RawScheme != tt.pUrl.RawScheme || pUrl.Host != tt.pUrl.Host || pUrl.Path != tt.pUrl.Path || pUrl.RawQuery != tt.pUrl.RawQuery {
					t.Errorf("Parse(%v) = %v; want %v", tt.url, pUrl, tt.pUrl)
				}
				if pUrl.FedInfo.DirectorEndpoint != tt.pUrl.FedInfo.DirectorEndpoint || pUrl.FedInfo.RegistryEndpoint != tt.pUrl.FedInfo.RegistryEndpoint || pUrl.FedInfo.JwksUri != tt.pUrl.FedInfo.JwksUri {
					t.Errorf("Parse(%v) = FedInfo: %v; want %v", tt.url, pUrl.FedInfo, tt.pUrl.FedInfo)
				}
			}
		})
	}
}

func TestGetRawUrl(t *testing.T) {
	tests := []struct {
		pUrl     string
		expected string
	}{
		{
			pUrl:     "pelican://director.com/foo/bar",
			expected: "pelican://director.com/foo/bar",
		},
		{
			pUrl:     "pelican://director.com/foo/bar?directread",
			expected: "pelican://director.com/foo/bar?directread",
		},
		{
			pUrl:     "osdf:///foo/bar",
			expected: "osdf:///foo/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pUrl, func(t *testing.T) {
			pUrl, err := Parse(tt.pUrl, nil, nil)
			require.NoError(t, err)
			rawUrl := pUrl.GetRawUrl()
			if rawUrl.String() != tt.expected {
				t.Errorf("getRawUrl(%v) = %v; want %v", tt.pUrl, rawUrl, tt.expected)
			}
		})
	}
}

func TestGetTokenName(t *testing.T) {
	tests := []struct {
		pUrl      string
		tokenName string
	}{
		{
			pUrl:      "pelican://director.com/foo/bar",
			tokenName: "",
		},
		{
			pUrl:      "mytoken+pelican://director.com/foo/bar",
			tokenName: "mytoken",
		},
		{
			pUrl:      "token+token2+pelican://director.com/foo/bar",
			tokenName: "token+token2",
		},
		{
			pUrl:      "token+token2+osdf:///foo/bar",
			tokenName: "token+token2",
		},
		{
			pUrl:      "token+token2+stash:///foo/bar",
			tokenName: "token+token2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pUrl, func(t *testing.T) {
			pUrl, err := Parse(tt.pUrl, nil, nil)
			require.NoError(t, err)
			tokenName := pUrl.GetTokenName()
			if tokenName != tt.tokenName {
				t.Errorf("getTokenName(%v) = %v; want %v", tt.pUrl, tokenName, tt.tokenName)
			}
		})
	}
}

func TestPUrlToString(t *testing.T) {
	tests := []struct {
		pUrl string
	}{
		{
			pUrl: "pelican://director.com/foo/bar",
		},
		{
			pUrl: "pelican://director.com/foo/bar?directread",
		},
		{
			pUrl: "osdf:///foo/bar",
		},
		{
			pUrl: "stash:///foo/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.pUrl, func(t *testing.T) {
			pUrl, err := Parse(tt.pUrl, nil, nil)
			require.NoError(t, err)
			if pUrl.String() != tt.pUrl {
				t.Errorf("pUrlToString(%v) = %v; want %v", tt.pUrl, pUrl.String(), tt.pUrl)
			}
		})
	}
}
