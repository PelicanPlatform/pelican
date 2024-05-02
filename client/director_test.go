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

package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	namespaces "github.com/pelicanplatform/pelican/namespaces"
	"github.com/pelicanplatform/pelican/utils"
)

func TestGetCachesFromDirectorResponse(t *testing.T) {
	// Construct the Director's Response, comprising headers and a body
	directorHeaders := make(map[string][]string)
	directorHeaders["Link"] = []string{"<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"}
	directorBody := []byte(`{"key": "value"}`)

	directorResponse := &http.Response{
		StatusCode: 307,
		Header:     directorHeaders,
		Body:       io.NopCloser(bytes.NewReader(directorBody)),
	}

	// Call the function in question
	caches, err := getCachesFromDirectorResponse(directorResponse, true)

	// Test for expected outputs
	assert.NoError(t, err, "Error getting caches from the Director's response")

	assert.Equal(t, "my-cache.edu:8443", caches[0].EndpointUrl)
	assert.Equal(t, 1, caches[0].Priority)
	assert.Equal(t, true, caches[0].AuthedReq)

	assert.Equal(t, "another-cache.edu:8443", caches[1].EndpointUrl)
	assert.Equal(t, 2, caches[1].Priority)
	assert.Equal(t, true, caches[1].AuthedReq)
}

func TestCreateNsFromDirectorResp(t *testing.T) {
	//Craft the Director's response
	directorHeaders := make(map[string][]string)
	directorHeaders["Link"] = []string{"<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"}
	directorHeaders["X-Pelican-Namespace"] = []string{"namespace=/foo/bar, readhttps=True, require-token=True"}
	directorHeaders["X-Pelican-Authorization"] = []string{"issuer=https://get-your-tokens.org", "issuer=https://get-your-tokens2.org"}
	directorBody := []byte(`{"key": "value"}`)

	directorResponse := &http.Response{
		StatusCode: 307,
		Header:     directorHeaders,
		Body:       io.NopCloser(bytes.NewReader(directorBody)),
	}

	// Create a namespace instance to test against
	cache1 := namespaces.DirectorCache{
		EndpointUrl: "my-cache.edu:8443",
		Priority:    1,
		AuthedReq:   true,
	}
	cache2 := namespaces.DirectorCache{
		EndpointUrl: "another-cache.edu:8443",
		Priority:    2,
		AuthedReq:   true,
	}

	caches := []namespaces.DirectorCache{}
	caches = append(caches, cache1)
	caches = append(caches, cache2)

	constructedNamespace := &namespaces.Namespace{
		SortedDirectorCaches: caches,
		Path:                 "/foo/bar",
		Issuer:               []string{"https://get-your-tokens.org", "https://get-your-tokens2.org"},
		ReadHTTPS:            true,
		UseTokenOnRead:       true,
	}

	// Call the function in question
	ns, err := CreateNsFromDirectorResp(directorResponse)

	// Test for expected outputs
	assert.NoError(t, err, "Error creating Namespace from Director response")

	assert.Equal(t, constructedNamespace.SortedDirectorCaches, ns.SortedDirectorCaches)
	assert.Equal(t, constructedNamespace.Path, ns.Path)
	assert.Equal(t, constructedNamespace.Issuer, ns.Issuer)
	assert.Equal(t, constructedNamespace.ReadHTTPS, ns.ReadHTTPS)
	assert.Equal(t, constructedNamespace.UseTokenOnRead, ns.UseTokenOnRead)

	// Test the old version of parsing the issuer from the director to ensure backwards compatibility with a V1 client and a V2 director
	var xPelicanAuthorization map[string]string
	var issuer string
	if len(directorResponse.Header.Values("X-Pelican-Authorization")) > 0 {
		xPelicanAuthorization = utils.HeaderParser(directorResponse.Header.Values("X-Pelican-Authorization")[0])
		issuer = xPelicanAuthorization["issuer"]
	}

	assert.Equal(t, "https://get-your-tokens.org", issuer)

}

func TestNewTransferDetailsUsingDirector(t *testing.T) {
	os.Setenv("http_proxy", "http://proxy.edu:3128")
	t.Cleanup(func() {
		require.NoError(t, os.Unsetenv("http_proxy"))
	})

	// Construct the input caches
	// Cache with http
	nonAuthCache := namespaces.DirectorCache{
		ResourceName: "mycache",
		EndpointUrl:  "my-cache-url:8000",
		Priority:     99,
		AuthedReq:    false,
	}

	// Cache with https
	authCache := namespaces.DirectorCache{
		ResourceName: "mycache",
		EndpointUrl:  "my-cache-url:8443",
		Priority:     99,
		AuthedReq:    true,
	}

	// Case 1: cache with http

	transfers := newTransferDetailsUsingDirector(nonAuthCache, transferDetailsOptions{nonAuthCache.AuthedReq, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 2: cache with https
	transfers = newTransferDetailsUsingDirector(authCache, transferDetailsOptions{authCache.AuthedReq, ""})
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "my-cache-url:8443", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)

	// Case 3: cache without port with http
	nonAuthCache.EndpointUrl = "my-cache-url"
	transfers = newTransferDetailsUsingDirector(nonAuthCache, transferDetailsOptions{nonAuthCache.AuthedReq, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "my-cache-url:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 4. cache without port with https
	authCache.EndpointUrl = "my-cache-url"
	transfers = newTransferDetailsUsingDirector(authCache, transferDetailsOptions{authCache.AuthedReq, ""})
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8444", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)
	assert.Equal(t, "my-cache-url:8443", transfers[1].Url.Host)
	assert.Equal(t, "https", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)
}

func TestQueryDirector(t *testing.T) {
	// Construct a local server that we can poke with QueryDirector
	expectedLocation := "http://redirect.com"
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", expectedLocation)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	// Call QueryDirector with the test server URL and a source path
	actualResp, err := queryDirector(context.Background(), "GET", "/foo/bar", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Check the Location header
	actualLocation := actualResp.Header.Get("Location")
	if actualLocation != expectedLocation {
		t.Errorf("Expected Location header %q, but got %q", expectedLocation, actualLocation)
	}

	// Check the HTTP status code
	if actualResp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("Expected HTTP status code %d, but got %d", http.StatusFound, actualResp.StatusCode)
	}
}
