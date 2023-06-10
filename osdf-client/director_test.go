package stashcp

import(
	"testing"
	"net/http"
	"net/http/httptest"
	"bytes"
	"io/ioutil"
	"os"
	"github.com/stretchr/testify/assert"

	namespaces "github.com/htcondor/osdf-client/v6/namespaces"
)

func TestHeaderParser(t *testing.T) {
	header1 := "namespace=/foo/bar, issuer = https://get-your-tokens.org, readhttps=False"
	newMap1 := HeaderParser(header1)

	assert.Equal(t, "/foo/bar", newMap1["namespace"])
	assert.Equal(t, "https://get-your-tokens.org", newMap1["issuer"])
	assert.Equal(t, "False", newMap1["readhttps"])

	header2 := ""
	newMap2 := HeaderParser(header2)
	assert.Equal(t, map[string]string{}, newMap2)
}

func TestGetCachesFromDirectorResponse(t *testing.T) {
	// Construct the Director's Response, comprising headers and a body
	directorHeaders := make(map[string][]string)
	directorHeaders["Link"] = []string{"<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"}
	directorBody := []byte(`{"key": "value"}`)
	
	directorResponse := &http.Response{
		StatusCode: 307,
		Header: directorHeaders,
		Body: ioutil.NopCloser(bytes.NewReader(directorBody)),
	}

	// Call the function in question
	caches, err := GetCachesFromDirectorResponse(directorResponse, true)

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
	directorHeaders["X-Osdf-Namespace"] = []string{"namespace=/foo/bar, readhttps=True, use-token-on-read=True"}	
	directorHeaders["X-Osdf-Authorization"] = []string{"issuer=https://get-your-tokens.org, base-path=/foo/bar"}
	directorBody := []byte(`{"key": "value"}`)

	directorResponse := &http.Response{
		StatusCode: 307,
		Header: directorHeaders,
		Body: ioutil.NopCloser(bytes.NewReader(directorBody)),
	}

	// Create a namespace instance to test against
	cache1 := namespaces.DirectorCache{
		EndpointUrl: "my-cache.edu:8443",
		Priority: 1,
		AuthedReq: true,
	} 
	cache2 := namespaces.DirectorCache{
		EndpointUrl: "another-cache.edu:8443",
		Priority: 2,
		AuthedReq: true,
	} 

	caches := []namespaces.DirectorCache{}
	caches = append(caches, cache1)
	caches = append(caches, cache2)
	
	constructedNamespace := &namespaces.Namespace{
		SortedDirectorCaches: caches,
		Path: "/foo/bar",
		Issuer: "https://get-your-tokens.org",
		ReadHTTPS: true,
		UseTokenOnRead: true,
	}

	// Call the function in question
	var ns namespaces.Namespace
	err := CreateNsFromDirectorResp(directorResponse, &ns)

	// Test for expected outputs
	assert.NoError(t, err, "Error creating Namespace from Director response")

	assert.Equal(t, constructedNamespace.SortedDirectorCaches, ns.SortedDirectorCaches)
	assert.Equal(t, constructedNamespace.Path, ns.Path)
	assert.Equal(t, constructedNamespace.Issuer, ns.Issuer)
	assert.Equal(t, constructedNamespace.ReadHTTPS, ns.ReadHTTPS)
	assert.Equal(t, constructedNamespace.UseTokenOnRead, ns.UseTokenOnRead)
}

func TestNewTransferDetailsUsingDirector(t *testing.T) {
	os.Setenv("http_proxy", "http://proxy.edu:3128")

	// Construct the input caches
	// Cache with http
	nonAuthCache := namespaces.DirectorCache{
		ResourceName: "mycache",
		EndpointUrl: "my-cache-url:8000",
		Priority: 99,
		AuthedReq: false,
	}

	// Cache with https
	authCache := namespaces.DirectorCache{
		ResourceName: "mycache",
		EndpointUrl: "my-cache-url:8443",
		Priority: 99,
		AuthedReq: true,
	}

	// Case 1: cache with http
	transfers := NewTransferDetailsUsingDirector(nonAuthCache, nonAuthCache.AuthedReq)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 2: cache with https
	transfers = NewTransferDetailsUsingDirector(authCache, authCache.AuthedReq)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "my-cache-url:8443", transfers[0].Url.Host)
	assert.Equal(t, "https", transfers[0].Url.Scheme)
	assert.Equal(t, false, transfers[0].Proxy)

	// Case 3: cache without port with http
	nonAuthCache.EndpointUrl = "my-cache-url"
	transfers = NewTransferDetailsUsingDirector(nonAuthCache, nonAuthCache.AuthedReq)
	assert.Equal(t, 2, len(transfers))
	assert.Equal(t, "my-cache-url:8000", transfers[0].Url.Host)
	assert.Equal(t, "http", transfers[0].Url.Scheme)
	assert.Equal(t, true, transfers[0].Proxy)
	assert.Equal(t, "my-cache-url:8000", transfers[1].Url.Host)
	assert.Equal(t, "http", transfers[1].Url.Scheme)
	assert.Equal(t, false, transfers[1].Proxy)

	// Case 4. cache without port with https
	authCache.EndpointUrl = "my-cache-url"
	transfers = NewTransferDetailsUsingDirector(authCache, authCache.AuthedReq)
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
		w.WriteHeader(http.StatusFound)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	// Call QueryDirector with the test server URL and a source path
	actualResp, err := QueryDirector("/foo/bar", server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Check the Location header
	actualLocation := actualResp.Header.Get("Location")
	if actualLocation != expectedLocation {
		t.Errorf("Expected Location header %q, but got %q", expectedLocation, actualLocation)
	}

	// Check the HTTP status code
	if actualResp.StatusCode != http.StatusFound {
		t.Errorf("Expected HTTP status code %d, but got %d", http.StatusFound, actualResp.StatusCode)
	}
}
