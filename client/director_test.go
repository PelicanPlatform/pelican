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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/utils"
)

func TestParseServersFromDirectorResponse(t *testing.T) {
	// Construct the Director's Response, comprising headers and a body
	directorHeaders := make(map[string][]string)
	directorHeaders["Link"] = []string{"<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"}
	directorBody := []byte(`{"key": "value"}`)

	directorResponse := &http.Response{
		StatusCode: 307,
		Header:     directorHeaders,
		Body:       io.NopCloser(bytes.NewReader(directorBody)),
	}

	sortedServers, err := parseServersFromDirectorResponse(directorResponse)
	assert.NoError(t, err, "Error getting sortedServers from the Director's response")
	assert.Equal(t, "my-cache.edu:8443", sortedServers[0].String())
	assert.Equal(t, "another-cache.edu:8443", sortedServers[1].String())
}

func TestParseDirectorInfo(t *testing.T) {
	// Craft the Director's response
	directorHeaders := make(map[string][]string)
	directorHeaders["Link"] = []string{"<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"}
	directorHeaders["X-Pelican-Namespace"] = []string{"namespace=/foo/bar, require-token=True, collections-url=https://my-collections.com"}
	directorHeaders["X-Pelican-Authorization"] = []string{"issuer=https://get-your-tokens.org, issuer=https://get-your-tokens2.org"}
	directorHeaders["X-Pelican-Token-Generation"] = []string{"issuer=https://get-your-tokens.org, base-path=/foo/bar, max-scope-depth=2, strategy=OAuth2"}
	directorBody := []byte(`{"key": "value"}`)

	directorResponse := &http.Response{
		StatusCode: 307,
		Header:     directorHeaders,
		Body:       io.NopCloser(bytes.NewReader(directorBody)),
	}

	parsed, err := ParseDirectorInfo(directorResponse)
	assert.NoError(t, err, "Error parsing Director response")

	assert.Equal(t, "/foo/bar", parsed.XPelNsHdr.Namespace)
	assert.Equal(t, true, parsed.XPelNsHdr.RequireToken)
	assert.NotNil(t, parsed.XPelNsHdr.CollectionsUrl)
	assert.Equal(t, "https://my-collections.com", parsed.XPelNsHdr.CollectionsUrl.String())

	assert.Equal(t, "https://get-your-tokens.org", parsed.XPelAuthHdr.Issuers[0].String())
	assert.Equal(t, "https://get-your-tokens2.org", parsed.XPelAuthHdr.Issuers[1].String())

	assert.Equal(t, "https://get-your-tokens.org", parsed.XPelTokGenHdr.Issuers[0].String())
	assert.Equal(t, "/foo/bar", parsed.XPelTokGenHdr.BasePaths[0])
	assert.Equal(t, uint(2), parsed.XPelTokGenHdr.MaxScopeDepth)
	assert.Equal(t, server_structs.OAuthStrategy, parsed.XPelTokGenHdr.Strategy)

	// Test the old version of parsing the issuer from the director to ensure backwards compatibility with a V1 client and a V2 director
	var xPelicanAuthorization map[string]string
	var issuer string
	if len(directorResponse.Header.Values("X-Pelican-Authorization")) > 0 {
		xPelicanAuthorization = utils.HeaderParser(directorResponse.Header.Values("X-Pelican-Authorization")[0])
		issuer = xPelicanAuthorization["issuer"]
	}

	assert.Equal(t, "https://get-your-tokens2.org", issuer)
}

// Tests for client logic when the Director is being queried. In particular,
// we check that various types of retries are triggered.
func TestQueryDirector(t *testing.T) {
	type testCase struct {
		name             string
		handler          http.HandlerFunc
		expectedLocation string
		expectedStatus   int
		expectedRetries  int
		expectedLog      string
		expectedError    bool
	}

	testCases := []testCase{
		{
			name: "Basic test case with expected values",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://redirect.com")
				w.WriteHeader(http.StatusTemporaryRedirect)
			},
			expectedLocation: "http://redirect.com",
			expectedStatus:   http.StatusTemporaryRedirect,
			expectedRetries:  0,
			expectedLog:      "",
			expectedError:    false,
		},
		{
			name: "Error with no Server header should retry",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Retry-Count") == "2" {
					w.Header().Set("Location", "http://redirect.com")
					w.WriteHeader(http.StatusTemporaryRedirect)
				} else {
					w.WriteHeader(http.StatusInternalServerError)
				}
			},
			expectedLocation: "http://redirect.com",
			expectedStatus:   http.StatusTemporaryRedirect,
			expectedRetries:  2,
			expectedLog:      "Response not from a Pelican process, the Director may be rebooting",
			expectedError:    false,
		},
		{
			name: "429 with correct Server header should retry",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Retry-Count") == "2" {
					w.Header().Set("Location", "http://redirect.com")
					w.WriteHeader(http.StatusTemporaryRedirect)
				} else {
					w.Header().Set("Server", "pelican/7.8.0")
					w.WriteHeader(http.StatusTooManyRequests)
				}
			},
			expectedLocation: "http://redirect.com",
			expectedStatus:   http.StatusTemporaryRedirect,
			expectedRetries:  2,
			expectedLog:      "The Director indicates it has just rebooted and is still discovering federation services.",
			expectedError:    false,
		},
		{
			name: "No retries for 404 from server that populates Server: pelican/ header",

			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "pelican/7.8.0")
				w.WriteHeader(http.StatusNotFound)
			},
			expectedLocation: "",
			expectedStatus:   http.StatusNotFound,
			expectedRetries:  0,
			expectedLog:      "",
			expectedError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var logBuffer bytes.Buffer
			log.SetOutput(&logBuffer)
			defer log.SetOutput(os.Stdout) // Restore stdout after the test

			retryCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("Retry-Count", fmt.Sprintf("%d", retryCount))
				tc.handler(w, r)
				retryCount++
			}))
			defer server.Close()

			pUrl := pelican_url.PelicanURL{
				FedInfo: pelican_url.FederationDiscovery{
					DirectorEndpoint: server.URL,
				},
				Path: "/foo/bar",
			}

			actualResp, err := queryDirector(context.Background(), "GET", &pUrl, "")
			if tc.expectedError {
				assert.Error(t, err)
				return
			} else {
				assert.NoError(t, err)
			}

			actualLocation := actualResp.Header.Get("Location")
			assert.Equal(t, tc.expectedLocation, actualLocation, "Expected Location header %q, but got %q", tc.expectedLocation, actualLocation)
			assert.Equal(t, tc.expectedStatus, actualResp.StatusCode, "Expected HTTP status code %d, but got %d", tc.expectedStatus, actualResp.StatusCode)
			assert.Equal(t, tc.expectedRetries, retryCount-1, "Expected %d retries, but got %d", tc.expectedRetries, retryCount-1)

			if tc.expectedLog != "" {
				logOutput := logBuffer.String()
				assert.Contains(t, logOutput, tc.expectedLog)
			}
		})
	}
}

func TestGetDirectorInfoForPath(t *testing.T) {
	// Craft the Director's response
	directorHeaders := make(map[string]string)
	directorHeaders["Link"] = "<my-cache.edu:8443>; rel=\"duplicate\"; pri=1, <another-cache.edu:8443>; rel=\"duplicate\"; pri=2"
	directorHeaders["X-Pelican-Namespace"] = "namespace=/foo/bar, require-token=True, collections-url=https://my-collections.com"
	directorHeaders["X-Pelican-Authorization"] = "issuer=https://get-your-tokens.org, issuer=https://get-your-tokens2.org"
	directorHeaders["X-Pelican-Token-Generation"] = "issuer=https://get-your-tokens.org, base-path=/foo/bar, max-scope-depth=2, strategy=OAuth2"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			queryParams := r.URL.Query()
			if _, ok := queryParams["directread"]; ok {
				// Prove the query made it through the various function calls. This is NOT
				// how the director would actually respond (but it's easier to mock in a test)
				// and it effectively shows preservation of the query.
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "direct read"}`))
				return
			}
			for key, value := range directorHeaders {
				w.Header().Add(key, value)
			}
			w.WriteHeader(http.StatusTemporaryRedirect)
		} else if r.Method == "PUT" {
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	tests := []struct {
		name          string
		resourcePath  string
		directorUrl   string
		httpMethod    string
		query         string
		expectedError string
	}{
		{
			name:          "No director URL",
			resourcePath:  "/test",
			directorUrl:   "",
			httpMethod:    http.MethodGet,
			query:         "",
			expectedError: "unable to retrieve information from a Director for object /test because none was found in pelican URL metadata.",
		},
		{
			name:          "Successful GET request",
			resourcePath:  "/test",
			directorUrl:   ts.URL,
			httpMethod:    http.MethodGet,
			query:         "",
			expectedError: "",
		},
		{
			name:          "PUT request changes verb", // also generates 405, although this is a feature of the director
			resourcePath:  "/test",
			directorUrl:   ts.URL,
			httpMethod:    http.MethodPut,
			query:         "",
			expectedError: "the director returned status code 405",
		},
		{
			name:          "Queries are propagated", // also generates 405, although this is a feature of the director
			resourcePath:  "/test",
			directorUrl:   ts.URL,
			httpMethod:    http.MethodGet,
			query:         "directread",
			expectedError: "200: {\"status\": \"direct read\"}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			urlStr := fmt.Sprintf("pelican://foo%s", tt.resourcePath)
			if tt.query != "" {
				urlStr += "?" + tt.query
			}

			pUrl, err := pelican_url.Parse(urlStr, nil, nil)
			assert.NoError(t, err)

			pUrl.FedInfo.DirectorEndpoint = tt.directorUrl

			_, err = GetDirectorInfoForPath(ctx, pUrl, tt.httpMethod, "")
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
