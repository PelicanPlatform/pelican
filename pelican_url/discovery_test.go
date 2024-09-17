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
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestSetOSDFDiscoveryHost(t *testing.T) {
	tests := []struct {
		host     string
		expected string
	}{
		{"director.org", "director.org"},
		{"director.org:1234", "director.org:1234"},
		{"https://director.org", "director.org"},
		{"https://director.org:1234", "director.org:1234"},
	}

	// Note we can't run these in parallel by wrapping in test.Run because they'll stomp on each other due to the global variable
	for _, test := range tests {
		_, err := SetOsdfDiscoveryHost(test.host)
		require.NoError(t, err)
		assert.Equal(t, test.expected, OsdfDiscoveryHost)
	}
}

func TestDiscoverFederation(t *testing.T) {
	discServer := getTestDiscoveryServer(t)
	defer discServer.Close()
	discUrl, err := url.Parse(discServer.URL)
	require.NoError(t, err)

	t.Run("TestVanilla", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		fedInfo, err := DiscoverFederation(ctx, client, "test-ua", discUrl)
		require.NoError(t, err)

		assert.Equal(t, "https://director.com", fedInfo.DirectorEndpoint, "Unexpected DirectorEndpoint")
		assert.Equal(t, "https://registration.com", fedInfo.RegistryEndpoint, "Unexpected RegistryEndpoint")
		assert.Equal(t, "https://tokens.com", fedInfo.JwksUri, "Unexpected JwksUri")
		assert.Equal(t, "https://broker.com", fedInfo.BrokerEndpoint, "Unexpected BrokerEndpoint")
	})

	t.Run("TestMetadataDiscoveryTimeout", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// Create a server that sleeps for a longer duration than the timeout
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
		}))
		defer server.Close()
		timeoutUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		// Set a short timeout for the test
		timeout := 1 * time.Second

		// Create a context with the timeout
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		// Call the function with the server URL and the context
		_, err = DiscoverFederation(ctx, client, "", timeoutUrl)

		// Assert that the error is the expected metadata timeout error
		assert.Error(t, err)
		assert.True(t, errors.Is(err, MetadataTimeoutErr))
	})

	t.Run("TestMetadataDiscoveryTimeoutRetry", func(t *testing.T) {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			// Set response header timeout to make sure we timeout as expected in the test
			ResponseHeaderTimeout: 300 * time.Millisecond,
		}
		client := &http.Client{Transport: tr}

		// Initialize the logger and add a test hook
		hook := test.NewGlobal()
		logrus.SetLevel(logrus.WarnLevel)

		// Create a server that sleeps for a longer duration than the timeout
		ctr := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ctr < 1 {
				time.Sleep(2 * time.Second)
			}

			ctr += 1
			w.WriteHeader(200)
			_, err := w.Write([]byte(`{
				"director_endpoint": "https://director.com",
				"namespace_registration_endpoint": "https://registration.com",
				"broker_endpoint": "https://broker.com",
				"jwks_uri": "https://tokens.com"
			}`))
			assert.NoError(t, err)
		}))
		defer server.Close()
		timeoutUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		// Set a short timeout for the test
		timeout := 5 * time.Second

		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		_, err = DiscoverFederation(ctx, client, "", timeoutUrl)

		// Check if hook.LastEntry() is not nil before accessing its Message field
		lastEntry := hook.LastEntry()
		require.NotNil(t, lastEntry, "Expected a log entry but got nil")
		assert.Equal(t, "Timeout occurred when querying discovery URL "+server.URL+"/.well-known/pelican-configuration for metadata; 2 retries remaining", lastEntry.Message)

		// Assert that the error is the expected metadata timeout error
		assert.NoError(t, err)
	})

	t.Run("TestCanceledContext", func(t *testing.T) {
		// Create a server that waits for the context to be canceled
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		discUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// Create a context and cancel it immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		// Call the function with the server URL and the canceled context
		_, err = DiscoverFederation(ctx, client, "", discUrl)

		// Assert that the error is the expected context cancel error
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})
}

// Custom round tripper to simulate a network error in startMetadataQuery test
type CustomRoundTripper struct{}

func (c *CustomRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: errors.New("simulated network error"),
	}
}

func TestStartMetadataQuery(t *testing.T) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	t.Run("SuccessfulRequest", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("Success"))
			require.NoError(t, err)
		}))
		defer server.Close()
		discUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		ctx := context.Background()
		resp, err := startMetadataQuery(ctx, client, "test-ua", discUrl)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("ContextCanceled", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		discUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		// Create a context and cancel it immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err = startMetadataQuery(ctx, client, "test-ua", discUrl)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, context.Canceled))
	})

	t.Run("TimeoutError", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
		}))
		defer server.Close()
		discUrl, err := url.Parse(server.URL)
		require.NoError(t, err)

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   1 * time.Second,
		}

		ctx := context.Background()
		_, err = startMetadataQuery(ctx, client, "test-ua", discUrl)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, MetadataTimeoutErr))
	})

	t.Run("NetworkError", func(t *testing.T) {
		// Use the custom RoundTripper to simulate a network error
		client := &http.Client{
			Transport: &CustomRoundTripper{},
		}

		discUrl, err := url.Parse("https://example.com")
		require.NoError(t, err)

		ctx := context.Background()
		_, err = startMetadataQuery(ctx, client, "test-ua", discUrl)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, NewMetadataError(err, "Error occurred when querying for metadata")))
	})
}
