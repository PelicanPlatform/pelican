//go:build !windows

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

package server_utils

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestWaitUntilWorking(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	hook := test.NewGlobal()
	origLevel := config.GetEffectiveLogLevel()
	config.SetLogging(logrus.DebugLevel) // Ensure all log levels are captured
	t.Cleanup(func() {
		config.SetLogging(origLevel)
	})
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
		ResetTestState()
	})

	require.NoError(t, param.Server_StartupTimeout.SetString("10s"))
	t.Run("success-with-HTTP-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // 200
		}))
		defer server.Close()

		err := WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.NoError(t, err)

		require.NotNil(t, hook.LastEntry())
		assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "server appears to be functioning")
		hook.Reset()
	})

	t.Run("server-returns-unexpected-status-code-no-body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError) // 500
		}))
		defer server.Close()

		err := WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)

		// Check for various things we expect to show up in the error message
		assert.Contains(t, err.Error(), "received bad status code")
		assert.Contains(t, err.Error(), "500")
		assert.Contains(t, err.Error(), "expected 200")
	})

	t.Run("server-returns-unexpected-status-code-str-body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound) // 404
			_, err := w.Write([]byte("404 page not found"))
			require.NoError(t, err)
		}))
		defer server.Close()

		err := WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "received bad status code")
		assert.Contains(t, err.Error(), "404 page not found")
		assert.Contains(t, err.Error(), "expected 200")
	})

	t.Run("server-returns-unexpected-status-code-json-body", func(t *testing.T) {
		jsonRes := map[string]string{"error": "bad request"}
		jsonBytes, err := json.Marshal(jsonRes)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest) // 400
			_, err := w.Write(jsonBytes)
			require.NoError(t, err)
		}))
		defer server.Close()

		err = WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "received bad status code")
		assert.Contains(t, err.Error(), "400")
		assert.Contains(t, err.Error(), string(jsonBytes))
	})

	t.Run("server-does-not-exist", func(t *testing.T) {
		// cancel wait until working after 1000ms so that we don't wait for 10s before it returns
		// Note: this was bumped up due to sporadic test failures on CI with 200ms; 1s should
		// be sufficient for a DNS resolution failure to return.
		earlyCancelCtx, earlyCancel := context.WithCancel(ctx)
		go func() {
			<-time.After(1000 * time.Millisecond)
			earlyCancel()
		}()
		err := WaitUntilWorking(earlyCancelCtx, "GET", "https://noserverexists.com", "testServer", http.StatusOK, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no such host")
		hook.Reset()
	})

	t.Run("server-timeout", func(t *testing.T) {
		// cancel wait until working after 1500ms so that we don't wait for 10s before it returns
		earlyCancelCtx, earlyCancel := context.WithCancel(ctx)
		go func() {
			<-time.After(1500 * time.Millisecond)
			earlyCancel()
		}()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// WaitUntilWorking as a 1s timeout, so we make sure to wait longer than that
			<-time.After(1100 * time.Millisecond)
			w.WriteHeader(http.StatusOK) // 200
		}))
		defer server.Close()

		err := WaitUntilWorking(earlyCancelCtx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeded while awaiting headers")
		require.NotNil(t, hook.LastEntry())
		assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, "Failed to send request")
	})

	t.Run("server-short-timeout", func(t *testing.T) {
		require.NoError(t, param.Server_StartupTimeout.SetString("1s"))
		earlyCancelCtx, earlyCancel := context.WithCancel(ctx)
		go func() {
			<-time.After(1500 * time.Millisecond)
			earlyCancel()
		}()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// WaitUntilWorking as a 1s timeout, so we make sure to wait longer than that
			<-time.After(2000 * time.Millisecond)
			w.WriteHeader(http.StatusOK) // 200
		}))
		defer server.Close()

		err := WaitUntilWorking(earlyCancelCtx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "didn't respond with the expected status code 200 within the timeout of 1s")
	})
}

func TestFilterTopLevelPrefixes(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	namespaceAds := []server_structs.NamespaceAdV2{
		{Path: "/foo"},
		{Path: "/foo/bar"},
		{Path: "/foo/bar/baz"},
		{Path: "/foogoo"},
		// Putting /goo/bar ahead of /goo/ to test that the function removes this
		// in favor of /goo/
		{Path: "/goo/bar"},
		{Path: "/goo/"},
		{Path: "/some/other/path"},
	}

	filtered := FilterTopLevelPrefixes(namespaceAds)

	var filteredPaths []string
	for _, nsAd := range filtered {
		filteredPaths = append(filteredPaths, nsAd.Path)
	}

	expectedPaths := []string{
		"/foo/",
		"/foogoo/",
		"/goo/",
		"/some/other/path/",
	}

	assert.ElementsMatch(t, expectedPaths, filteredPaths)
}

// Mocked server to fulfill the XRootDServer interface in testing
type mockServer struct {
	tokenLoc     string
	uid          int
	gid          int
	pids         []int
	serverType   server_structs.ServerType
	namespaceAds []server_structs.NamespaceAdV2
}

func (m *mockServer) GetServerType() server_structs.ServerType           { return m.serverType }
func (m *mockServer) SetNamespaceAds(ads []server_structs.NamespaceAdV2) { m.namespaceAds = ads }
func (m *mockServer) GetNamespaceAds() []server_structs.NamespaceAdV2    { return m.namespaceAds }
func (m *mockServer) CreateAdvertisement(name, id, serverUrl, serverWebUrl string, downtimes []server_structs.Downtime) (*server_structs.OriginAdvertiseV2, error) {
	return nil, nil
}
func (m *mockServer) GetNamespaceAdsFromDirector() error { return nil }
func (m *mockServer) GetAdTokCfg(directorUrl string) (server_structs.AdTokCfg, error) {
	return server_structs.AdTokCfg{}, nil
}
func (m *mockServer) GetFedTokLocation() string { return m.tokenLoc }
func (m *mockServer) GetPids() []int            { return m.pids }
func (m *mockServer) SetPids(pids []int)        { m.pids = pids }

func TestSetBrokerURL(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	setFederationParams := func(brokerURL string) {
		require.NoError(t, param.Federation_DiscoveryUrl.Set("https://discovery.example.com"))
		require.NoError(t, param.SetRaw("Federation.DirectorUrl", "https://director.example.com"))
		require.NoError(t, param.SetRaw("Federation.RegistryUrl", "https://registry.example.com"))
		require.NoError(t, param.SetRaw("Federation.JwkUrl", "https://jwks.example.com"))
		require.NoError(t, param.SetRaw("Federation.BrokerUrl", brokerURL))
	}

	t.Run("multiple-prefixes-broker-url-not-set", func(t *testing.T) {
		ResetTestState()
		t.Cleanup(ResetTestState)
		require.NoError(t, param.Server_Hostname.Set("origin.example.com"))
		require.NoError(t, param.Origin_EnableBroker.Set(true))
		setFederationParams("https://broker.example.com")

		ad := &server_structs.OriginAdvertiseV2{}
		err := SetBrokerURL(ad, server_structs.OriginType, []string{"/prefix1", "/prefix2"})
		require.NoError(t, err)
		assert.Empty(t, ad.BrokerURL, "Broker URL should not be set when multiple prefixes are present")
	})

	t.Run("broker-disabled-broker-url-not-set", func(t *testing.T) {
		ResetTestState()
		t.Cleanup(ResetTestState)
		require.NoError(t, param.Server_Hostname.Set("cache.example.com"))
		require.NoError(t, param.Cache_EnableBroker.Set(false))
		setFederationParams("https://broker.example.com")

		ad := &server_structs.OriginAdvertiseV2{}
		err := SetBrokerURL(ad, server_structs.CacheType, []string{"/single"})
		require.NoError(t, err)
		assert.Empty(t, ad.BrokerURL, "Broker URL should not be set when broker is disabled")
	})

	t.Run("invalid-broker-endpoint-returns-error", func(t *testing.T) {
		ResetTestState()
		t.Cleanup(ResetTestState)
		require.NoError(t, param.Server_Hostname.Set("origin.example.com"))
		require.NoError(t, param.Origin_EnableBroker.Set(true))
		// Use a URL with invalid percent-encoding so url.Parse returns an error
		setFederationParams("https://broker.example.com/%2")

		ad := &server_structs.OriginAdvertiseV2{}
		err := SetBrokerURL(ad, server_structs.OriginType, []string{"/prefix"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid Broker URL")
		assert.Empty(t, ad.BrokerURL)
	})

	t.Run("valid-single-prefix-origin-sets-broker-url", func(t *testing.T) {
		ResetTestState()
		t.Cleanup(ResetTestState)
		require.NoError(t, param.Server_Hostname.Set("origin.example.com"))
		require.NoError(t, param.Origin_EnableBroker.Set(true))
		setFederationParams("https://broker.example.com")

		ad := &server_structs.OriginAdvertiseV2{}
		err := SetBrokerURL(ad, server_structs.OriginType, []string{"/test/prefix"})
		require.NoError(t, err)
		require.NotEmpty(t, ad.BrokerURL)
		assert.Contains(t, ad.BrokerURL, "https://broker.example.com")
		assert.Contains(t, ad.BrokerURL, "/api/v1.0/broker/reverse")
		assert.Contains(t, ad.BrokerURL, "origin=origin.example.com")
		assert.Contains(t, ad.BrokerURL, "prefix=%2Ftest%2Fprefix")
	})
}

func TestSetFedTok(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))
	testCases := []struct {
		name      string
		server    *mockServer
		token     string
		setupDir  bool // Whether to create directory structure
		expectErr bool
		errMsg    string
	}{
		{
			name: "Valid token write",
			server: &mockServer{
				tokenLoc: filepath.Join(t.TempDir(), "tokens", "fed.token"),
				uid:      os.Getuid(),
				gid:      os.Getgid(),
			},
			token:     "test-token",
			setupDir:  true,
			expectErr: false,
			errMsg:    "",
		},
		{
			name: "Empty token location",
			server: &mockServer{
				tokenLoc: "",
			},
			token:     "test-token",
			setupDir:  false,
			expectErr: true,
			errMsg:    "token location is empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setupDir {
				err := SetupFedTokDirs(tc.server)
				require.NoError(t, err)
			}

			err := SetFedTok(context.Background(), tc.server, tc.token, nil)

			if tc.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
				return
			}
			require.NoError(t, err)

			content, err := os.ReadFile(tc.server.tokenLoc)
			require.NoError(t, err)
			assert.Equal(t, tc.token, string(content))

			info, err := os.Stat(tc.server.tokenLoc)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		})
	}
}
