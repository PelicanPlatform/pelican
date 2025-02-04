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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/test_utils"
)

func TestWaitUntilWorking(t *testing.T) {
	hook := test.NewGlobal()
	logrus.SetLevel(logrus.DebugLevel) // Ensure all log levels are captured
	ctx, cancel, _ := test_utils.TestContext(context.Background(), t)
	t.Cleanup(func() {
		cancel()
	})

	t.Run("success-with-HTTP-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // 200
		}))
		defer server.Close()

		err := WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.NoError(t, err)

		assert.Equal(t, logrus.DebugLevel, hook.LastEntry().Level)
		assert.Equal(t, "testServer server appears to be functioning at "+server.URL, hook.LastEntry().Message, "Expected log message not found")
		hook.Reset()
	})

	t.Run("server-returns-unexpected-status-code-no-body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError) // 500
		}))
		defer server.Close()

		err := WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		expectedErrorMsg := fmt.Sprintf("Received bad status code in reply to server ping at %s: %d. Expected %d. Response body is empty.", server.URL, 500, 200)
		assert.Contains(t, err.Error(), expectedErrorMsg)
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
		expectedErrorMsg := fmt.Sprintf("Received bad status code in reply to server ping at %s: %d. Expected %d. Response body: %s", server.URL, 404, 200, "404 page not found")
		assert.Equal(t, expectedErrorMsg, err.Error())
	})

	t.Run("server-returns-unexpected-status-code-json-body", func(t *testing.T) {
		jsonRes := map[string]string{"error": "bad request"}
		jsonBytes, err := json.Marshal(jsonRes)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest) // 400
			_, err := w.Write([]byte(jsonBytes))
			require.NoError(t, err)
		}))
		defer server.Close()

		err = WaitUntilWorking(ctx, "GET", server.URL, "testServer", http.StatusOK, false)
		require.Error(t, err)
		expectedErrorMsg := fmt.Sprintf("Received bad status code in reply to server ping at %s: %d. Expected %d. Response body: %s", server.URL, 400, 200, string(jsonBytes))
		assert.Equal(t, expectedErrorMsg, err.Error())
	})

	t.Run("server-does-not-exist", func(t *testing.T) {
		// cancel wait until working after 200ms so that we don't wait for 10s before it returns
		earlyCancelCtx, earlyCancel := context.WithCancel(ctx)
		go func() {
			<-time.After(200 * time.Millisecond)
			earlyCancel()
		}()
		err := WaitUntilWorking(earlyCancelCtx, "GET", "https://noserverexists.com", "testServer", http.StatusOK, false)
		require.Error(t, err)
		expectedErrorMsg := fmt.Sprintf("Failed to send request to testServer at %s; likely server is not up (will retry in 50ms):", "https://noserverexists.com")
		assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, expectedErrorMsg)
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
		expectedErrorMsg := fmt.Sprintf("Failed to send request to testServer at %s; likely server is not up (will retry in 50ms):", server.URL)
		assert.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
		assert.Contains(t, hook.LastEntry().Message, expectedErrorMsg)
	})

	t.Run("server-short-timeout", func(t *testing.T) {
		viper.Set("Server.StartupTimeout", "1s")
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
		expectedErrorMsg := fmt.Sprintf("The testServer server at %s either did not startup or did not respond quickly enough after 1s of waiting", server.URL)
		assert.Equal(t, expectedErrorMsg, err.Error())
	})
}

func TestFilterTopLevelPrefixes(t *testing.T) {
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
func (m *mockServer) CreateAdvertisement(name, serverUrl, serverWebUrl string) (*server_structs.OriginAdvertiseV2, error) {
	return nil, nil
}
func (m *mockServer) GetNamespaceAdsFromDirector() error { return nil }
func (m *mockServer) GetAdTokCfg(ctx context.Context) (server_structs.AdTokCfg, error) {
	return server_structs.AdTokCfg{}, nil
}
func (m *mockServer) GetFedTokLocation() string { return m.tokenLoc }
func (m *mockServer) GetPids() []int            { return m.pids }
func (m *mockServer) SetPids(pids []int)        { m.pids = pids }

func TestSetFedTok(t *testing.T) {
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
				require.NoError(t, os.MkdirAll(filepath.Dir(tc.server.tokenLoc), 0755))
			}

			err := SetFedTok(context.Background(), tc.server, tc.token)

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
