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
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		jsonRes := map[string]string{"error": "bad reqeust"}
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
}
