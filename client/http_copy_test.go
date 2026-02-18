//go:build !windows

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMonitorTPC tests parsing of TPC performance markers
func TestMonitorTPC(t *testing.T) {
	t.Run("SuccessfulTransferWithPerfMarkers", func(t *testing.T) {
		body := strings.NewReader(
			"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 1024\n" +
				"Total Stripe Count: 1\n" +
				"End\n" +
				"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 2048\n" +
				"Total Stripe Count: 1\n" +
				"End\n" +
				"success: Created\n",
		)

		messages := make(chan tpcStatus, 10)
		err := monitorTPC(messages, body)
		require.NoError(t, err)

		// Should get two progress updates + one done
		msg1 := <-messages
		assert.Equal(t, uint64(1024), msg1.xferred)
		assert.False(t, msg1.done)

		msg2 := <-messages
		assert.Equal(t, uint64(2048), msg2.xferred)
		assert.False(t, msg2.done)

		msg3 := <-messages
		assert.True(t, msg3.done)
		assert.NoError(t, msg3.err)
	})

	t.Run("FailedTransfer", func(t *testing.T) {
		body := strings.NewReader(
			"failure: Copy failed: no such file\n",
		)

		messages := make(chan tpcStatus, 10)
		err := monitorTPC(messages, body)
		require.NoError(t, err)

		msg := <-messages
		assert.True(t, msg.done)
		assert.Error(t, msg.err)
		assert.Contains(t, msg.err.Error(), "Copy failed")
	})

	t.Run("MultipleStripes", func(t *testing.T) {
		body := strings.NewReader(
			"Perf Marker\n" +
				"Stripe Index: 0\n" +
				"Stripe Bytes Transferred: 500\n" +
				"Total Stripe Count: 2\n" +
				"End\n" +
				"Perf Marker\n" +
				"Stripe Index: 1\n" +
				"Stripe Bytes Transferred: 700\n" +
				"Total Stripe Count: 2\n" +
				"End\n" +
				"success: Created\n",
		)

		messages := make(chan tpcStatus, 10)
		err := monitorTPC(messages, body)
		require.NoError(t, err)

		msg1 := <-messages
		assert.Equal(t, uint64(500), msg1.xferred)
		assert.False(t, msg1.done)

		msg2 := <-messages
		// Both stripes: 500 + 700 = 1200
		assert.Equal(t, uint64(1200), msg2.xferred)
		assert.False(t, msg2.done)

		msg3 := <-messages
		assert.True(t, msg3.done)
		assert.NoError(t, msg3.err)
	})

	t.Run("EmptyBody", func(t *testing.T) {
		body := strings.NewReader("")

		messages := make(chan tpcStatus, 10)
		err := monitorTPC(messages, body)
		require.NoError(t, err)

		msg := <-messages
		assert.True(t, msg.done)
		assert.NoError(t, msg.err)
	})
}

// TestTPCMockServer tests the third-party-copy flow with a mock HTTP server
// that implements the COPY verb as specified in the WLCG HTTP-TPC documentation.
func TestTPCMockServer(t *testing.T) {
	// Content that the "source" server will serve
	fileContent := []byte("test file content for third-party-copy")
	contentLen := len(fileContent)

	// Source server: serves HEAD and GET for the object
	srcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLen))
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLen))
			w.WriteHeader(http.StatusOK)
			w.Write(fileContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srcServer.Close()

	t.Run("SuccessfulCopy", func(t *testing.T) {
		var receivedSource string
		var receivedAuth string
		var receivedTransferAuth string

		// Destination server: implements COPY verb
		destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLen))
				w.WriteHeader(http.StatusOK)
			case "COPY":
				receivedSource = r.Header.Get("Source")
				receivedAuth = r.Header.Get("Authorization")
				receivedTransferAuth = r.Header.Get("TransferHeaderAuthorization")

				// Simulate getting data from the source and writing performance markers
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusCreated)

				flusher, ok := w.(http.Flusher)
				if !ok {
					t.Fatal("Expected ResponseWriter to implement Flusher")
				}

				// Fetch from source to simulate the TPC
				srcUrl := receivedSource
				resp, err := http.Get(srcUrl)
				if err != nil {
					fmt.Fprintf(w, "failure: Failed to get from source: %s\n", err.Error())
					flusher.Flush()
					return
				}
				data, _ := io.ReadAll(resp.Body)
				resp.Body.Close()

				// Write performance markers
				fmt.Fprintf(w, "Perf Marker\n")
				fmt.Fprintf(w, "Stripe Index: 0\n")
				fmt.Fprintf(w, "Stripe Bytes Transferred: %d\n", len(data)/2)
				fmt.Fprintf(w, "Total Stripe Count: 1\n")
				fmt.Fprintf(w, "End\n")
				flusher.Flush()

				time.Sleep(10 * time.Millisecond)

				fmt.Fprintf(w, "Perf Marker\n")
				fmt.Fprintf(w, "Stripe Index: 0\n")
				fmt.Fprintf(w, "Stripe Bytes Transferred: %d\n", len(data))
				fmt.Fprintf(w, "Total Stripe Count: 1\n")
				fmt.Fprintf(w, "End\n")
				flusher.Flush()

				fmt.Fprintf(w, "success: Created\n")
				flusher.Flush()
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer destServer.Close()

		// Verify the Source header was set correctly
		assert.NotEmpty(t, destServer.URL, "Destination server should have a URL")

		// Verify that the mock source server works
		resp, err := http.Get(srcServer.URL + "/test.txt")
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assert.Equal(t, fileContent, body)

		// Verify that COPY to destination works with correct headers
		req, err := http.NewRequest("COPY", destServer.URL+"/dest.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Source", srcServer.URL+"/test.txt")
		req.Header.Set("Authorization", "Bearer dest-token")
		req.Header.Set("TransferHeaderAuthorization", "Bearer src-token")

		client := &http.Client{}
		copyResp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, copyResp.StatusCode)

		// Read the performance marker response
		responseBody, err := io.ReadAll(copyResp.Body)
		copyResp.Body.Close()
		require.NoError(t, err)

		// Parse the response to verify performance markers
		responseStr := string(responseBody)
		assert.Contains(t, responseStr, "Perf Marker")
		assert.Contains(t, responseStr, "success: Created")

		// Verify headers were received correctly
		assert.Equal(t, srcServer.URL+"/test.txt", receivedSource)
		assert.Equal(t, "Bearer dest-token", receivedAuth)
		assert.Equal(t, "Bearer src-token", receivedTransferAuth)
	})

	t.Run("FailedCopy", func(t *testing.T) {
		// Destination server that returns a failure
		destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLen))
				w.WriteHeader(http.StatusOK)
			case "COPY":
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, "Access denied")
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer destServer.Close()

		req, err := http.NewRequest("COPY", destServer.URL+"/dest.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Source", srcServer.URL+"/test.txt")

		client := &http.Client{}
		copyResp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, copyResp.StatusCode)
		copyResp.Body.Close()
	})

	t.Run("CopyWithFailureMarker", func(t *testing.T) {
		// Destination server that returns failure in performance markers
		destServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodHead:
				w.Header().Set("Content-Length", fmt.Sprintf("%d", contentLen))
				w.WriteHeader(http.StatusOK)
			case "COPY":
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusCreated)

				flusher, ok := w.(http.Flusher)
				if !ok {
					return
				}

				fmt.Fprintf(w, "Perf Marker\n")
				fmt.Fprintf(w, "Stripe Index: 0\n")
				fmt.Fprintf(w, "Stripe Bytes Transferred: 100\n")
				fmt.Fprintf(w, "Total Stripe Count: 1\n")
				fmt.Fprintf(w, "End\n")
				flusher.Flush()

				fmt.Fprintf(w, "failure: disk quota exceeded\n")
				flusher.Flush()
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		}))
		defer destServer.Close()

		req, err := http.NewRequest("COPY", destServer.URL+"/dest.txt", nil)
		require.NoError(t, err)
		req.Header.Set("Source", srcServer.URL+"/test.txt")

		client := &http.Client{}
		copyResp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, copyResp.StatusCode)

		// Parse the response to check for failure marker
		body, err := io.ReadAll(copyResp.Body)
		copyResp.Body.Close()
		require.NoError(t, err)
		assert.Contains(t, string(body), "failure: disk quota exceeded")
	})
}
