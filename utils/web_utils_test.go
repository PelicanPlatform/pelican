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

package utils

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestClientIPAddr(t *testing.T) {
	r := gin.Default()

	r.GET("/test", func(c *gin.Context) {
		ip := ClientIPAddr(c)
		c.String(http.StatusOK, ip.String())
	})

	t.Run("correct-ip-addr", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			require.NoError(t, err)
		}

		req.RemoteAddr = "192.168.1.1:12345"

		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Check the response status code
		assert.Equal(t, http.StatusOK, w.Code)
		expectedIP, _ := netip.ParseAddr("192.168.1.1")
		assert.Equal(t, expectedIP.String(), w.Body.String())
	})

	t.Run("correct-ip-forward-header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			require.NoError(t, err)
		}

		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "192.168.1.1")

		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Check the response status code
		assert.Equal(t, http.StatusOK, w.Code)
		expectedIP, _ := netip.ParseAddr("192.168.1.1")
		assert.Equal(t, expectedIP.String(), w.Body.String())
	})

	t.Run("correct-ip-real-ip-header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "/test", nil)
		if err != nil {
			require.NoError(t, err)
		}

		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Real-IP", "192.168.1.1")

		w := httptest.NewRecorder()

		r.ServeHTTP(w, req)

		// Check the response status code
		assert.Equal(t, http.StatusOK, w.Code)
		expectedIP, _ := netip.ParseAddr("192.168.1.1")
		assert.Equal(t, expectedIP.String(), w.Body.String())
	})
}

// staleConnServer answers the first request on its first connection with
// keep-alive, then reads the next request on that connection and hangs up
// without a reply -- what a client sees when it reuses a pooled connection
// the server has just closed.  Requests on later connections are answered
// normally.  It records the bodies of the requests it answers.
func staleConnServer(t *testing.T) (addr string, bodies func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var answered []string
	reply := func(conn net.Conn, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		answered = append(answered, string(body))
		mu.Unlock()
		_, _ = io.WriteString(conn, "HTTP/1.1 207 Multi-Status\r\nContent-Length: 0\r\n\r\n")
	}
	go func() {
		for first := true; ; first = false {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn, first bool) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				reply(conn, req)
				if first {
					// Read the next request, then hang up without answering.
					if req, err := http.ReadRequest(br); err == nil {
						_, _ = io.ReadAll(req.Body)
					}
				}
			}(conn, first)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), answered...)
	}
}

func TestRetrySafeMethods(t *testing.T) {
	propfind := func(client *http.Client, addr, body string) (*http.Response, error) {
		req, err := http.NewRequest("PROPFIND", "http://"+addr+"/dir/", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Depth", "1")
		return client.Do(req)
	}

	t.Run("unmarked-propfind-fails-on-stale-connection", func(t *testing.T) {
		// The failure this guards against, reproduced with a plain transport.
		addr, _ := staleConnServer(t)
		client := &http.Client{Transport: &http.Transport{}}
		resp, err := propfind(client, addr, "<propfind/>")
		require.NoError(t, err)
		resp.Body.Close()
		_, err = propfind(client, addr, "<propfind/>")
		// Depending on whether the hang-up lands before or after the request
		// is written, net/http reports "server closed idle connection" (as
		// seen in CI) or a bare EOF; it retries both on a reused connection,
		// but only for replayable requests.
		require.Error(t, err)
		assert.Regexp(t, `server closed idle connection|EOF`, err.Error())
	})

	t.Run("marked-propfind-is-retried-with-its-body", func(t *testing.T) {
		addr, bodies := staleConnServer(t)
		client := &http.Client{Transport: RetrySafeMethods(&http.Transport{})}
		resp, err := propfind(client, addr, "<first/>")
		require.NoError(t, err)
		resp.Body.Close()
		resp, err = propfind(client, addr, "<second/>")
		require.NoError(t, err, "the request must be resent on a new connection")
		resp.Body.Close()
		assert.Equal(t, http.StatusMultiStatus, resp.StatusCode)
		assert.Equal(t, []string{"<first/>", "<second/>"}, bodies(), "the retry carries the original body")
	})

	t.Run("marking-sends-no-header-and-leaves-other-methods-alone", func(t *testing.T) {
		req, err := http.NewRequest("PROPFIND", "http://example.org/", nil)
		require.NoError(t, err)
		MarkRetryableIfSafe(req)
		_, marked := req.Header["Idempotency-Key"]
		assert.True(t, marked)
		var wire bytes.Buffer
		require.NoError(t, req.Write(&wire))
		assert.NotContains(t, wire.String(), "Idempotency-Key", "the marker is not sent on the wire")

		post, err := http.NewRequest(http.MethodPost, "http://example.org/", nil)
		require.NoError(t, err)
		MarkRetryableIfSafe(post)
		_, marked = post.Header["Idempotency-Key"]
		assert.False(t, marked, "only safe methods are marked")
	})
}
