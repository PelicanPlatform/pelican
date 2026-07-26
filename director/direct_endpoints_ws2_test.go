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

package director

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/server_structs"
)

func TestIsBrokerOnlyOrigin(t *testing.T) {
	brokerURL, err := url.Parse("https://broker.example/api/v1.0/broker/reverse?origin=o&prefix=/origins/o")
	require.NoError(t, err)

	t.Run("broker URL and no direct endpoints is broker-only", func(t *testing.T) {
		assert.True(t, isBrokerOnlyOrigin(server_structs.ServerAd{BrokerURL: *brokerURL}))
	})
	t.Run("broker URL but with direct endpoints is directly reachable (WS2)", func(t *testing.T) {
		assert.False(t, isBrokerOnlyOrigin(server_structs.ServerAd{
			BrokerURL:       *brokerURL,
			DirectEndpoints: []string{"192.0.2.10:8443"},
		}))
	})
	t.Run("no broker URL is not broker-only", func(t *testing.T) {
		assert.False(t, isBrokerOnlyOrigin(server_structs.ServerAd{}))
	})
}

func TestAutoCaptureDirectEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newCtx := func(remoteAddr string) *gin.Context {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest("POST", "/api/v1.0/director/registerOrigin", nil)
		req.RemoteAddr = remoteAddr
		c.Request = req
		return c
	}
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}

	t.Run("private data host + public peer captures the peer with the data port", func(t *testing.T) {
		ep := autoCaptureDirectEndpoint(newCtx("203.0.113.5:40000"), mustURL("https://10.0.0.5:8443"))
		assert.Equal(t, "203.0.113.5:8443", ep)
	})

	t.Run("loopback data host + public peer captures the peer", func(t *testing.T) {
		ep := autoCaptureDirectEndpoint(newCtx("203.0.113.5:40000"), mustURL("https://127.0.0.1:8443"))
		assert.Equal(t, "203.0.113.5:8443", ep)
	})

	t.Run("public data host is left untouched (no capture)", func(t *testing.T) {
		ep := autoCaptureDirectEndpoint(newCtx("203.0.113.5:40000"), mustURL("https://198.51.100.7:8443"))
		assert.Empty(t, ep)
	})

	t.Run("DNS hostname data host is left untouched (no capture)", func(t *testing.T) {
		ep := autoCaptureDirectEndpoint(newCtx("203.0.113.5:40000"), mustURL("https://origin.example.org:8443"))
		assert.Empty(t, ep)
	})

	t.Run("private peer is not captured (unroutable)", func(t *testing.T) {
		ep := autoCaptureDirectEndpoint(newCtx("10.1.2.3:40000"), mustURL("https://10.0.0.5:8443"))
		assert.Empty(t, ep)
	})
}

func TestGenerateXDirectEndpointsHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newCtx := func(userAgent string) (*gin.Context, *httptest.ResponseRecorder) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		req := httptest.NewRequest("GET", "/foo/bar", nil)
		if userAgent != "" {
			req.Header.Set("User-Agent", userAgent)
		}
		c.Request = req
		return c, w
	}

	adsWithEndpoints := []server_structs.ServerAd{{
		ServerID:        "18f1jk5",
		DirectEndpoints: []string{"192.0.2.10:8443", "[2001:db8::1]:8443"},
	}}

	headerName := string(server_structs.XPelicanDirectEndpointsHeaderName)

	t.Run("emitted to a Pelican client with leading sni slug then ordered endpoints", func(t *testing.T) {
		c, w := newCtx("pelican-client/7.16.0")
		generateXDirectEndpointsHeader(c, adsWithEndpoints)
		assert.Equal(t, "sni=18f1jk5, 192.0.2.10:8443, [2001:db8::1]:8443", w.Header().Get(headerName))
	})

	t.Run("not emitted to a non-Pelican client (curl)", func(t *testing.T) {
		c, w := newCtx("curl/8.0.1")
		generateXDirectEndpointsHeader(c, adsWithEndpoints)
		assert.Empty(t, w.Header().Get(headerName))
	})

	t.Run("not emitted to a pelican origin/cache service", func(t *testing.T) {
		c, w := newCtx("pelican-cache/7.16.0")
		generateXDirectEndpointsHeader(c, adsWithEndpoints)
		assert.Empty(t, w.Header().Get(headerName))
	})

	t.Run("not emitted when the chosen server has no direct endpoints", func(t *testing.T) {
		c, w := newCtx("pelican-client/7.16.0")
		generateXDirectEndpointsHeader(c, []server_structs.ServerAd{{}})
		assert.Empty(t, w.Header().Get(headerName))
	})

	t.Run("only the top-ranked server's endpoints are emitted", func(t *testing.T) {
		c, w := newCtx("pelican-client/7.16.0")
		ads := []server_structs.ServerAd{
			{ServerID: "aaa1111", DirectEndpoints: []string{"192.0.2.10:8443"}},
			{ServerID: "bbb2222", DirectEndpoints: []string{"203.0.113.5:8443"}},
		}
		generateXDirectEndpointsHeader(c, ads)
		assert.Equal(t, "sni=aaa1111, 192.0.2.10:8443", w.Header().Get(headerName))
	})
}
