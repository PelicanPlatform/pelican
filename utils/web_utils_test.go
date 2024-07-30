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
	"net/http"
	"net/http/httptest"
	"net/netip"
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
