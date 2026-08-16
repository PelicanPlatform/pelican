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

package origin_serve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A client that probes an origin's capabilities asks for them once per host
// and applies the answer to every path there -- xrdcl-curl keys its verbs
// cache by scheme, host and port and probes exactly scheme://host:port. The
// root used to carry no route at all, so that probe got a 405 with no Allow
// header and the client concluded the origin could not do PROPFIND, which is
// the opposite of what every namespace route on it advertises.
func TestRootOptionsAdvertisesWebDAVVerbs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	copyEnabledPrefixes = map[string]bool{}
	t.Cleanup(func() { copyEnabledPrefixes = nil })
	registerRootOptions(engine)

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "OPTIONS on the root must not 405")

	allow := rec.Header().Get("Allow")
	require.NotEmpty(t, allow, "a capability probe is useless without an Allow header")
	for _, verb := range []string{"OPTIONS", "GET", "HEAD", "PUT", "PROPFIND"} {
		assert.Contains(t, allow, verb, "Allow should advertise %s", verb)
	}
	assert.Equal(t, "1, 2", rec.Header().Get("DAV"))
}

// The probe must work without credentials: OPTIONS asks what the server can
// do, not what the caller may do, and a 401 is as unhelpful to it as a 405.
func TestRootOptionsNeedsNoCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	copyEnabledPrefixes = map[string]bool{}
	t.Cleanup(func() { copyEnabledPrefixes = nil })
	registerRootOptions(engine)

	req := httptest.NewRequest(http.MethodOptions, "/", nil) // no Authorization
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Allow"), "PROPFIND")
}

// COPY is enabled per export, so it is advertised only when some export has it.
func TestRootOptionsAdvertisesCopyOnlyWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	probe := func() string {
		engine := gin.New()
		registerRootOptions(engine)
		req := httptest.NewRequest(http.MethodOptions, "/", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec.Header().Get("Allow")
	}

	copyEnabledPrefixes = map[string]bool{}
	t.Cleanup(func() { copyEnabledPrefixes = nil })
	assert.False(t, strings.Contains(probe(), "COPY"),
		"COPY must not be advertised when no export enables it")

	copyEnabledPrefixes = map[string]bool{"/test": true}
	assert.True(t, strings.Contains(probe(), "COPY"),
		"COPY should be advertised once an export enables it")
}
