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

package local_cache

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

// newFederationRoutingCache builds a cache whose lot index holds one lot per
// federation for the same namespace path, which is the situation federation
// qualification exists to disambiguate.
func newFederationRoutingCache(t *testing.T) *PersistentCache {
	t.Helper()
	InitIssuerKeyForTests(t)
	cdb, err := NewCacheDB(context.Background(), t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { cdb.Close() })

	li := newLotIndex()
	li.setEntries([]lotPathEntry{
		{lotName: "primary-atlas", path: "/primary.example/atlas", recursive: true},
		{lotName: "other-atlas", path: "/other.example/atlas", recursive: true},
	})
	return &PersistentCache{
		db:           cdb,
		lotIndex:     li,
		defaultFed:   "primary.example",
		namespaceMap: map[string]NamespaceID{},
	}
}

// TestGetNamespaceIDHonoursRequestFederation covers the resolution step from the
// shape the serving path actually produces: a bare, cleaned object path plus a
// request context. The multi-federation route strips the discovery host out of
// the URL before any handler runs, so unless the host travels on the context
// every object is attributed to the cache's primary federation -- and one
// federation's traffic is charged against another's quota, which is exactly what
// the qualification is supposed to prevent.
//
// The pre-existing federation test feeds federationQualifiedKey synthetic
// "pelican://fedB.org/..." strings that the request path never produces, so it
// passes either way.
func TestGetNamespaceIDHonoursRequestFederation(t *testing.T) {
	pc := newFederationRoutingCache(t)

	// A bare path, as serveObject derives it from the URL.
	const objectPath = "/atlas/data/file.root"

	primaryID := pc.getNamespaceID(context.Background(), objectPath)
	otherID := pc.getNamespaceID(WithFederationHost(context.Background(), "other.example"), objectPath)

	require.NotEqual(t, primaryID, otherID,
		"the same path in two federations must not share one accounting bucket")

	// And each maps to the lot that actually owns it.
	byID := map[NamespaceID]string{}
	pc.namespaceMapMu.RLock()
	for name, id := range pc.namespaceMap {
		byID[id] = name
	}
	pc.namespaceMapMu.RUnlock()

	require.Equal(t, "primary-atlas", byID[primaryID])
	require.Equal(t, "other-atlas", byID[otherID])
}

// TestGetNamespaceIDFallsBackToPrimaryFederation pins the single-federation
// route's behaviour: no host on the context means the cache's own federation.
func TestGetNamespaceIDFallsBackToPrimaryFederation(t *testing.T) {
	pc := newFederationRoutingCache(t)

	untagged := pc.getNamespaceID(context.Background(), "/atlas/x")
	explicit := pc.getNamespaceID(WithFederationHost(context.Background(), "primary.example"), "/atlas/x")

	require.Equal(t, untagged, explicit,
		"an untagged request must resolve as the primary federation")
}

// TestDiscoveryRouteTagsRequestContext covers the wiring itself: the route must
// put the decoded discovery host on the *request* context, because serveObject
// is a plain http.Handler that never sees the gin context, and the host is
// stripped from the URL a line later.
func TestDiscoveryRouteTagsRequestContext(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)
	require.NoError(t, param.Cache_AllowedFederations.Set([]string{"other.example"}))

	pc := newFederationRoutingCache(t)

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	var (
		sawHost string
		sawPath string
	)
	// Stand in for serveObject, which only ever receives (w, r).
	engine.GET("/api/v1.0/cache/data/:discovery/*path", func(c *gin.Context) {
		if !pc.setupDiscoveryContext(c) {
			return
		}
		sawHost = FederationHostFrom(c.Request.Context())
		sawPath = c.Request.URL.Path
		c.Status(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1.0/cache/data/other.example/atlas/data/file.root", nil)
	engine.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "other.example", sawHost,
		"the discovery host must reach the handler via the request context")
	require.Equal(t, "/atlas/data/file.root", sawPath,
		"the discovery prefix is still stripped from the path")
}
