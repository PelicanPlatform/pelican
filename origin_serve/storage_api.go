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

// Storage-backend introspection API.
//
// This is an *administrative* interface to the storage backend, not part of
// the origin's data or federation API.  It is mounted under
// /api/v1.0/origin/storage precisely so that is obvious from the path: nothing
// here serves objects, participates in discovery, or is reachable by a
// federation client.  Every route requires an administrator.
//
// It exists because a pstore keeps its namespace in an encrypted database that
// holds an exclusive lock while the origin runs, so the offline CLI cannot
// look at a live store.  Answering "what is in there right now" needs the
// running process to answer it.
//
// Only operations that are meaningful against a moving target are exposed.
// Listing, stat, usage, and digests all describe a moment and are honest about
// it.  A consistency check is not: scanning an index while it is being
// rewritten produces findings that are indistinguishable from real ones, so
// fsck stays offline where its answers mean something.  Repair is likewise
// absent -- changing a store underneath a running origin is not something to
// offer over HTTP.

package origin_serve

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/local_cache"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pstore"
	"github.com/pelicanplatform/pelican/server_structs"
)

// storageBackendKind names the backend an introspection response came from,
// so a client can tell whether the fields it wants are even applicable.
type storageBackendKind string

const storageBackendPStore storageBackendKind = "pstore"

// storageEntryResponse describes one namespace entry.
type storageEntryResponse struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	IsDir    bool      `json:"isDir"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	ETag     string    `json:"etag,omitempty"`
}

// storageListResponse is a page of a directory listing.
type storageListResponse struct {
	Backend storageBackendKind     `json:"backend"`
	Path    string                 `json:"path"`
	Entries []storageEntryResponse `json:"entries"`
	// More reports that the directory continues past this page; pass the last
	// entry's name as "after" to continue.
	More bool `json:"more"`
}

// storageUsageResponse reports what a store is holding.
type storageUsageResponse struct {
	Backend storageBackendKind `json:"backend"`
	// UsedBytes counts committed plus reserved bytes across the store.
	UsedBytes int64 `json:"usedBytes"`
	// CapacityBytes is the configured ceiling; zero means unbounded.
	CapacityBytes int64 `json:"capacityBytes"`
}

// storageDigestResponse reports the checksums recorded at ingest.
type storageDigestResponse struct {
	Backend storageBackendKind `json:"backend"`
	Path    string             `json:"path"`
	// Digest is the value the origin would send in an RFC 3230 Digest header.
	Digest string `json:"digest"`
}

// RegisterStorageAPI mounts the administrative storage-backend routes.
//
// Registering nothing when the backend is not a pstore is deliberate: a 404
// tells an operator plainly that this origin has no such interface, which is
// better than a route that exists and always fails.
//
// The middleware is variadic because admin authorization takes two handlers,
// not one: web_ui.AdminAuthHandler only inspects the "User" the authentication
// handler put in the context, so on its own it rejects everyone with a 401 and
// the authorization it implements never runs. Every other admin route in the
// server registers the pair (see local_cache.RegisterPersistentCacheAPI,
// web_ui.RegisterPprofRoutes, director's RegisterDirectorWebAPI).
func RegisterStorageAPI(router *gin.RouterGroup, auth ...gin.HandlerFunc) {
	store := singlePStore()
	if store == nil {
		return
	}

	// "storage" rather than something under the origin's own API surface:
	// these routes describe the backend, not the origin's role in a
	// federation, and nothing here is for federation clients.
	group := router.Group("/origin/storage/pstore", auth...)
	{
		group.GET("/ls/*path", func(c *gin.Context) { handleStorageList(c, store) })
		group.GET("/stat/*path", func(c *gin.Context) { handleStorageStat(c, store) })
		group.GET("/digest/*path", func(c *gin.Context) { handleStorageDigest(c, store) })
		group.GET("/usage", func(c *gin.Context) { handleStorageUsage(c, store) })
	}
}

// singlePStore returns the store to introspect, when there is exactly one.
//
// Exports share a store, so in every supported configuration there is one.
// Returning nil rather than picking arbitrarily keeps a future multi-store
// setup from being silently misreported.
func singlePStore() *pstore.Store {
	if server_structs.OriginStorageType(param.Origin_StorageType.GetString()) !=
		server_structs.OriginStoragePStore {
		return nil
	}
	if len(openStores) != 1 {
		return nil
	}
	for _, s := range openStores {
		return s
	}
	return nil
}

// requestPath extracts the wildcard path, defaulting to the store root.
func requestPath(c *gin.Context) string {
	p := c.Param("path")
	if p == "" {
		return "/"
	}
	return p
}

// respondStorageError maps a store error onto a status the caller can act on.
func respondStorageError(c *gin.Context, err error) {
	c.JSON(storageErrorStatus(err), server_structs.SimpleApiResp{
		Status: server_structs.RespFailed,
		Msg:    err.Error(),
	})
}

// storageErrorStatus chooses the status for a store error.
func storageErrorStatus(err error) int {
	// Specific before general.  ErrNotExist is the broadest of these
	// sentinels, and platforms differ on which errnos they fold into it, so
	// testing it first can swallow a more precise answer.
	switch {
	case errors.Is(err, pstore.ErrNotDir), errors.Is(err, pstore.ErrIsDir),
		errors.Is(err, pstore.ErrInvalidPath):
		return http.StatusBadRequest
	case errors.Is(err, pstore.ErrNotExist):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func handleStorageList(c *gin.Context, store *pstore.Store) {
	limit := 1000
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 0 {
			c.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "limit must be a non-negative integer",
			})
			return
		}
		limit = parsed
	}

	path := requestPath(c)
	entries, more, err := store.List(path, c.Query("after"), limit)
	if err != nil {
		respondStorageError(c, err)
		return
	}

	resp := storageListResponse{
		Backend: storageBackendPStore,
		Path:    path,
		Entries: make([]storageEntryResponse, 0, len(entries)),
		More:    more,
	}
	for _, e := range entries {
		resp.Entries = append(resp.Entries, entryResponse(path, e.Name, e.Dirent))
	}
	c.JSON(http.StatusOK, resp)
}

func handleStorageStat(c *gin.Context, store *pstore.Store) {
	path := requestPath(c)
	d, err := store.Stat(path)
	if err != nil {
		respondStorageError(c, err)
		return
	}
	c.JSON(http.StatusOK, entryResponse("", path, d))
}

func handleStorageDigest(c *gin.Context, store *pstore.Store) {
	path := requestPath(c)
	digests, err := store.Digests(path)
	if err != nil {
		respondStorageError(c, err)
		return
	}
	c.JSON(http.StatusOK, storageDigestResponse{
		Backend: storageBackendPStore,
		Path:    path,
		Digest:  local_cache.FormatDigestHeader(digests),
	})
}

func handleStorageUsage(c *gin.Context, store *pstore.Store) {
	used, capacity := store.Usage()
	c.JSON(http.StatusOK, storageUsageResponse{
		Backend:       storageBackendPStore,
		UsedBytes:     used,
		CapacityBytes: capacity,
	})
}

// entryResponse renders one entry.  When parent is empty, name is taken as a
// full path.
func entryResponse(parent, name string, d *pstore.Dirent) storageEntryResponse {
	full := name
	if parent != "" {
		if parent == "/" {
			full = "/" + name
		} else {
			full = parent + "/" + name
		}
	} else {
		name = pathBase(name)
	}

	e := storageEntryResponse{
		Name:     name,
		Path:     full,
		IsDir:    d.IsDir(),
		Size:     d.Size,
		Modified: time.Unix(0, d.MTimeNanos),
	}
	if !d.IsDir() && d.Generation != "" {
		e.ETag = `"` + d.Generation + `"`
	}
	return e
}

// pathBase returns the final component of a namespace path.
func pathBase(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == len(p)-1 && len(p) > 1 {
				continue
			}
			return p[i+1:]
		}
	}
	return p
}
