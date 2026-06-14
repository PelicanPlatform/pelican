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

// File object_metadata_admin.go exposes the operator-facing HTTP
// endpoints for inspecting the local object-metadata tracking DB.
// Endpoints sit alongside the metadata-queue admin endpoints,
// inherit the same web_ui auth stack, and return JSON only.
//
// Routes (mounted under /api/v1.0/origin_ui by the caller):
//
//   GET  /object_metadata?namespace=N[&limit=L&offset=O]
//        List live (non-deleted) rows in a namespace, oldest first.
//
//   GET  /object_metadata/lookup?namespace=N&path=P[&history=H]
//        Single-object lookup: returns the live row (or 404) plus,
//        when `history` > 0, the most recent H history rows for the
//        same path.
//
//   GET  /object_metadata/history?namespace=N&path=P[&limit=L]
//        Full history listing for one object, oldest first.

package origin_serve

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// adminObjectMetadataRow is the JSON shape of one live row.
type adminObjectMetadataRow struct {
	Namespace    string     `json:"namespace"`
	ObjectPath   string     `json:"object_path"`
	Size         int64      `json:"size"`
	ETag         string     `json:"etag"`
	EtagSource   string     `json:"etag_source"`
	BackendMtime time.Time  `json:"backend_mtime"`
	CreatedAt    time.Time  `json:"created_at"`
	LastModified time.Time  `json:"last_modified"`
	LastAccessed *time.Time `json:"last_accessed,omitempty"`
	Actor        string     `json:"actor"`
}

func adminRowFromLive(r *ObjectMetadataRow) adminObjectMetadataRow {
	return adminObjectMetadataRow{
		Namespace:    r.Namespace,
		ObjectPath:   r.ObjectPath,
		Size:         r.Size,
		ETag:         r.ETag,
		EtagSource:   r.EtagSource,
		BackendMtime: r.BackendMtime,
		CreatedAt:    r.CreatedAt,
		LastModified: r.LastModified,
		LastAccessed: r.LastAccessed,
		Actor:        r.Actor,
	}
}

// adminObjectMetadataHistoryRow is the JSON shape of one history row.
//
// Checksums and Extra are decoded server-side into typed objects so
// API consumers don't have to do a second JSON parse on a nested
// string. The raw column values in the DB stay as the canonical
// JSON-encoded form; the admin layer is what unwraps them.
type adminObjectMetadataHistoryRow struct {
	EventID      string         `json:"event_id"`
	Namespace    string         `json:"namespace"`
	ObjectPath   string         `json:"object_path"`
	EventType    string         `json:"event_type"`
	EventTS      time.Time      `json:"event_ts"`
	Size         *int64         `json:"size,omitempty"`
	ETag         *string        `json:"etag,omitempty"`
	EtagSource   *string        `json:"etag_source,omitempty"`
	BackendMtime *time.Time     `json:"backend_mtime,omitempty"`
	Checksums    map[string]any `json:"checksums"`
	Actor        string         `json:"actor"`
	Extra        map[string]any `json:"extra"`
}

func adminHistoryRowFromRow(r *ObjectMetadataHistoryRow) adminObjectMetadataHistoryRow {
	return adminObjectMetadataHistoryRow{
		EventID:      r.EventID,
		Namespace:    r.Namespace,
		ObjectPath:   r.ObjectPath,
		EventType:    r.EventType,
		EventTS:      r.EventTS,
		Size:         r.Size,
		ETag:         r.ETag,
		EtagSource:   r.EtagSource,
		BackendMtime: r.BackendMtime,
		Checksums:    decodeJSONColumnOrEmpty(r.ChecksumsJSON, r.EventID, "checksums_json"),
		Actor:        r.Actor,
		Extra:        decodeJSONColumnOrEmpty(r.Extra, r.EventID, "extra"),
	}
}

// decodeJSONColumnOrEmpty parses a stored-as-JSON column value into
// a generic map. On parse failure (which would indicate corruption
// or a future schema change) we log and return an empty map so the
// admin endpoint stays consumable. The hot path on a well-formed
// `{}` is a single json.Unmarshal call.
func decodeJSONColumnOrEmpty(raw, eventID, column string) map[string]any {
	if raw == "" || raw == "{}" {
		return map[string]any{}
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		log.Debugf("admin: failed to parse %s for event %s: %v", column, eventID, err)
		return map[string]any{}
	}
	return out
}

// RegisterObjectMetadataAdminAPI registers the routes on the given
// router group. Pass any auth middlewares the caller wants applied.
func RegisterObjectMetadataAdminAPI(rg *gin.RouterGroup, mw ...gin.HandlerFunc) {
	om := rg.Group("/object_metadata", mw...)
	om.GET("", listObjectMetadataHandler)
	om.GET("/lookup", lookupObjectMetadataHandler)
	om.GET("/history", historyObjectMetadataHandler)
}

// requireObjectMetadataDAO is the guard for endpoints that need the
// DAO. Returns false (and writes 503) when tracking is disabled.
func requireObjectMetadataDAO(c *gin.Context) bool {
	if objectMetaDAO == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
			"error": "object-metadata tracking is not enabled on this origin",
		})
		return false
	}
	return true
}

func listObjectMetadataHandler(c *gin.Context) {
	if !requireObjectMetadataDAO(c) {
		return
	}
	ns := c.Query("namespace")
	if ns == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing required query parameter: namespace"})
		return
	}
	limit := 100
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	offset := 0
	if o := c.Query("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil {
			offset = n
		}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	if offset < 0 {
		offset = 0
	}

	var rows []ObjectMetadataRow
	err := objectMetaDAO.db.WithContext(c.Request.Context()).
		Where("namespace = ? AND deleted_at IS NULL", ns).
		Order("created_at ASC").
		Limit(limit).
		Offset(offset).
		Find(&rows).Error
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]adminObjectMetadataRow, 0, len(rows))
	for i := range rows {
		out = append(out, adminRowFromLive(&rows[i]))
	}
	c.JSON(http.StatusOK, gin.H{
		"namespace": ns,
		"rows":      out,
		"limit":     limit,
		"offset":    offset,
		"count":     len(out),
	})
}

func lookupObjectMetadataHandler(c *gin.Context) {
	if !requireObjectMetadataDAO(c) {
		return
	}
	ns := c.Query("namespace")
	path := c.Query("path")
	if ns == "" || path == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "missing required query parameters: namespace, path",
		})
		return
	}
	live, err := objectMetaDAO.LookupLive(c.Request.Context(), ns, path)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := gin.H{
		"namespace": ns,
		"path":      path,
	}
	if live != nil {
		row := adminRowFromLive(live)
		resp["live"] = row
	}
	// Optional inline history: ?history=N
	if h := c.Query("history"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 {
			hrows, hErr := objectMetaDAO.ListHistory(c.Request.Context(), ns, path, n)
			if hErr != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": hErr.Error()})
				return
			}
			out := make([]adminObjectMetadataHistoryRow, 0, len(hrows))
			for _, r := range hrows {
				out = append(out, adminHistoryRowFromRow(r))
			}
			resp["history"] = out
		}
	}
	if live == nil {
		// 404 only when no live AND no history was requested —
		// caller intent ambiguous, default to "no live = 404".
		if _, asked := resp["history"]; !asked {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no live row for the supplied (namespace, path)"})
			return
		}
	}
	c.JSON(http.StatusOK, resp)
}

func historyObjectMetadataHandler(c *gin.Context) {
	if !requireObjectMetadataDAO(c) {
		return
	}
	ns := c.Query("namespace")
	path := c.Query("path")
	if ns == "" || path == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "missing required query parameters: namespace, path",
		})
		return
	}
	limit := 100
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			limit = n
		}
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := objectMetaDAO.ListHistory(c.Request.Context(), ns, path, limit)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]adminObjectMetadataHistoryRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, adminHistoryRowFromRow(r))
	}
	c.JSON(http.StatusOK, gin.H{
		"namespace": ns,
		"path":      path,
		"rows":      out,
		"limit":     limit,
		"count":     len(out),
	})
}
