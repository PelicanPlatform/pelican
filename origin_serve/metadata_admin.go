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

// File metadata_admin.go exposes the operator-facing HTTP endpoints
// for inspecting and managing the metadata publish queue.
//
// The endpoints are registered under the existing origin_ui router
// group (mounted at /api/v1.0/origin_ui) and inherit its authentication
// stack: web_ui.AuthHandler + web_ui.AdminAuthHandler.

package origin_serve

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// adminQueueRow is the JSON shape of one row as returned by the API.
// Mirrors MetadataPublishRow but uses external-friendly field names
// and excludes the internal autoincrement primary key.
type adminQueueRow struct {
	EventID       string    `json:"event_id"`
	Namespace     string    `json:"namespace"`
	ObjectPath    string    `json:"object_path"`
	ObjectSize    int64     `json:"object_size"`
	ETag          string    `json:"etag"`
	ObjectCreated time.Time `json:"object_created"`
	CreatedAt     time.Time `json:"created_at"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	Attempts      int       `json:"attempts"`
	LastError     string    `json:"last_error"`
}

func adminQueueRowFromRow(r *MetadataPublishRow) adminQueueRow {
	return adminQueueRow{
		EventID:       r.EventID,
		Namespace:     r.Namespace,
		ObjectPath:    r.ObjectPath,
		ObjectSize:    r.ObjectSize,
		ETag:          r.ETag,
		ObjectCreated: r.ObjectCreated,
		CreatedAt:     r.CreatedAt,
		NextAttemptAt: r.NextAttemptAt,
		Attempts:      r.Attempts,
		LastError:     r.LastError,
	}
}

// RegisterMetadataAdminAPI registers the metadata-queue admin endpoints
// on the supplied router group. Pass `gin.HandlerFunc`s for the auth
// middleware so the registrar doesn't need a hard dependency on
// web_ui.
func RegisterMetadataAdminAPI(rg *gin.RouterGroup, mw ...gin.HandlerFunc) {
	queue := rg.Group("/metadata_queue", mw...)
	queue.GET("", listQueueHandler)
	queue.GET("/_health", queueHealthHandler)
	queue.GET("/:event_id", getQueueRowHandler)
	queue.DELETE("/:event_id", deleteQueueRowHandler)
	queue.POST("/:event_id/retry", retryQueueRowHandler)
}

// requireController is a guard for endpoints that need a live
// controller. Returns false (and writes a 503) when metadata is
// disabled at the origin.
func requireController(c *gin.Context) bool {
	if metadataCtl == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "metadata publishing is not enabled on this origin"})
		return false
	}
	return true
}

func listQueueHandler(c *gin.Context) {
	if !requireController(c) {
		return
	}
	opts := listOptions{
		Namespace: c.Query("namespace"),
	}
	if l := c.Query("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			opts.Limit = n
		}
	}
	if o := c.Query("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil {
			opts.Offset = n
		}
	}
	rows, err := metadataCtl.queue.ListPending(opts)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	out := make([]adminQueueRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, adminQueueRowFromRow(r))
	}
	c.JSON(http.StatusOK, gin.H{
		"rows":   out,
		"limit":  opts.Limit,
		"offset": opts.Offset,
	})
}

func getQueueRowHandler(c *gin.Context) {
	if !requireController(c) {
		return
	}
	eventID := c.Param("event_id")
	row, err := metadataCtl.queue.FindByEventID(eventID)
	if errors.Is(err, ErrEventNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, adminQueueRowFromRow(row))
}

func deleteQueueRowHandler(c *gin.Context) {
	if !requireController(c) {
		return
	}
	eventID := c.Param("event_id")
	row, lookupErr := metadataCtl.queue.FindByEventID(eventID)
	if errors.Is(lookupErr, ErrEventNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	if lookupErr != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": lookupErr.Error()})
		return
	}
	if err := metadataCtl.queue.DeleteByEventID(eventID); err != nil {
		if errors.Is(err, ErrEventNotFound) {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "event not found"})
			return
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	metadataAdminDeletes.WithLabelValues(row.Namespace).Inc()
	c.Status(http.StatusNoContent)
}

func retryQueueRowHandler(c *gin.Context) {
	if !requireController(c) {
		return
	}
	eventID := c.Param("event_id")
	row, err := metadataCtl.queue.FindByEventID(eventID)
	if errors.Is(err, ErrEventNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "event not found"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// Push next_attempt_at to now without bumping `attempts` (so the
	// retry curve isn't artificially compressed).
	if err := metadataCtl.queue.handle().Model(&MetadataPublishRow{}).
		Where("id = ?", row.ID).
		Update("next_attempt_at", time.Now().UTC()).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"event_id": eventID, "next_attempt_at": time.Now().UTC()})
}

func queueHealthHandler(c *gin.Context) {
	if !requireController(c) {
		return
	}
	stats, err := metadataCtl.queue.QueueStats()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	state := computeHealthState(stats.OldestCreatedAt, time.Now().UTC(), metadataCtl.warnAfter, metadataCtl.errorAfter)
	out := gin.H{
		"state":     state,
		"total":     stats.Total,
		"per_namespace": stats.PerNamespace,
	}
	if stats.OldestCreatedAt != nil {
		out["oldest_created_at"] = stats.OldestCreatedAt.UTC()
	}
	c.JSON(http.StatusOK, out)
}
