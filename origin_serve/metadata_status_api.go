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

// File metadata_status_api.go exposes the *client-facing* capability endpoints
// for an eventual-mode metadata publish: a query endpoint (read the current
// status) and a manage endpoint (cancel/delete a publish that's going badly).
//
// Unlike the operator/admin queue API (metadata_admin.go, gated by the origin
// admin scope), these endpoints carry NO auth middleware. Each queued row is
// minted two long random tokens at enqueue time; the origin hands the client
// URLs embedding those tokens on the upload response. Possession of the
// unguessable URL IS the authorization — the query token can only read, the
// manage token can also cancel. This lets the uploader manage its own publish
// without being issued a separate bearer token.
//
// SECURITY: because the token is a capability, it rides in the request URL
// path (/metadata_publish/<token>). Anything that records full request URLs —
// HTTP access logs, proxy logs, browser history — captures the token, and a
// reader of those logs could cancel a client's publish. Operators fronting the
// origin should scrub these paths from access logs (or the tokens from them).
// A future revision could move the token to an Authorization header or request
// body to keep it out of URLs entirely.

package origin_serve

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"github.com/pelicanplatform/pelican/param"
)

// metadataStatusRoutePrefix is the path (under the origin_ui router group)
// where the capability endpoints are mounted. The full URL handed to clients
// is <Server.ExternalWebUrl><prefix>/<token>.
const metadataStatusRoutePrefix = "/api/v1.0/origin_ui/metadata_publish"

// newCapabilityToken returns a URL-safe, unguessable random token (192 bits).
func newCapabilityToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// newManagementTokens mints the (query, manage) token pair for a queued row.
func newManagementTokens() (query string, manage string, err error) {
	if query, err = newCapabilityToken(); err != nil {
		return "", "", err
	}
	if manage, err = newCapabilityToken(); err != nil {
		return "", "", err
	}
	return query, manage, nil
}

// metadataStatusURL builds the absolute capability URL for a token. Returns ""
// for an empty token (transactional rows) or an unparsable external URL.
func metadataStatusURL(token string) string {
	if token == "" {
		return ""
	}
	u, err := url.JoinPath(param.Server_ExternalWebUrl.GetString(), metadataStatusRoutePrefix, token)
	if err != nil {
		return ""
	}
	return u
}

// RegisterMetadataStatusAPI mounts the capability endpoints on rg. It is
// registered WITHOUT auth middleware on purpose: the random token in the path
// is the capability. Call it with the same router group the admin API uses;
// the resulting paths are <group>/metadata_publish/:token.
func RegisterMetadataStatusAPI(rg *gin.RouterGroup) {
	rg.GET("/metadata_publish/:token", handleMetadataStatus)
	rg.DELETE("/metadata_publish/:token", handleMetadataCancel)
}

// requireStatusController writes a 503 and returns false when metadata
// publishing is not enabled on this origin.
func requireStatusController(c *gin.Context) bool {
	if metadataCtl == nil {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "metadata publishing is not enabled on this origin"})
		return false
	}
	return true
}

// metadataStatusView is the JSON body returned by the query endpoint.
func metadataStatusView(row *MetadataPublishRow) gin.H {
	return gin.H{
		"event_id":        row.EventID,
		"namespace":       row.Namespace,
		"object_path":     row.ObjectPath,
		"state":           row.State, // "pending" | "rejected"
		"attempts":        row.Attempts,
		"last_error":      row.LastError,
		"created_at":      row.CreatedAt.UTC(),
		"next_attempt_at": row.NextAttemptAt.UTC(),
	}
}

// handleMetadataStatus (GET) reports the current state of a queued publish.
// Either capability token works. A 404 means the token is unknown OR the
// publish already completed successfully (successful rows are deleted).
func handleMetadataStatus(c *gin.Context) {
	if !requireStatusController(c) {
		return
	}
	row, _, err := metadataCtl.queue.FindByToken(c.Param("token"))
	if errors.Is(err, ErrEventNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{
			"error": "no pending or rejected publish for this token (it may have already completed, or the token is unknown)",
		})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, metadataStatusView(row))
}

// handleMetadataCancel (DELETE) cancels/deletes a publish. It requires the
// MANAGE token; the (read-only) query token gets a 403.
func handleMetadataCancel(c *gin.Context) {
	if !requireStatusController(c) {
		return
	}
	row, isManage, err := metadataCtl.queue.FindByToken(c.Param("token"))
	if errors.Is(err, ErrEventNotFound) {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "no publish found for this token"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !isManage {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "this URL can only query status; use the manage URL to cancel"})
		return
	}
	if err := metadataCtl.queue.deleteByID(row.ID); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	metadataAdminDeletes.WithLabelValues(row.Namespace).Inc()
	c.JSON(http.StatusOK, gin.H{"event_id": row.EventID, "cancelled": true})
}
