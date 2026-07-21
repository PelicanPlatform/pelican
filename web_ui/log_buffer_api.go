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

package web_ui

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token_scopes"
)

// logTailCursor encodes an int64 seq as a URL-safe base64 string so the
// wire format stays opaque. The zero seq round-trips to the empty string,
// so a client with no cursor sends `?since=` and gets everything.
func logTailCursor(seq int64) string {
	if seq == 0 {
		return ""
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(seq))
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

// parseLogTailCursor decodes what logTailCursor produced. The empty
// string is a valid "give me everything" cursor and maps to seq 0.
func parseLogTailCursor(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != 8 {
		return 0, fmt.Errorf("invalid cursor")
	}
	return int64(binary.BigEndian.Uint64(raw)), nil
}

// LogTailResponse is the payload of GET /logs/tail. FirstCursor and
// LastCursor are opaque tokens that bracket the seq range covered by
// Content -- pass LastCursor back as the next `since=` for forward
// polling, or FirstCursor back as the next `before=` for scrolling into
// older history. Reached is true when scroll-up has hit the wall: no
// content older than FirstCursor is currently held.
type LogTailResponse struct {
	Enabled     bool   `json:"enabled"`
	Content     string `json:"content"`
	FirstCursor string `json:"firstCursor"`
	LastCursor  string `json:"lastCursor"`
	Reached     bool   `json:"reached"`
	// InstanceID identifies the buffer that produced this response. It
	// changes when the server restarts (or the buffer is otherwise
	// re-initialized); clients use a change here as a signal to drop
	// their local state and start fresh -- cursors from a previous
	// instance are meaningless against the new one.
	InstanceID string `json:"instanceId"`
}

// LogReadAuthHandler is the middleware that gates every log-read endpoint.
// Requires either server.admin (already implies everything) or the
// dedicated pelican.log_read scope.
func LogReadAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	if user == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login required to view server logs",
			})
		return
	}
	var groups []string
	if v, exists := ctx.Get("Groups"); exists {
		if s, ok := v.([]string); ok {
			groups = s
		}
	}
	identity := UserIdentity{
		Username: user,
		Groups:   groups,
		ID:       ctx.GetString("UserId"),
		Sub:      ctx.GetString("OIDCSub"),
	}
	// server.admin implies all lower scopes -- match the pattern
	// EffectiveScopesForIdentity uses in the derivation path.
	if isAdmin, _ := CheckAdmin(identity); isAdmin {
		ctx.Next()
		return
	}
	if hasScope(identity, token_scopes.Pelican_LogRead) {
		ctx.Next()
		return
	}
	ctx.AbortWithStatusJSON(http.StatusForbidden,
		server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "You do not have permission to read server logs",
		})
}

// HandleLogTail returns log lines relative to an opaque cursor. The
// caller supplies exactly one of:
//
//	?since=<cursor>              -- lines strictly after cursor (forward
//	                                polling / live tail); pass
//	                                response.lastCursor back as the next
//	                                since. Empty (or absent) since yields
//	                                every line currently held.
//	?before=<cursor>&count=<N>   -- lines strictly before cursor
//	                                (scroll-up into older history); pass
//	                                response.firstCursor back as the
//	                                next before. count is a hint
//	                                (default: one batch's worth) -- the
//	                                server rounds up to whole batches so
//	                                a batch is decompressed at most once
//	                                per scroll session.
//
// Providing both since and before is a bad request. Cursors are opaque
// URL-safe base64 tokens; internal structure (batching, LZ4 compression,
// pending buffer) is not part of the API contract and clients must not
// interpret cursors beyond echoing them.
func HandleLogTail(ctx *gin.Context) {
	buf := config.GlobalLogRingBuffer()
	if buf == nil {
		ctx.JSON(http.StatusOK, LogTailResponse{Enabled: false})
		return
	}

	sinceRaw := ctx.Query("since")
	beforeRaw := ctx.Query("before")
	countRaw := ctx.Query("count")
	limitRaw := ctx.Query("limit")

	if sinceRaw != "" && beforeRaw != "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "since= and before= are mutually exclusive",
		})
		return
	}

	var tail config.LogTail
	switch {
	case beforeRaw != "":
		before, err := parseLogTailCursor(beforeRaw)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invalid before= cursor",
			})
			return
		}
		count := 0
		if countRaw != "" {
			n, err := parseCount(countRaw)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    err.Error(),
				})
				return
			}
			count = n
		}
		tail = buf.TailBefore(before, count)
	default:
		since, err := parseLogTailCursor(sinceRaw)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "invalid since= cursor",
			})
			return
		}
		// limit caps the number of newest lines returned (used by the
		// viewer to bound its initial load when the server is
		// configured with a large buffer). 0 means unbounded.
		limit := 0
		if limitRaw != "" {
			n, err := parseCount(limitRaw)
			if err != nil {
				ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
					Status: server_structs.RespFailed,
					Msg:    "invalid limit=",
				})
				return
			}
			limit = n
		}
		tail = buf.TailSince(since, limit)
	}

	ctx.JSON(http.StatusOK, LogTailResponse{
		Enabled:     true,
		Content:     string(tail.Content),
		FirstCursor: logTailCursor(tail.FirstSeq),
		LastCursor:  logTailCursor(tail.LastSeq),
		Reached:     tail.Reached,
		InstanceID:  buf.InstanceID(),
	})
}

// parseCount decodes the `count=` hint that accompanies a before= scroll-up
// request. Negative or non-numeric input is rejected.
func parseCount(raw string) (int, error) {
	var n int
	_, err := fmt.Sscanf(raw, "%d", &n)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid count=")
	}
	return n, nil
}

// downloadFilenameSanitizer strips characters from a hostname that would
// need shell-quoting in a Content-Disposition filename. A conservative
// allow-list keeps the download filename copy-pastable on every shell.
var downloadFilenameSanitizer = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// HandleLogTailDownload gzip-streams every log line the buffer currently
// holds. The filename embeds the server hostname and a UTC timestamp so
// downloads from different servers or times don't collide when saved
// into the same directory.
func HandleLogTailDownload(ctx *gin.Context) {
	buf := config.GlobalLogRingBuffer()
	if buf == nil {
		ctx.JSON(http.StatusOK, server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "log buffer is not available",
		})
		return
	}
	host := downloadFilenameSanitizer.ReplaceAllString(param.Server_Hostname.GetString(), "-")
	if host == "" {
		host = "server"
	}
	stamp := time.Now().UTC().Format("20060102-150405Z")
	fname := fmt.Sprintf("pelican-logs-%s-%s.log.gz", host, stamp)
	ctx.Header("Content-Type", "application/gzip")
	ctx.Header("Content-Disposition", `attachment; filename="`+fname+`"`)

	gz := gzip.NewWriter(ctx.Writer)
	defer func() {
		if err := gz.Close(); err != nil {
			log.Debugln("log buffer: gzip close failed:", err)
		}
	}()

	// TailSince(0) returns everything the buffer currently holds in a
	// single call: batches concatenated in seq order, followed by the
	// pending body. Handing the whole thing to gzip is fine at the
	// buffer's cap (default 1 MB compressed / ~5 MB raw).
	tail := buf.TailSince(0, 0)
	if _, err := gz.Write(tail.Content); err != nil {
		log.Debugln("log buffer: gzip write failed:", err)
	}
}
