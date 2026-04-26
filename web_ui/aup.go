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

// AUP (Acceptable Use Policy) handling lives in this file as a single
// surface so the gate (RequireAUPCompliance), the rendering endpoint
// (handleGetAUP / versioned variants), and the agreement bookkeeping
// (handleRecordMyAUPAgreement) all read from the same place.
//
// Source-of-truth resolution (see resolveAUP):
//   1. Active row in aup_documents (the operator-edited copy).
//   2. The file at Server.AUPFile (legacy operator path).
//   3. The Pelican-shipped default in resources/default_aup.md.
//   4. None — when Server.AUPFile is the literal "none" the AUP
//      requirement is disabled entirely.
//
// Embedding a default means a fresh Pelican install enforces an AUP out
// of the box. Operators can either point Server.AUPFile at a file
// they manage out-of-band, or edit the AUP through the Settings UI
// (which writes to aup_documents and supersedes both the file and the
// embedded default).

import (
	_ "embed"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
)

//go:embed resources/default_aup.md
var defaultAUPMarkdown string

// aupSourceNone is the literal Server.AUPFile value that disables the
// AUP requirement entirely. Distinct from "" (which falls through to
// the embedded default).
const aupSourceNone = "none"

// AUPSource describes where the served AUP came from. Useful so the
// UI can label which kind of policy is active and so logs make it
// obvious which copy was used during a given request.
type AUPSource string

const (
	AUPSourceNone     AUPSource = "none"     // explicitly disabled
	AUPSourceDefault  AUPSource = "default"  // embedded default
	AUPSourceOperator AUPSource = "operator" // file pointed at by Server.AUPFile
	AUPSourceDB       AUPSource = "db"       // operator-edited copy in aup_documents
)

// AUPDocumentResp is everything a caller needs to render the AUP: the
// content (Markdown), the version hash, the source the content came
// from, and the optional last-updated / canonical-link footer fields.
type AUPDocumentResp struct {
	Content      string    `json:"content"`
	Version      string    `json:"version"`
	Source       AUPSource `json:"source"`
	LastUpdated  string    `json:"lastUpdated,omitempty"`
	CanonicalURL string    `json:"canonicalUrl,omitempty"`
	// Editable indicates that the active copy is operator-managed
	// in-DB (Source == AUPSourceDB) — the Settings UI uses this to
	// decide whether to show "you are editing the active version" vs
	// "you are about to override the embedded/file default with a
	// fresh DB copy."
	Editable bool `json:"editable"`
}

// resolveAUP returns the active AUP, or (nil, nil) when AUPs are
// disabled via Server.AUPFile = "none". Errors are returned only for
// the "operator-pointed file is unreadable" case so callers can decide
// whether to fall back; the embedded default never errors and the DB
// path returns nil when no row exists.
//
// Resolution order:
//  1. Active row in aup_documents (operator-edited via Settings UI).
//  2. File at Server.AUPFile (legacy operator path).
//  3. Embedded default.
//
// "none" short-circuits before any of those — operators who want zero
// AUP requirement set Server.AUPFile = "none" explicitly.
func resolveAUP() (*AUPDocumentResp, error) {
	configured := param.Server_AUPFile.GetString()
	if configured == aupSourceNone {
		return nil, nil
	}

	// 1. DB-stored, operator-edited copy. Wins over file + embedded.
	if database.ServerDatabase != nil {
		dbDoc, err := database.GetActiveAUPDocument(database.ServerDatabase)
		if err == nil && dbDoc != nil {
			lastUpdated := strings.TrimSpace(dbDoc.LastUpdatedLabel)
			if lastUpdated == "" {
				lastUpdated = strings.TrimSpace(param.Server_AUPLastUpdated.GetString())
			}
			return &AUPDocumentResp{
				Content:      dbDoc.Content,
				Version:      dbDoc.Version,
				Source:       AUPSourceDB,
				LastUpdated:  lastUpdated,
				CanonicalURL: strings.TrimSpace(param.Server_AUPCanonicalURL.GetString()),
				Editable:     true,
			}, nil
		} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			// Unexpected DB error; log and fall through to file/embedded
			// rather than failing the request entirely.
			log.Warnf("Failed to read aup_documents: %v", err)
		}
	}

	// 2/3. File or embedded default.
	var content string
	var source AUPSource
	if configured == "" {
		content = defaultAUPMarkdown
		source = AUPSourceDefault
	} else {
		raw, err := os.ReadFile(configured)
		if err != nil {
			return nil, err
		}
		content = string(raw)
		source = AUPSourceOperator
	}

	return &AUPDocumentResp{
		Content:      content,
		Version:      database.HashAUPContent(content),
		Source:       source,
		LastUpdated:  strings.TrimSpace(param.Server_AUPLastUpdated.GetString()),
		CanonicalURL: strings.TrimSpace(param.Server_AUPCanonicalURL.GetString()),
		Editable:     false,
	}, nil
}

// CurrentAUPVersion is a thin convenience wrapper around resolveAUP for
// callers that only need the version string (e.g. the AUP gate). Keeps
// the file path in the result for diagnostic logging — empty when
// Server.AUPFile is unset (default) or "none" (disabled).
func CurrentAUPVersion() (path string, version string, err error) {
	doc, err := resolveAUP()
	if err != nil {
		return param.Server_AUPFile.GetString(), "", err
	}
	if doc == nil {
		return "", "", nil
	}
	return param.Server_AUPFile.GetString(), doc.Version, nil
}

// handleGetAUP serves the active AUP. Public (no auth) by design: the
// AUP must be readable BEFORE login so a prospective user can decide
// whether to accept it before signing up. The endpoint also accepts an
// optional :version path parameter; when supplied and the value
// matches the active version, the response is unchanged. When it
// doesn't match, the handler tries to resolve it as a historical row
// in aup_documents (so users can audit the exact text they signed)
// and falls back to 404 when that misses too.
func handleGetAUP(ctx *gin.Context) {
	doc, err := resolveAUP()
	if err != nil {
		log.Warnf("Failed to read configured AUP file: %v", err)
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to read AUP file",
		})
		return
	}
	if doc == nil {
		ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "No AUP is configured on this server",
		})
		return
	}

	// Versioned URL form. The bare /aup path serves the active doc;
	// /aup/:version returns the active doc when its hash matches, or
	// looks up the historical row by version for older signed copies.
	if requested := ctx.Param("version"); requested != "" {
		if requested != doc.Version {
			if database.ServerDatabase != nil {
				if histDoc, histErr := database.GetAUPDocumentByVersion(database.ServerDatabase, requested); histErr == nil {
					ctx.JSON(http.StatusOK, AUPDocumentResp{
						Content:      histDoc.Content,
						Version:      histDoc.Version,
						Source:       AUPSourceDB,
						LastUpdated:  histDoc.LastUpdatedLabel,
						CanonicalURL: strings.TrimSpace(param.Server_AUPCanonicalURL.GetString()),
						Editable:     false,
					})
					return
				}
			}
			ctx.JSON(http.StatusNotFound, server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "That AUP version is not available on this server. The current version is " + doc.Version + ".",
			})
			return
		}
	}

	ctx.JSON(http.StatusOK, doc)
}

// updateAUPReq is the body for PUT /aup — admin-only AUP edit.
type updateAUPReq struct {
	// Content is the full Markdown body of the new AUP. Required.
	Content string `json:"content"`
	// LastUpdated is the human-readable date the operator wants
	// rendered in the footer. Optional; empty falls back to the
	// row's CreatedAt.
	LastUpdated string `json:"lastUpdated"`
}

// handleUpdateAUP saves a new AUP version and flips it to active.
// Admin-only (route is gated by AdminAuthHandler upstream). The
// resulting row's version hash is what gets compared against
// users.aup_version, so this rotation forces every user to re-accept.
func handleUpdateAUP(ctx *gin.Context) {
	var req updateAUPReq
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Invalid request body",
		})
		return
	}
	if strings.TrimSpace(req.Content) == "" {
		ctx.JSON(http.StatusBadRequest, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "AUP content is required",
		})
		return
	}

	authMethod, authMethodID := captureAuthMethod(ctx)
	creator := database.Creator{
		UserID:       ctx.GetString("UserId"),
		AuthMethod:   authMethod,
		AuthMethodID: authMethodID,
	}
	doc, err := database.SaveActiveAUPDocument(database.ServerDatabase, req.Content, strings.TrimSpace(req.LastUpdated), creator)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to save AUP: " + err.Error(),
		})
		return
	}

	// Echo back the resolved view (same shape handleGetAUP returns)
	// so the UI doesn't need a second fetch to refresh the editor.
	resp := AUPDocumentResp{
		Content:      doc.Content,
		Version:      doc.Version,
		Source:       AUPSourceDB,
		LastUpdated:  doc.LastUpdatedLabel,
		CanonicalURL: strings.TrimSpace(param.Server_AUPCanonicalURL.GetString()),
		Editable:     true,
	}
	ctx.JSON(http.StatusOK, resp)
}

// handleListAUPVersions returns the full version history. Useful for
// the admin UI and for incident-response work where you need to know
// what users actually signed.
func handleListAUPVersions(ctx *gin.Context) {
	docs, err := database.ListAUPDocuments(database.ServerDatabase)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to list AUP versions",
		})
		return
	}
	ctx.JSON(http.StatusOK, docs)
}
