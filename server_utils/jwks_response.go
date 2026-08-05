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

package server_utils

import (
	"encoding/json"
	"mime"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwk"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
)

// WriteJWKS marshals set as an indented JSON JWKS document and writes it to
// ctx with HTTP 200. The set is written verbatim: this helper is only an HTTP
// concern and does no key sanitization, so callers must pass a set that already
// contains public key material (e.g. via config.GetIssuerPublicJWKS for the
// server's own keys, or the registry's serving sanitizer for stored keys).
//
// By default the body is served inline, which is what machine consumers of a
// JWKS endpoint (OIDC discovery libraries, jwk.Fetch, and the like) expect; the
// Content-Disposition header they ignore is simply omitted. If a non-empty
// filename is supplied, a "Content-Disposition: attachment" header naming that
// file is added instead, for the endpoints that exist to hand a human a
// downloadable key file. On marshal failure it aborts with HTTP 500 and a
// SimpleApiResp body.
func WriteJWKS(ctx *gin.Context, set jwk.Set, filename ...string) {
	jsonData, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshal public JWKS: %v", err)
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    "Failed to marshal public key",
		})
		return
	}
	// Append a trailing newline so a downloaded file ends cleanly.
	jsonData = append(jsonData, '\n')
	if len(filename) > 0 && filename[0] != "" {
		// Build the header via mime.FormatMediaType so a filename containing
		// quotes, spaces, or CR/LF cannot break out of the header or inject
		// a new one. If the name can't be represented, fall back to a bare
		// "attachment" disposition rather than emitting a malformed header.
		disposition := mime.FormatMediaType("attachment", map[string]string{"filename": filename[0]})
		if disposition == "" {
			disposition = "attachment"
		}
		ctx.Header("Content-Disposition", disposition)
	}
	ctx.Data(http.StatusOK, "application/json", jsonData)
}
