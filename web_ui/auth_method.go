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
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/pelicanplatform/pelican/api_token"
	"github.com/pelicanplatform/pelican/database"
)

// captureAuthMethod inspects the request and reports how the calling user
// was authenticated. This is intended for *audit fields* on records the
// handler is about to create (e.g. invite links, API token activity logs);
// it is not an authorization decision.
//
// Returns ("", "") if no recognised credential is present — the caller
// should still be running behind AuthHandler, so this only happens when
// we're called outside an authenticated route or with a malformed request.
//
// API token IDs are the 5-character prefix of the `<id>.<secret>` token
// format (see api_token.ApiTokenRegex). Web-cookie sessions don't have a
// stable session id today, so AuthMethodID stays empty for that case.
// CaptureAuthMethod is the exported counterpart to captureAuthMethod
// for callers in sibling packages (e.g. origin/collections.go) that
// need to record the same audit fields when minting their own
// records (ownership-invite links, etc.). It just delegates.
func CaptureAuthMethod(ctx *gin.Context) (database.AuthMethod, string) {
	return captureAuthMethod(ctx)
}

func captureAuthMethod(ctx *gin.Context) (database.AuthMethod, string) {
	if header := ctx.Request.Header.Get("Authorization"); header != "" {
		tok := strings.TrimPrefix(header, "Bearer ")
		if tok != header && tok != "" {
			if api_token.ApiTokenRegex.MatchString(tok) {
				if dot := strings.IndexByte(tok, '.'); dot > 0 {
					return database.AuthMethodAPIToken, tok[:dot]
				}
				return database.AuthMethodAPIToken, ""
			}
			return database.AuthMethodBearerJWT, ""
		}
	}
	if _, err := ctx.Cookie("login"); err == nil {
		return database.AuthMethodWebCookie, ""
	}
	return "", ""
}
