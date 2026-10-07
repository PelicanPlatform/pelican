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

package token

import "strings"

// CutBearerPrefix removes a leading "Bearer" scheme from a credential and
// reports whether one was there.
//
// The scheme name is matched without regard to case. The separator may be a
// space or a literal "%20": an XRootD server forwards a client's Authorization
// header as the query parameter "?authz=Bearer%20<jwt>", and XrdSciTokens
// accepts the same spelling. On a match the remaining token is returned with
// surrounding whitespace removed. Without a match the input comes back
// unchanged; callers trim it themselves if they need to.
func CutBearerPrefix(s string) (token string, found bool) {
	for _, prefix := range []string{"bearer ", "bearer%20"} {
		if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			return strings.TrimSpace(s[len(prefix):]), true
		}
	}
	return s, false
}

// StripBearerPrefix is CutBearerPrefix without the report: the token after a
// "Bearer" scheme, or the unchanged input when there is none. Use it where a
// bare token is acceptable, such as a query parameter.
func StripBearerPrefix(s string) string {
	token, _ := CutBearerPrefix(s)
	return token
}
