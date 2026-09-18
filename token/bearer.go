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

// CutBearerPrefix removes a leading "Bearer" HTTP authentication scheme from a
// credential and reports whether one was present.
//
// The scheme belongs in an Authorization header, but it also turns up in URL
// query parameters: an XRootD server copies the client's Authorization header
// into CGI (http.header2cgi Authorization authz), so a Pelican service behind
// an XRootD cache receives "?authz=Bearer%20<jwt>". Every place that accepts a
// token from a query parameter therefore has to tolerate the scheme, and this
// function is the one that knows how to remove it.
//
// The scheme name is matched case-insensitively (RFC 7235 section 2.1). The
// separator may be a space or a literal "%20": the latter is what a
// percent-encoded value looks like before decoding, and what survives when a
// value was encoded twice; XrdSciTokens accepts the same spelling. Whitespace
// around the remaining token is dropped. A value that merely starts with the
// letters "Bearer" and no separator is returned unchanged with found=false.
func CutBearerPrefix(s string) (token string, found bool) {
	s = strings.TrimLeft(s, " \t")
	for _, prefix := range []string{"bearer ", "bearer%20"} {
		if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
			return strings.TrimSpace(s[len(prefix):]), true
		}
	}
	return strings.TrimSpace(s), false
}

// StripBearerPrefix returns the credential without a leading "Bearer" scheme
// when one is present and the whitespace-trimmed input otherwise.
//
// Use it where a bare token is acceptable (a query parameter); use
// CutBearerPrefix where the scheme is required (an Authorization header).
func StripBearerPrefix(s string) string {
	token, _ := CutBearerPrefix(s)
	return token
}
