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

package server_structs

import "strings"

// AcceptRedirectHeader is the request header through which a client tells a
// cache which non-HTTP URL schemes it is able to follow if redirected to one.
// Its value is a comma-separated list of schemes.
//
// It lives here, rather than as a literal on each side, because the client
// writing it and the cache reading it are in different packages and a
// mismatch would not fail to compile -- it would silently disable the
// feature, or worse, silently enable a redirect the client cannot follow.
//
// See docs/pelican-http-headers.md.
const AcceptRedirectHeader = "X-Pelican-Accept-Redirect"

// RedirectSchemeFile is advertised by a client that can read objects straight
// off a filesystem it shares with the cache.
const RedirectSchemeFile = "file"

// AcceptsRedirectScheme reports whether an X-Pelican-Accept-Redirect header
// value advertises the given scheme.
//
// http and https are deliberately not special-cased here: every client can
// follow those, so callers never need to ask about them, and answering "true"
// for an absent header would make the only interesting question -- did the
// client opt in? -- impossible to express.
//
// The answer is an assertion by the client about itself, which a server
// cannot verify.  That is exactly why an advertisement is required for these
// schemes: a cache must not direct a client to read a local path unless the
// client said it could.
func AcceptsRedirectScheme(headerValue, scheme string) bool {
	if scheme == "" {
		return false
	}
	for _, advertised := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(advertised), scheme) {
			return true
		}
	}
	return false
}
