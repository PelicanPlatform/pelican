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

package utils

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// secretURLParams are the URL query parameters that carry a secret in some
// tool's or driver's spelling.  Matching is case-insensitive.
var secretURLParams = map[string]bool{
	"accesskey":         true,
	"access_key":        true,
	"accountkey":        true,
	"awsaccesskeyid":    true,
	"awssecretkey":      true,
	"awssessiontoken":   true,
	"password":          true,
	"sas_token":         true,
	"secret_access_key": true,
	"secretkey":         true,
	"session_token":     true,
	"token":             true,
}

// IsSecretURLParam reports whether a URL query parameter name is one that
// carries a credential.
func IsSecretURLParam(key string) bool { return secretURLParams[strings.ToLower(key)] }

// RedactURLCredentials returns rawURL with its credentials replaced, for
// logging and for anything persisted as a human-readable identity: the
// userinfo component and the value of every secret-bearing query parameter.
// An unparsable URL is replaced outright rather than risk echoing part of a
// secret.
//
// It lives here, free of any cloud SDK, so that code with no business
// linking one -- the configuration dump, which the client shares -- can use
// the same rules as the storage backends.
func RedactURLCredentials(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "[unparsable blob URL redacted]"
	}
	if u.User != nil {
		u.User = url.UserPassword("redacted", "redacted")
	}
	q := u.Query()
	changed := false
	for key := range q {
		if IsSecretURLParam(key) {
			q.Set(key, "redacted")
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// URLHasCredentials reports whether s is a URL -- one with a scheme -- that
// carries credentials in its userinfo or a secret-bearing query parameter.
// Anything that is not such a URL, including arbitrary text, reports false,
// so it is safe to apply to every string in a configuration.
func URLHasCredentials(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" {
		return false
	}
	if u.User != nil {
		return true
	}
	for key := range u.Query() {
		if IsSecretURLParam(key) {
			return true
		}
	}
	return false
}

// CheckNoURLCredentials reports an error when rawURL carries credentials: a
// userinfo component, or any secret-bearing query parameter.  The error
// never quotes the secret.
//
// For a storage provider URL this is stricter than redaction, and for good
// reason.  Embedded credentials do not work through gocloud.dev's openers in
// the first place: its S3 driver ignores userinfo entirely and falls back to
// the ambient credential chain -- possibly a far more privileged identity
// than the one the operator meant to use -- and the drivers reject secret
// query parameters as unknown.  Refusing them up front is the only behaviour
// that is neither silently wrong nor a leak; callers say where credentials
// should come from instead, since that depends on the setting.
func CheckNoURLCredentials(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		// Do not quote the input: it may be a URL with a secret in it.
		return fmt.Errorf("not a valid URL")
	}
	if u.User != nil {
		return fmt.Errorf("embeds credentials in its userinfo (%s); credentials must be supplied outside the URL",
			RedactURLCredentials(rawURL))
	}
	var found []string
	for key := range u.Query() {
		if IsSecretURLParam(key) {
			found = append(found, key)
		}
	}
	if len(found) > 0 {
		sort.Strings(found)
		return fmt.Errorf("embeds credentials in query parameter(s) %s; credentials must be supplied outside the URL",
			strings.Join(found, ", "))
	}
	return nil
}
