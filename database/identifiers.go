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

package database

import (
	"errors"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// ErrInvalidIdentifier is returned when a user-supplied name (a username
// or a group name — the *machine-readable* names, NOT display names)
// fails identifier validation. Callers — both DB-layer functions and
// HTTP handlers — should treat this as a bad-request: surface the
// specific reason to the user, do not fall back silently.
var ErrInvalidIdentifier = errors.New("invalid identifier: must be 2-64 characters; allowed: A-Z, a-z, 0-9, '.', '_', '@', '-'; must start with a letter or digit; '/' is forbidden")

// identifierPattern is intentionally narrow.
//
// Any value matching this is going to be embedded in places that have
// historically been a source of bugs and exploits when the character
// class was loose:
//
//   - object-name policy strings (e.g. `/foo/bar` paths in token scopes
//     and ACLs) — '/' would create namespace ambiguity, so it is banned
//     outright per the design doc;
//   - URLs, query strings, and HTML attributes in the web UI;
//   - configuration files (admin lists, group lists);
//   - log lines.
//
// Keeping the character class to alphanumerics plus a small set of
// safe punctuation means none of the above have to think about
// escaping, quoting, or canonicalisation. Length 2-64 is generous
// enough for human-readable handles and tight enough to keep DB rows
// compact.
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$`)

// ValidateIdentifier returns nil if name is a well-formed user/group
// machine identifier per the design contract on the User/Group structs,
// or ErrInvalidIdentifier otherwise. Apply at every point a name enters
// the system: HTTP create/rename handlers, OIDC bootstrap candidate
// selection, CLI flags. Display names go through their own (laxer)
// validator.
func ValidateIdentifier(name string) error {
	if !identifierPattern.MatchString(name) {
		return ErrInvalidIdentifier
	}
	// '..' is not strictly necessary to ban (it's just two dots in a row,
	// which the pattern already permits) but it shows up everywhere as a
	// path-traversal marker and there is no legitimate reason a username
	// or group name would contain it. Cheap, conservative.
	if strings.Contains(name, "..") {
		return ErrInvalidIdentifier
	}
	return nil
}

// ErrInvalidDisplayName is the analogous error for display names. We
// allow a much wider character class here (display names are meant for
// humans, not policy strings) but still bound length and reject control
// characters.
var ErrInvalidDisplayName = errors.New("invalid display name: must be 1-128 characters with no control characters")

// ValidateDisplayName returns nil for an acceptable display name. Empty
// is fine (the field is optional). Length is the only real constraint;
// otherwise we accept any printable Unicode so users can spell their
// names correctly.
func ValidateDisplayName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 128 {
		return ErrInvalidDisplayName
	}
	for _, r := range name {
		// Disallow ASCII control characters (incl. tab, CR, LF).
		// Other Unicode "control" categories are very rare in real
		// names and are easier to reject than to defend against.
		if r < 0x20 || r == 0x7f {
			return ErrInvalidDisplayName
		}
	}
	return nil
}

// SanitizeIdentifier coerces a candidate identifier (typically a value
// pulled from an OIDC claim) into a form that passes ValidateIdentifier,
// or returns "" if no useful sanitisation exists.
//
// The conservative substitution rules:
//
//   - Disallowed characters become '_'.
//   - Leading non-alphanumerics (which would fail the pattern's anchor)
//     are stripped.
//   - Repeated dots, which trip the '..' guard, are collapsed to one.
//   - Result is truncated to 64 chars.
//
// Used by LookupOrBootstrapUser to rescue claims like "bockelman/admin"
// (which would otherwise be rejected) into "bockelman_admin". Returning
// empty is allowed — the caller falls back to a synthetic name.
func SanitizeIdentifier(s string) string {
	if s == "" {
		return ""
	}
	// Replace disallowed runes with '_'. We walk byte-wise because the
	// allowed set is ASCII; non-ASCII runes get replaced too, which is
	// the right call for identifiers used in policy strings.
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '.', c == '_', c == '@', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	// Strip leading punctuation so the anchor matches. The pattern
	// requires the first byte to be alphanumeric.
	for len(out) > 0 {
		c := out[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			break
		}
		out = out[1:]
	}
	// Collapse '..' to '.' to avoid the path-traversal guard.
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	// Truncate.
	if len(out) > 64 {
		out = out[:64]
	}
	// Ensure the trimmed result still satisfies the pattern (length floor
	// of 2, etc.). If not, signal failure to the caller.
	if ValidateIdentifier(out) != nil {
		return ""
	}
	return out
}

// ErrInvalidNamespacePath is returned when a federation namespace path
// (a collection or share namespace — a '/'-rooted object path, NOT a
// machine identifier) fails validation. Surface it as a bad-request.
var ErrInvalidNamespacePath = errors.New("invalid namespace path: must be an absolute '/'-rooted path with no whitespace, control characters, or ':'")

// CleanNamespacePath validates and canonicalizes a federation namespace
// path. It is the single choke point for namespaces that later get
// spliced into token scope strings (e.g. storage.read:/foo,
// share.access:/id) and compared by path prefix. Two properties it
// guarantees, each closing a concrete escalation path:
//
//  1. It returns path.Clean'd output, so a prefix check performed on the
//     result and a scope minted from the result can never disagree.
//     Without this, a raw-string prefix check accepts a traversal like
//     "/org/foo/../../secret" (it literally starts with "/org/foo/")
//     while the mint-side path.Clean turns it into "/secret" — granting
//     a storage scope on a prefix entirely outside the parent.
//
//  2. It rejects whitespace, control characters, and ':'. The WLCG scope
//     claim is space-delimited and ':' separates a scope from its path,
//     so a namespace like "/parent/x storage.modify:/etc" would split
//     into two scopes downstream — injecting an authorization the caller
//     never held.
//
// Callers must use the returned, cleaned value for BOTH the authorization
// prefix check and persistence; validating the raw input but storing or
// minting from a different form would reopen property (1).
func CleanNamespacePath(ns string) (string, error) {
	if ns == "" || !strings.HasPrefix(ns, "/") {
		return "", ErrInvalidNamespacePath
	}
	for _, r := range ns {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == ':' {
			return "", ErrInvalidNamespacePath
		}
	}
	return path.Clean(ns), nil
}
