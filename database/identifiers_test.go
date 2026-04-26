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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateIdentifier(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		// happy paths
		{"alice", true},
		{"alice.smith", true},
		{"alice_smith", true},
		{"alice-smith", true},
		{"alice@example.org", true},
		{"a1", true},
		{"User2026", true},
		{strings.Repeat("a", 64), true},

		// banned characters — '/' is the most important
		{"alice/admin", false},
		{`alice\admin`, false},
		{"alice admin", false},  // whitespace
		{"alice\tadmin", false}, // tab
		{"alice:admin", false},
		{"alice;admin", false},
		{"alice,admin", false},
		{"alice<script>", false},

		// length / structure
		{"", false},
		{"a", false},                     // too short (length floor of 2)
		{strings.Repeat("a", 65), false}, // too long
		{".alice", false},                // leading punctuation
		{"-alice", false},                // leading dash
		{"_alice", false},                // leading underscore
		{"alice..bob", false},            // path-traversal pattern
	}
	for _, tc := range cases {
		err := ValidateIdentifier(tc.name)
		if tc.valid {
			assert.NoErrorf(t, err, "expected %q to be valid", tc.name)
		} else {
			assert.Errorf(t, err, "expected %q to be rejected", tc.name)
		}
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		// already valid
		{"alice", "alice"},
		{"alice.smith", "alice.smith"},

		// disallowed chars become '_'
		{"alice/admin", "alice_admin"},
		{"alice admin", "alice_admin"},
		{"alice:admin", "alice_admin"},
		{`alice\admin`, "alice_admin"},

		// leading punctuation stripped, then validated
		{".alice", "alice"},
		{"_alice", "alice"},
		{"-_-alice", "alice"},
		{"////alice", "alice"},

		// path-traversal collapse
		{"alice..bob", "alice.bob"},
		{"alice...bob", "alice.bob"},

		// truncation
		{strings.Repeat("a", 200), strings.Repeat("a", 64)},

		// nothing salvageable returns ""
		{"/", ""},
		{"/// ", ""},
		{"", ""},
		{"a", ""}, // single char fails length floor
	}
	for _, tc := range cases {
		got := SanitizeIdentifier(tc.in)
		assert.Equalf(t, tc.out, got, "SanitizeIdentifier(%q)", tc.in)
		// Whatever we return non-empty must itself validate, by construction.
		if got != "" {
			assert.NoErrorf(t, ValidateIdentifier(got),
				"SanitizeIdentifier(%q) returned %q but it does not validate", tc.in, got)
		}
	}
}

// TestSanitizeIdentifierEdgeCases exercises corners that aren't
// obvious from the table in TestSanitizeIdentifier: unicode, cases
// where every "fix" combines (non-ASCII + leading punct + double
// dots), and boundary lengths where truncation interacts with the
// length floor of 2. The contract is: whatever non-empty value
// Sanitize returns must itself ValidateIdentifier without error.
func TestSanitizeIdentifierEdgeCases(t *testing.T) {
	cases := []struct {
		in, out string
		why     string
	}{
		// Unicode replaced with '_' — Sanitize walks byte-by-byte so
		// each non-ASCII byte yields one underscore. Documented and
		// asserted here so a future "smarter" rune-based rewrite
		// doesn't silently change downstream behavior. The é in
		// "renée" is two UTF-8 bytes; the CJK chars are three each.
		{"renée", "ren__e", "non-ASCII becomes underscore (per byte)"},
		{"日本語alice", "alice", "leading non-ASCII strips with leading-punct rule"},
		{"alice.日本", "alice.______", "trailing non-ASCII fills with one underscore per byte"},

		// Underscore burst: the leading-punct strip walks until it
		// finds an alphanumeric. It must not over-strip past the
		// first valid letter.
		{"___bob", "bob", "leading underscores strip, body intact"},
		{"___b", "", "after stripping, body is single char => fails length floor"},

		// Double-dot collapse runs to fixed point — three dots fold
		// to one, not two, even after a single pass.
		{"a....b", "a.b", "many-dot collapse"},

		// Disallowed run + truncation: produce a string EXACTLY at
		// the 64-char limit so we verify the limit is inclusive.
		{strings.Repeat("a", 64) + "garbage", strings.Repeat("a", 64), "truncate to inclusive 64"},

		// Sanitize MUST never return a string that begins with '.'
		// or ends in something the validator rejects.
		{".", "", "single dot = nothing salvageable"},
		{"..", "", "double dot collapses then leading-strips to empty"},
	}
	for _, tc := range cases {
		got := SanitizeIdentifier(tc.in)
		assert.Equalf(t, tc.out, got, "SanitizeIdentifier(%q): %s", tc.in, tc.why)
		if got != "" {
			assert.NoErrorf(t, ValidateIdentifier(got),
				"SanitizeIdentifier(%q) -> %q must itself validate", tc.in, got)
		}
	}
}

// TestSanitizeIdentifierAlwaysValidates is the property test: for a
// pile of typical OIDC-claim shapes, whatever Sanitize returns
// non-empty MUST validate. The set is hand-picked rather than a
// fuzzer so failures are easy to read in CI.
func TestSanitizeIdentifierAlwaysValidates(t *testing.T) {
	inputs := []string{
		"",
		"alice",
		"alice@example.com",
		"https://idp.example/users/12345",
		"DOMAIN\\alice",
		"alice (admin)",
		"alice; DROP TABLE users; --",
		"<script>alert(1)</script>",
		"\x00\x01alice",
		"​alice", // zero-width space
		"-_-",    // only punctuation
		strings.Repeat(".", 200),
		strings.Repeat("/", 200),
	}
	for _, s := range inputs {
		got := SanitizeIdentifier(s)
		if got == "" {
			continue // empty is the documented "no salvage" sentinel
		}
		assert.NoErrorf(t, ValidateIdentifier(got),
			"SanitizeIdentifier(%q) returned %q which does NOT validate",
			s, got)
	}
}

func TestValidateDisplayName(t *testing.T) {
	cases := []struct {
		name  string
		valid bool
	}{
		{"", true},                        // empty allowed
		{"Brian Bockelman", true},         // spaces allowed in display names
		{"Renée Müller", true},            // accents
		{"日本語", true},                     // CJK
		{"O'Brien (special chars)", true}, // punctuation
		{strings.Repeat("a", 128), true},  // at the limit
		{strings.Repeat("a", 129), false}, // over the limit
		{"hello\tworld", false},           // control chars
		{"hello\nworld", false},
		{"hello\x00world", false},
	}
	for _, tc := range cases {
		err := ValidateDisplayName(tc.name)
		if tc.valid {
			assert.NoErrorf(t, err, "expected %q to be valid", tc.name)
		} else {
			assert.Errorf(t, err, "expected %q to be rejected", tc.name)
		}
	}
}
