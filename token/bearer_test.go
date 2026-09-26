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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCutBearerPrefix(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantToken string
		wantFound bool
	}{
		{"bare-token", "abc.def.ghi", "abc.def.ghi", false},
		{"bearer-space", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"lowercase-scheme", "bearer abc.def.ghi", "abc.def.ghi", true},
		{"uppercase-scheme", "BEARER abc.def.ghi", "abc.def.ghi", true},
		// What Go's URL decoding yields for a doubly percent-encoded value,
		// and the spelling XrdSciTokens tolerates for un-decoded CGI.
		{"undecoded-percent-20", "Bearer%20abc.def.ghi", "abc.def.ghi", true},
		{"surrounding-whitespace", "  Bearer abc.def.ghi  ", "abc.def.ghi", true},
		{"multiple-spaces-after-scheme", "Bearer   abc.def.ghi", "abc.def.ghi", true},
		{"scheme-only-is-empty", "Bearer ", "", true},
		{"scheme-without-separator-is-untouched", "Bearerabc", "Bearerabc", false},
		{"token-merely-starting-with-bearer-is-untouched", "BearerToken.abc", "BearerToken.abc", false},
		{"other-scheme-is-untouched", "Basic dXNlcjpwYXNz", "Basic dXNlcjpwYXNz", false},
		{"bare-token-is-trimmed", "  abc.def.ghi ", "abc.def.ghi", false},
		{"empty", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, found := CutBearerPrefix(tc.in)
			assert.Equal(t, tc.wantToken, got)
			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, tc.wantToken, StripBearerPrefix(tc.in), "StripBearerPrefix must agree with CutBearerPrefix")
		})
	}
}
