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

package launcher_utils

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithheldNamespacesFromResponse pins down how an accepted
// advertisement's body is read: a director that withheld namespaces names
// them, an older director (plain SimpleApiResp) or an empty list means
// nothing was withheld, and an undecodable body is not mistaken for either.
func TestWithheldNamespacesFromResponse(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantWithheld []string
		wantMsg      string
	}{
		{
			name: "older director answers with a plain SimpleApiResp",
			body: `{"status":"success","msg":"Successful registration"}`,
		},
		{
			name: "nothing withheld",
			body: `{"status":"success","msg":"Successful registration","withheldNamespaces":[]}`,
		},
		{
			name:         "withheld namespaces are returned with the director's message",
			body:         `{"status":"success","msg":"Successful registration; 1 namespace(s) withheld pending administrator approval: /foo/bar. Contact admin@example.org for help.","withheldNamespaces":["/foo/bar"]}`,
			wantWithheld: []string{"/foo/bar"},
			wantMsg:      "Successful registration; 1 namespace(s) withheld pending administrator approval: /foo/bar. Contact admin@example.org for help.",
		},
		{
			name: "an undecodable body is not treated as withheld",
			body: "not json",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			withheld, msg := withheldNamespacesFromResponse([]byte(tc.body))
			assert.Equal(t, tc.wantWithheld, withheld)
			assert.Equal(t, tc.wantMsg, msg)
		})
	}
}

// TestAdPartiallyAcceptedErrorIsDistinct guards what advertiseAll and
// doAdvertise rely on: a partial acceptance is recognizable through
// errors.As (even wrapped), is never mistaken for a retryable rejection, and
// reads as the director's own message when there is one.
func TestAdPartiallyAcceptedErrorIsDistinct(t *testing.T) {
	base := &adPartiallyAcceptedError{namespaces: []string{"/foo/bar"}}

	var partial *adPartiallyAcceptedError
	require.True(t, errors.As(error(base), &partial))
	assert.Equal(t, []string{"/foo/bar"}, partial.namespaces)
	assert.Contains(t, base.Error(), "/foo/bar", "without a director message the namespaces are named")

	partial = nil
	wrapped := errors.Wrap(error(base), "failed to advertise")
	require.True(t, errors.As(wrapped, &partial), "wrapping must not hide a partial acceptance")

	var retryable *retryableAdError
	assert.False(t, errors.As(error(base), &retryable), "a partial acceptance is not something to retry")

	withMsg := &adPartiallyAcceptedError{namespaces: []string{"/foo/bar"}, msg: "the director's words"}
	assert.Equal(t, "the director's words", withMsg.Error())
}
