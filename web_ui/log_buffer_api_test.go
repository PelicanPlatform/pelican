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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCount(t *testing.T) {
	t.Parallel()

	t.Run("valid values", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want int
		}{
			{"0", 0},
			{"1", 1},
			{"100", 100},
			{"10000", 10000},
		} {
			got, err := parseCount(tc.in)
			require.NoError(t, err, "input %q", tc.in)
			assert.Equal(t, tc.want, got, "input %q", tc.in)
		}
	})

	t.Run("rejects invalid values", func(t *testing.T) {
		// The strict strconv.Atoi parse must reject partly-numeric input
		// (the reason we moved off fmt.Sscanf), negatives, and non-numbers.
		for _, in := range []string{"", "100abc", "abc", "-1", "-100", "1.5", " 100", "0x10"} {
			_, err := parseCount(in)
			assert.Error(t, err, "input %q should be rejected", in)
		}
	})
}

func TestLogTailCursorRoundTrip(t *testing.T) {
	t.Parallel()

	// The empty cursor is the "give me everything" sentinel and maps to seq 0.
	got, err := parseLogTailCursor("")
	require.NoError(t, err)
	assert.Equal(t, int64(0), got)
	assert.Equal(t, "", logTailCursor(0))

	for _, seq := range []int64{1, 42, 1 << 20, 1<<63 - 1} {
		encoded := logTailCursor(seq)
		assert.NotEmpty(t, encoded, "seq %d should encode to a non-empty cursor", seq)
		decoded, err := parseLogTailCursor(encoded)
		require.NoError(t, err, "seq %d", seq)
		assert.Equal(t, seq, decoded, "seq %d should round-trip", seq)
	}

	_, err = parseLogTailCursor("not-valid-base64!!")
	assert.Error(t, err)
}
