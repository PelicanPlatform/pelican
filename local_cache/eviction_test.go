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

package local_cache

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPurgeShare: a directory's share of a purge target is proportional to
// its size, including at sizes where targetBytes * maxSize overflows 64 bits
// (two 10 TiB directories already do).
func TestPurgeShare(t *testing.T) {
	const tib = int64(1) << 40
	tests := []struct {
		name        string
		targetBytes uint64
		maxSize     int64
		totalMax    uint64
		want        int64
	}{
		{"small", 40, 30, 60, 20},
		{"overflowing product", uint64(10 * tib), 10 * tib, uint64(20 * tib), 5 * tib},
		{"uneven split", uint64(12 * tib), 30 * tib, uint64(40 * tib), 9 * tib},
		{"target above total", uint64(80 * tib), 10 * tib, uint64(20 * tib), 10 * tib},
		{"maximal sizes", math.MaxUint64, math.MaxInt64, math.MaxUint64, math.MaxInt64},
		{"zero target", 0, 10 * tib, uint64(20 * tib), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, purgeShare(tt.targetBytes, tt.maxSize, tt.totalMax))
		})
	}
}
