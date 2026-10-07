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
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAddSpanMergesSequentialReads checks how a reader records the blocks it
// served: sequential and overlapping reads extend one span in place, and a
// seek starts another.
func TestAddSpanMergesSequentialReads(t *testing.T) {
	var spans []blockSpan
	for b := uint32(0); b < 100; b += 8 {
		spans = addSpan(spans, blockSpan{b, b + 7})
	}
	assert.Equal(t, []blockSpan{{0, 103}}, spans, "sequential reads make one span")

	spans = addSpan(spans, blockSpan{50, 60})
	assert.Equal(t, []blockSpan{{0, 103}}, spans, "a read inside the span changes nothing")

	spans = addSpan(spans, blockSpan{200, 210})
	spans = addSpan(spans, blockSpan{195, 199})
	assert.Equal(t, []blockSpan{{0, 103}, {195, 210}}, spans, "a seek starts a span, and an adjoining read extends it")

	max := ^uint32(0)
	spans = addSpan(nil, blockSpan{max - 1, max})
	spans = addSpan(spans, blockSpan{max, max})
	assert.Equal(t, []blockSpan{{max - 1, max}}, spans, "no overflow at the last block")
}
