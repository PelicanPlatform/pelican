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

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrintColumns_Empty(t *testing.T) {
	var buf bytes.Buffer
	printColumns(&buf, []string{}, 80)
	assert.Empty(t, buf.String())
}

func TestPrintColumns_SingleEntry(t *testing.T) {
	var buf bytes.Buffer
	printColumns(&buf, []string{"file.txt"}, 80)
	assert.Equal(t, "file.txt\n", buf.String())
}

func TestPrintColumns_FitsOnOneLine(t *testing.T) {
	var buf bytes.Buffer
	// Each name is 3 chars; colWidth = 3+2 = 5; 80/5 = 16 columns.
	// Three names fit on a single line.
	printColumns(&buf, []string{"aaa", "bbb", "ccc"}, 80)

	lines := nonBlankLines(buf.String())
	require.Len(t, lines, 1)
	// All three names should appear in order.
	assert.Contains(t, lines[0], "aaa")
	assert.Contains(t, lines[0], "bbb")
	assert.Contains(t, lines[0], "ccc")
	assert.True(t, strings.Index(lines[0], "aaa") < strings.Index(lines[0], "bbb"))
	assert.True(t, strings.Index(lines[0], "bbb") < strings.Index(lines[0], "ccc"))
}

func TestPrintColumns_WrapsToMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	// colWidth = 5+2 = 7; 14/7 = 2 columns → 3 names wrap to 2 lines.
	names := []string{"alpha", "beta_", "gamma"}
	printColumns(&buf, names, 14)

	lines := nonBlankLines(buf.String())
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], "alpha")
	assert.Contains(t, lines[0], "beta_")
	assert.Contains(t, lines[1], "gamma")
}

func TestPrintColumns_NarrowTerminalForcesOneColumn(t *testing.T) {
	var buf bytes.Buffer
	// Terminal width of 1 forces numCols = 1.
	names := []string{"file-a.txt", "file-b.txt", "file-c.txt"}
	printColumns(&buf, names, 1)

	lines := nonBlankLines(buf.String())
	require.Len(t, lines, 3)
	assert.Equal(t, "file-a.txt", lines[0])
	assert.Equal(t, "file-b.txt", lines[1])
	assert.Equal(t, "file-c.txt", lines[2])
}

func TestPrintColumns_ColumnWidthDrivenByLongestName(t *testing.T) {
	var buf bytes.Buffer
	// "short" = 5 chars, "a-very-long-name" = 16 chars.
	// colWidth = 16+2 = 18; 80/18 = 4 columns.
	names := []string{"short", "a-very-long-name", "b", "c", "d"}
	printColumns(&buf, names, 80)

	output := buf.String()
	// All names must appear in the output.
	for _, name := range names {
		assert.Contains(t, output, name)
	}
}

// nonBlankLines returns non-empty, non-whitespace-only lines from s.
func nonBlankLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}
