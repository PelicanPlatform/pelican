//go:build client

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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/client"
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

func TestFormatLongEntry_RegularFile(t *testing.T) {
	modTime := time.Date(2025, 5, 5, 19, 4, 2, 0, time.UTC)
	info := client.FileInfo{
		Name:         "/ns/empty.txt",
		Size:         0,
		ModTime:      modTime,
		IsCollection: false,
	}
	row := formatLongEntry(info)
	fields := strings.Split(row, "\t")
	require.Len(t, fields, 3)
	assert.Equal(t, "/ns/empty.txt", fields[0])
	assert.Equal(t, "0", fields[1], "size must be '0' for a zero-byte file, not 'DIR'")
	assert.Equal(t, "2025-05-05 19:04:02", fields[2])
}

func TestFormatLongEntry_NonEmptyFile(t *testing.T) {
	modTime := time.Date(2025, 3, 14, 13, 39, 34, 0, time.UTC)
	info := client.FileInfo{
		Name:         "/ns/README.txt",
		Size:         43,
		ModTime:      modTime,
		IsCollection: false,
	}
	row := formatLongEntry(info)
	fields := strings.Split(row, "\t")
	require.Len(t, fields, 3)
	assert.Equal(t, "/ns/README.txt", fields[0])
	assert.Equal(t, "43", fields[1])
}

func TestFormatLongEntry_Collection(t *testing.T) {
	modTime := time.Date(2025, 5, 5, 19, 6, 26, 0, time.UTC)
	info := client.FileInfo{
		Name:         "/ns/sub-directory",
		Size:         0,
		ModTime:      modTime,
		IsCollection: true,
	}
	row := formatLongEntry(info)
	fields := strings.Split(row, "\t")
	require.Len(t, fields, 3)
	assert.Equal(t, "/ns/sub-directory", fields[0])
	assert.Equal(t, "DIR", fields[1], "size must be 'DIR' for a collection, not '0'")
	assert.Equal(t, "2025-05-05 19:06:26", fields[2])
}

func TestFormatLongEntry_CollectionVsZeroByteFile_AreDistinguishable(t *testing.T) {
	ts := time.Date(2025, 5, 5, 0, 0, 0, 0, time.UTC)
	dir := formatLongEntry(client.FileInfo{Name: "/ns/prefix", Size: 0, ModTime: ts, IsCollection: true})
	file := formatLongEntry(client.FileInfo{Name: "/ns/empty.txt", Size: 0, ModTime: ts, IsCollection: false})
	assert.NotEqual(t, dir, file, "a zero-byte file and a collection must produce different output")
	dirFields := strings.Split(dir, "\t")
	fileFields := strings.Split(file, "\t")
	assert.Equal(t, "DIR", dirFields[1], "collection size field must be 'DIR'")
	assert.Equal(t, "0", fileFields[1], "zero-byte file size field must be '0'")
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
