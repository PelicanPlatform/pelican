package main

import (
	"bufio"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReadMultiTransfer test if we can read multiple transfers from stdin
func TestReadMultiTransfer(t *testing.T) {
	t.Parallel()

	// Test with multiple transfers
	stdin := "[ LocalFileName = \"/path/to/local/copy/of/foo\"; Url = \"url://server/some/directory//foo\" ]\n[ LocalFileName = \"/path/to/local/copy/of/bar\"; Url = \"url://server/some/directory//bar\" ]\n[ LocalFileName = \"/path/to/local/copy/of/qux\"; Url = \"url://server/some/directory//qux\" ]"
	transfers, err := readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 3, len(transfers))
	assert.Equal(t, "/path/to/local/copy/of/foo", transfers[0].destination)
	assert.Equal(t, "url://server/some/directory//foo", transfers[0].source)
	assert.Equal(t, "/path/to/local/copy/of/bar", transfers[1].destination)
	assert.Equal(t, "url://server/some/directory//bar", transfers[1].source)
	assert.Equal(t, "/path/to/local/copy/of/qux", transfers[2].destination)
	assert.Equal(t, "url://server/some/directory//qux", transfers[2].source)

	// Test with single transfers
	stdin = "[ LocalFileName = \"/path/to/local/copy/of/blah\"; Url = \"url://server/some/directory//blah\" ]"
	transfers, err = readMultiTransfers(*bufio.NewReader(strings.NewReader(stdin)))
	assert.NoError(t, err)
	assert.Equal(t, 1, len(transfers))
	assert.Equal(t, "url://server/some/directory//blah", transfers[0].source)
	assert.Equal(t, "/path/to/local/copy/of/blah", transfers[0].destination)
}
