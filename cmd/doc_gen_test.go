//go:build client || server

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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEscapeMDXAngleBrackets(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no angle brackets",
			input:    "pelican origin serve --server https://my-origin:8447",
			expected: "pelican origin serve --server https://my-origin:8447",
		},
		{
			name:     "placeholder with angle brackets",
			input:    "    --id <client-id> \\",
			expected: "    --id &lt;client-id> \\",
		},
		{
			name:     "closing tag",
			input:    "</some-tag>",
			expected: "&lt;/some-tag>",
		},
		{
			name:     "html comment opener",
			input:    "<!-- comment -->",
			expected: "&lt;!-- comment -->",
		},
		{
			name:     "numeric comparison – must not be escaped",
			input:    "value < 5",
			expected: "value < 5",
		},
		{
			name:     "less-than followed by space – must not be escaped",
			input:    "a < b",
			expected: "a < b",
		},
		{
			name:     "multiple placeholders",
			input:    "copy <src> to <dst>",
			expected: "copy &lt;src> to &lt;dst>",
		},
		{
			name:     "uppercase placeholder",
			input:    "use <TOKEN> here",
			expected: "use &lt;TOKEN> here",
		},
		{
			name:     "line without < is returned unchanged (fast path)",
			input:    "no special chars here",
			expected: "no special chars here",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := escapeMDXAngleBrackets(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestPostProcessMdxFiles_EscapesAngleBracketsOutsideCodeBlocks(t *testing.T) {
	dir := t.TempDir()

	// Create an MDX file that simulates Cobra-generated output with a
	// placeholder like <client-id> outside a code block.
	input := `---
title: pelican origin issuer client update
---

## pelican origin issuer client update

Update an existing OIDC client

### Synopsis

Example:
  pelican origin issuer client update --server https://my-origin:8447 \
    --id <client-id> \
    --scopes "openid,storage.read:/"

` + "```" + `
pelican origin issuer client update [flags]
` + "```" + `

### Options

` + "```" + `
      --id string   Client ID to update (required)
      --<not-a-flag> string   inside a code block – must NOT be escaped
` + "```" + `
`

	filePath := filepath.Join(dir, "page.mdx")
	err := os.WriteFile(filePath, []byte(input), 0644)
	require.NoError(t, err)

	err = postProcessMdxFiles(dir)
	require.NoError(t, err)

	output, err := os.ReadFile(filePath)
	require.NoError(t, err)
	outputStr := string(output)

	// The placeholder outside a code block must be escaped.
	assert.Contains(t, outputStr, "&lt;client-id>")
	assert.NotContains(t, outputStr, "<client-id>")

	// Content inside the fenced code blocks must NOT be modified.
	assert.Contains(t, outputStr, "pelican origin issuer client update [flags]")
	// The flag inside the code block must remain untouched.
	assert.Contains(t, outputStr, "      --<not-a-flag> string")
}
