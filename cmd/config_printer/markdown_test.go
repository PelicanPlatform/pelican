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

package config_printer

import (
	"strings"
	"testing"

	"github.com/fatih/color"
	"github.com/stretchr/testify/assert"
)

func renderMarkdownForTest(t *testing.T, noColor bool, source string) string {
	saved := color.NoColor
	color.NoColor = noColor
	t.Cleanup(func() { color.NoColor = saved })

	var b strings.Builder
	renderMarkdown(&b, source)
	return b.String()
}

func TestRenderMarkdown(t *testing.T) {
	// A word too wide to fit beside the first column.
	url := "https://example.com/" + strings.Repeat("a-very-long-path/", 4)
	tests := []struct {
		name     string
		source   string
		expected string
	}{
		{
			name: "paragraphs-are-wrapped",
			source: "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.\n" +
				"The quick brown fox jumps over the lazy dog.\n\nA second paragraph.\n",
			expected: "  The quick brown fox jumps over the lazy dog. The quick brown fox jumps over\n" +
				"  the lazy dog. The quick brown fox jumps over the lazy dog.\n" +
				"\n" +
				"  A second paragraph.\n",
		},
		{
			name:     "headings-do-not-show-their-levels",
			source:   "# Title\n\nBody.\n\nSubtitle\n--------\n\nMore.\n",
			expected: "  Title\n\n  Body.\n\n  Subtitle\n\n  More.\n",
		},
		{
			name:     "blocks-that-print-nothing-get-no-separator",
			source:   "A\n\n#\n\n```\n```\n\n![](x.png)\n\nB\n\n#\n",
			expected: "  A\n\n  B\n",
		},
		{
			name:     "loose-list-items-ending-in-nothing-get-one-separator",
			source:   "- A\n\n  #\n\n- B\n",
			expected: "  • A\n\n  • B\n",
		},
		{
			name:     "block-quotes-ending-in-nothing-get-one-separator",
			source:   "> A\n>\n> #\n\nB\n",
			expected: "  │ A\n\n  B\n",
		},
		{
			name:     "tight-list-items-ending-in-nothing-get-no-separator",
			source:   "- > A\n  >\n  > ![](x.png)\n- B\n",
			expected: "  • │ A\n  • B\n",
		},
		{
			name:     "hard-line-breaks-are-kept",
			source:   "One line.\\\nAnother line.\n",
			expected: "  One line.\n  Another line.\n",
		},
		{
			name:     "code-spans-keep-their-backticks",
			source:   "Set `Origin.Exports`.\n",
			expected: "  Set `Origin.Exports`.\n",
		},
		{
			name:     "emphasis-keeps-its-asterisks",
			source:   "Set *one*, __two__, ***three***, or *`four` [five](/5)*.\n",
			expected: "  Set *one*, **two**, ***three***, or *`four` five (/5)*.\n",
		},
		{
			name:     "asterisks-count-toward-the-width",
			source:   strings.Repeat("word ", 14) + "abcde *x* end.\n",
			expected: "  " + strings.Repeat("word ", 14) + "abcde\n  *x* end.\n",
		},
		{
			name:     "code-spans-keep-runs-of-spaces",
			source:   "Use `a  b` or `  c`, not  d.\n",
			expected: "  Use `a  b` or `  c`, not d.\n",
		},
		{
			name:     "code-spans-at-line-breaks-keep-their-spaces",
			source:   "Use `foo\n` or `\nbar` here.\n",
			expected: "  Use `foo ` or ` bar` here.\n",
		},
		{
			name:   "backticks-stay-with-their-code",
			source: strings.Repeat("word ", 14) + "abcd `  c` end.\n\n" + strings.Repeat("word ", 14) + "abcde `c  ` end.\n",
			expected: "  " + strings.Repeat("word ", 14) + "abcd\n  `  c` end.\n" +
				"\n" +
				"  " + strings.Repeat("word ", 14) + "abcde\n  `c  ` end.\n",
		},
		{
			name:     "no-break-spaces-do-not-wrap",
			source:   strings.Repeat("word ", 15) + "10&nbsp;MB and more.\n",
			expected: "  " + strings.Repeat("word ", 14) + "word\n  10 MB and more.\n",
		},
		{
			name:     "links-include-their-destinations",
			source:   "See [the docs](https://example.com/docs), [example.com](example.com), and <https://example.com>.\n",
			expected: "  See the docs (https://example.com/docs), example.com, and https://example.com.\n",
		},
		{
			name:     "empty-link-destinations-are-omitted",
			source:   "See [the docs]() and [these](<>).\n",
			expected: "  See the docs and these.\n",
		},
		{
			name:     "link-reference-definitions-are-omitted",
			source:   "[a]: https://example.com/a\n\nSee [the docs][docs].\n\n[docs]: https://example.com/docs\n",
			expected: "  See the docs (https://example.com/docs).\n",
		},
		{
			name:     "placeholders-are-kept",
			source:   "It is stored at <path>/.lot/lotman_cpp.sqlite.\n",
			expected: "  It is stored at <path>/.lot/lotman_cpp.sqlite.\n",
		},
		{
			name:   "lists-are-indented",
			source: "Options:\n - One\n - Two that is long enough to need wrapping, because it goes on and on and on and on.\n   - Nested\n\n1. First\n2. Second\n",
			expected: "  Options:\n" +
				"\n" +
				"  • One\n" +
				"  • Two that is long enough to need wrapping, because it goes on and on and on\n" +
				"    and on.\n" +
				"    • Nested\n" +
				"\n" +
				"  1. First\n" +
				"  2. Second\n",
		},
		{
			name:   "empty-list-items-are-kept",
			source: "- a\n-\n- b\n\n1. a\n\n2.\n\n3. [x]: /x\n",
			expected: "  • a\n" +
				"  •\n" +
				"  • b\n" +
				"\n" +
				"  1. a\n" +
				"\n" +
				"  2.\n" +
				"\n" +
				"  3.\n",
		},
		{
			name:     "list-items-without-words-are-kept",
			source:   "1. a\n2. ![](x.png)\n3. b\n",
			expected: "  1. a\n  2.\n  3. b\n",
		},
		{
			name:   "ordered-lists-keep-their-starts-and-markers",
			source: "9) Nine\n10) Ten that is long enough to need wrapping, because it goes on and on and on.\n",
			expected: "  9) Nine\n" +
				"  10) Ten that is long enough to need wrapping, because it goes on and on and\n" +
				"      on.\n",
		},
		{
			name:   "code-blocks-are-indented-but-not-wrapped",
			source: "Example:\n```yaml\nOrigin:\n  Exports: [\"/one/two/three/four/five/six/seven/eight/nine/ten/eleven/twelve\"]\n```\n",
			expected: "  Example:\n" +
				"\n" +
				"    Origin:\n" +
				"      Exports: [\"/one/two/three/four/five/six/seven/eight/nine/ten/eleven/twelve\"]\n",
		},
		{
			name:     "block-quotes-are-marked",
			source:   "> WARNING: One.\n>\n> Two.\n",
			expected: "  │ WARNING: One.\n  │\n  │ Two.\n",
		},
		{
			name:     "thematic-breaks-extend-to-the-width",
			source:   "---\n\n> ***\n",
			expected: "  " + strings.Repeat("─", 78) + "\n\n  │ " + strings.Repeat("─", 76) + "\n",
		},
		{
			name:     "deeply-nested-thematic-breaks-are-empty",
			source:   strings.Repeat("> ", 41) + "---\n",
			expected: "  " + strings.TrimSpace(strings.Repeat("│ ", 41)) + "\n",
		},
		{
			name:     "escapes-and-references-are-resolved",
			source:   "Not \\*emphasis\\*: &lt;path&gt; &amp; &#42; &#x2A; `\\*&lt;`.\n",
			expected: "  Not *emphasis*: <path> & * * `\\*&lt;`.\n",
		},
		{
			name:     "invalid-numeric-references-are-replaced",
			source:   "Zero: &#0;. Surrogate: &#xD800;. Beyond Unicode: &#x110000; &#1114112;. Not beyond: &#x10FFFF;.\n",
			expected: "  Zero: \ufffd. Surrogate: \ufffd. Beyond Unicode: \ufffd \ufffd. Not beyond: \U0010FFFF.\n",
		},
		{
			name:     "numeric-references-have-limited-digits",
			source:   "References: &#0000042; &#x00002A; &#X2A;. Not references: &#00000042; &#x000002A; &#12345678;.\n",
			expected: "  References: * * *. Not references: &#00000042; &#x000002A; &#12345678;.\n",
		},
		{
			name:     "escaped-ampersands-are-literal",
			source:   "Not references: \\&amp; \\&#42; [x](/a\\&amp;b).\n",
			expected: "  Not references: &amp; &#42; x (/a&amp;b).\n",
		},
		{
			name:     "references-need-semicolons",
			source:   "Not references: ?a=1&region=us &copy &notit; [x](/?a=1&region=us).\n",
			expected: "  Not references: ?a=1&region=us &copy &notit; x (/?a=1&region=us).\n",
		},
		{
			name: "control-characters-are-replaced",
			source: "Hidden: &#27;[8m &#x9b;8m \x1b]52;c;eA==\x07 `\x1b[8m`\n" +
				"```\na\x1b[8m\tb\n```\n" +
				"<pre>\x1b[8m\n</pre>\x1b[0m\n",
			expected: "  Hidden: \ufffd[8m \ufffd8m \ufffd]52;c;eA==\ufffd `\ufffd[8m`\n" +
				"\n" +
				"    a\ufffd[8m\tb\n" +
				"\n" +
				"  <pre>\ufffd[8m\n" +
				"  </pre>\ufffd[0m\n",
		},
		{
			name:     "html-blocks-are-kept-whole",
			source:   "<pre>\nfoo\nbar</pre>\n",
			expected: "  <pre>\n  foo\n  bar</pre>\n",
		},
		{
			name:   "tables-are-aligned",
			source: "| Left | Center | Right |\n| :--- | :----: | ----: |\n| `a\\|b` | x | 1 |\n| long text | yy |\n",
			expected: "  Left      │ Center │ Right\n" +
				"  ──────────┼────────┼──────\n" +
				"  `a|b`     │   x    │     1\n" +
				"  long text │   yy   │\n",
		},
		{
			name: "wide-tables-are-wrapped",
			source: "| Value | Default | Meaning |\n| --- | :---: | --- |\n" +
				"| `none` | no | Do not cache objects; every request goes to the origin, which can be slow for clients far from it. |\n" +
				"| `all` | yes | Cache everything. |\n",
			expected: "  Value  │ Default │ Meaning\n" +
				"  " + strings.Repeat("─", 7) + "┼" + strings.Repeat("─", 9) + "┼" + strings.Repeat("─", 60) + "\n" +
				"  `none` │   no    │ Do not cache objects; every request goes to the origin,\n" +
				"         │         │ which can be slow for clients far from it.\n" +
				"  `all`  │   yes   │ Cache everything.\n",
		},
		{
			name:   "tables-with-long-words-overflow",
			source: "| Name | See |\n| --- | --- |\n| S3 | See " + url + " for details. |\n",
			expected: "  Name │ See\n" +
				"  " + strings.Repeat("─", 5) + "┼" + strings.Repeat("─", len(url)+1) + "\n" +
				"  S3   │ See\n" +
				"       │ " + url + "\n" +
				"       │ for details.\n",
		},
		{
			name:   "tables-measure-runs-of-spaces-in-code",
			source: "| Code | Note |\n| --- | --- |\n| `a  b` | x |\n",
			expected: "  Code   │ Note\n" +
				"  ───────┼─────\n" +
				"  `a  b` │ x\n",
		},
		{
			name:   "tables-in-lists-are-indented",
			source: "- | A | B |\n  | - | -: |\n  | x | 10 |\n",
			expected: "  • A │  B\n" +
				"    ──┼───\n" +
				"    x │ 10\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, renderMarkdownForTest(t, true, tc.source))
		})
	}
}

func TestRenderMarkdownInColor(t *testing.T) {
	source := "Set `Origin.Exports` to the namespaces that the origin **exports**, which it reads from the storage.\n"
	rendered := renderMarkdownForTest(t, false, source)

	assert.Contains(t, rendered, color.New(markdownCodeStyle...).Sprint("Origin.Exports"))
	assert.Contains(t, rendered, color.New(color.Bold).Sprint("exports"))
	// Escape codes do not count toward the width, and styles replace
	// the backticks and asterisks.
	assert.Equal(t,
		"  Set Origin.Exports to the namespaces that the origin exports, which it reads\n"+
			"  from the storage.\n",
		stripAnsiCodes(rendered))
}

func TestRenderMarkdownTableInColor(t *testing.T) {
	source := "| Value | Meaning |\n| --- | --- |\n| `none` | Do not cache. |\n"
	rendered := renderMarkdownForTest(t, false, source)

	assert.Contains(t, rendered, color.New(color.Bold).Sprint("Value"))
	assert.Contains(t, rendered, color.New(markdownCodeStyle...).Sprint("none"))
	// Escape codes do not count toward the widths of columns.
	assert.Equal(t,
		"  Value │ Meaning\n"+
			"  ──────┼──────────────\n"+
			"  none  │ Do not cache.\n",
		stripAnsiCodes(rendered))
}

func TestRenderMarkdownHeadingInColor(t *testing.T) {
	// Without color, a heading looks like a paragraph. With color, it is bold.
	rendered := renderMarkdownForTest(t, false, "## Title\n")
	assert.Equal(t, "  "+color.New(color.Bold).Sprint("Title")+"\n", rendered)
}
