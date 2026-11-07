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

// A minimal renderer of Markdown for terminals.
//
// Libraries that render Markdown for terminals, such as glamour,
// tend to execute templates with text/template, which can call methods
// by name. That makes the linker keep every exported method
// of every reachable type, which bloats the client binary. So, this file
// uses goldmark only to parse Markdown, and it renders the elements
// that config parameter descriptions are likely to contain.
//
// goldmark.New constructs an HTML renderer, but the linker keeps
// only the renderer's constructor and options, a few KiB. Never render
// with goldmark, such as by calling goldmark.Convert, since that would link
// the rendering code.
//
// goldmark's syntax tree has two kinds of nodes, which render differently:
//
//   - Blocks, such as paragraphs, lists, and block quotes,
//     determine the document's lines and each line's prefix. Each block
//     receives two prefixes of the same width: first, for its first line,
//     and rest, for its other lines. A container, such as a list item
//     or a block quote, extends both for its children. For example,
//     a list item's first line gets a bullet, and its other lines get
//     spaces.
//
//   - Inlines, such as text, emphasis, code spans, and links, become words,
//     styled with ANSI escape codes. When the block that holds them ends,
//     the words are wrapped into lines that fit, and the lines are printed
//     after the block's prefixes. Escape codes occupy no columns,
//     so each word records its width apart from its text,
//     counting each rune as one column.
//
// Code blocks and HTML blocks are printed line for line, without wrapping.
// Tables wrap each cell's words to fit the cell's column.
//
// Rendering recurses down the tree. renderMarkdown parses the document
// and passes it to blocks, which calls block on each child. block recurses
// through blocks into containers. For a paragraph or heading, it calls
// inlines, which calls inline on each child to collect words,
// and then flush, which wraps and prints them. Tables go to table.
//
// goldmark leaves backslash escapes and character references,
// such as "&amp;", in the text and resolves them only when it renders HTML.
// So, this file resolves them itself.

import (
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fatih/color"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

const (
	// The number of columns to wrap text within, including prefixes.
	// Lines that cannot be wrapped, such as those of code blocks,
	// may be wider.
	markdownWidth = 80
	// The indentation of the rendered document, which every prefix
	// starts with.
	markdownMargin = "  "
	// The additional indentation of code blocks.
	markdownCodeIndent = "  "
)

var (
	// The style of code spans and code blocks.
	markdownCodeStyle = []color.Attribute{color.FgMagenta}
	// The style of link destinations and autolinks.
	markdownLinkStyle = []color.Attribute{color.FgBlue, color.Underline}
)

// A word to wrap: a run of text, usually without breaking spaces,
// which wrapping keeps on one line. A word can span several inlines.
// For example, in "set `Origin.Exports`.", the code span and the period
// form one word, so the period cannot wrap onto a line by itself.
type markdownWord struct {
	// The word's text, including escape codes. Each styled piece of it
	// starts and ends with escape codes that turn its style on and off,
	// so that no style leaks into the spaces and prefixes
	// around the word.
	styled string
	// The number of columns that the word occupies,
	// excluding escape codes.
	width int
	// The number of spaces before the word, beyond the one
	// that separates any two words, when the word does not start a line.
	// Only spaces in code spans produce them.
	extraSpaces int
	// Whether this is a hard line break rather than a word.
	lineBreak bool
}

// A line of words, which wrap has joined with spaces. It excludes
// the prefix that it is printed after and, in a table, the padding
// that aligns it.
type markdownLine struct {
	// The line's text, including the words' escape codes.
	styled string
	// The number of columns that the line occupies,
	// excluding escape codes.
	width int
}

// The state of rendering one document.
//
// Blocks print their lines to w as they are rendered. The inlines
// of a paragraph or heading become words, which accumulate until the block
// ends and flush wraps and prints them. A table instead takes
// each cell's words and lays them out itself.
type markdownRenderer struct {
	// Where to print the rendered document.
	w io.Writer
	// The Markdown being rendered. Nodes of the syntax tree refer
	// to their text by its offsets in source.
	source []byte
	// The styles to apply to text, innermost last. styled pushes
	// and pops them.
	styles []color.Attribute
	// The finished words of the paragraph being rendered.
	words []markdownWord
	// The word being built. text adds to it, and endWord moves it
	// to words.
	word markdownWord
	// Whether the text being rendered is in a code span, where runs
	// of spaces are kept.
	code bool
	// The number of lines printed so far.
	printed int
	// The blank line that separates the next block from the one
	// before it, if separate is set. line prints it
	// just before the next line, so that a block that prints nothing
	// gets no separator.
	separator string
	separate  bool
}

// renderMarkdown writes source to w, formatted for a terminal. It wraps
// text and, unless color output is disabled, styles it
// with ANSI escape codes. It prints no blank lines
// before or after the document, so the caller decides how to separate it
// from the surrounding output.
func renderMarkdown(w io.Writer, source string) {
	r := &markdownRenderer{w: w, source: []byte(source)}
	// Also parse tables, from GitHub Flavored Markdown.
	p := goldmark.New(goldmark.WithExtensions(extension.Table)).Parser()
	doc := p.Parse(text.NewReader(r.source))
	r.blocks(doc, markdownMargin, markdownMargin, false)
}

// blocks renders the children of parent, which are blocks,
// after the prefixes first and rest. Unless tight, as in a tight list,
// a blank line separates each child from the next. The blank line gets
// rest, so that, for example, a block quote's bar continues through it.
// first goes to the first line that the children print,
// even if earlier children print nothing, as a paragraph of only an image
// without text does. blocks reports whether it printed any lines.
func (r *markdownRenderer) blocks(parent ast.Node, first, rest string, tight bool) bool {
	start := r.printed
	for c := parent.FirstChild(); c != nil; c = c.NextSibling() {
		// goldmark keeps link reference definitions in the syntax tree,
		// but they render as nothing.
		if c.Kind() == ast.KindLinkReferenceDefinition {
			continue
		}
		if r.printed > start {
			if !tight {
				r.separator, r.separate = rest, true
			}
			first = rest
		}
		r.block(c, first, rest)
	}
	if r.printed == start {
		// Any pending separator is the caller's, which it still needs.
		return false
	}
	// Any pending separator was set for children that printed nothing.
	// Discard it, so that it does not separate this block
	// from whatever the caller prints next.
	r.separate = false
	return true
}

// block renders n, which is a block, after the prefixes first and rest.
// Containers, such as lists and block quotes, extend the prefixes
// and render their children. Paragraphs and headings collect their inlines
// as words and flush them. Tables lay out their cells with table.
// Most other blocks, such as code blocks, are printed line for line.
func (r *markdownRenderer) block(n ast.Node, first, rest string) {
	switch n := n.(type) {
	case *ast.Paragraph, *ast.TextBlock:
		// A TextBlock is a paragraph in a tight list.
		r.inlines(n)
		r.flush(first, rest)
	case *ast.Heading:
		// A heading is bold. Its level is not shown.
		r.styled([]color.Attribute{color.Bold}, func() { r.inlines(n) })
		r.flush(first, rest)
	case *ast.List:
		// Items are separated as blocks are, by blank lines unless the list
		// is tight. An item's first line gets a bullet, or the item's number
		// in an ordered list, and its other lines are indented to match.
		number := n.Start
		for item := n.FirstChild(); item != nil; item = item.NextSibling() {
			if item != n.FirstChild() {
				if !n.IsTight {
					r.separator, r.separate = rest, true
				}
				first = rest
			}
			bullet := "• "
			if n.IsOrdered() {
				// The marker is "." or ")", as in the source.
				bullet = fmt.Sprintf("%d%c ", number, n.Marker)
				number++
			}
			indent := strings.Repeat(" ", utf8.RuneCountInString(bullet))
			// An item that prints nothing, such as an empty one, still gets
			// a line with its bullet.
			if !r.blocks(item, first+bullet, rest+indent, n.IsTight) {
				r.line(first + bullet)
			}
		}
	case *ast.Blockquote:
		// Every line of a block quote, even a blank one, gets a bar.
		r.blocks(n, first+"│ ", rest+"│ ", false)
	case *ast.ThematicBreak:
		// A rule extends to markdownWidth, unless the prefix already does.
		r.line(first + strings.Repeat("─", max(0, markdownWidth-utf8.RuneCountInString(first))))
	case *east.Table:
		r.table(n, first, rest)
	case *ast.FencedCodeBlock, *ast.CodeBlock:
		// Wrapping code would change it, so print it as is,
		// indented further.
		r.lines(n, first+markdownCodeIndent, rest+markdownCodeIndent, markdownCodeStyle)
	default:
		// For example, HTML. Print it as is.
		r.lines(n, first, rest, nil)
		// goldmark keeps the line that closes some HTML blocks
		// apart from the block's other lines.
		if n, ok := n.(*ast.HTMLBlock); ok && n.HasClosure() {
			r.line(rest + printable(strings.TrimRight(string(n.ClosureLine.Value(r.source)), "\r\n")))
		}
	}
}

// lines prints the source lines of n, which is a block,
// after the prefixes first and rest. It styles them with style
// but does not wrap them.
func (r *markdownRenderer) lines(n ast.Node, first, rest string, style []color.Attribute) {
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		segment := lines.At(i)
		line := printable(strings.TrimRight(string(segment.Value(r.source)), "\r\n"))
		if i > 0 {
			first = rest
		}
		r.line(first + applyStyle(style, line))
	}
}

// inlines adds the children of parent, which are inlines, to the paragraph
// being rendered.
func (r *markdownRenderer) inlines(parent ast.Node) {
	for c := parent.FirstChild(); c != nil; c = c.NextSibling() {
		r.inline(c)
	}
}

// inline adds n, which is an inline, to the paragraph being rendered.
// Its text becomes words, and its formatting becomes styles on those words.
// Inlines that a terminal cannot show, such as images, add only their text.
func (r *markdownRenderer) inline(n ast.Node) {
	switch n := n.(type) {
	case *ast.Text:
		// goldmark ends a Text at each line break in the source.
		// A soft line break separates words, as a space does.
		// A hard line break ends the line.
		r.text(textValue(n, r.source))
		if n.HardLineBreak() {
			r.endWord()
			r.words = append(r.words, markdownWord{lineBreak: true})
		} else if n.SoftLineBreak() {
			r.endWord()
		}
	case *ast.String:
		// Text that an extension added, rather than text from the source.
		r.text(string(n.Value))
	case *ast.CodeSpan:
		code := plainText(n, r.source)
		r.styled(markdownCodeStyle, func() {
			// While r.code is set, text keeps runs of spaces.
			r.code = true
			if color.NoColor {
				// Without color, keep the backticks to set the code apart.
				// Join each backtick, and any spaces between it and the code,
				// to the code's first or last word, so that wrapping cannot separate
				// them.
				rest := strings.TrimLeftFunc(code, isBreakingSpace)
				inner := strings.TrimRightFunc(rest, isBreakingSpace)
				r.join("`" + code[:len(code)-len(rest)])
				r.text(inner)
				r.join(rest[len(inner):] + "`")
			} else {
				r.text(code)
			}
			r.code = false
		})
	case *ast.Emphasis:
		// *Emphasis* is italic, and **strong emphasis** is bold.
		attr := color.Italic
		if n.Level > 1 {
			attr = color.Bold
		}
		r.styled([]color.Attribute{attr}, func() {
			// Without color, keep the asterisks to set the text apart,
			// as code spans keep their backticks. Join each
			// to the text's first or last word, so that wrapping cannot separate
			// them.
			delimiter := strings.Repeat("*", n.Level)
			if color.NoColor {
				r.join(delimiter)
			}
			r.inlines(n)
			if color.NoColor {
				r.join(delimiter)
			}
		})
	case *ast.Link:
		// Add the link's text and then, as a separate word, its destination
		// in parentheses, unless the destination is empty or the text
		// already shows it, as in [example.com](example.com).
		r.inlines(n)
		destination := unescapeMarkdown(n.Destination)
		if destination != "" && destination != plainText(n, r.source) {
			r.endWord()
			r.text("(")
			r.styled(markdownLinkStyle, func() { r.text(destination) })
			r.text(")")
		}
	case *ast.AutoLink:
		// For example, <https://example.com>, which renders
		// without its angle brackets.
		r.styled(markdownLinkStyle, func() { r.text(string(n.Label(r.source))) })
	case *ast.RawHTML:
		// Add it as is. For example, "<path>" is likely a placeholder
		// rather than HTML.
		for i := 0; i < n.Segments.Len(); i++ {
			segment := n.Segments.At(i)
			r.text(string(segment.Value(r.source)))
		}
	default:
		// For example, an image. Add only its text.
		r.inlines(n)
	}
}

// styled calls render with style applied to the text that render adds,
// in addition to any styles that already apply.
func (r *markdownRenderer) styled(style []color.Attribute, render func()) {
	depth := len(r.styles)
	r.styles = append(r.styles, style...)
	render()
	r.styles = r.styles[:depth]
}

// text adds s, in the current style, to the paragraph being rendered.
// Whitespace in s, other than no-break spaces, separates words.
// Outside code spans, a run of whitespace is one space.
func (r *markdownRenderer) text(s string) {
	for s != "" {
		// Add the text up to the next breaking space to the current word.
		end := strings.IndexFunc(s, isBreakingSpace)
		if end < 0 {
			end = len(s)
		}
		if end > 0 {
			r.join(s[:end])
			s = s[end:]
		}
		// The space ends the current word, if there is one. In a code span,
		// a space that does not end a word, such as the second of two,
		// widens the gap before the next word instead.
		if s != "" {
			if r.code && r.word.width == 0 {
				r.word.extraSpaces++
			}
			r.endWord()
			_, size := utf8.DecodeRuneInString(s)
			s = s[size:]
		}
	}
}

// join adds s, in the current style, to the word being built. Unlike text,
// it keeps s in one word, even if s contains breaking spaces, which become
// spaces. Some breaking spaces, such as line breaks, are control characters,
// so they become spaces before printable would replace them.
func (r *markdownRenderer) join(s string) {
	s = printable(strings.Map(func(c rune) rune {
		if isBreakingSpace(c) {
			return ' '
		}
		return c
	}, s))
	r.word.styled += applyStyle(r.styles, s)
	r.word.width += utf8.RuneCountInString(s)
}

// printable returns s with each control character other than tab replaced
// by U+FFFD, so that the only escape codes in the output are those
// that applyStyle adds.
func printable(s string) string {
	return strings.Map(func(c rune) rune {
		if c != '\t' && unicode.IsControl(c) {
			return utf8.RuneError
		}
		return c
	}, s)
}

// isBreakingSpace reports whether c is whitespace at which a line may wrap.
// No-break spaces, such as those that "&nbsp;" produces, are not.
func isBreakingSpace(c rune) bool {
	switch c {
	case '\u00a0', '\u2007', '\u202f':
		return false
	}
	return unicode.IsSpace(c)
}

// endWord ends the word being built, if there is one. Otherwise, it keeps
// the extra spaces counted for the next word.
func (r *markdownRenderer) endWord() {
	if r.word.width > 0 {
		r.words = append(r.words, r.word)
		r.word = markdownWord{}
	}
}

// takeWords ends the paragraph being rendered and returns its words.
// Then, it starts a new paragraph.
func (r *markdownRenderer) takeWords() []markdownWord {
	r.endWord()
	words := r.words
	r.words = nil
	// A code span that ends in spaces may leave extra spaces counted
	// for the next word. Discard them, so that they cannot carry
	// into the next paragraph.
	r.word = markdownWord{}
	return words
}

// flush prints the paragraph being rendered, wrapped to fit,
// after the prefixes first and rest. Then, it starts a new paragraph.
func (r *markdownRenderer) flush(first, rest string) {
	// first is as wide as rest, so either determines the width left.
	for i, line := range wrap(r.takeWords(), markdownWidth-utf8.RuneCountInString(rest)) {
		if i > 0 {
			first = rest
		}
		r.line(first + line.styled)
	}
}

// wrap joins words into lines that fit in width columns. A word
// that is wider than width gets a line to itself, and a hard line break
// ends a line, even an empty one.
func wrap(words []markdownWord, width int) []markdownLine {
	var lines []markdownLine
	var line markdownLine
	for _, word := range words {
		if word.lineBreak {
			lines = append(lines, line)
			line = markdownLine{}
			continue
		}
		// If the word does not fit on the line, start a new one. The spaces
		// before a word are dropped at the start of a line.
		spaces := 1 + word.extraSpaces
		if line.width > 0 && line.width+spaces+word.width > width {
			lines = append(lines, line)
			line = markdownLine{}
		}
		if line.width > 0 {
			line.styled += strings.Repeat(" ", spaces)
			line.width += spaces
		}
		line.styled += word.styled
		line.width += word.width
	}
	if line.width > 0 {
		lines = append(lines, line)
	}
	return lines
}

// table renders n, which is a table, after the prefixes first and rest.
// Each column is as wide as its widest cell, unless that would make
// the table too wide. Then, the widest columns are narrowed,
// and their cells wrapped.
func (r *markdownRenderer) table(n *east.Table, first, rest string) {
	columns := len(n.Alignments)
	// The words of each row's cells. The first row is the header.
	var rows [][][]markdownWord
	// Each column's width if its cells were not wrapped.
	natural := make([]int, columns)
	// Each column's minimum width: that of its widest word,
	// which wrapping cannot split.
	minimum := make([]int, columns)

	// Render the words of each cell, and measure them. Ignore any cells
	// beyond the columns that the table's delimiter row defines.
	for row := n.FirstChild(); row != nil; row = row.NextSibling() {
		var style []color.Attribute
		if _, ok := row.(*east.TableHeader); ok {
			style = []color.Attribute{color.Bold}
		}
		cells := make([][]markdownWord, columns)
		col := 0
		for cell := row.FirstChild(); cell != nil && col < columns; cell = cell.NextSibling() {
			// Render the cell as a paragraph, and then take its words,
			// which flush would otherwise print.
			r.styled(style, func() { r.inlines(cell) })
			cells[col] = r.takeWords()
			// Measure the cell as wrap lays it out when nothing
			// makes it wrap.
			for _, line := range wrap(cells[col], math.MaxInt) {
				natural[col] = max(natural[col], line.width)
			}
			for _, word := range cells[col] {
				minimum[col] = max(minimum[col], word.width)
			}
			col++
		}
		rows = append(rows, cells)
	}

	// Fit the columns, and the " │ " separators between them,
	// within the width that the prefix leaves.
	separators := 3 * max(0, columns-1)
	widths := tableWidths(natural, minimum, markdownWidth-utf8.RuneCountInString(rest)-separators)
	printLine := func(s string) {
		r.line(first + s)
		first = rest
	}

	// Print each row in as many lines as its tallest cell needs
	// once wrapped, padding shorter cells with blank lines
	// at the bottom.
	for i, cells := range rows {
		lines := make([][]markdownLine, columns)
		height := 1
		for col, words := range cells {
			lines[col] = wrap(words, widths[col])
			height = max(height, len(lines[col]))
		}
		for j := 0; j < height; j++ {
			parts := make([]string, columns)
			for col := range parts {
				var line markdownLine
				if j < len(lines[col]) {
					line = lines[col][j]
				}
				parts[col] = alignCell(line, widths[col], n.Alignments[col])
			}
			printLine(strings.Join(parts, " │ "))
		}
		// A rule separates the header from the other rows.
		if i == 0 {
			rules := make([]string, columns)
			for col, width := range widths {
				rules[col] = strings.Repeat("─", width)
			}
			printLine(strings.Join(rules, "─┼─"))
		}
	}
}

// tableWidths returns the widths of a table's columns,
// given their natural and minimum widths, so that their total
// is at most width, if possible. It repeatedly narrows by one
// the widest column that is still wider than its minimum.
func tableWidths(natural, minimum []int, width int) []int {
	widths := slices.Clone(natural)
	total := 0
	for _, w := range widths {
		total += w
	}
	for ; total > width; total-- {
		widest := -1
		for col, w := range widths {
			if w > minimum[col] && (widest < 0 || w > widths[widest]) {
				widest = col
			}
		}
		if widest < 0 {
			break
		}
		widths[widest]--
	}
	return widths
}

// alignCell pads line with spaces to width, as align says.
func alignCell(line markdownLine, width int, align east.Alignment) string {
	padding := max(0, width-line.width)
	left := 0
	switch align {
	case east.AlignRight:
		left = padding
	case east.AlignCenter:
		left = padding / 2
	}
	return strings.Repeat(" ", left) + line.styled + strings.Repeat(" ", padding-left)
}

// line prints s as a line of the rendered document. It trims
// trailing spaces, such as those of a blank line's prefix
// or a table cell's padding.
func (r *markdownRenderer) line(s string) {
	if r.separate {
		r.separate = false
		r.line(r.separator)
	}
	fmt.Fprintln(r.w, strings.TrimRight(s, " "))
	r.printed++
}

// applyStyle returns s between escape codes that turn style on and off.
// If style or s is empty, or if color output is disabled, it returns s
// as is.
func applyStyle(style []color.Attribute, s string) string {
	if len(style) == 0 || s == "" {
		return s
	}
	return color.New(style...).Sprint(s)
}

// plainText returns the text of n's descendants, without any formatting.
func plainText(n ast.Node, source []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if t, ok := n.(*ast.Text); ok && entering {
			b.WriteString(textValue(t, source))
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

// textValue returns the text that n represents. Except in raw text,
// such as code spans, it resolves backslash escapes
// and character references.
func textValue(n *ast.Text, source []byte) string {
	if n.IsRaw() {
		return string(n.Value(source))
	}
	return unescapeMarkdown(n.Value(source))
}

// unescapeMarkdown resolves backslash escapes and character references
// in s. It does both in one pass, so that an escaped "&" stays literal.
func unescapeMarkdown(s []byte) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		// A backslash escapes ASCII punctuation, and only that.
		if c == '\\' && i+1 < len(s) && util.IsPunct(s[i+1]) {
			i++
			b.WriteByte(s[i])
			continue
		}
		if c == '&' {
			if value, n := characterReference(s[i:]); n > 0 {
				b.WriteString(value)
				i += n - 1
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// characterReference parses the character reference, such as "&amp;",
// "&#38;", or "&#x26;", at the start of s. It returns the text
// that the reference represents and the reference's length, or a length
// of 0 if s does not start with a reference.
//
// Unlike html.UnescapeString, it requires the terminating ";",
// as CommonMark does, so that, for example, "?a=1&region=us" is left alone.
func characterReference(s []byte) (string, int) {
	// Determine whether s might start with a named, decimal,
	// or hexadecimal reference. CommonMark limits the number of digits
	// in numeric ones.
	start, base, maxDigits, valid := 1, 0, 0, util.IsAlphaNumeric
	if len(s) > 2 && s[1] == '#' {
		start, base, maxDigits, valid = 2, 10, 7, util.IsNumeric
		if s[2] == 'x' || s[2] == 'X' {
			start, base, maxDigits, valid = 3, 16, 6, util.IsHexDecimal
		}
	}
	// The name or digits must not be empty and must end with ";".
	end, ok := util.ReadWhile(s, [2]int{start, len(s)}, valid)
	if !ok || end >= len(s) || s[end] != ';' {
		return "", 0
	}
	name := string(s[start:end])
	// A named reference must be one that HTML5 defines.
	if base == 0 {
		entity, ok := util.LookUpHTML5EntityByName(name)
		if !ok {
			return "", 0
		}
		return string(entity.Characters), end + 1
	}
	if len(name) > maxDigits {
		return "", 0
	}
	// A numeric reference to 0, to a surrogate, or beyond Unicode
	// represents U+FFFD.
	v, _ := strconv.ParseUint(name, base, 32)
	if v > unicode.MaxRune {
		return string(utf8.RuneError), end + 1
	}
	return string(util.ToValidRune(rune(v))), end + 1
}
