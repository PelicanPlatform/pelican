package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// angleTagRe matches bare angle-bracket identifiers that MDX would interpret as
// JSX tags (e.g. <client-id>, <path>, <pelican-url>).
var angleTagRe = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9_-]*)>`)

// hiddenFromDocs lists command paths (relative to the docs root, using forward
// slashes) whose generated documentation pages should remain on disk and
// remain reachable by direct URL, but should not be discoverable via the
// site's navigation. Use this for features that are not yet ready for general
// use but where targeted users (e.g., bug-fix testers) still need a link to
// the docs.
//
// Effects of inclusion:
//   - The on-disk page.mdx files for the command (and its subcommands) are
//     still generated, so links like /commands-reference/<cmd>/ continue to
//     resolve and can be shared directly. This works even when the cobra
//     command itself is marked Hidden (so it doesn't appear in `pelican -h`):
//     during doc generation we temporarily flip Hidden off so cobra's
//     generator descends into the command and emits all its pages.
//   - The corresponding entry is omitted from the parent's _meta.js sidebar.
//   - The corresponding "SEE ALSO" bullet line is stripped from the parent
//     command's page.mdx so the page does not advertise the hidden command.
var hiddenFromDocs = map[string]bool{
	// rclone integration is not yet functional.
	"rclone": true,
	// SSH origin backend is not yet functional.
	"origin/ssh-auth": true,
}

// generateCLIDocs creates per-command docs under the given directory. If the path
// is relative, it is resolved against the repository root (directory containing go.mod).
func generateCLIDocs(outputDir string) error {
	resolvedDir, err := resolveOutputPath(outputDir)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(resolvedDir, 0o755); err != nil {
		return err
	}

	docPathRoot := filepath.Base(outputDir)

	// Generate a markdown file per command, with custom file names and content wrapper
	linkHandler := func(name string) string {
		// Cobra passes names like "pelican_serve.md"; strip root prefix but keep underscores so we can group by tokens
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if base == "pelican" {
			base = ""
		} else {
			base = strings.TrimPrefix(base, "pelican_")
		}
		path := strings.ReplaceAll(base, "_", "/")
		// Must be an absolute path from the site root
		if path == "" {
			return fmt.Sprintf("/%s/", docPathRoot)
		}
		return fmt.Sprintf("/%s/%s/", docPathRoot, path)
	}

	filePrepender := func(filename string) string {
		// Create a minimal MDX frontmatter; derive a title from filename
		title := filename
		if base := filepath.Base(filename); base != "" {
			title = strings.TrimSuffix(base, filepath.Ext(base))
			title = strings.ReplaceAll(title, "_", " ")
			title = strings.ReplaceAll(title, "-", " ")
			title = strings.ToLower(title)
		}
		return fmt.Sprintf("---\ntitle: %s\n---\n\n", title)
	}

	// Cobra's doc generator skips commands whose Hidden field is true (and,
	// transitively, all of their subcommands). For features in hiddenFromDocs
	// we still want the pages generated so testers can reach them via direct
	// URLs, so temporarily un-hide them for the duration of generation.
	restoreHidden := temporarilyUnhideForDocs(rootCmd)
	defer restoreHidden()

	// Cobra writes files directly to the destination directory (with .md extension)
	if err := doc.GenMarkdownTreeCustom(rootCmd, resolvedDir, filePrepender, linkHandler); err != nil {
		return err
	}

	// Rename generated .md files to .mdx so links and index work as expected
	if err := renameMdToMdx(resolvedDir); err != nil {
		return err
	}

	// Group by command tokens: e.g., object/get -> object/get/page.mdx
	if err := enforceAppRouterLayout(resolvedDir); err != nil {
		return err
	}

	if err := generateMetaFiles(resolvedDir); err != nil {
		return err
	}

	if err := postProcessMdxFiles(resolvedDir, docPathRoot); err != nil {
		return err
	}

	return nil
}

// renameMdToMdx renames all .md files in dir to .mdx
func renameMdToMdx(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".md" {
			continue
		}
		oldPath := filepath.Join(dir, name)
		newPath := filepath.Join(dir, strings.TrimSuffix(name, ".md")+".mdx")
		if err := os.Rename(oldPath, newPath); err != nil {
			return err
		}
	}
	return nil
}

// enforceAppRouterLayout moves each command .mdx into nested subfolders based on underscore tokens, ending with page.mdx
func enforceAppRouterLayout(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".mdx" || name == "page.mdx" {
			continue
		}
		base := strings.TrimSuffix(name, ".mdx")
		// Build nested path from underscore-delimited tokens
		segments := strings.Split(base, "_")
		if len(segments) > 0 && segments[0] == "pelican" {
			segments = segments[1:]
		}
		// Create nested directory path
		targetDir := filepath.Join(append([]string{dir}, segments...)...)
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return err
		}
		src := filepath.Join(dir, name)
		dst := filepath.Join(targetDir, "page.mdx")
		_ = os.Remove(dst)
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}
	return nil
}

// resolveOutputPath returns an absolute path for the output. If the provided path
// is absolute, it is returned as-is. If it is relative, we attempt to resolve it
// relative to the repository root (detected by locating go.mod). If no repo root
// can be determined, it is resolved relative to the current working directory.
func resolveOutputPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}

	repoRoot, err := findRepoRoot()
	if err == nil && repoRoot != "" {
		return filepath.Join(repoRoot, path), nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(cwd, path), nil
}

// findRepoRoot walks up from the current working directory to find a directory
// containing go.mod and returns that directory path.
func findRepoRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := cwd
	for {
		if fileExists(filepath.Join(dir, "go.mod")) {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir { // reached filesystem root
			return "", errors.New("repository root not found (no go.mod)")
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func generateMetaFiles(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}

		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		var subdirs []string
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			subdirs = append(subdirs, entry.Name())
		}

		if len(subdirs) > 0 {
			metaFilePath := filepath.Join(path, "_meta.js")

			relPath, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}

			commandPrefix := "pelican"
			if relPath != "." {
				commandPrefix += " " + strings.ReplaceAll(relPath, string(filepath.Separator), " ")
			}

			content := "export default {\n"
			for _, subdir := range subdirs {
				relEntry, err := filepath.Rel(dir, filepath.Join(path, subdir))
				if err != nil {
					return err
				}
				if hiddenFromDocs[filepath.ToSlash(relEntry)] {
					// Nextra 4: { display: 'hidden' } keeps the page reachable
					// by direct URL but removes it from the sidebar navigation.
					content += fmt.Sprintf("    \"%s\": { display: 'hidden' },\n", subdir)
				} else {
					title := commandPrefix + " " + subdir
					content += fmt.Sprintf("    \"%s\": \"%s\",\n", subdir, title)
				}
			}
			content += "}\n"

			if err := os.WriteFile(metaFilePath, []byte(content), 0644); err != nil {
				return err
			}
		}
		return nil
	})
}

func postProcessMdxFiles(dir string, docPathRoot string) error {
	// Build the set of doc-root-relative URL paths whose SEE ALSO references
	// should be stripped from generated page.mdx files.
	hiddenURLs := make(map[string]bool, len(hiddenFromDocs))
	for relPath := range hiddenFromDocs {
		hiddenURLs[fmt.Sprintf("/%s/%s/", docPathRoot, relPath)] = true
	}

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".mdx") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			if len(content) == 0 {
				return nil
			}

			// Trim trailing spaces on each line, and drop SEE ALSO bullets that
			// reference hidden-from-docs commands.
			lines := strings.Split(string(content), "\n")
			filtered := make([]string, 0, len(lines))
			for _, line := range lines {
				trimmed := strings.TrimRight(line, " \t")
				if isHiddenSeeAlsoLine(trimmed, hiddenURLs) {
					continue
				}
				filtered = append(filtered, trimmed)
			}
			fullContent := strings.Join(filtered, "\n")

			// Ensure single newline at EOF
			fullContent = strings.TrimRight(fullContent, "\n") + "\n"

			// Escape bare angle-bracket identifiers in prose sections so
			// MDX does not try to parse them as JSX tags. Code fences are
			// left untouched.
			fullContent = escapeMdxAngleBrackets(fullContent)

			if string(content) != fullContent {
				info, err := d.Info()
				if err != nil {
					return err
				}
				if err := os.WriteFile(path, []byte(fullContent), info.Mode()); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// escapeMdxAngleBrackets replaces bare angle-bracket identifiers (e.g. <path>,
// <client-id>) with HTML entities so that MDX/JSX parsers do not interpret them
// as JSX tags. Lines inside code fences (delimited by ```) are left unchanged
// because their content is rendered literally by the markdown renderer.
func escapeMdxAngleBrackets(content string) string {
	lines := strings.Split(content, "\n")
	inCodeFence := false
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "```") {
			inCodeFence = !inCodeFence
			// Don't modify the fence delimiter line itself.
			continue
		}
		if !inCodeFence {
			lines[i] = angleTagRe.ReplaceAllString(line, "&lt;$1&gt;")
		}
	}
	return strings.Join(lines, "\n")
}

// isHiddenSeeAlsoLine reports whether the given line is a generated SEE ALSO
// bullet referencing one of the hidden-from-docs URL paths.
func isHiddenSeeAlsoLine(line string, hiddenURLs map[string]bool) bool {
	if !strings.HasPrefix(line, "* [") {
		return false
	}
	open := strings.Index(line, "](")
	if open < 0 {
		return false
	}
	rest := line[open+2:]
	close := strings.Index(rest, ")")
	if close < 0 {
		return false
	}
	url := rest[:close]
	return hiddenURLs[url]
}

// temporarilyUnhideForDocs flips Hidden=false on the cobra commands whose
// docs-relative paths appear in hiddenFromDocs, so cobra's documentation
// generator emits pages for them and their subcommands. The returned function
// restores the original Hidden value on each affected command.
func temporarilyUnhideForDocs(root *cobra.Command) func() {
	var toRestore []*cobra.Command
	for relPath := range hiddenFromDocs {
		c := findCommandByPath(root, relPath)
		if c != nil && c.Hidden {
			c.Hidden = false
			toRestore = append(toRestore, c)
		}
	}
	return func() {
		for _, c := range toRestore {
			c.Hidden = true
		}
	}
}

// findCommandByPath walks the command tree under root following the given
// slash-separated path of command names. Returns nil if any segment is not
// found.
func findCommandByPath(root *cobra.Command, path string) *cobra.Command {
	cur := root
	for _, seg := range strings.Split(path, "/") {
		var next *cobra.Command
		for _, child := range cur.Commands() {
			if child.Name() == seg {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}
