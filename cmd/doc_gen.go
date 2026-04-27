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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra/doc"
)

// angleTagRe matches bare angle-bracket identifiers that MDX would interpret as
// JSX tags (e.g. <client-id>, <path>, <pelican-url>).
var angleTagRe = regexp.MustCompile(`<([a-zA-Z][a-zA-Z0-9_-]*)>`)

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

	// Override rootCmd.Use so Cobra names generated files correctly (e.g.
	// "pelican-server_origin_serve.md" rather than a temp-binary path).
	rootCmd.Use = docBinaryName

	// docPathRoot is the site-relative path used in generated hyperlinks.
	// Strip the leading "docs/app/" prefix so that e.g.
	// "docs/app/commands-reference/pelican" becomes
	// "commands-reference/pelican".
	docPathRoot := strings.TrimPrefix(filepath.ToSlash(outputDir), "docs/app/")

	// Generate a markdown file per command, with custom file names and content wrapper
	linkHandler := func(name string) string {
		// Cobra passes names like "pelican-server_origin_serve.md"; strip the
		// binary-name prefix so only the subcommand path remains.
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if base == docBinaryName {
			base = ""
		} else {
			base = strings.TrimPrefix(base, docBinaryName+"_")
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

	if err := postProcessMdxFiles(resolvedDir); err != nil {
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
		if len(segments) > 0 && segments[0] == docBinaryName {
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
			if entry.IsDir() {
				subdirs = append(subdirs, entry.Name())
			}
		}

		if len(subdirs) > 0 {
			metaFilePath := filepath.Join(path, "_meta.js")

			relPath, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}

			commandPrefix := docBinaryName
			if relPath != "." {
				commandPrefix += " " + strings.ReplaceAll(relPath, string(filepath.Separator), " ")
			}

			content := "export default {\n"
			for _, subdir := range subdirs {
				title := commandPrefix + " " + subdir
				content += fmt.Sprintf("    \"%s\": \"%s\",\n", subdir, title)
			}
			content += "}\n"

			if err := os.WriteFile(metaFilePath, []byte(content), 0644); err != nil {
				return err
			}
		}
		return nil
	})
}

func postProcessMdxFiles(dir string) error {
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

			// Trim trailing spaces on each line
			lines := strings.Split(string(content), "\n")
			for i, line := range lines {
				lines[i] = strings.TrimRight(line, " \t")
			}
			fullContent := strings.Join(lines, "\n")

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
