package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra/doc"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// copied from generate/next_generator.go
func GenPlaceholderPathForNext() {
	dir := "../web_ui/frontend/out"
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Fatalf("error: %v", err)
	}

	filePath := filepath.Join(dir, "placeholder")

	file, err := os.Create(filePath)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	file.Close()
}

// generateCLIDocs creates per-command docs under the given directory. If the path
// is relative, it is resolved against the repository root (directory containing go.mod).
func generateCLIDocs(outputDir string) error {
	GenPlaceholderPathForNext()
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
		path := strings.ReplaceAll(base, "_", "/")
		// Must be an absolute path from the site root
		result := fmt.Sprintf("/%s/%s/", docPathRoot, path)
		return result
	}

	filePrepender := func(filename string) string {
		// Create a minimal MDX frontmatter; derive a title from filename
		title := filename
		if base := filepath.Base(filename); base != "" {
			title = strings.TrimSuffix(base, filepath.Ext(base))
			title = strings.ReplaceAll(title, "_", " ")
			title = strings.ReplaceAll(title, "-", " ")
			title = cases.Title(language.English).String(title)
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
		if len(segments) == 0 {
			continue
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
