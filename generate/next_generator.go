package main

// This should not be included in any release of pelican

import (
	"log"
	"os"
	"path/filepath"
)

// Generate a placeholder file under web_ui/frontend/out so that
// we can build Go without error. This is mainly for the linter
// GitHub Action that doesn't need frontend to be built. Refer to
// linter GHA for details.
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
